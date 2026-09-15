"""Celery worker for browser execution."""
from celery import Celery
from datetime import UTC, datetime
from sqlalchemy import update
from sqlalchemy.orm import Session
from pathlib import Path
from typing import Dict, Any
import hashlib
import os

from backend_api.db.session import get_db
from backend_api.models.test_case import TestCase, TestCaseStatus
from backend_api.models.execution import Execution, OracleStatus
from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from browser_workers.executor import BrowserExecutor
from backend_api.utils.logger import logger
from backend_api.config import settings
from backend_api.utils.scope_guard import is_endpoint_in_scope
from backend_api.utils.rate_limiter import rate_limiter, CircuitOpenError
from backend_api.utils.log_serializer import (
    sanitize_execution_logs,
    serialize_execution_logs,
)

# Initialize Celery app
is_eager = os.getenv('CELERY_TASK_ALWAYS_EAGER', 'False').lower() in ('true', '1', 't')

celery_app = Celery(
    'browser_workers',
    broker=settings.REDIS_URL,
    backend=None if is_eager else settings.REDIS_URL
)

# Celery configuration
celery_app.conf.update(
    task_always_eager=is_eager,
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    broker_transport_options={'visibility_timeout': 7200},
    task_routes={'execute_test_case': {'queue': 'browser'}},
)


def _emit_case_event(
    test_case: TestCase,
    event_type: str,
    message: str,
    *,
    level: str = "INFO",
    detail: str | None = None,
    data: Dict[str, Any] | None = None,
) -> None:
    """Persist a complete test-case lifecycle event without leaking credentials."""
    try:
        from backend_api.services.log_service import LogService

        endpoint = getattr(test_case, "endpoint", None)
        param = getattr(test_case, "param", None)
        context = getattr(test_case, "context", None)
        target = getattr(endpoint, "target", None) if endpoint else None
        payload = str(getattr(test_case, "payload", "") or "")
        metadata = (
            test_case.research_metadata
            if isinstance(getattr(test_case, "research_metadata", None), dict)
            else {}
        )
        LogService.emit(
            level,
            "browser.case",
            message,
            detail=detail,
            experiment_id=getattr(test_case, "experiment_id", None),
            target_id=getattr(endpoint, "target_id", None),
            data={
                "event_type": event_type,
                "test_case_id": getattr(test_case, "id", None),
                "attempt": int(getattr(test_case, "attempt_count", 0) or 0),
                "status": (
                    test_case.status.value
                    if hasattr(getattr(test_case, "status", None), "value")
                    else str(getattr(test_case, "status", "unknown"))
                ),
                "method": getattr(endpoint, "method", None),
                "endpoint": getattr(endpoint, "url_pattern", None),
                "target": getattr(target, "base_url", None),
                "param": getattr(param, "name", None),
                "param_location": getattr(param, "location", None),
                "context_id": getattr(test_case, "context_id", None),
                "context_type": getattr(context, "context_type", None),
                "technique": getattr(test_case, "technique", None),
                "classification": metadata.get("classification") or metadata.get("auditor") or (
                    "xss" if getattr(test_case, "context_id", None) else "unclassified_probe"
                ),
                "research_hypothesis_id": getattr(test_case, "research_hypothesis_id", None),
                "payload": payload,
                "payload_sha256": hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest(),
                "oracle_token_sha256": hashlib.sha256(
                    str(getattr(test_case, "token", "")).encode("utf-8", errors="replace")
                ).hexdigest(),
                **(data or {}),
            },
        )
    except Exception as log_error:
        logger.debug("Could not persist case lifecycle event: %s", log_error)

def context_already_confirmed(db: Session, test_case) -> bool:
    """True if this (param, context) already has a CONFIRMED oracle HIT from a sibling test case.

    Early-exit signal: once a parameter is proven vulnerable in a given injection context, firing
    the remaining candidate payloads only re-proves the same bug at the cost of expensive browser
    executions. Keyed on ``context_id`` so a different context is still tested — no winrate loss.
    """
    if getattr(test_case, "context_id", None) is None:
        return False
    return (
        db.query(Execution.id)
        .join(TestCase, Execution.test_case_id == TestCase.id)
        .filter(TestCase.context_id == test_case.context_id)
        .filter(TestCase.id != test_case.id)
        .filter(Execution.oracle_status == OracleStatus.HIT)
        .first()
        is not None
    )


def reconcile_persisted_oracle_hit(db: Session, test_case_id: int) -> bool:
    """Return the authoritative callback result after a browser run.

    Oracle callbacks are handled in a different request/database session while
    Chromium is running.  The browser executor can therefore finish with its
    local ``oracle_hit=False`` even though the callback has already consumed the
    token and persisted a HIT.  End this worker session's read transaction and
    re-read both durable proof signals before classifying the attempt.
    """
    db.commit()
    db.expire_all()

    persisted_hit = (
        db.query(Execution.id)
        .filter(
            Execution.test_case_id == test_case_id,
            Execution.oracle_status == OracleStatus.HIT,
        )
        .first()
        is not None
    )
    if persisted_hit:
        return True

    # The execution callback atomically consumes the token before writing its
    # Execution row.  This closes the very small commit window between those
    # operations without mistaking taint-only telemetry for execution.
    consumed_at = (
        db.query(TestCase.token_consumed_at)
        .filter(TestCase.id == test_case_id)
        .scalar()
    )
    return consumed_at is not None


def claim_runtime_lineage_probe_attempt(db: Session, test_case: TestCase) -> bool:
    """Durably reserve the one bounded A/A/B series allowed for a test case."""
    from backend_api.services.run_budget_service import RunBudgetService

    return RunBudgetService.reserve_runtime_lineage_probe(db, test_case)


def claim_runtime_lineage_probe_attempt_if_eligible(
    db: Session,
    test_case: TestCase,
    executor: Any,
    test_case_data: Dict[str, Any],
    primary_result: Dict[str, Any],
    *,
    param_name: str,
    param_location: str,
) -> bool:
    """Reserve an A/A/B attempt only after its pure safety preflight passes."""
    from browser_workers.runtime_lineage_probe_runner import (
        can_run_safe_url_probe_series,
    )

    if not can_run_safe_url_probe_series(
        executor,
        test_case_data,
        primary_result,
        param_name=param_name,
        param_location=param_location,
    ):
        return False
    return claim_runtime_lineage_probe_attempt(db, test_case)


def browser_rate_limit_signal(result: Dict[str, Any]) -> tuple[bool, float | None]:
    """Extract the worker's bounded WAF/rate-limit signal from one result."""
    status_code = result.get("status_code")
    headers = result.get("headers") if isinstance(result.get("headers"), dict) else {}
    is_rate_limited = status_code in {403, 429}
    retry_after_secs = None
    retry_after = headers.get("retry-after")
    if is_rate_limited and retry_after is not None:
        try:
            retry_after_secs = max(0.0, min(86_400.0, float(retry_after)))
        except (TypeError, ValueError, OverflowError):
            retry_after_secs = None
    if not is_rate_limited:
        logs = result.get("logs")
        errors = logs.get("errors", []) if isinstance(logs, dict) else []
        for error in errors if isinstance(errors, list) else []:
            lowered = str(error).lower()
            if any(marker in lowered for marker in (
                "429", "too many requests", "rate limit", "access denied", "forbidden",
            )):
                is_rate_limited = True
                break
    return is_rate_limited, retry_after_secs


def _check_experiment_completion(db: Session, experiment_id: int):
    """Finalize a terminal execution plan without overstating its evidence.

    ``COMPLETED`` means the scheduled work ran without an operational error. It
    does *not* mean the target is clean. Evidence certainty is stored separately
    in ``limits.coverage`` and ``limits.done.safe_claim``.
    """
    try:
        from datetime import UTC, datetime
        from backend_api.models.experiment import Experiment, ExperimentStatus
        from backend_api.models.test_case import TestCase, TestCaseStatus
        from backend_api.services.fuzzing_service import FuzzingService
        
        non_final_count = db.query(TestCase).filter(
            TestCase.experiment_id == experiment_id,
            TestCase.status.in_([TestCaseStatus.PENDING, TestCaseStatus.QUEUED, TestCaseStatus.RUNNING])
        ).count()
        
        if non_final_count == 0:
            experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
            if experiment and experiment.status == ExperimentStatus.RUNNING:
                limits = dict(experiment.limits) if isinstance(experiment.limits, dict) else {}
                previous_coverage = (
                    limits.get("coverage") if isinstance(limits.get("coverage"), dict) else {}
                )
                total_case_count = db.query(TestCase.id).filter(
                    TestCase.experiment_id == experiment_id,
                ).count()
                execution_error_count = (
                    db.query(Execution.id)
                    .join(TestCase, Execution.test_case_id == TestCase.id)
                    .filter(TestCase.experiment_id == experiment_id)
                    .filter(Execution.oracle_status == OracleStatus.ERROR)
                    .count()
                )
                failed_case_count = db.query(TestCase.id).filter(
                    TestCase.experiment_id == experiment_id,
                    TestCase.status == TestCaseStatus.FAILED,
                ).count()
                run_succeeded = execution_error_count == 0 and failed_case_count == 0

                # The reachability ledger is deliberately conservative: a
                # browser MISS is INCONCLUSIVE, never proof that a sink is safe.
                try:
                    from backend_api.services.ledger_service import LedgerService

                    ledger_report = LedgerService.coverage_for_experiment(db, experiment_id)
                except Exception as ledger_error:
                    logger.warning(
                        "Could not build evidence ledger for experiment %s: %s",
                        experiment_id,
                        ledger_error,
                    )
                    ledger_report = {
                        "coverage": {},
                        "confirmed": [],
                        "gaps": [],
                        "trustworthy_clean": False,
                    }

                coverage = {
                    **previous_coverage,
                    "complete": True,
                    "execution_plan_complete": True,
                    "planned_cases": total_case_count,
                    "terminal_cases": total_case_count,
                    "evidence": ledger_report.get("coverage") or {},
                    "confirmed": ledger_report.get("confirmed") or [],
                    "gaps": ledger_report.get("gaps") or [],
                    "trustworthy_clean": bool(
                        total_case_count > 0 and ledger_report.get("trustworthy_clean")
                    ),
                }
                limits["coverage"] = coverage
                experiment.status = ExperimentStatus.COMPLETED if run_succeeded else ExperimentStatus.FAILED
                experiment.completed_at = datetime.now(UTC)
                db.commit()
                logger.info(
                    "Experiment %s finalized as %s (execution_plan_complete=True, execution_errors=%s, failed_cases=%s). "
                    "Correlating valid evidence...",
                    experiment_id,
                    experiment.status.value,
                    execution_error_count,
                    failed_case_count,
                )
                from backend_api.models.run_state import RunStageName
                from backend_api.services.run_state_service import RunStateService
                RunStateService.complete_stage(db, experiment_id, RunStageName.EXECUTION)
                RunStateService.claim_stage(db, experiment_id, RunStageName.CORRELATION, "completion-worker")
                RunStateService.record_progress(
                    db,
                    experiment_id,
                    phase="correlation",
                    tool="evidence correlator",
                    message="Correlating valid browser hits into deduplicated findings",
                    overall_percent=92,
                )
                
                # Automatically correlate and create findings
                fuzzer = FuzzingService(db)
                findings = fuzzer.correlate_and_create_findings(experiment_id)
                RunStateService.complete_stage(
                    db, experiment_id, RunStageName.CORRELATION, {"finding_count": len(findings)}
                )
                logger.info(f"Created/correlated {len(findings)} findings for experiment {experiment_id}.")

                from backend_api.models.target import TargetStatus
                from backend_api.services.campaign_report_service import CampaignReportService
                campaign_findings = CampaignReportService.get_findings_for_experiment(db, experiment_id)
                try:
                    from backend_api.services.smart_campaign_brain import SmartCampaignBrain

                    done_reason = SmartCampaignBrain.completion_reason(db, experiment_id)
                except Exception:
                    done_reason = None
                if execution_error_count or failed_case_count:
                    done_reason = "execution_errors"
                elif coverage.get("budget_exhausted"):
                    done_reason = "planned_budget_completed"
                elif not done_reason:
                    done_reason = "all_planned_evidence_collected"
                safe_claim = bool(
                    run_succeeded
                    and coverage.get("trustworthy_clean")
                    and not coverage.get("budget_exhausted")
                    and not campaign_findings
                )
                limits["done"] = {
                    "terminal": True,
                    "reason": done_reason,
                    "status": experiment.status.value,
                    "execution_plan_complete": True,
                    "coverage_complete": bool(coverage.get("trustworthy_clean")),
                    "execution_errors": execution_error_count,
                    "failed_cases": failed_case_count,
                    # Completing a bounded plan is not proof that the target is
                    # safe. Only an unexhausted, complete plan can make that
                    # stronger claim.
                    "safe_claim": safe_claim,
                    "completed_at": datetime.now(UTC).isoformat(),
                }
                experiment.limits = limits
                experiment.target.status = (
                    TargetStatus.TRIAGE if campaign_findings
                    else TargetStatus.DONE if safe_claim
                    else TargetStatus.RECON_ONLY
                )
                db.commit()
                
                # Automatically generate campaign HTML and Markdown reports
                try:
                    RunStateService.claim_stage(db, experiment_id, RunStageName.REPORTING, "completion-worker")
                    RunStateService.record_progress(
                        db,
                        experiment_id,
                        phase="reporting",
                        tool="campaign report builder",
                        message="Building the final evidence report",
                        overall_percent=97,
                    )
                    CampaignReportService.generate_report(db, experiment_id)
                    RunStateService.complete_stage(db, experiment_id, RunStageName.REPORTING)
                except Exception as rep_err:
                    RunStateService.fail_stage(db, experiment_id, RunStageName.REPORTING, rep_err)
                    logger.error(f"Failed to generate automated campaign report: {rep_err}", exc_info=True)
                RunStateService.record_progress(
                    db,
                    experiment_id,
                    phase="complete",
                    tool="scan orchestrator",
                    message=(
                        f"Run finished with {len(campaign_findings)} finding(s)"
                        if campaign_findings
                        else "Run finished with proof-quality clean coverage"
                        if safe_claim
                        else "Run finished inconclusive; no vulnerability was confirmed"
                        if run_succeeded
                        else f"Run failed operationally: {done_reason}"
                    ),
                    state="done" if run_succeeded else "error",
                    completed=1,
                    total=1,
                    overall_percent=100 if run_succeeded else None,
                    detail=f"Status: {experiment.status.value}; safe claim: {limits['done']['safe_claim']}",
                )
                try:
                    from backend_api.services.log_service import LogService

                    LogService.emit(
                        "ERROR" if not run_succeeded else "HIT" if campaign_findings else "INFO",
                        "completion",
                        (
                            f"Experiment #{experiment_id} failed operationally"
                            if not run_succeeded
                            else f"Experiment #{experiment_id} completed with {len(campaign_findings)} finding(s)"
                        ),
                        experiment_id=experiment_id,
                        target_id=experiment.target_id,
                        data={
                            "event_type": "experiment_finalized",
                            "status": experiment.status.value,
                            "done_reason": done_reason,
                            "safe_claim": safe_claim,
                            "finding_count": len(campaign_findings),
                            "test_case_count": total_case_count,
                            "execution_errors": execution_error_count,
                            "failed_cases": failed_case_count,
                            "coverage": coverage,
                        },
                        db=db,
                    )
                except Exception:
                    pass
    except Exception as e:
        logger.error(f"Error checking experiment completion for {experiment_id}: {e}", exc_info=True)

import threading
_local_storage = threading.local()

def get_browser_executor():
    """Retrieve or initialize the persistent thread-local browser executor."""
    if not hasattr(_local_storage, 'executor') or _local_storage.executor is None:
        logger.info("Initializing persistent thread-local browser executor...")
        _local_storage.executor = BrowserExecutor(oracle_url=settings.ORACLE_SERVER_URL + "/api/v1/oracle")
        _local_storage.executor.start()
        _local_storage.runs = 0
    else:
        try:
            # Check responsiveness by checking browser connection status
            if settings.USE_UNDETECTED_CHROME:
                if not _local_storage.executor.uc_driver or _local_storage.executor.uc_driver.service.process.poll() is not None:
                    raise RuntimeError("Undetected Chrome disconnected")
            else:
                if not _local_storage.executor.browser or not _local_storage.executor.browser.is_connected():
                    raise RuntimeError("Browser disconnected")
        except Exception:
            logger.warning("Thread-local worker browser is unresponsive. Recreating...")
            stop_browser_executor()
            _local_storage.executor = BrowserExecutor(oracle_url=settings.ORACLE_SERVER_URL + "/api/v1/oracle")
            _local_storage.executor.start()
            _local_storage.runs = 0
            
    return _local_storage.executor


def stop_browser_executor():
    """Shutdown thread-local browser executor cleanly."""
    if hasattr(_local_storage, 'executor') and _local_storage.executor is not None:
        try:
            _local_storage.executor.stop()
        except Exception as err:
            logger.warning(f"Failed to stop thread-local browser: {err}")
        _local_storage.executor = None
        _local_storage.runs = 0


def recycle_browser_if_needed():
    """Periodically restart Chrome so long scans do not retain renderer memory."""
    runs = getattr(_local_storage, 'runs', 0)
    restart_every = max(0, settings.BROWSER_RESTART_EVERY_TESTS)
    if not restart_every or runs < restart_every:
        return

    logger.info(f"Restarting thread-local browser after {runs} payload checks to release memory...")
    stop_browser_executor()


from celery.signals import worker_process_shutdown

@worker_process_shutdown.connect
def shutdown_worker_browser(**kwargs):
    """Shutdown persistent browser driver cleanly when worker process terminates."""
    logger.info("Stopping thread-local browser executor on worker process shutdown...")
    stop_browser_executor()



@celery_app.task(name='execute_test_case', bind=True, max_retries=3, queue='browser')
def execute_test_case_task(self, test_case_id: int, worker_id: str = None):
    """Execute a test case in browser.
    
    Args:
        test_case_id: Test case ID
        worker_id: Worker identifier
        
    Returns:
        Execution result dictionary
    """
    db: Session = next(get_db())
    
    
    try:
        # Get test case
        test_case = db.query(TestCase).filter(TestCase.id == test_case_id).first()
        if not test_case:
            raise ValueError(f"Test case {test_case_id} not found")
        _emit_case_event(
            test_case,
            "delivery_received",
            f"Browser worker received test case #{test_case_id}",
            data={"worker_id": worker_id or getattr(self.request, "hostname", None)},
        )

        # Celery can redeliver a task after a worker restart or visibility
        # timeout. A completed test case is immutable: returning its existing
        # execution prevents duplicate browser runs and duplicate evidence.
        if test_case.status == TestCaseStatus.COMPLETED:
            existing_hit = (
                db.query(Execution)
                .filter(
                    Execution.test_case_id == test_case_id,
                    Execution.oracle_status == OracleStatus.HIT,
                )
                .order_by(Execution.executed_at.desc())
                .first()
            )
            existing_execution = existing_hit or (
                db.query(Execution)
                .filter(Execution.test_case_id == test_case_id)
                .order_by(Execution.executed_at.desc())
                .first()
            )
            logger.info(f"Skipping duplicate delivery for completed test case {test_case_id}")
            _emit_case_event(
                test_case,
                "duplicate_delivery_skipped",
                f"Skipped duplicate delivery for completed test case #{test_case_id}",
                data={"existing_execution_id": existing_execution.id if existing_execution else None},
            )
            return {
                'test_case_id': test_case_id,
                'execution_id': existing_execution.id if existing_execution else None,
                'oracle_hit': existing_hit is not None,
                'status': 'already_completed',
            }
        
        # Check if experiment is paused
        from backend_api.models.experiment import ExperimentStatus
        if test_case.experiment.status == ExperimentStatus.PAUSED:
            test_case.status = TestCaseStatus.PENDING
            db.commit()
            logger.info(f"Test case {test_case_id} execution deferred because experiment {test_case.experiment_id} is PAUSED.")
            _emit_case_event(test_case, "deferred_paused", f"Deferred test case #{test_case_id}: run is paused", level="WARNING")
            return {
                'test_case_id': test_case_id,
                'status': 'deferred_paused'
            }

        if not test_case.endpoint or not is_endpoint_in_scope(test_case.endpoint):
            test_case.status = TestCaseStatus.FAILED
            db.commit()
            logger.warning(f"Blocked out-of-scope test case {test_case_id} before browser execution.")
            _emit_case_event(test_case, "blocked_out_of_scope", f"Blocked out-of-scope test case #{test_case_id}", level="ERROR")

            is_eager = os.getenv('CELERY_TASK_ALWAYS_EAGER', 'False').lower() in ('true', '1', 't')
            if not is_eager:
                from backend_api.services.fuzzing_service import FuzzingService
                FuzzingService.queue_next_batch(db, test_case.experiment_id)
                _check_experiment_completion(db, test_case.experiment_id)

            return {
                'test_case_id': test_case_id,
                'status': 'blocked_out_of_scope'
            }
        
        # Atomically acquire an expiring lease. A redelivery can reclaim RUNNING
        # work after a dead worker's lease expires, but not while a live worker
        # still owns it.
        from backend_api.services.test_case_lease_service import TestCaseLeaseService

        lease_owner = worker_id or getattr(self.request, "hostname", None) or os.getenv("HOSTNAME", "unknown")
        claimed_test_case = TestCaseLeaseService.claim(
            db,
            test_case_id,
            lease_owner,
            settings.BROWSER_LEASE_SECONDS,
        )
        if claimed_test_case is None:
            db.refresh(test_case)
            if test_case.status == TestCaseStatus.SKIPPED:
                logger.info(
                    "Skipped test case %s: experiment request budget is exhausted",
                    test_case_id,
                )
                _emit_case_event(
                    test_case,
                    "request_budget_exhausted",
                    f"Skipped test case #{test_case_id}: run request budget exhausted",
                    level="WARNING",
                )
                _check_experiment_completion(db, test_case.experiment_id)
                return {
                    "test_case_id": test_case_id,
                    "status": "skipped_request_budget_exhausted",
                }
            existing_execution = db.query(Execution).filter_by(test_case_id=test_case_id).first()
            logger.info(f"Skipping unclaimed duplicate delivery for test case {test_case_id}")
            _emit_case_event(test_case, "lease_rejected", f"Skipped test case #{test_case_id}: another worker owns the lease", level="WARNING")
            return {
                'test_case_id': test_case_id,
                'execution_id': existing_execution.id if existing_execution else None,
                'status': 'already_claimed',
            }
        test_case = claimed_test_case
        attempt_no = test_case.attempt_count
        _emit_case_event(
            test_case,
            "lease_acquired",
            f"Acquired browser lease for test case #{test_case_id}",
            data={"lease_owner": lease_owner, "attempt_no": attempt_no},
        )

        # Smart hunter — stop firing once this (param, context) is already CONFIRMED vulnerable.
        # Re-proving the same bug wastes the most expensive resource: real browser executions.
        # Keyed on context_id, so a different injection context is still tested (no winrate loss).
        if context_already_confirmed(db, test_case):
            test_case.status = TestCaseStatus.SKIPPED
            db.commit()
            logger.info(f"Skipped test case {test_case_id}: (param, context) already confirmed vulnerable.")
            _emit_case_event(test_case, "redundant_case_skipped", f"Skipped test case #{test_case_id}: context already confirmed")
            is_eager = os.getenv('CELERY_TASK_ALWAYS_EAGER', 'False').lower() in ('true', '1', 't')
            if not is_eager:
                from backend_api.services.fuzzing_service import FuzzingService
                FuzzingService.queue_next_batch(db, test_case.experiment_id)
                _check_experiment_completion(db, test_case.experiment_id)
            return {'test_case_id': test_case_id, 'status': 'skipped_already_confirmed'}

        # Get endpoint and param
        endpoint = test_case.endpoint
        param = test_case.param
        
        # Build request data
        url = endpoint.url_pattern
        method = endpoint.method
        
        # Resolve the campaign identity on every delivery so refreshed sessions
        # are picked up after MFA/login intervention without rebuilding cases.
        from backend_api.services.auth_session_service import AuthSessionService

        limits = test_case.experiment.limits if isinstance(test_case.experiment.limits, dict) else {}
        research_metadata = test_case.research_metadata if isinstance(test_case.research_metadata, dict) else {}
        auth_identity = research_metadata.get("auth_identity") or limits.get("auth_identity")
        target_auth = endpoint.target.auth_info if endpoint.target else {}
        merged_context = AuthSessionService.request_context(
            target_auth,
            auth_identity,
            endpoint.auth_context or {},
        )
        headers, cookies = AuthSessionService.split_request_context(merged_context)
        auth_spec = (
            AuthSessionService.material(target_auth, auth_identity).browser_spec()
            if target_auth else None
        )
        resolved_identity = auth_spec.get("label") if auth_spec else None
        stored_revisit_auth_specs = []
        if target_auth and endpoint.method.upper() in {"POST", "PUT", "PATCH"}:
            for label in AuthSessionService.identity_labels(target_auth):
                if label != resolved_identity:
                    stored_revisit_auth_specs.append(
                        AuthSessionService.material(target_auth, label).browser_spec()
                    )
        
        # Build request body/params based on param location
        body = None
        json_data = None
        params = {}
        
        # Get all parameters of the endpoint to preserve other parameters
        all_params = db.query(Param).filter(Param.endpoint_id == endpoint.id).all()
        
        # Build path parameter values map
        path_params = {
            p.name: (p.sample_value or "1")
            for p in all_params
            if p.location == "path"
        }
        for p_name, p_val in path_params.items():
            placeholder = f"{{{p_name}}}"
            if param.location == "path" and param.name == p_name:
                url = url.replace(placeholder, test_case.payload)
            else:
                url = url.replace(placeholder, p_val)
        
        # Load sample request body or JSON
        if endpoint.sample_request_body and isinstance(endpoint.sample_request_body, dict):
            if any(p.location == "json" for p in all_params) or param.location == "json":
                json_data = endpoint.sample_request_body.copy()
            elif any(p.location == "body" for p in all_params) or param.location == "body":
                body = endpoint.sample_request_body.copy()

        # Fill in other parameters (only if they have a meaningful sample value, to avoid bloated queries causing HTTP 414 / 431)
        for p in all_params:
            if p.location == param.location and p.name == param.name:
                continue
            if p.sample_value:
                if p.location == "query":
                    params[p.name] = p.sample_value
                elif p.location == "body":
                    if body is None:
                        body = {}
                    body[p.name] = p.sample_value
                elif p.location == "json":
                    if json_data is None:
                        json_data = {}
                    keys = p.name.split('.')
                    current = json_data
                    for key in keys[:-1]:
                        if key not in current or not isinstance(current[key], dict):
                            current[key] = {}
                        current = current[key]
                    current[keys[-1]] = p.sample_value
                elif p.location == "header":
                    headers[p.name] = p.sample_value
                elif p.location == "cookie":
                    cookies[p.name] = p.sample_value

        # Set the active fuzzed parameter (parsing Prototype Pollution key-values if applicable)
        is_proto_pollution = False
        if "=" in test_case.payload:
            key_candidate, val_candidate = test_case.payload.split("=", 1)
            if "__proto__" in key_candidate or "constructor" in key_candidate:
                is_proto_pollution = True

        if is_proto_pollution:
            key_candidate, val_candidate = test_case.payload.split("=", 1)
            if param.location == "query":
                params[key_candidate] = val_candidate
            elif param.location == "body":
                if body is None:
                    body = {}
                body[key_candidate] = val_candidate
            elif param.location == "json":
                if json_data is None:
                    json_data = {}
                json_data[key_candidate] = val_candidate
            elif param.location == "cookie":
                cookies[key_candidate] = val_candidate
            elif param.location == "header":
                headers[key_candidate] = val_candidate
        else:
            if param.location == "query":
                params[param.name] = test_case.payload
            elif param.location in {"fragment", "hash"}:
                from urllib.parse import quote

                url = f"{url.split('#', 1)[0]}#{quote(test_case.payload, safe='')}"
            elif param.location == "body":
                if body is None:
                    body = {}
                body[param.name] = test_case.payload
            elif param.location == "json":
                if json_data is None:
                    json_data = {}
                keys = param.name.split('.')
                current = json_data
                for key in keys[:-1]:
                    if key not in current or not isinstance(current[key], dict):
                        current[key] = {}
                    current = current[key]
                current[keys[-1]] = test_case.payload
            elif param.location == "header":
                headers[param.name] = test_case.payload
            elif param.location == "cookie":
                cookies[param.name] = test_case.payload
        
        # Automatically discover and associate stored GET view endpoints for POST test cases
        stored_view_url = None
        if method == 'POST':
            try:
                sibling_endpoints = db.query(Endpoint).filter(
                    Endpoint.target_id == endpoint.target_id,
                    Endpoint.method == 'GET'
                ).all()
                for sib in sibling_endpoints:
                    if 'view' in sib.url_pattern.lower() or 'show' in sib.url_pattern.lower():
                        from urllib.parse import urlparse, urlunparse
                        parsed_root = urlparse(url)
                        parsed_sib = urlparse(sib.url_pattern)
                        stored_view_url = urlunparse((
                            parsed_root.scheme,
                            parsed_root.netloc,
                            parsed_sib.path,
                            parsed_sib.params,
                            parsed_sib.query,
                            parsed_sib.fragment
                        ))
                        logger.info(f"Associated Stored XSS view URL: {stored_view_url} for POST endpoint {endpoint.url_pattern}")
                        break
            except Exception as e:
                logger.warning(f"Failed to resolve Stored XSS sibling endpoints: {e}")
        if method in {"POST", "PUT", "PATCH"} and not stored_view_url and target_auth:
            try:
                declared_render_urls = AuthSessionService.stored_render_urls(
                    target_auth,
                    endpoint.url_pattern,
                    endpoint.target.base_url,
                )
                stored_view_url = declared_render_urls[0] if declared_render_urls else None
                if stored_view_url:
                    logger.info(
                        "Associated declared stored-XSS render URL %s for %s",
                        stored_view_url,
                        endpoint.url_pattern,
                    )
            except Exception as error:
                logger.warning("Failed to resolve declared stored-XSS render URL: %s", error)

        endpoint_steps = endpoint.custom_steps
        if isinstance(endpoint_steps, dict) and isinstance(endpoint_steps.get("by_param"), dict):
            endpoint_steps = endpoint_steps["by_param"].get(param.name)

        # Prepare test case data
        test_case_data = {
            'test_case_id': test_case_id,
            'method': method,
            'url': url,
            'headers': headers,
            'cookies': cookies,
            'params': params,
            'body': body,
            'json': json_data,
            'token': test_case.token,
            'stored_view_url': stored_view_url,
            'payload': test_case.payload,
            'steps': endpoint_steps,
            'target_base_url': endpoint.target.base_url if endpoint.target else url,
            'target_scope_tags': endpoint.target.scope_tags if endpoint.target else None,
            'auth_identity': auth_identity,
            'auth_spec': auth_spec,
            'stored_revisit_auth_specs': stored_revisit_auth_specs,
            # Instrumented local/research probes may model weak origin checks.
            # This is never inferred: callers must explicitly declare it.
            'fake_message_origin': research_metadata.get('fake_message_origin'),
        }
        _emit_case_event(
            test_case,
            "request_prepared",
            f"Prepared redacted browser request for test case #{test_case_id}",
            data={
                "request": {
                    "method": method,
                    "url": url,
                    "query": params,
                    "body": body,
                    "json": json_data,
                    "header_names": sorted(headers.keys()),
                    "cookie_names": sorted(cookies.keys()),
                    "auth_identity": resolved_identity or auth_identity,
                    "stored_view_url": stored_view_url,
                    "custom_step_count": len(endpoint_steps) if isinstance(endpoint_steps, list) else int(bool(endpoint_steps)),
                }
            },
        )
        
        # Screenshot directory
        screenshot_dir = Path(os.getenv('SCREENSHOT_DIR', './screenshots'))
        
        # Retrieve persistent browser executor
        executor = get_browser_executor()
        
        # Reset browser session to prevent state leakage (cookies and DOM)
        try:
            if settings.USE_UNDETECTED_CHROME:
                if not executor.uc_driver or executor.uc_driver.service.process.poll() is not None:
                    raise RuntimeError("Undetected Chrome disconnected")
            else:
                if not executor.browser or not executor.browser.is_connected():
                    raise RuntimeError("Browser disconnected")
        except Exception as reset_err:
            logger.warning(f"Failed to verify browser connection status: {reset_err}. Recreating browser...")
            stop_browser_executor()
            executor = get_browser_executor()
            
        # --- Rate limiter: wait for a slot before hitting the target ---
        target_url = test_case_data['url']
        try:
            waited_s = rate_limiter.wait_for_slot(target_url)
            if waited_s > 0.1:
                logger.info(f"Rate limiter: waited {waited_s:.1f}s before test case {test_case_id}")
                _emit_case_event(
                    test_case,
                    "rate_limit_wait",
                    f"Rate limiter delayed test case #{test_case_id}",
                    data={"waited_seconds": round(waited_s, 3)},
                )
        except CircuitOpenError as cb_err:
            logger.warning(f"Circuit breaker blocks execution: {cb_err}")
            # Mark test case as FAILED
            TestCaseLeaseService.finish(db, test_case, TestCaseStatus.FAILED)
            _emit_case_event(
                test_case,
                "circuit_breaker_blocked",
                f"Circuit breaker blocked test case #{test_case_id}",
                level="ERROR",
                detail=str(cb_err),
            )
            
            # Record warning in experiment limits
            try:
                experiment = test_case.experiment
                limits = dict(experiment.limits) if isinstance(experiment.limits, dict) else {}
                warnings = list(limits.get("warnings", []))
                warning = {
                    "level": "error",
                    "phase": "execution",
                    "message": f"Circuit breaker tripped for {rate_limiter._host_from_url(target_url)}",
                    "detail": str(cb_err),
                }
                if not any(isinstance(item, dict) and item.get("message") == warning["message"] for item in warnings):
                    warnings.append(warning)
                limits["warnings"] = warnings[-12:]
                experiment.limits = limits
                db.commit()
            except Exception as db_err:
                logger.error(f"Failed to record circuit breaker warning to DB: {db_err}")
                
            # Queue next batch of pending tasks
            is_eager = os.getenv('CELERY_TASK_ALWAYS_EAGER', 'False').lower() in ('true', '1', 't')
            if not is_eager:
                from backend_api.services.fuzzing_service import FuzzingService
                FuzzingService.queue_next_batch(db, test_case.experiment_id)
                _check_experiment_completion(db, test_case.experiment_id)
                
            if hasattr(_local_storage, 'runs'):
                _local_storage.runs += 1
            else:
                _local_storage.runs = 1
            recycle_browser_if_needed()
            
            return {
                'test_case_id': test_case_id,
                'error': str(cb_err),
                'status': 'skipped_circuit_open'
            }
        
        try:
            _emit_case_event(
                test_case,
                "browser_execution_started",
                f"Started isolated browser execution for test case #{test_case_id}",
                data={"attempt_no": attempt_no},
            )
            result = executor.execute_test_case(test_case_data, screenshot_dir)
            intervention = result.get("human_intervention")
            if intervention:
                from backend_api.services.human_intervention_service import HumanInterventionService

                HumanInterventionService.raise_intervention(
                    db,
                    test_case.experiment_id,
                    kind=intervention.get("kind") or "authentication_challenge",
                    reason=intervention.get("reason") or "Authentication requires operator input",
                    identity=intervention.get("identity") or auth_identity,
                    url=intervention.get("url"),
                )
                TestCaseLeaseService.finish(db, test_case, TestCaseStatus.PENDING)
                _emit_case_event(
                    test_case,
                    "human_intervention_required",
                    f"Paused test case #{test_case_id} for operator intervention",
                    level="WARNING",
                    detail=intervention.get("reason"),
                    data={"intervention": intervention},
                )
                return {
                    "test_case_id": test_case_id,
                    "status": "awaiting_human_intervention",
                    "intervention": intervention,
                }
            execution_error = result.get("execution_error")
            callback_hit = reconcile_persisted_oracle_hit(db, test_case_id)
            if callback_hit and not result.get("oracle_hit"):
                logger.info(
                    "Reconciled authoritative oracle callback HIT for test case %s",
                    test_case_id,
                )
            result["oracle_hit"] = bool(result.get("oracle_hit") or callback_hit)
            rate_limiter_pre_reported = False

            from browser_workers.runtime_lineage_probe_runner import (
                runtime_lineage_capture_supports_probes,
            )

            lineage_probe_enabled = bool(
                (
                    getattr(settings, "RUNTIME_LINEAGE_AAB_PROBES", False)
                    or research_metadata.get("runtime_lineage_aab") is True
                )
                and runtime_lineage_capture_supports_probes(
                    getattr(settings, "CAPTURE_RUNTIME_LINEAGE", "off")
                )
                and not getattr(settings, "USE_UNDETECTED_CHROME", True)
            )
            lineage_probe_param_name = str(getattr(param, "name", "") or "")
            lineage_probe_param_location = str(
                getattr(param, "location", "") or ""
            )
            if (
                lineage_probe_enabled
                and not execution_error
                and not result["oracle_hit"]
                and claim_runtime_lineage_probe_attempt_if_eligible(
                    db,
                    test_case,
                    executor,
                    test_case_data,
                    result,
                    param_name=lineage_probe_param_name,
                    param_location=lineage_probe_param_location,
                )
            ):
                try:
                    from browser_workers.runtime_lineage_probe_runner import (
                        run_safe_url_probe_series,
                    )

                    primary_rate_limited, primary_retry_after = browser_rate_limit_signal(
                        result
                    )
                    if primary_rate_limited:
                        rate_limiter.report_error(
                            target_url,
                            is_rate_limit=True,
                            retry_after_secs=primary_retry_after,
                        )
                    else:
                        rate_limiter.report_success(target_url)
                    rate_limiter_pre_reported = True

                    def report_lineage_probe_response(
                        probe_result: Dict[str, Any],
                    ) -> None:
                        probe_rate_limited, probe_retry_after = (
                            browser_rate_limit_signal(probe_result)
                        )
                        probe_status = probe_result.get("status_code")
                        if probe_rate_limited:
                            rate_limiter.report_error(
                                target_url,
                                is_rate_limit=True,
                                retry_after_secs=probe_retry_after,
                            )
                        elif (
                            type(probe_status) is int
                            and 200 <= probe_status < 400
                        ):
                            rate_limiter.report_success(target_url)
                        else:
                            rate_limiter.report_error(target_url)

                    upgraded_lineage = run_safe_url_probe_series(
                        executor,
                        test_case_data,
                        result,
                        param_name=lineage_probe_param_name,
                        param_location=lineage_probe_param_location,
                        attempt_no=attempt_no,
                        before_request=rate_limiter.wait_for_slot,
                        after_request=report_lineage_probe_response,
                    )
                    if upgraded_lineage is not None:
                        logs = result.get("logs") if isinstance(result.get("logs"), dict) else {}
                        logs["runtime_lineage"] = upgraded_lineage
                        result["logs"] = logs
                        _emit_case_event(
                            test_case,
                            "runtime_lineage_value_influence",
                            f"Recorded order-confounded A/A/B priority signal for test case #{test_case_id}",
                            data={
                                "probe_runs": 3,
                                "classification": "value_influence",
                            },
                        )
                except Exception as lineage_probe_error:
                    # A failed prioritization probe must never turn a successful
                    # primary browser execution into an operational failure.
                    logger.debug(
                        "Runtime lineage A/A/B follow-up stopped for test case %s: %s",
                        test_case_id,
                        lineage_probe_error,
                    )

            if not execution_error:
                try:
                    from backend_api.services.auditors.browser_result import BrowserResultAuditor
                    auditor_vuln = BrowserResultAuditor.audit(test_case, test_case_data, result)
                    if auditor_vuln:
                        result["oracle_hit"] = True
                        logs = result.get("logs") if isinstance(result.get("logs"), dict) else {}
                        logs["auditor_vuln"] = auditor_vuln
                        result["logs"] = logs
                        logger.info(
                            "Auditor confirmed %s for test case %s",
                            auditor_vuln.get("title", auditor_vuln.get("vuln_type", "vulnerability")),
                            test_case_id,
                        )
                except Exception as audit_err:
                    logger.warning(f"Browser result auditor failed for test case {test_case_id}: {audit_err}")

            # The three optional probes lengthen the task. Re-read the durable
            # callback state immediately before persistence so a primary oracle
            # hit that arrived during them can never be recorded as a stale miss.
            late_callback_hit = reconcile_persisted_oracle_hit(db, test_case_id)
            if late_callback_hit and not result.get("oracle_hit"):
                logger.info(
                    "Reconciled late authoritative oracle callback HIT for test case %s",
                    test_case_id,
                )
            result["oracle_hit"] = bool(result.get("oracle_hit") or late_callback_hit)

            # Project untrusted browser lineage to its bounded, value-free form
            # before any persistence or downstream service can observe the logs.
            result["logs"] = sanitize_execution_logs(
                result.get("logs"),
                test_case_id=test_case_id,
                attempt_no=attempt_no,
            )
            
            # Create execution record
            execution = Execution(
                test_case_id=test_case_id,
                attempt_no=attempt_no,
                idempotency_key=f"browser:{test_case_id}:{attempt_no}",
                browser_worker_id=worker_id or os.getenv('HOSTNAME', 'unknown'),
                oracle_status=(
                    OracleStatus.HIT if result['oracle_hit']
                    else OracleStatus.ERROR if execution_error
                    else OracleStatus.MISSED
                ),
                oracle_token=test_case.token if result['oracle_hit'] else None,
                logs=serialize_execution_logs(
                    result["logs"],
                    test_case_id=test_case_id,
                    attempt_no=attempt_no,
                ),
                screenshot_path=result.get('screenshot_path'),
                dom_snapshot=result.get('dom_snapshot'),
                duration_ms=result.get('duration_ms'),
            )
            db.add(execution)
            
            # Update test case status
            test_case.status = (
                TestCaseStatus.COMPLETED
                if result['oracle_hit'] or not execution_error
                else TestCaseStatus.FAILED
            )
            test_case.lease_owner = None
            test_case.lease_expires_at = None

            # Commit with retry on transient SQLite lock
            committed = False
            for _attempt in range(5):
                try:
                    db.commit()
                    committed = True
                    break
                except Exception as commit_err:
                    db.rollback()
                    if "locked" in str(commit_err).lower() and _attempt < 4:
                        import time
                        time.sleep(0.5 * (_attempt + 1))
                        db.add(execution)
                        test_case.status = TestCaseStatus.FAILED if execution_error else TestCaseStatus.COMPLETED
                        test_case.lease_owner = None
                        test_case.lease_expires_at = None
                    else:
                        raise commit_err
            result_logs = result.get("logs") if isinstance(result.get("logs"), dict) else {}
            _emit_case_event(
                test_case,
                "browser_execution_finished",
                (
                    f"Oracle HIT for test case #{test_case_id}"
                    if result["oracle_hit"]
                    else f"Browser execution error for test case #{test_case_id}"
                    if execution_error
                    else f"Oracle MISS for test case #{test_case_id}"
                ),
                level="HIT" if result["oracle_hit"] else "ERROR" if execution_error else "INFO",
                detail=str(execution_error) if execution_error else None,
                data={
                    "execution_id": execution.id,
                    "oracle_status": execution.oracle_status.value,
                    "duration_ms": result.get("duration_ms"),
                    "status_code": result.get("status_code"),
                    "final_url": result.get("final_url"),
                    "screenshot_path": result.get("screenshot_path"),
                    "dom_snapshot_captured": bool(result.get("dom_snapshot")),
                    "console_entries": len(result_logs.get("console") or []),
                    "page_errors": len(result_logs.get("errors") or result_logs.get("page_errors") or []),
                    "callbacks": len(result_logs.get("callbacks") or result_logs.get("oracle_callbacks") or []),
                    "auditor_vulnerability": result_logs.get("auditor_vuln"),
                },
            )
            try:
                from backend_api.services.run_state_service import RunStateService

                total_cases = db.query(TestCase.id).filter(
                    TestCase.experiment_id == test_case.experiment_id
                ).count()
                terminal_cases = db.query(TestCase.id).filter(
                    TestCase.experiment_id == test_case.experiment_id,
                    TestCase.status.in_([
                        TestCaseStatus.COMPLETED,
                        TestCaseStatus.FAILED,
                        TestCaseStatus.CANCELLED,
                        TestCaseStatus.SKIPPED,
                    ]),
                ).count()
                RunStateService.record_progress(
                    db,
                    test_case.experiment_id,
                    phase="browser",
                    tool="Chromium execution oracle",
                    message=(
                        f"Confirmed an oracle hit for payload #{test_case_id}"
                        if result['oracle_hit']
                        else f"Recorded execution error for payload #{test_case_id}"
                        if execution_error
                        else f"Payload #{test_case_id} did not execute"
                    ),
                    state="error" if execution_error else "working",
                    completed=terminal_cases,
                    total=total_cases,
                    overall_percent=55 + (35 * terminal_cases / max(1, total_cases)),
                    detail=(execution_error or {}).get("message") if execution_error else None,
                    doing_status=(
                        f"The Sea of Findings: Confirmed XSS Oracle Hit on payload #{test_case_id}!"
                        if result['oracle_hit']
                        else f"Browser Whirlpool: Executed payload #{test_case_id} ({terminal_cases}/{total_cases})"
                    ),
                    river_stage="sea" if result['oracle_hit'] else "browser",
                    micro_state={
                        "action": "oracle_hit" if result['oracle_hit'] else "browser_exec",
                        "endpoint": test_case.endpoint.url_pattern if getattr(test_case, 'endpoint', None) else None,
                        "param": test_case.param.name if getattr(test_case, 'param', None) else None,
                        "substep": f"Payload #{test_case_id}: {test_case.payload[:60]}",
                        "result": "HIT - Alert Fired" if result['oracle_hit'] else ("Error" if execution_error else "Missed"),
                    },
                )
            except Exception as progress_error:
                logger.debug(f"Could not persist browser progress: {progress_error}")
            try:
                from backend_api.services.evidence_service import EvidenceService

                EvidenceService.register_execution(
                    db,
                    execution,
                    request_data=test_case_data,
                    result=result,
                )
            except Exception as evidence_error:
                logger.warning(f"Failed to hash evidence for execution {execution.id}: {evidence_error}")

            if not execution_error:
              try:
                from backend_api.services.research_service import ResearchService

                learning = ResearchService.learn_from_execution(db, execution, result)
                if learning:
                    logger.info(
                        "Research feedback: hypothesis=%s outcome=%s technique=%s",
                        learning.get("hypothesis_id"),
                        learning.get("outcome"),
                        learning.get("technique"),
                    )
              except Exception as research_error:
                logger.warning(f"Failed to record research feedback for execution {execution.id}: {research_error}")

            # Close the observe -> learn -> re-plan loop after every browser
            # outcome. This adjusts pending alternatives using actual evidence
            # and records an operator-readable decision trace.
            if not execution_error:
              try:
                from backend_api.services.smart_campaign_brain import SmartCampaignBrain

                brain_decision = SmartCampaignBrain.observe(db, execution, result)
                logger.info(
                    "Campaign brain: action=%s rationale=%s",
                    brain_decision.get("action"),
                    brain_decision.get("rationale"),
                )
              except Exception as brain_error:
                logger.warning(f"Campaign brain observation failed: {brain_error}")

            # Adaptive Pruning on Finding Confirmation:
            # When an execution hit is verified for this parameter, prune remaining lower-priority speculative test cases.
            if not execution_error and result['oracle_hit']:
                try:
                    pruned = (
                        db.query(TestCase)
                        .filter(
                            TestCase.experiment_id == test_case.experiment_id,
                            TestCase.param_id == test_case.param_id,
                            TestCase.id != test_case.id,
                            TestCase.status.in_([TestCaseStatus.PENDING, TestCaseStatus.QUEUED])
                        )
                        .update({"status": TestCaseStatus.CANCELLED}, synchronize_session=False)
                    )
                    if pruned > 0:
                        db.commit()
                        logger.info(f"Hit confirmed: pruned {pruned} redundant pending test cases for parameter {test_case.param_id}")
                except Exception as prune_err:
                    logger.debug(f"Failed to prune test cases on hit: {prune_err}")

            # Adaptive Pruning on Triage Verdict:
            # If this was the Request-#1 mega-polyglot and it came back with the input dead (token
            # absent, response not WAF-blocked), cancel the parameter's remaining speculative cases —
            # the single most valuable rate-budget saving under strict req/min limits.
            elif not execution_error:
                try:
                    from backend_api.services.adaptive_pruning_service import AdaptivePruningService

                    trace = AdaptivePruningService.apply_triage_verdict(db, test_case, result)
                    if trace.get("action") == "prune" and trace.get("pruned"):
                        logger.info(
                            f"Triage prune: parameter {test_case.param_id} dead "
                            f"(cancelled {trace['pruned']} pending cases) — {trace.get('notes', '')}"
                        )
                    elif trace.get("applied") and trace.get("action") == "keep" and trace.get("reflected"):
                        logger.info(
                            f"Triage residue: parameter {test_case.param_id} survives in "
                            f"{trace.get('contexts')} — narrowing subsequent fuzzing"
                        )
                except Exception as triage_err:
                    logger.debug(f"Triage verdict handling failed: {triage_err}")

            # Correlate findings live on hit
            logger.info(
                f"Test case {test_case_id} executed: "
                f"status={'error' if execution_error else 'hit' if result['oracle_hit'] else 'missed'}"
            )
            
            # --- Rate limiter: check response status and headers ---
            status_code = result.get('status_code')
            is_rate_limited, retry_after_secs = browser_rate_limit_signal(result)
            
            if is_rate_limited:
                if not rate_limiter_pre_reported:
                    rate_limiter.report_error(
                        target_url,
                        is_rate_limit=True,
                        retry_after_secs=retry_after_secs,
                    )
                try:
                    experiment = test_case.experiment
                    limits = dict(experiment.limits) if isinstance(experiment.limits, dict) else {}
                    warnings = list(limits.get("warnings", []))
                    warning = {
                        "level": "warning",
                        "phase": "execution",
                        "message": f"Rate limit / WAF warning from {rate_limiter._host_from_url(target_url)}",
                        "detail": f"Status: {status_code}. Retry-After: {retry_after_secs}s. Adaptive delay increased.",
                    }
                    if not any(isinstance(item, dict) and item.get("message") == warning["message"] for item in warnings):
                        warnings.append(warning)
                    limits["warnings"] = warnings[-12:]
                    experiment.limits = limits
                    db.commit()
                except Exception as db_err:
                    logger.error(f"Failed to record rate limit warning to DB: {db_err}")
            else:
                if not rate_limiter_pre_reported:
                    rate_limiter.report_success(target_url)
            
            if hasattr(_local_storage, 'runs'):
                _local_storage.runs += 1
            else:
                _local_storage.runs = 1
            recycle_browser_if_needed()
            
            return {
                'test_case_id': test_case_id,
                'execution_id': execution.id,
                'oracle_hit': result['oracle_hit'],
                'status': 'error' if execution_error else 'completed',
                'error': execution_error,
                'duration_ms': result.get('duration_ms'),
            }
        
        except Exception as run_err:
            # Recreate browser on unexpected runner errors
            logger.error(f"Execution run error: {run_err}. Restarting driver...")
            # --- Rate limiter: report error with timeout detection ---
            err_str = str(run_err).lower()
            is_rate_signal = any(kw in err_str for kw in [
                'timeout', 'timed out', '429', 'rate limit', 'connection refused',
                'connection reset', 'err_connection', 'access denied'
            ])
            rate_limiter.report_error(target_url, is_rate_limit=is_rate_signal)
            stop_browser_executor()
            _emit_case_event(
                test_case,
                "browser_runner_exception",
                f"Browser runner exception for test case #{test_case_id}",
                level="ERROR",
                detail=str(run_err),
            )
            raise run_err
    
    except Exception as e:
        logger.error(f"Error executing test case {test_case_id}: {e}", exc_info=True)
        try:
            db.rollback()
        except Exception:
            pass

        should_retry = self.request.retries < self.max_retries

        # Retrying work is still active, not failed. Marking it FAILED before
        # self.retry() allowed the experiment to complete and the same Celery
        # delivery to run again later, producing duplicate executions.
        if 'test_case' in locals():
            from backend_api.services.test_case_lease_service import TestCaseLeaseService
            TestCaseLeaseService.finish(
                db,
                test_case,
                TestCaseStatus.QUEUED if should_retry else TestCaseStatus.FAILED,
            )
            _emit_case_event(
                test_case,
                "delivery_retry_scheduled" if should_retry else "delivery_failed",
                (
                    f"Retry scheduled for test case #{test_case_id}"
                    if should_retry
                    else f"Test case #{test_case_id} exhausted retries"
                ),
                level="WARNING" if should_retry else "ERROR",
                detail=str(e),
                data={"retry_number": int(self.request.retries) + 1, "max_retries": int(self.max_retries)},
            )
            if hasattr(_local_storage, 'runs'):
                _local_storage.runs += 1
            else:
                _local_storage.runs = 1
            recycle_browser_if_needed()
            
            # Only release the queue slot after retries are exhausted.
            is_eager = os.getenv('CELERY_TASK_ALWAYS_EAGER', 'False').lower() in ('true', '1', 't')
            if not should_retry and not is_eager:
                from backend_api.services.fuzzing_service import FuzzingService
                FuzzingService.queue_next_batch(db, test_case.experiment_id)
                _check_experiment_completion(db, test_case.experiment_id)
        
        # Retry if not max retries
        if should_retry:
            raise self.retry(exc=e, countdown=60)
        
        raise
    
    finally:
        db.close()
