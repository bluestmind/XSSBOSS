
"""Experiments router."""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from backend_api.db.session import get_db
from backend_api.schemas.experiment import ExperimentCreate, ExperimentUpdate, ExperimentResponse, ExperimentMonitorResponse
from backend_api.models.experiment import ExperimentStatus
from backend_api.services.experiment_service import ExperimentService
from backend_api.services.run_state_service import RunStateService
from backend_api.utils.rate_limiter import rate_limiter
from backend_api.utils.log_serializer import (
    parse_execution_logs,
    safe_unparsed_execution_log_text,
    sanitize_execution_logs,
    serialize_execution_logs,
)
from backend_api.utils.runtime_lineage_evidence import normalize_runtime_lineage_evidence

router = APIRouter(prefix="/experiments", tags=["experiments"])


@router.post("/", response_model=ExperimentResponse, status_code=201)
def create_experiment(experiment: ExperimentCreate, db: Session = Depends(get_db)):
    """Create a new experiment."""
    try:
        experiment_data = experiment.model_dump()
        db_experiment = ExperimentService.create_experiment(db, experiment_data)
        return db_experiment
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/", response_model=List[ExperimentResponse])
def list_experiments(
    target_id: Optional[int] = None,
    status: Optional[ExperimentStatus] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """List experiments, optionally filtered by target or status."""
    experiments = ExperimentService.list_experiments(
        db, target_id=target_id, status=status, skip=skip, limit=limit
    )
    return experiments


@router.get("/{experiment_id}", response_model=ExperimentResponse)
def get_experiment(experiment_id: int, db: Session = Depends(get_db)):
    """Get an experiment by ID."""
    try:
        experiment = ExperimentService.get_experiment(db, experiment_id)
        return experiment
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{experiment_id}", response_model=ExperimentResponse)
def update_experiment(
    experiment_id: int,
    experiment_update: ExperimentUpdate,
    db: Session = Depends(get_db)
):
    """Update an experiment."""
    try:
        update_data = experiment_update.dict(exclude_unset=True)
        experiment = ExperimentService.update_experiment(db, experiment_id, update_data)
        return experiment
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def run_fuzzing_task(experiment_id: int):
    from backend_api.db.session import SessionLocal
    from backend_api.services.fuzzing_service import FuzzingService
    from backend_api.utils.logger import logger
    db = SessionLocal()
    try:
        fuzzer = FuzzingService(db)
        fuzzer.run_experiment(experiment_id)
    except Exception as e:
        logger.error(f"Error running fuzzing task for experiment {experiment_id}: {e}", exc_info=True)
    finally:
        db.close()

def continue_fuzzing_task(experiment_id: int):
    from backend_api.db.session import SessionLocal
    from backend_api.services.fuzzing_service import FuzzingService
    from backend_api.utils.logger import logger
    
    db = SessionLocal()
    try:
        fuzzer = FuzzingService(db)
        fuzzer.run_experiment(experiment_id)
    except Exception as e:
        logger.error(f"Error continuing fuzzing task for experiment {experiment_id}: {e}", exc_info=True)
    finally:
        db.close()

@router.post("/{experiment_id}/start", response_model=ExperimentResponse)
def start_experiment(
    experiment_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Start an experiment."""
    try:
        experiment = ExperimentService.start_experiment(db, experiment_id)
        background_tasks.add_task(run_fuzzing_task, experiment_id)
        return experiment
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{experiment_id}/stop", response_model=ExperimentResponse)
def stop_experiment(experiment_id: int, db: Session = Depends(get_db)):
    """Stop/pause an experiment."""
    try:
        experiment = ExperimentService.stop_experiment(db, experiment_id)
        return experiment
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{experiment_id}/continue", response_model=ExperimentResponse)
def continue_experiment(
    experiment_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Continue/resume a paused experiment."""
    try:
        experiment = ExperimentService.continue_experiment(db, experiment_id)
        background_tasks.add_task(continue_fuzzing_task, experiment_id)
        return experiment
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{experiment_id}/stats")
def get_experiment_stats(experiment_id: int, db: Session = Depends(get_db)):
    """Get experiment statistics."""
    try:
        stats = ExperimentService.get_experiment_stats(db, experiment_id)
        return stats
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{experiment_id}/monitor", response_model=ExperimentMonitorResponse)
def get_experiment_monitor(experiment_id: int, db: Session = Depends(get_db)):
    """Return an operator-focused live monitor snapshot."""
    try:
        from backend_api.models.execution import Execution, OracleStatus
        from backend_api.models.test_case import TestCase, TestCaseStatus
        from backend_api.models.run_state import RunStage
        import json

        experiment = ExperimentService.get_experiment(db, experiment_id)
        pipeline_stages = db.query(RunStage).filter(
            RunStage.experiment_id == experiment_id
        ).order_by(RunStage.id).all()
        stats = ExperimentService.get_experiment_stats(db, experiment_id)
        monitor_limits = {
            "checks": 80,
            "executions": 40,
            "findings": 25,
            "activity": 120,
            "dom_chars": 12000,
        }

        def clip_text(value, max_chars):
            if value is None:
                return None
            text = str(value)
            if len(text) <= max_chars:
                return text
            return text[:max_chars] + f"\n\n[truncated {len(text) - max_chars} chars in live monitor]"

        def summarize_execution_logs(
            raw_logs,
            *,
            test_case_id=None,
            attempt_no=None,
        ):
            if not raw_logs:
                return None
            try:
                parsed = json.loads(raw_logs)
            except Exception:
                return safe_unparsed_execution_log_text(raw_logs)[:280]

            if not isinstance(parsed, dict):
                return safe_unparsed_execution_log_text(raw_logs)[:280]
            parsed = sanitize_execution_logs(
                parsed,
                test_case_id=test_case_id,
                attempt_no=attempt_no,
            )

            errors = parsed.get("errors") or parsed.get("page_errors") or []
            console = parsed.get("console") or parsed.get("console_messages") or []
            callbacks = parsed.get("callbacks") or parsed.get("oracle_callbacks") or []
            if errors:
                return "Error: " + str(errors[0])[:260]
            if callbacks:
                return "Oracle callback observed: " + str(callbacks[0])[:240]
            if console:
                return "Console: " + str(console[0])[:260]
            return "Browser completed without console errors or oracle callback."

        def payload_decision(check):
            context_type = check.context.context_type if check.context else "UNKNOWN_CONTEXT"
            param_name = check.param.name if check.param else "unknown parameter"
            if check.status == TestCaseStatus.QUEUED:
                return f"Engine selected this payload for browser execution because priority={check.priority}, context={context_type}, parameter={param_name}."
            if check.status == TestCaseStatus.RUNNING:
                return f"Engine is testing this payload now against {param_name} in {context_type}."
            if check.status == TestCaseStatus.FAILED:
                return f"Engine marked this payload failed before/while executing. Review endpoint reachability, scope, or browser error details."
            return f"Engine generated this payload from context={context_type}, parameter={param_name}, priority={check.priority}."

        total = stats["total_test_cases"]
        finished = stats["completed"] + stats["failed"]
        operational_execution_errors = (
            db.query(Execution.id)
            .join(TestCase, Execution.test_case_id == TestCase.id)
            .filter(TestCase.experiment_id == experiment_id)
            .filter(Execution.oracle_status == OracleStatus.ERROR)
            .count()
        )
        progress_percent = round((finished / total) * 100, 1) if total else 0.0
        limits = experiment.limits if isinstance(experiment.limits, dict) else {}
        live_progress = limits.get("live_progress") if isinstance(limits.get("live_progress"), dict) else None
        progress_history = [
            item for item in (limits.get("progress_history") or []) if isinstance(item, dict)
        ][-30:]
        from datetime import datetime, timezone
        now_utc = datetime.now(timezone.utc)

        def as_utc(value):
            if not value:
                return None
            if isinstance(value, datetime):
                parsed = value
            else:
                try:
                    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                except (TypeError, ValueError):
                    return None
            return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)

        started_utc = as_utc(experiment.started_at or experiment.created_at)
        ended_utc = as_utc(experiment.completed_at) or now_utc
        heartbeat_utc = as_utc((live_progress or {}).get("updated_at")) or as_utc(experiment.updated_at)
        elapsed_seconds = max(0.0, (ended_utc - started_utc).total_seconds()) if started_utc else 0.0
        idle_seconds = max(0.0, (now_utc - heartbeat_utc).total_seconds()) if heartbeat_utc else 0.0
        progress_stale = experiment.status == ExperimentStatus.RUNNING and idle_seconds > 30
        warnings = limits.get("warnings") if isinstance(limits.get("warnings"), list) else []
        context_probe_failures = int(limits.get("context_probe_failures") or 0)
        burp_scan_status = limits.get("burp_scan_status") or limits.get("burp_status")
        burp_scan_message = limits.get("burp_scan_message")
        burp_seed_urls = limits.get("burp_seed_urls") if isinstance(limits.get("burp_seed_urls"), list) else []
        burp_scan_metrics = limits.get("burp_scan_metrics") if isinstance(limits.get("burp_scan_metrics"), dict) else {}
        scan_mode = str(limits.get("scan_mode") or "full")
        recon_only = scan_mode == "recon" or limits.get("vuln_checks_enabled") is False
        recon_endpoint_count = int(limits.get("recon_endpoint_count") or 0)
        recon_param_count = int(limits.get("recon_param_count") or 0)
        burp_blocked = (
            burp_scan_status
            and (
                "paused" in str(burp_scan_status).lower()
                or "failed" in str(burp_scan_status).lower()
                or "could not connect" in str(burp_scan_message or "").lower()
            )
        )

        if experiment.status == ExperimentStatus.COMPLETED and recon_only:
            stage = "recon_complete"
            progress_percent = 100.0
            stage_detail = (
                f"Recon completed with {recon_endpoint_count} endpoint(s) and {recon_param_count} parameter(s). "
                "Run the full vuln scan when you are ready to test the discovered surface."
            )
        elif experiment.status == ExperimentStatus.COMPLETED and total == 0 and burp_blocked:
            stage = "burp_blocked"
            stage_detail = (
                burp_scan_message
                or "Burp paused or failed before crawling a seed URL. Fix Burp's scan connectivity, then run again."
            )
        elif experiment.status == ExperimentStatus.COMPLETED and total == 0 and context_probe_failures:
            stage = "target_unreachable"
            stage_detail = (
                "Run ended without generated payload checks because Burp/proxy context probes timed out. "
                "Burp also needs to be able to reach the seed URL."
            )
        elif experiment.status == ExperimentStatus.COMPLETED and total == 0:
            stage = "no_checks"
            stage_detail = (
                "Run ended without generated payload checks. The crawler/import step did not produce controllable "
                "parameters or reflected contexts for this URL."
            )
        elif (
            experiment.status == ExperimentStatus.FAILED
            and total > 0
            and finished == total
            and stats["failed"] == 0
            and operational_execution_errors == 0
        ):
            stage = "inconclusive"
            stage_detail = (
                "All scheduled checks finished without an execution error, but no vulnerability was confirmed. "
                "This historical run was mislabeled failed by the legacy completion-state bug; inspect the forensic audit."
            )
        elif experiment.status == ExperimentStatus.COMPLETED:
            done = limits.get("done") if isinstance(limits.get("done"), dict) else {}
            if done and not done.get("safe_claim") and not stats.get("failed"):
                stage = "inconclusive"
                stage_detail = (
                    "The execution plan completed, but the available evidence is not proof that the target is safe."
                )
            else:
                stage = "completed"
                stage_detail = "Finished running generated payload checks."
        elif stats["running"]:
            stage = "executing"
            stage_detail = f"Executing {stats['running']} payload check(s) in a browser."
        elif stats["queued"]:
            stage = "queued"
            stage_detail = f"{stats['queued']} payload check(s) are waiting for browser execution."
        elif stats["pending"]:
            stage = "profiling"
            stage_detail = "Generating and prioritizing payload checks from discovered contexts."
        elif total == 0 and experiment.status == ExperimentStatus.RUNNING:
            stage = "recon"
            stage_detail = (
                "Running recon only: importing Burp crawl data, same-host pages, forms, scripts, and parameters."
                if recon_only
                else "Discovering parameters, reflections, filters, and contexts."
            )
        else:
            stage = experiment.status.value
            stage_detail = f"Experiment is {experiment.status.value}."

        if live_progress and experiment.status in {ExperimentStatus.RUNNING, ExperimentStatus.PAUSED}:
            stage = str(live_progress.get("phase") or stage)
            stage_detail = str(live_progress.get("message") or stage_detail)
            if live_progress.get("overall_percent") is not None:
                progress_percent = max(progress_percent, float(live_progress["overall_percent"]))

        recent_checks = (
            db.query(TestCase)
            .filter(TestCase.experiment_id == experiment_id)
            .order_by(TestCase.updated_at.desc())
            .limit(monitor_limits["checks"])
            .all()
        )

        check_rows = []
        activity_log = [{
            "timestamp": experiment.created_at,
            "level": "info",
            "phase": "scope",
            "message": f"Created authorized scan target for {experiment.target.base_url}.",
            "detail": f"Experiment #{experiment.id} uses {experiment.strategy.value if hasattr(experiment.strategy, 'value') else experiment.strategy} strategy.",
        }]

        if experiment.started_at:
            activity_log.append({
                "timestamp": experiment.started_at,
                "level": "info",
                "phase": "recon",
                "message": "Started recon-only discovery." if recon_only else "Started recon and vulnerability scan.",
                "detail": (
                    "Burp, crawler, archive hints, script mining, and parameter inventory are handled before vulnerability testing."
                    if recon_only
                    else "Crawler, parameter discovery, typed audit modules, payload generation, and browser verification are handled by the scan pipeline."
                ),
            })

        if burp_scan_status:
            burp_detail_parts = []
            if burp_scan_message:
                burp_detail_parts.append(str(burp_scan_message))
            if burp_seed_urls:
                burp_detail_parts.append("Seeds: " + ", ".join(str(seed) for seed in burp_seed_urls[:4]))
            if burp_scan_metrics:
                burp_detail_parts.append(
                    "Metrics: "
                    f"crawl_requests={burp_scan_metrics.get('crawl_requests_made')}, "
                    f"crawl_errors={burp_scan_metrics.get('crawl_network_errors')}, "
                    f"visited={burp_scan_metrics.get('crawl_unique_locations_visited')}."
                )
            activity_log.append({
                "timestamp": experiment.updated_at,
                "level": "warning" if "paused" in str(burp_scan_status).lower() or "error" in str(burp_scan_status).lower() else "info",
                "phase": "burp",
                "message": f"Burp task status: {burp_scan_status}.",
                "detail": " ".join(burp_detail_parts) or "Burp scan task was synced through the REST API.",
            })

        for warning in warnings[-8:]:
            if isinstance(warning, dict):
                activity_log.append({
                    "timestamp": experiment.updated_at,
                    "level": warning.get("level", "warning"),
                    "phase": warning.get("phase", "probe"),
                    "message": warning.get("message", "Scan warning."),
                    "detail": warning.get("detail"),
                })

        for check in recent_checks:
            check_rows.append({
                "id": check.id,
                "status": check.status.value if hasattr(check.status, "value") else str(check.status),
                "priority": check.priority,
                "payload_preview": check.payload[:160],
                "payload": check.payload,
                "token_preview": check.token[:16],
                "token": check.token,
                "technique": getattr(check, "technique", None),
                "attempt_count": getattr(check, "attempt_count", 0),
                "endpoint_id": check.endpoint_id,
                "endpoint_method": check.endpoint.method if check.endpoint else "",
                "endpoint_url": check.endpoint.url_pattern if check.endpoint else "",
                "param_name": check.param.name if check.param else "",
                "param_location": check.param.location if check.param else "",
                "context_type": check.context.context_type if check.context else None,
                "context_tag": check.context.tag if check.context else None,
                "context_attribute": check.context.attribute if check.context else None,
                "context_snippet": check.context.snippet if check.context else None,
                "sinks": [s.sink_type for s in check.context.sinks] if (check.context and getattr(check.context, "sinks", None)) else [],
                "updated_at": check.updated_at,
            })
            if check.status in [TestCaseStatus.QUEUED, TestCaseStatus.RUNNING, TestCaseStatus.FAILED]:
                status_value = check.status.value if hasattr(check.status, "value") else str(check.status)
                activity_log.append({
                    "timestamp": check.updated_at,
                    "level": "error" if check.status == TestCaseStatus.FAILED else "info",
                    "phase": "payload",
                    "message": f"Payload #{check.id} is {status_value}: {check.payload[:120]}",
                    "detail": payload_decision(check),
                })

        for progress_event in progress_history:
            event_time = as_utc(progress_event.get("updated_at")) or experiment.updated_at
            activity_log.append({
                "timestamp": event_time,
                "level": (
                    "error" if progress_event.get("state") == "error"
                    else "info"
                ),
                "phase": progress_event.get("phase") or "scan",
                "message": progress_event.get("message") or "Scan progress updated.",
                "detail": (
                    f"Tool: {progress_event.get('tool')}. {progress_event.get('detail') or ''}"
                ).strip(),
            })

        recent_executions = (
            db.query(Execution)
            .join(TestCase, Execution.test_case_id == TestCase.id)
            .filter(TestCase.experiment_id == experiment_id)
            .order_by(Execution.executed_at.desc())
            .limit(monitor_limits["executions"])
            .all()
        )

        execution_rows = []
        for execution in recent_executions:
            check = execution.test_case
            oracle_status = execution.oracle_status.value if hasattr(execution.oracle_status, "value") else str(execution.oracle_status)

            parsed_logs = sanitize_execution_logs(
                parse_execution_logs(execution.logs),
                test_case_id=execution.test_case_id,
                attempt_no=execution.attempt_no,
            )
            safe_raw_logs = serialize_execution_logs(
                parsed_logs,
                test_case_id=execution.test_case_id,
                attempt_no=execution.attempt_no,
            )

            status_code = parsed_logs.get("status_code")
            response_headers = parsed_logs.get("headers", {})
            response_posture = (
                parsed_logs.get("response_posture")
                if isinstance(parsed_logs.get("response_posture"), dict)
                else None
            )
            runtime_code_coverage = (
                parsed_logs.get("runtime_code_coverage")
                if isinstance(parsed_logs.get("runtime_code_coverage"), dict)
                else None
            )
            runtime_lineage = normalize_runtime_lineage_evidence(
                parsed_logs.get("runtime_lineage")
                if isinstance(parsed_logs.get("runtime_lineage"), dict)
                else parsed_logs.get("runtime_causal_lineage"),
                test_case_id=execution.test_case_id,
                attempt_no=execution.attempt_no,
            )
            dom_marker_differential = (
                parsed_logs.get("dom_marker_differential")
                if isinstance(parsed_logs.get("dom_marker_differential"), dict)
                else None
            )
            final_url = parsed_logs.get("final_url") or (check.endpoint.url_pattern if check and check.endpoint else None)
            console_entries = parsed_logs.get("console", []) if isinstance(parsed_logs.get("console"), list) else []
            taint_flows = [c for c in console_entries if isinstance(c, dict) and "[TaintFlow]" in str(c.get("text", ""))]

            sinks_list = []
            if check and check.context and getattr(check.context, "sinks", None):
                sinks_list = [s.sink_type for s in check.context.sinks]

            execution_rows.append({
                "id": execution.id,
                "test_case_id": execution.test_case_id,
                "oracle_status": oracle_status,
                "duration_ms": execution.duration_ms,
                "logs": summarize_execution_logs(
                    safe_raw_logs,
                    test_case_id=execution.test_case_id,
                    attempt_no=execution.attempt_no,
                ),
                "raw_logs": safe_raw_logs,
                "dom_snapshot": clip_text(execution.dom_snapshot, monitor_limits["dom_chars"]),
                "browser_worker_id": execution.browser_worker_id,
                "attempt_no": execution.attempt_no,
                "screenshot_path": execution.screenshot_path,
                "executed_at": execution.executed_at,
                "endpoint_url": check.endpoint.url_pattern if check and check.endpoint else None,
                "endpoint_method": check.endpoint.method if check and check.endpoint else "GET",
                "param_name": check.param.name if check and check.param else None,
                "param_location": check.param.location if check and check.param else "query",
                "context_type": check.context.context_type if check and check.context else None,
                "context_tag": check.context.tag if check and check.context else None,
                "context_attribute": check.context.attribute if check and check.context else None,
                "sinks": sinks_list,
                "payload": check.payload if check else None,
                "token": check.token if check else None,
                "status_code": status_code,
                "response_headers": response_headers,
                "response_posture": response_posture,
                "runtime_code_coverage": runtime_code_coverage,
                "runtime_lineage": runtime_lineage,
                "dom_marker_differential": dom_marker_differential,
                "final_url": final_url,
                "taint_flows": taint_flows,
            })
            activity_log.append({
                "timestamp": execution.executed_at,
                "level": "success" if oracle_status == "hit" else ("error" if oracle_status == "error" else "info"),
                "phase": "result",
                "message": f"Result for payload #{execution.test_case_id}: {oracle_status}.",
                "detail": summarize_execution_logs(
                    safe_raw_logs,
                    test_case_id=execution.test_case_id,
                    attempt_no=execution.attempt_no,
                ),
            })

        # Findings are run-owned results. Filtering only by target leaked old
        # findings from previous experiments into a new scan on the same host.
        from backend_api.services.campaign_report_service import CampaignReportService
        recent_findings = sorted(
            CampaignReportService.get_findings_for_experiment(db, experiment_id),
            key=lambda finding: finding.created_at,
            reverse=True,
        )[:monitor_limits["findings"]]

        finding_rows = []
        for finding in recent_findings:
            execution_logs = None
            dom_snapshot = None
            screenshot_file = None
            
            if finding.evidence_refs and isinstance(finding.evidence_refs, dict):
                test_case_id = finding.evidence_refs.get('test_case_id')
                if test_case_id:
                    from backend_api.models.execution import OracleStatus
                    exec_rec = (
                        db.query(Execution)
                        .filter(Execution.test_case_id == test_case_id)
                        .filter(Execution.oracle_status == OracleStatus.HIT)
                        .first()
                    )
                    if exec_rec:
                        execution_logs = summarize_execution_logs(
                            exec_rec.logs,
                            test_case_id=exec_rec.test_case_id,
                            attempt_no=exec_rec.attempt_no,
                        )
                        dom_snapshot = clip_text(exec_rec.dom_snapshot, monitor_limits["dom_chars"])
            
            if finding.screenshot_path:
                import os
                screenshot_file = os.path.basename(finding.screenshot_path)

            finding_rows.append({
                "id": finding.id,
                "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                "status": finding.status.value if hasattr(finding.status, "value") else str(finding.status),
                "vuln_type": finding.vuln_type or "xss",
                "scanner_module": finding.scanner_module or "xss_fuzzer",
                "confidence": finding.confidence or "firm",
                "evidence_summary": finding.evidence_summary,
                "endpoint_url": finding.endpoint.url_pattern if finding.endpoint else "",
                "param_name": finding.param.name if finding.param else "",
                "payload_preview": finding.best_payload,
                "created_at": finding.created_at,
                "poc_request": finding.poc_request,
                "screenshot_path": screenshot_file,
                "execution_logs": execution_logs,
                "dom_snapshot": dom_snapshot,
            })
            activity_log.append({
                "timestamp": finding.created_at,
                "level": "success",
                "phase": "finding",
                "message": f"{(finding.vuln_type or 'xss').replace('_', ' ').title()} finding #{finding.id} created with {finding.severity.value if hasattr(finding.severity, 'value') else finding.severity} severity.",
                "detail": f"{finding.endpoint.url_pattern if finding.endpoint else ''} :: {finding.param.name if finding.param else ''} :: {finding.best_payload[:220]}",
            })

        if experiment.completed_at:
            zero_check_completion = experiment.status == ExperimentStatus.COMPLETED and total == 0
            activity_log.append({
                "timestamp": experiment.completed_at,
                "level": "success" if recon_only else ("warning" if zero_check_completion else ("success" if experiment.status == ExperimentStatus.COMPLETED else "error")),
                "phase": "complete",
                "message": f"Experiment finished with status {experiment.status.value}.",
                "detail": (
                    f"Recon finished with {recon_endpoint_count} endpoint(s) and {recon_param_count} parameter(s). Start a full scan to run typed vulnerability checks against this inventory."
                    if recon_only
                    else
                    f"Burp scanner stopped before usable crawl data was produced: {burp_scan_message}"
                    if zero_check_completion and burp_blocked
                    else
                    "Burp/proxy context probes timed out, so no reflection contexts or payload checks could be generated. "
                    "Confirm Burp can reach the seed URL and that its proxy/upstream settings allow outbound HTTPS."
                    if zero_check_completion and context_probe_failures
                    else
                    "No payload checks were generated, so the run completed quickly. Use a URL with query/form inputs, "
                    "confirm the crawler can reach the site, or import traffic from Burp."
                    if zero_check_completion
                    else f"{stats['completed']} completed, {stats['failed']} failed, {len(finding_rows)} finding(s) currently visible."
                ),
            })

        activity_log = sorted(
            activity_log,
            key=lambda row: as_utc(row.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )[:monitor_limits["activity"]]

        # Calculate advanced analytics: Context distribution
        from backend_api.models.context import Context
        from backend_api.models.endpoint import Endpoint
        from backend_api.models.param import Param
        from backend_api.models.filter_profile import FilterProfile
        from sqlalchemy import func

        context_counts_raw = (
            db.query(Context.context_type, func.count(Context.id))
            .join(Endpoint, Context.endpoint_id == Endpoint.id)
            .filter(Endpoint.target_id == experiment.target_id)
            .group_by(Context.context_type)
            .all()
        )
        context_distribution = {str(row[0]): int(row[1]) for row in context_counts_raw}

        # Attack Surface summary
        endpoint_count = db.query(func.count(Endpoint.id)).filter(Endpoint.target_id == experiment.target_id).scalar() or 0
        param_count = (
            db.query(func.count(Param.id))
            .join(Endpoint, Param.endpoint_id == Endpoint.id)
            .filter(Endpoint.target_id == experiment.target_id)
            .scalar() or 0
        )
        controllable_param_count = (
            db.query(func.count(Param.id))
            .join(Endpoint, Param.endpoint_id == Endpoint.id)
            .filter(Endpoint.target_id == experiment.target_id)
            .filter(Param.is_controllable == True)
            .scalar() or 0
        )
        context_count = sum(context_distribution.values())
        attack_surface = {
            "endpoint_count": endpoint_count,
            "param_count": param_count,
            "controllable_param_count": controllable_param_count,
            "context_count": context_count,
        }

        # Execution performance metrics
        execution_durations = [e.duration_ms for e in recent_executions if e.duration_ms is not None]
        avg_duration_ms = round(sum(execution_durations) / len(execution_durations), 1) if execution_durations else 0
        min_duration_ms = min(execution_durations) if execution_durations else 0
        max_duration_ms = max(execution_durations) if execution_durations else 0

        total_exec_count = (
            db.query(func.count(Execution.id))
            .join(TestCase, Execution.test_case_id == TestCase.id)
            .filter(TestCase.experiment_id == experiment_id)
            .scalar() or 0
        )
        from backend_api.models.execution import OracleStatus
        hit_exec_count = (
            db.query(func.count(Execution.id))
            .join(TestCase, Execution.test_case_id == TestCase.id)
            .filter(TestCase.experiment_id == experiment_id)
            .filter(Execution.oracle_status == OracleStatus.HIT)
            .scalar() or 0
        )
        error_exec_count = (
            db.query(func.count(Execution.id))
            .join(TestCase, Execution.test_case_id == TestCase.id)
            .filter(TestCase.experiment_id == experiment_id)
            .filter(Execution.oracle_status == OracleStatus.ERROR)
            .scalar() or 0
        )
        miss_exec_count = max(0, total_exec_count - hit_exec_count - error_exec_count)
        hit_rate = round((hit_exec_count / total_exec_count) * 100, 1) if total_exec_count > 0 else 0.0

        if experiment.started_at:
            from datetime import datetime, timezone
            now_dt = datetime.now(timezone.utc)
            start_dt = experiment.started_at
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)
            end_dt = experiment.completed_at or now_dt
            if end_dt.tzinfo is None:
                end_dt = end_dt.replace(tzinfo=timezone.utc)
            elapsed_seconds = (end_dt - start_dt).total_seconds()
            throughput_per_min = round((total_exec_count / max(1, elapsed_seconds)) * 60, 1)
        else:
            throughput_per_min = 0.0

        performance_metrics = {
            "avg_duration_ms": avg_duration_ms,
            "min_duration_ms": min_duration_ms,
            "max_duration_ms": max_duration_ms,
            "total_executions": total_exec_count,
            "oracle_hit_count": hit_exec_count,
            "oracle_miss_count": miss_exec_count,
            "oracle_error_count": error_exec_count,
            "hit_rate_percent": hit_rate,
            "throughput_per_min": throughput_per_min,
        }

        # Filter / WAF profile summary
        filter_profiles = (
            db.query(FilterProfile)
            .join(Endpoint, FilterProfile.endpoint_id == Endpoint.id)
            .filter(Endpoint.target_id == experiment.target_id)
            .all()
        )
        waf_detected = any(fp.waf_detected for fp in filter_profiles)
        sanitizers = [fp.sanitizer_detected for fp in filter_profiles if fp.sanitizer_detected]
        all_blocked = []
        all_allowed = []
        for fp in filter_profiles:
            if isinstance(fp.blocked_tokens, list):
                all_blocked.extend(fp.blocked_tokens)
            if isinstance(fp.allowed_tokens, list):
                all_allowed.extend(fp.allowed_tokens)

        waf_status = {
            "waf_detected": waf_detected,
            "sanitizer_detected": sanitizers[0] if sanitizers else None,
            "blocked_tokens_count": len(set(all_blocked)),
            "allowed_tokens_count": len(set(all_allowed)),
            "sample_blocked_tokens": list(set(all_blocked))[:8],
            "sample_allowed_tokens": list(set(all_allowed))[:8],
        }

        micro_events = list(limits.get("micro_events") or [])
        micro_state = limits.get("micro_state") or ((live_progress or {}).get("micro_state"))
        doing_status = limits.get("doing_status") or ((live_progress or {}).get("doing_status")) or stage_detail
        river_flow = RunStateService.get_river_flow_snapshot(db, experiment_id)

        return {
            "experiment": experiment,
            "target": {
                "id": experiment.target.id,
                "name": experiment.target.name,
                "base_url": experiment.target.base_url,
                "status": experiment.target.status.value if hasattr(experiment.target.status, "value") else str(experiment.target.status),
            },
            "stats": stats,
            "stage": stage,
            "stage_detail": stage_detail,
            "doing_status": doing_status,
            "micro_state": micro_state,
            "micro_events": micro_events[-100:],
            "river_flow": river_flow,
            "progress_percent": progress_percent,
            "live_progress": live_progress,
            "progress_history": progress_history,
            "elapsed_seconds": round(elapsed_seconds, 1),
            "idle_seconds": round(idle_seconds, 1),
            "progress_stale": progress_stale,
            "pipeline_stages": [
                {
                    "name": item.name.value if hasattr(item.name, "value") else str(item.name),
                    "status": item.status.value if hasattr(item.status, "value") else str(item.status),
                    "attempt_count": item.attempt_count,
                    "started_at": item.started_at,
                    "completed_at": item.completed_at,
                    "error": item.error,
                }
                for item in pipeline_stages
            ],
            "recent_checks": check_rows,
            "recent_executions": execution_rows,
            "recent_findings": finding_rows,
            "activity_log": activity_log,
            "throttle_status": rate_limiter.get_status(experiment.target.base_url),
            "context_distribution": context_distribution,
            "performance_metrics": performance_metrics,
            "waf_status": waf_status,
            "attack_surface": attack_surface,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{experiment_id}/audit")
def get_experiment_audit(experiment_id: int, db: Session = Depends(get_db)):
    """Return a complete, evidence-oriented account of what a run actually did."""
    try:
        from collections import defaultdict
        import json

        from backend_api.models.execution import Execution, OracleStatus
        from backend_api.models.test_case import TestCase

        experiment = ExperimentService.get_experiment(db, experiment_id)
        limits = experiment.limits if isinstance(experiment.limits, dict) else {}
        cases = (
            db.query(TestCase)
            .filter(TestCase.experiment_id == experiment_id)
            .order_by(TestCase.id)
            .all()
        )
        executions = (
            db.query(Execution)
            .join(TestCase, Execution.test_case_id == TestCase.id)
            .filter(TestCase.experiment_id == experiment_id)
            .order_by(Execution.id)
            .all()
        )
        executions_by_case = defaultdict(list)
        for execution in executions:
            executions_by_case[execution.test_case_id].append(execution)

        def enum_value(value):
            return value.value if hasattr(value, "value") else str(value)

        def parsed_logs(item):
            if not item.logs:
                return None
            parsed = parse_execution_logs(item.logs)
            if parsed:
                return sanitize_execution_logs(
                    parsed,
                    test_case_id=item.test_case_id,
                    attempt_no=item.attempt_no,
                )
            return {"text": safe_unparsed_execution_log_text(item.logs)}

        def classification(case):
            metadata = case.research_metadata if isinstance(case.research_metadata, dict) else {}
            if metadata.get("classification"):
                return str(metadata["classification"])
            if metadata.get("auditor"):
                return str(metadata["auditor"])
            if "xssboss-open-redirect" in case.payload:
                return "redirect_probe"
            return "xss" if case.context_id is not None else "unclassified_probe"

        payload_groups = {}
        case_rows = []
        outcome_counts = defaultdict(int)
        capture_counts = {"screenshots": 0, "dom_snapshots": 0, "execution_logs": 0}
        total_duration_ms = 0

        for case in cases:
            case_execs = executions_by_case.get(case.id, [])
            statuses = [enum_value(item.oracle_status) for item in case_execs]
            for status in statuses:
                outcome_counts[status] += 1
            total_duration_ms += sum(int(item.duration_ms or 0) for item in case_execs)
            capture_counts["screenshots"] += sum(bool(item.screenshot_path) for item in case_execs)
            capture_counts["dom_snapshots"] += sum(bool(item.dom_snapshot) for item in case_execs)
            capture_counts["execution_logs"] += sum(bool(item.logs) for item in case_execs)

            case_classification = classification(case)
            group_key = (case.payload, case.technique or "unclassified", case_classification)
            group = payload_groups.setdefault(group_key, {
                "payload": case.payload,
                "technique": case.technique or "unclassified",
                "classification": case_classification,
                "times_scheduled": 0,
                "endpoint_urls": set(),
                "parameters": set(),
                "outcomes": defaultdict(int),
            })
            group["times_scheduled"] += 1
            group["endpoint_urls"].add(case.endpoint.url_pattern if case.endpoint else "")
            group["parameters"].add(case.param.name if case.param else "")
            for status in statuses:
                group["outcomes"][status] += 1

            case_rows.append({
                "id": case.id,
                "classification": case_classification,
                "technique": case.technique or "unclassified",
                "payload": case.payload,
                "status": enum_value(case.status),
                "attempt_count": int(case.attempt_count or 0),
                "endpoint": {
                    "id": case.endpoint_id,
                    "method": case.endpoint.method if case.endpoint else None,
                    "url": case.endpoint.url_pattern if case.endpoint else None,
                },
                "parameter": {
                    "id": case.param_id,
                    "name": case.param.name if case.param else None,
                    "location": case.param.location if case.param else None,
                },
                "context": {
                    "id": case.context_id,
                    "type": case.context.context_type if case.context else None,
                    "tag": case.context.tag if case.context else None,
                    "attribute": case.context.attribute if case.context else None,
                },
                "research_hypothesis_id": case.research_hypothesis_id,
                "research_metadata": case.research_metadata,
                "executions": [
                    {
                        "id": item.id,
                        "oracle_status": enum_value(item.oracle_status),
                        "duration_ms": item.duration_ms,
                        "browser_worker_id": item.browser_worker_id,
                        "attempt_no": item.attempt_no,
                        "executed_at": item.executed_at,
                        "screenshot_path": item.screenshot_path,
                        "dom_snapshot_captured": bool(item.dom_snapshot),
                        "logs": parsed_logs(item),
                    }
                    for item in case_execs
                ],
            })

        payload_inventory = []
        for group in payload_groups.values():
            payload_inventory.append({
                **group,
                "endpoint_urls": sorted(value for value in group["endpoint_urls"] if value),
                "parameters": sorted(value for value in group["parameters"] if value),
                "outcomes": dict(group["outcomes"]),
            })
        payload_inventory.sort(key=lambda item: (-item["times_scheduled"], item["payload"]))

        hit_count = int(outcome_counts.get(OracleStatus.HIT.value, 0))
        error_count = int(outcome_counts.get(OracleStatus.ERROR.value, 0))
        failed_cases = sum(enum_value(case.status) == "failed" for case in cases)
        if hit_count:
            evidence_verdict = "confirmed_vulnerability_evidence"
        elif error_count or failed_cases:
            evidence_verdict = "operational_failure"
        else:
            evidence_verdict = "inconclusive_no_confirmed_vulnerability"

        llm_preflight = limits.get("llm_preflight") if isinstance(limits.get("llm_preflight"), dict) else {}
        brain = limits.get("campaign_brain") if isinstance(limits.get("campaign_brain"), dict) else {}
        integrations = {
            "burp": {
                "rest_used": bool(limits.get("burp_task_id")),
                "task_id": limits.get("burp_task_id"),
                "status": limits.get("burp_scan_status") or limits.get("burp_status") or "not_used",
                "message": limits.get("burp_scan_message"),
                "extension_used": bool((limits.get("burp_extension_activity") or {}).get("used"))
                if isinstance(limits.get("burp_extension_activity"), dict)
                else False,
                "extension_activity": limits.get("burp_extension_activity"),
            },
            "local_llm": {
                "mode": limits.get("llm_mode") or "not_recorded",
                "preflight": llm_preflight,
                "pivot_calls": int(brain.get("llm_pivot_calls") or 0),
                "pivot_failures": int(brain.get("llm_pivot_failures") or 0),
                "unavailable": bool(brain.get("llm_unavailable")),
                "applied_pivots": sum(
                    bool(item.get("applied"))
                    for item in (brain.get("llm_pivots") or {}).values()
                    if isinstance(item, dict)
                ) if isinstance(brain.get("llm_pivots"), dict) else 0,
                "last_error": brain.get("last_llm_error"),
            },
            "browser": {
                "used": bool(executions),
                "engine": "isolated Chromium browser executor",
                "oracle": "runtime callback for XSS; final-origin comparison for redirect probes",
                "capture_policy": "screenshots and DOM snapshots may be hit-only; logs are retained per execution",
            },
        }
        from backend_api.services.log_service import LogService

        log_summary = LogService.get_stats(db, experiment_id=experiment_id)

        return {
            "experiment": {
                "id": experiment.id,
                "name": experiment.name,
                "status": enum_value(experiment.status),
                "strategy": enum_value(experiment.strategy),
                "target": experiment.target.base_url,
                "started_at": experiment.started_at,
                "completed_at": experiment.completed_at,
            },
            "verdict": {
                "state": evidence_verdict,
                "safe_claim": bool((limits.get("done") or {}).get("safe_claim"))
                if isinstance(limits.get("done"), dict) else False,
                "explanation": (
                    "At least one evidence oracle confirmed the tested behavior."
                    if hit_count else
                    "One or more tests failed operationally; coverage cannot be interpreted."
                    if error_count or failed_cases else
                    "All recorded tests missed their confirmation oracle. A miss is not proof that the target is safe."
                ),
            },
            "summary": {
                "test_cases": len(cases),
                "executions": len(executions),
                "distinct_payloads": len(payload_inventory),
                "outcomes": dict(outcome_counts),
                "failed_cases": failed_cases,
                "total_browser_duration_ms": total_duration_ms,
                "captures": capture_counts,
            },
            "integrations": integrations,
            "diagnostic_logs": {
                **log_summary,
                "live_url": f"/api/v1/logs?experiment_id={experiment_id}",
                "export_url": f"/api/v1/logs/export?experiment_id={experiment_id}",
                "format": "application/x-ndjson",
                "redaction": "credentials, cookies, passwords, API keys, and session tokens are redacted",
            },
            "coverage": limits.get("coverage"),
            "warnings": limits.get("warnings") or [],
            "payload_inventory": payload_inventory,
            "test_cases": case_rows,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{experiment_id}", status_code=204)
def delete_experiment(experiment_id: int, db: Session = Depends(get_db)):
    """Delete an experiment."""
    try:
        ExperimentService.delete_experiment(db, experiment_id)
        return None
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{experiment_id}/throttle")
def get_throttle_status(experiment_id: int, db: Session = Depends(get_db)):
    """Return current rate-limiter status for the experiment's target."""
    experiment = ExperimentService.get_experiment(db, experiment_id)
    return rate_limiter.get_status(experiment.target.base_url)


@router.post("/{experiment_id}/throttle/reset")
def reset_throttle(experiment_id: int, db: Session = Depends(get_db)):
    """Reset adaptive throttle state for the experiment's target (e.g. after VPN switch)."""
    experiment = ExperimentService.get_experiment(db, experiment_id)
    rate_limiter.reset(experiment.target.base_url)
    return {"message": "Throttle state reset", **rate_limiter.get_status(experiment.target.base_url)}


@router.post("/{experiment_id}/retry-test-case/{test_case_id}")
def retry_test_case(experiment_id: int, test_case_id: int, db: Session = Depends(get_db)):
    """Re-queue an existing test case for immediate execution."""
    from backend_api.models.test_case import TestCase, TestCaseStatus
    test_case = (
        db.query(TestCase)
        .filter(TestCase.id == test_case_id, TestCase.experiment_id == experiment_id)
        .first()
    )
    if not test_case:
        raise HTTPException(status_code=404, detail=f"Test case #{test_case_id} not found in experiment #{experiment_id}")

    test_case.status = TestCaseStatus.QUEUED
    test_case.attempt_count = (test_case.attempt_count or 0) + 1
    db.commit()
    db.refresh(test_case)

    try:
        from browser_workers.worker import execute_test_case_task
        task = execute_test_case_task.delay(test_case.id)
        return {
            "status": "queued",
            "message": f"Test case #{test_case.id} queued for execution",
            "task_id": getattr(task, "id", None),
        }
    except Exception as exc:
        return {
            "status": "queued_locally",
            "message": f"Test case #{test_case.id} state set to queued",
            "detail": str(exc),
        }


class LiveInjectPayloadRequest(BaseModel):
    endpoint_id: int
    param_id: int
    context_id: Optional[int] = None
    payload: str


@router.post("/{experiment_id}/inject-payload")
def inject_live_payload(experiment_id: int, req: LiveInjectPayloadRequest, db: Session = Depends(get_db)):
    """Dispatch a custom payload directly into the active hunt."""
    from backend_api.models.test_case import TestCase, TestCaseStatus
    from backend_api.models.endpoint import Endpoint
    from backend_api.models.param import Param
    from backend_api.utils.tokenizer import Tokenizer
    from backend_api.utils.scope_guard import is_endpoint_in_scope

    experiment = ExperimentService.get_experiment(db, experiment_id)
    endpoint = db.query(Endpoint).filter(Endpoint.id == req.endpoint_id).first()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    if not is_endpoint_in_scope(endpoint):
        raise HTTPException(status_code=403, detail="Endpoint is out of scope")

    param = db.query(Param).filter(Param.id == req.param_id).first()
    if not param:
        raise HTTPException(status_code=404, detail="Param not found")

    token = Tokenizer.generate_token()
    test_case = TestCase(
        experiment_id=experiment.id,
        endpoint_id=endpoint.id,
        param_id=param.id,
        context_id=req.context_id,
        payload=req.payload,
        token=token,
        priority=100,
        status=TestCaseStatus.QUEUED,
    )
    db.add(test_case)
    db.commit()
    db.refresh(test_case)

    try:
        from browser_workers.worker import execute_test_case_task
        task = execute_test_case_task.delay(test_case.id)
        return {
            "status": "queued",
            "test_case_id": test_case.id,
            "token": token,
            "message": "Custom payload dispatched to browser workers",
            "task_id": getattr(task, "id", None),
        }
    except Exception as exc:
        return {
            "status": "queued",
            "test_case_id": test_case.id,
            "token": token,
            "message": "Custom payload queued in database",
            "detail": str(exc),
        }
