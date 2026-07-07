"""Experiments router."""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
from backend_api.db.session import get_db
from backend_api.schemas.experiment import ExperimentCreate, ExperimentUpdate, ExperimentResponse, ExperimentMonitorResponse
from backend_api.models.experiment import ExperimentStatus
from backend_api.services.experiment_service import ExperimentService
from backend_api.utils.rate_limiter import rate_limiter

router = APIRouter(prefix="/experiments", tags=["experiments"])


@router.post("/", response_model=ExperimentResponse, status_code=201)
def create_experiment(experiment: ExperimentCreate, db: Session = Depends(get_db)):
    """Create a new experiment."""
    try:
        experiment_data = experiment.dict()
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
        from backend_api.models.endpoint import Endpoint
        from backend_api.models.execution import Execution
        from backend_api.models.finding import Finding
        from backend_api.models.param import Param
        from backend_api.models.test_case import TestCase, TestCaseStatus
        import json

        experiment = ExperimentService.get_experiment(db, experiment_id)
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

        def summarize_execution_logs(raw_logs):
            if not raw_logs:
                return None
            try:
                parsed = json.loads(raw_logs)
            except Exception:
                return str(raw_logs)[:280]

            if not isinstance(parsed, dict):
                return str(parsed)[:280]

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
        progress_percent = round((finished / total) * 100, 1) if total else 0.0
        limits = experiment.limits if isinstance(experiment.limits, dict) else {}
        warnings = limits.get("warnings") if isinstance(limits.get("warnings"), list) else []
        context_probe_failures = int(limits.get("context_probe_failures") or 0)
        burp_scan_status = limits.get("burp_scan_status")
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
        elif experiment.status == ExperimentStatus.COMPLETED:
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
                "token_preview": check.token[:16],
                "endpoint_id": check.endpoint_id,
                "endpoint_method": check.endpoint.method if check.endpoint else "",
                "endpoint_url": check.endpoint.url_pattern if check.endpoint else "",
                "param_name": check.param.name if check.param else "",
                "param_location": check.param.location if check.param else "",
                "context_type": check.context.context_type if check.context else None,
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
            execution_rows.append({
                "id": execution.id,
                "test_case_id": execution.test_case_id,
                "oracle_status": oracle_status,
                "duration_ms": execution.duration_ms,
                "logs": summarize_execution_logs(execution.logs),
                "screenshot_path": execution.screenshot_path,
                "executed_at": execution.executed_at,
                "endpoint_url": check.endpoint.url_pattern if check and check.endpoint else None,
                "param_name": check.param.name if check and check.param else None,
                "payload": check.payload if check else None,
            })
            activity_log.append({
                "timestamp": execution.executed_at,
                "level": "success" if oracle_status == "hit" else ("error" if oracle_status == "error" else "info"),
                "phase": "result",
                "message": f"Result for payload #{execution.test_case_id}: {oracle_status}.",
                "detail": summarize_execution_logs(execution.logs),
            })

        recent_findings = (
            db.query(Finding)
            .join(Endpoint, Finding.endpoint_id == Endpoint.id)
            .filter(Endpoint.target_id == experiment.target_id)
            .order_by(Finding.created_at.desc())
            .limit(monitor_limits["findings"])
            .all()
        )

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
                        execution_logs = summarize_execution_logs(exec_rec.logs)
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

        activity_log = sorted(activity_log, key=lambda row: row["timestamp"], reverse=True)[:monitor_limits["activity"]]

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
            "progress_percent": progress_percent,
            "recent_checks": check_rows,
            "recent_executions": execution_rows,
            "recent_findings": finding_rows,
            "activity_log": activity_log,
            "throttle_status": rate_limiter.get_status(experiment.target.base_url),
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
