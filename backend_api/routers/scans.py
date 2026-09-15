"""One-shot scan router."""
from datetime import UTC, datetime, timedelta
from threading import Lock
import os
import socket
import time
from urllib.parse import parse_qs, parse_qsl, urlencode, urlparse

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend_api.db.session import SessionLocal, get_db
from backend_api.config import settings
from backend_api.models.endpoint import Endpoint
from backend_api.models.experiment import Experiment, ExperimentStatus
from backend_api.models.param import Param
from backend_api.models.target import Target
from backend_api.models.target import TargetStatus
from backend_api.models.run_state import RunStage, RunStageName, RunStageStatus
from backend_api.schemas.scan import ScanCreate, ScanMode, ScanResponse
from backend_api.services.experiment_service import ExperimentService
from backend_api.services.fuzzing_service import FuzzingService
from backend_api.services.recon_service import ReconService
from backend_api.services.target_service import TargetService
from backend_api.services.run_state_service import RunStateService
from backend_api.services.log_service import LogService
from backend_api.utils.logger import logger
from recon_engine.crawler import Crawler

router = APIRouter(prefix="/scans", tags=["scans"])

BURP_TRIGGER_DEDUPE_SECONDS = 600
COMMON_QUERY_PROBE_NAMES = ("q", "s", "search", "query", "keyword", "redirect", "url", "next")
_burp_trigger_lock = Lock()
_recent_burp_triggers = {}


class InterventionResolution(BaseModel):
    resolution: str = Field(default="operator resolved", max_length=500)
    auth_info: dict | None = None


@router.get("/health")
def scan_health():
    """Health check reachable through the UI API proxy."""
    return {"status": "healthy", "service": "XSS Boss API"}


def _origin_for_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=422, detail="URL must be an absolute http(s) URL")
    return f"{parsed.scheme}://{parsed.netloc}"


def _host_for_url(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.hostname or "").lower()


def _request_from_url(url: str) -> dict:
    parsed = urlparse(url)
    query = {
        key: values[0] if len(values) == 1 else values
        for key, values in parse_qs(parsed.query, keep_blank_values=True).items()
    }
    return {
        "method": "GET",
        "url": url,
        "headers": {},
        "query": query,
        "body": None,
        "json": None,
    }


def _url_with_query_param(url: str, name: str, value: str) -> str:
    from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

    parts = list(urlparse(url))
    query = dict(parse_qsl(parts[4], keep_blank_values=True))
    query[name] = value
    parts[4] = urlencode(query, doseq=True)
    return urlunparse(parts)


def _normalize_scan_url(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)), doseq=True)
    return f"{scheme}://{netloc}{path}?{query}" if query else f"{scheme}://{netloc}{path}"


def _experiment_limits(experiment: Experiment) -> dict:
    return experiment.limits if isinstance(experiment.limits, dict) else {}


def _record_scan_progress(
    db: Session,
    experiment_id: int,
    *,
    phase: str,
    tool: str,
    message: str,
    state: str = "working",
    completed: int | None = None,
    total: int | None = None,
    overall_percent: float | None = None,
    detail: str | None = None,
    doing_status: str | None = None,
    micro_state: dict | None = None,
    river_stage: str | None = None,
) -> None:
    RunStateService.record_progress(
        db,
        experiment_id,
        phase=phase,
        tool=tool,
        message=message,
        state=state,
        completed=completed,
        total=total,
        overall_percent=overall_percent,
        detail=detail,
        doing_status=doing_status,
        micro_state=micro_state,
        river_stage=river_stage,
    )


def _find_recent_same_url_experiment(db: Session, target_id: int, scan_url: str):
    normalized_url = _normalize_scan_url(scan_url)
    experiments = (
        db.query(Experiment)
        .filter(Experiment.target_id == target_id)
        .filter(Experiment.status.in_([
            ExperimentStatus.RUNNING,
            ExperimentStatus.PAUSED,
            ExperimentStatus.PENDING,
        ]))
        .order_by(Experiment.updated_at.desc())
        .all()
    )
    for experiment in experiments:
        limits = _experiment_limits(experiment)
        if (
            limits.get("source") == "one_shot_scan"
            and limits.get("request_url") == normalized_url
        ):
            return experiment
    return None


def _claim_burp_trigger(scan_url: str) -> bool:
    now = datetime.now(UTC)
    normalized_url = _normalize_scan_url(scan_url)
    expires_before = now - timedelta(seconds=BURP_TRIGGER_DEDUPE_SECONDS)
    with _burp_trigger_lock:
        stale_keys = [
            key for key, started_at in _recent_burp_triggers.items()
            if started_at < expires_before
        ]
        for key in stale_keys:
            _recent_burp_triggers.pop(key, None)

        last_started_at = _recent_burp_triggers.get(normalized_url)
        if last_started_at and last_started_at >= expires_before:
            return False

        _recent_burp_triggers[normalized_url] = now
        return True


def _sync_burp_task(db: Session, target_id: int, experiment: Experiment, poll_attempts: int = 4) -> int:
    limits = _experiment_limits(experiment)
    task_id = limits.get("burp_task_id")
    if not task_id:
        return 0

    from backend_api.services.burp_service import BurpService

    imported = 0
    for attempt in range(max(1, poll_attempts)):
        if attempt:
            time.sleep(2)
        try:
            result = BurpService.import_from_rest(
                db=db,
                target_id=target_id,
                api_url=settings.BURP_API_URL,
                api_key=settings.BURP_API_KEY,
                task_id=task_id,
            )
            updated_limits = dict(_experiment_limits(experiment))
            updated_limits["burp_scan_status"] = result.get("scan_status")
            burp_message = result.get("scan_caption") or result.get("message")
            if burp_message:
                updated_limits["burp_scan_message"] = burp_message
            metrics = result.get("scan_metrics") or {}
            if metrics:
                updated_limits["burp_scan_metrics"] = {
                    "crawl_requests_made": metrics.get("crawl_requests_made"),
                    "crawl_network_errors": metrics.get("crawl_network_errors"),
                    "crawl_unique_locations_visited": metrics.get("crawl_unique_locations_visited"),
                    "audit_requests_made": metrics.get("audit_requests_made"),
                    "audit_network_errors": metrics.get("audit_network_errors"),
                    "current_url": metrics.get("current_url"),
                }
            experiment.limits = updated_limits
            db.commit()
            imported = max(imported, int(result.get("imported_endpoints", 0) or 0))
            if imported > 0:
                break
        except Exception as sync_err:
            logger.warning(f"Burp REST sync attempt {attempt + 1} failed for task {task_id}: {sync_err}")
    return imported


def _target_endpoint_count(db: Session, target_id: int) -> int:
    return db.query(Endpoint).filter(Endpoint.target_id == target_id).count()


def _target_param_count(db: Session, target_id: int) -> int:
    return (
        db.query(Param)
        .join(Endpoint, Param.endpoint_id == Endpoint.id)
        .filter(Endpoint.target_id == target_id)
        .count()
    )


def _endpoint_param_count(db: Session, endpoint_ids: set[int]) -> int:
    if not endpoint_ids:
        return 0
    return db.query(Param).filter(Param.endpoint_id.in_(endpoint_ids)).count()


def _persist_run_scope(
    db: Session,
    experiment: Experiment,
    endpoint_ids: set[int],
    imported_count: int,
) -> None:
    """Persist the exact recon inventory owned by one scan run."""
    scoped_ids = sorted(endpoint_ids)
    RunStateService.add_endpoints(db, experiment.id, scoped_ids, "recon")
    limits = dict(_experiment_limits(experiment))
    limits["endpoint_ids"] = scoped_ids
    limits["recon_imported_count"] = imported_count
    limits["recon_endpoint_count"] = len(scoped_ids)
    limits["recon_param_count"] = _endpoint_param_count(db, set(scoped_ids))
    limits["recon_completed_at"] = datetime.now(UTC).isoformat()
    experiment.limits = limits
    db.commit()


def _fail_scan(db: Session, experiment_id: int, error: Exception) -> None:
    """Move a background scan to a terminal state and retain the cause."""
    experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
    if not experiment:
        return
    limits = dict(_experiment_limits(experiment))
    warnings = limits.get("warnings") if isinstance(limits.get("warnings"), list) else []
    warnings.append({
        "level": "error",
        "phase": "scan",
        "message": "The scan pipeline stopped before producing a complete result.",
        "detail": str(error),
    })
    limits["warnings"] = warnings[-12:]
    limits["failed_at"] = datetime.now(UTC).isoformat()
    experiment.limits = limits
    experiment.status = ExperimentStatus.FAILED
    experiment.completed_at = datetime.now(UTC)
    if experiment.target:
        experiment.target.status = TargetStatus.RECON_ONLY
    db.commit()
    _record_scan_progress(
        db,
        experiment_id,
        phase="failed",
        tool="scan orchestrator",
        message="The scan stopped before completing its evidence plan",
        state="error",
        detail=str(error),
    )
    running_stage = db.query(RunStage).filter(
        RunStage.experiment_id == experiment_id,
        RunStage.status == RunStageStatus.RUNNING,
    ).order_by(RunStage.id.desc()).first()
    if running_stage:
        RunStateService.fail_stage(db, experiment_id, running_stage.name, error)
    try:
        from backend_api.services.campaign_report_service import CampaignReportService
        CampaignReportService.generate_report(db, experiment_id)
    except Exception as report_err:
        logger.error(f"Failed to generate failure report for experiment {experiment_id}: {report_err}", exc_info=True)


def _seed_query_probe_endpoints(db: Session, target_id: int, url: str) -> list[int]:
    if parse_qs(urlparse(url).query, keep_blank_values=True):
        return []

    endpoint_ids = []
    for name in COMMON_QUERY_PROBE_NAMES:
        probe_url = _url_with_query_param(url, name, "xssboss")
        endpoint = ReconService.create_endpoint_from_request(
            db,
            target_id,
            "GET",
            probe_url,
            _request_from_url(probe_url),
        )
        endpoint_ids.append(endpoint.id)
    unique_endpoint_ids = sorted(set(endpoint_ids))
    if unique_endpoint_ids:
        logger.info(f"Seeded {len(unique_endpoint_ids)} same-host query probe endpoint(s) for bare URL {url}")
    return unique_endpoint_ids


def _run_scan_task(
    experiment_id: int,
    target_id: int,
    url: str,
    crawl: bool,
    passive_recon: bool,
    max_depth: int,
    max_pages: int,
    run_vuln_checks: bool,
):
    db = SessionLocal()
    stage_owner = f"{socket.gethostname()}:{os.getpid()}"
    run_endpoint_ids: set[int] = set()
    initial_target_endpoint_ids: set[int] = set()
    LogService.info(
        "orchestrator",
        f"🚀 Pipeline Scan Initiated: {url}",
        detail=f"Target ID: {target_id} | Mode: {'Recon + Vuln Checks' if run_vuln_checks else 'Recon Only'} | Crawl: {crawl} | Passive Recon: {passive_recon}",
        experiment_id=experiment_id,
        target_id=target_id,
        db=db,
        data={
            "event_type": "scan_started",
            "url": url,
            "crawl": crawl,
            "passive_recon": passive_recon,
            "max_depth": max_depth,
            "max_pages": max_pages,
            "vulnerability_checks": run_vuln_checks,
            "burp_api_url": settings.BURP_API_URL,
            "llm_enabled": settings.LLM_ENABLED,
            "llm_model": settings.LLM_MODEL,
            "capture_screenshots": settings.CAPTURE_SCREENSHOTS,
            "capture_dom_snapshot": settings.CAPTURE_DOM_SNAPSHOT,
            "browser_worker_concurrency": settings.BROWSER_WORKER_CONCURRENCY,
            "max_test_cases": settings.MAX_TEST_CASES_PER_EXPERIMENT,
        },
    )
    # Auto-trigger Burp active scan
    try:
        RunStateService.ensure_pipeline(db, experiment_id)
        _record_scan_progress(
            db,
            experiment_id,
            phase="recon",
            tool="scan orchestrator",
            message="Preparing authorized scope and discovery tools",
            overall_percent=1,
        )
        recon_stage = db.query(RunStage).filter_by(
            experiment_id=experiment_id, name=RunStageName.RECON
        ).one()
        if recon_stage.status != RunStageStatus.COMPLETED and not RunStateService.claim_stage(
            db, experiment_id, RunStageName.RECON, stage_owner
        ):
            logger.info(f"Scan task {experiment_id} already has a live recon owner; skipping duplicate delivery")
            return
        experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
        limits = _experiment_limits(experiment) if experiment else {}
        if experiment and not isinstance(limits.get("llm_preflight"), dict):
            from backend_api.services.llm_service import LLMService

            llm_status = LLMService.provider_status()
            llm_status["checked_at"] = datetime.now(UTC).isoformat()
            updated_limits = dict(limits)
            updated_limits["llm_preflight"] = llm_status
            updated_limits["llm_mode"] = (
                "available"
                if llm_status.get("reachable") and llm_status.get("model_available")
                else "deterministic_only"
            )
            if settings.LLM_ENABLED and updated_limits["llm_mode"] == "deterministic_only":
                warnings = (
                    updated_limits.get("warnings")
                    if isinstance(updated_limits.get("warnings"), list)
                    else []
                )
                warnings.append({
                    "level": "warning",
                    "phase": "llm",
                    "message": "Local LLM was unavailable; AI advice was disabled for this run.",
                    "detail": str(llm_status.get("error") or "Configured model is not installed.")[:500],
                })
                updated_limits["warnings"] = warnings[-12:]
            experiment.limits = updated_limits
            db.commit()
            limits = updated_limits
            LogService.emit(
                "INFO" if updated_limits["llm_mode"] == "available" else "WARNING",
                "llm.preflight",
                (
                    "Local LLM preflight passed"
                    if updated_limits["llm_mode"] == "available"
                    else "Local LLM preflight failed; deterministic-only mode selected"
                ),
                detail=llm_status.get("error"),
                experiment_id=experiment_id,
                target_id=target_id,
                data={"event_type": "llm_preflight", **llm_status, "mode": updated_limits["llm_mode"]},
                db=db,
            )
            if updated_limits["llm_mode"] == "deterministic_only":
                _record_scan_progress(
                    db,
                    experiment_id,
                    phase="recon",
                    tool="local LLM preflight",
                    message="Local LLM unavailable — deterministic engine remains active",
                    state="warning",
                    detail=str(llm_status.get("error") or "Configured model is unavailable.")[:500],
                )
        from backend_api.utils.proxy_health import resolve_worker_proxy

        proxy_status = resolve_worker_proxy()
        experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
        if experiment:
            updated_limits = dict(_experiment_limits(experiment))
            updated_limits["proxy_preflight"] = proxy_status
            experiment.limits = updated_limits
            db.commit()
            limits = updated_limits
        LogService.emit(
            "WARNING" if proxy_status.get("fallback_direct") else "INFO",
            "proxy.preflight",
            (
                "Configured proxy unavailable; direct fallback selected"
                if proxy_status.get("fallback_direct")
                else f"Network path selected: {proxy_status.get('source', 'direct')}"
            ),
            experiment_id=experiment_id,
            target_id=target_id,
            data={"event_type": "proxy_preflight", **proxy_status},
            db=db,
        )
        run_endpoint_ids.update(int(value) for value in limits.get("endpoint_ids", []) if value is not None)
        initial_target_endpoint_ids = {
            endpoint_id for (endpoint_id,) in
            db.query(Endpoint.id).filter(Endpoint.target_id == target_id).all()
        }
        if limits.get("burp_task_id") or limits.get("burp_scan_started_at"):
            logger.info(f"Burp Active Scan already recorded for experiment {experiment_id}; skipping duplicate trigger")
        elif not _claim_burp_trigger(url):
            logger.info(f"Burp Active Scan recently triggered for {url}; skipping duplicate trigger")
        else:
            from backend_api.services.burp_service import BurpService
            burp_scan = BurpService.trigger_scan(
                api_url=settings.BURP_API_URL,
                target_urls=[url],
                api_key=settings.BURP_API_KEY,
                startup_timeout_seconds=settings.BURP_SCAN_STARTUP_TIMEOUT_SECONDS,
            )
            if experiment and burp_scan.get("task_id"):
                updated_limits = dict(limits)
                updated_limits["burp_scan_started_at"] = datetime.now(UTC).isoformat()
                updated_limits["burp_task_id"] = burp_scan.get("task_id")
                updated_limits["burp_status"] = burp_scan.get("status")
                updated_limits["burp_seed_urls"] = burp_scan.get("seed_urls") or [url]
                updated_limits["burp_preflights"] = burp_scan.get("preflights") or []
                warnings = updated_limits.get("warnings") if isinstance(updated_limits.get("warnings"), list) else []
                for preflight in updated_limits["burp_preflights"]:
                    if isinstance(preflight, dict) and not preflight.get("reachable"):
                        warnings.append({
                            "level": "warning",
                            "phase": "burp",
                            "message": "Burp seed preflight could not reach the submitted URL.",
                            "detail": preflight.get("error") or preflight.get("url"),
                        })
                updated_limits["warnings"] = warnings[-12:]
                experiment.limits = updated_limits
                db.commit()
                logger.info(f"Automatically triggered Burp Active Scan on target URL: {url}")
                LogService.info(
                    "burp",
                    "Burp REST scan task started",
                    experiment_id=experiment_id,
                    target_id=target_id,
                    data={
                        "event_type": "burp_task_started",
                        "task_id": burp_scan.get("task_id"),
                        "status": burp_scan.get("status"),
                        "seed_urls": burp_scan.get("seed_urls") or [url],
                        "preflights": burp_scan.get("preflights") or [],
                    },
                    db=db,
                )
            else:
                if experiment:
                    updated_limits = dict(limits)
                    updated_limits["burp_scan_started_at"] = datetime.now(UTC).isoformat()
                    updated_limits["burp_status"] = str(burp_scan.get("status") or "not_started")
                    updated_limits["burp_scan_message"] = str(
                        burp_scan.get("message") or "Burp returned no scan task id."
                    )[:500]
                    warnings = (
                        updated_limits.get("warnings")
                        if isinstance(updated_limits.get("warnings"), list)
                        else []
                    )
                    warnings.append({
                        "level": "warning",
                        "phase": "burp",
                        "message": "Burp did not start; the run continued with local tools only.",
                        "detail": updated_limits["burp_scan_message"],
                    })
                    updated_limits["warnings"] = warnings[-12:]
                    experiment.limits = updated_limits
                    db.commit()
                    LogService.warn(
                        "burp",
                        "Burp returned no scan task; continuing local-only",
                        detail=updated_limits["burp_scan_message"],
                        experiment_id=experiment_id,
                        target_id=target_id,
                        data={"event_type": "burp_task_not_started", "response": burp_scan},
                        db=db,
                    )
                logger.info("Burp Active Scan was not started; continuing with the local one-shot pipeline")
    except Exception as burp_scan_err:
        logger.warning(f"Auto Burp active scan trigger failed (is Burp REST running?): {burp_scan_err}")
        experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
        if experiment:
            updated_limits = _experiment_limits(experiment)
            updated_limits["burp_scan_started_at"] = datetime.now(UTC).isoformat()
            updated_limits["burp_status"] = "unavailable"
            updated_limits["burp_scan_message"] = str(burp_scan_err)[:500]
            warnings = (
                updated_limits.get("warnings")
                if isinstance(updated_limits.get("warnings"), list)
                else []
            )
            warnings.append({
                "level": "warning",
                "phase": "burp",
                "message": "Burp REST was unavailable; the run continued with local tools only.",
                "detail": str(burp_scan_err)[:500],
            })
            updated_limits["warnings"] = warnings[-12:]
            experiment.limits = updated_limits
            db.commit()
            _record_scan_progress(
                db,
                experiment_id,
                phase="recon",
                tool="Burp Suite REST",
                message="Burp unavailable — continuing in local-only mode",
                state="warning",
                detail=str(burp_scan_err)[:500],
            )
            LogService.error(
                "burp",
                "Burp REST unavailable; continuing local-only",
                detail=str(burp_scan_err),
                experiment_id=experiment_id,
                target_id=target_id,
                data={
                    "event_type": "burp_unavailable",
                    "api_url": settings.BURP_API_URL,
                    "fallback": "local_pipeline",
                },
                db=db,
            )
    try:
        imported = 0
        recon_signals: list[dict] = []
        experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
        if experiment:
            # Burp coordination loop: poll until the crawl phase finishes
            limits = experiment.limits or {}
            task_id = limits.get("burp_task_id")
            if task_id:
                logger.info("Coordinating scan: polling Burp crawl phase to complete before local fuzzing...")
                max_polls = 18  # 3 minutes max wait for crawl
                for poll in range(max_polls):
                    _record_scan_progress(
                        db,
                        experiment_id,
                        phase="burp",
                        tool="Burp REST coordinator",
                        message="Waiting for Burp crawl inventory",
                        state="waiting",
                        completed=poll + 1,
                        total=max_polls,
                        overall_percent=2 + (3 * (poll + 1) / max_polls),
                        detail="The local pipeline will continue when Burp leaves crawling/paused state or the wait limit expires.",
                    )
                    # Fetch status & update database
                    _sync_burp_task(db, target_id, experiment, poll_attempts=1)
                    db.refresh(experiment)
                    current_limits = experiment.limits or {}
                    status = str(current_limits.get("burp_scan_status") or "").lower()
                    logger.info(f"Burp task status: {status}")
                    # If Burp finished crawling (i.e. is auditing, succeeded, or failed)
                    if status and status not in ("crawling", "paused"):
                        break
                    time.sleep(10)

            # Final sync to capture any remaining endpoints
            imported += _sync_burp_task(db, target_id, experiment)

        if crawl:
            try:
                def _record_crawler_decision(event: dict) -> None:
                    event_type = str(event.get("event_type") or "crawler_event")
                    messages = {
                        "crawler_url_selected": "Crawler selected URL from priority frontier",
                        "crawler_page_complete": "Crawler completed page feature analysis",
                        "crawler_template_skipped": "Crawler skipped a template-equivalent URL",
                        "crawler_feature_duplicate": "Crawler avoided duplicate expensive interactions",
                        "crawler_page_timeout": "Crawler page navigation timed out",
                        "crawler_page_error": "Crawler page analysis failed",
                        "crawler_frontier_complete": "Crawler priority frontier completed",
                        "crawler_rate_wait_started": "Crawler entered the host rate limiter",
                        "crawler_navigation_complete": "Browser navigation completed",
                        "crawler_links_extracted": "Crawler extracted route candidates",
                        "crawler_interactions_complete": "Safe SPA interaction pass completed",
                        "crawler_bundle_started": "Client bundle analysis started",
                        "crawler_bundle_complete": "Client bundle analysis completed",
                        "crawler_bundle_unavailable": "Client bundle content was unavailable",
                        "crawler_bundle_error": "Client bundle analysis failed",
                        "crawler_interaction_budget_exhausted": "SPA interaction time budget exhausted",
                        "crawler_bundle_budget_exhausted": "Client bundle analysis time budget exhausted",
                    }
                    level = "ERROR" if event_type == "crawler_page_error" else (
                        "WARNING" if event_type == "crawler_page_timeout" else "INFO"
                    )
                    LogService.emit(
                        level,
                        "crawler.decision",
                        messages.get(event_type, event_type.replace("_", " ").title()),
                        detail=str(event.get("url") or event.get("stop_reason") or "")[:1000] or None,
                        experiment_id=experiment_id,
                        target_id=target_id,
                        data=event,
                        db=db,
                    )

                crawler = Crawler(
                    base_url=url,
                    max_depth=max_depth,
                    max_pages=max_pages,
                    delay=0.25,
                    follow_external=False,
                    auth_identity=_experiment_limits(experiment).get("auth_identity") if experiment else None,
                    progress_callback=lambda page_url, depth, visited, limit: _record_scan_progress(
                        db,
                        experiment_id,
                        phase="recon",
                        tool="Chromium crawler",
                        message=f"Crawling page {visited} of at most {limit}",
                        completed=visited,
                        total=limit,
                        overall_percent=5 + (15 * visited / max(1, limit)),
                        detail=f"Depth {depth}: {page_url}",
                        doing_status=f"Recon Rapids: Crawling page {visited}/{limit} ({page_url})",
                        micro_state={
                            "action": "crawl_page",
                            "endpoint": page_url,
                            "substep": f"Depth {depth} crawl",
                            "result": f"Page {visited}/{limit}",
                        },
                        river_stage="recon",
                    ),
                    decision_callback=_record_crawler_decision,
                )
                crawled = crawler.crawl_to_database(target_id, db)
                imported += crawled
                run_endpoint_ids.update(crawler.saved_endpoint_ids)
                recon_signals.extend(crawler.research_signals)
                _record_scan_progress(
                    db,
                    experiment_id,
                    phase="recon",
                    tool="priority Chromium crawler",
                    message="Feature-aware crawl frontier completed",
                    detail=(
                        f"Visited {len(crawler.visited)} representative page(s), found "
                        f"{len(crawler.route_template_counts)} route template(s), and skipped "
                        f"{len(crawler.skipped_template_urls)} template-equivalent URL(s)."
                    ),
                    overall_percent=20,
                    doing_status="Recon Rapids: feature-aware crawl complete",
                    micro_state={
                        "action": "crawl_complete",
                        "result": {
                            "visited_pages": len(crawler.visited),
                            "route_templates": len(crawler.route_template_counts),
                            "template_urls_skipped": len(crawler.skipped_template_urls),
                            "frontier_peak": crawler.frontier_peak,
                        },
                    },
                    river_stage="recon",
                )
                logger.info(f"Imported {crawled} endpoint(s) from crawler for target {target_id}")
                if crawler.interventions:
                    from backend_api.services.human_intervention_service import HumanInterventionService

                    for intervention in crawler.interventions:
                        HumanInterventionService.raise_intervention(
                            db,
                            experiment_id,
                            kind=intervention.get("kind") or "authentication_blocked",
                            reason=intervention.get("reason") or "Authentication requires operator input",
                            identity=intervention.get("identity"),
                            url=intervention.get("url"),
                            workflow=intervention.get("workflow"),
                        )
                    logger.warning("Campaign %s paused with %s operator intervention(s)", experiment_id, len(crawler.interventions))
                    return
            except Exception as crawl_err:
                logger.warning(f"Crawler failed for scan target {target_id}: {crawl_err}", exc_info=True)

            if passive_recon:
                try:
                    _record_scan_progress(
                        db,
                        experiment_id,
                        phase="recon",
                        tool="passive recon analyzer",
                        message="Mining scripts, routes, and passive attack-surface signals",
                        overall_percent=18,
                    )
                    from recon_engine.advanced_recon import AdvancedRecon
                    adv = AdvancedRecon(db, target_id)
                    adv_crawled = adv.run_all(url)
                    imported += adv_crawled
                    run_endpoint_ids.update(adv.imported_endpoint_ids)
                    logger.info(f"Imported {adv_crawled} endpoint(s) from advanced recon for target {target_id}")
                except Exception as adv_err:
                    logger.warning(f"Advanced recon failed for target {target_id}: {adv_err}", exc_info=True)

        if imported == 0:
            logger.info(f"Running scan for target {target_id} using the submitted URL only")

        # Include records created by importers that cannot return endpoint IDs,
        # while excluding stale inventory that predates this run.
        current_target_endpoint_ids = {
            endpoint_id for (endpoint_id,) in
            db.query(Endpoint.id).filter(Endpoint.target_id == target_id).all()
        }
        run_endpoint_ids.update(current_target_endpoint_ids - initial_target_endpoint_ids)

        if _endpoint_param_count(db, run_endpoint_ids) == 0:
            seeded_endpoint_ids = _seed_query_probe_endpoints(db, target_id, url)
            run_endpoint_ids.update(seeded_endpoint_ids)
            imported += len(seeded_endpoint_ids)

        experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
        if experiment:
            _persist_run_scope(db, experiment, run_endpoint_ids, imported)
            workflow_summary = {}
            try:
                from backend_api.services.workflow_discovery_service import WorkflowDiscoveryService

                _record_scan_progress(
                    db,
                    experiment_id,
                    phase="workflow_discovery",
                    tool="form workflow planner",
                    message="Mapping reusable safe form workflows",
                    detail=f"Analyzing {len(run_endpoint_ids)} in-run endpoint(s); each captured page is parsed once.",
                    overall_percent=20.5,
                    river_stage="recon",
                )
                workflow_summary = WorkflowDiscoveryService.discover_for_experiment(
                    db, experiment_id, run_endpoint_ids
                )
                LogService.info(
                    "workflow.discovery",
                    "Safe form workflow discovery completed",
                    experiment_id=experiment_id,
                    target_id=target_id,
                    data={"event_type": "workflow_discovery_complete", **workflow_summary},
                    db=db,
                )
                logger.info(
                    "Workflow discovery attached %s validated flow(s) for experiment %s",
                    workflow_summary.get("attached", 0),
                    experiment_id,
                )
            except Exception as workflow_error:
                logger.warning("Autonomous workflow discovery failed: %s", workflow_error, exc_info=True)
            research_summary = {}
            if bool(_experiment_limits(experiment).get("autonomous_research", True)):
                try:
                    from backend_api.services.research_service import ResearchService

                    _record_scan_progress(
                        db,
                        experiment_id,
                        phase="research",
                        tool="attack-surface research planner",
                        message="Building prioritized cross-bug hypotheses",
                        detail="Connecting endpoints, parameters, contexts, filters, sinks, and client-bundle evidence.",
                        overall_percent=21,
                        river_stage="params",
                    )
                    research_summary = ResearchService.plan_experiment(
                        db, experiment_id, recon_signals=recon_signals
                    )
                    LogService.info(
                        "research.planner",
                        "Attack-surface hypothesis plan completed",
                        experiment_id=experiment_id,
                        target_id=target_id,
                        data={"event_type": "research_plan_complete", **research_summary},
                        db=db,
                    )
                    logger.info(
                        "Research planner built %s hypotheses over %s graph nodes for experiment %s",
                        research_summary.get("hypotheses", 0),
                        research_summary.get("surface_nodes", 0),
                        experiment_id,
                    )
                except Exception as research_error:
                    logger.warning("Autonomous research planning failed: %s", research_error, exc_info=True)
            RunStateService.complete_stage(
                db,
                experiment_id,
                RunStageName.RECON,
                {
                    "endpoint_count": len(run_endpoint_ids),
                    "param_count": _endpoint_param_count(db, run_endpoint_ids),
                    "imported_count": imported,
                    "workflows": workflow_summary,
                    "research": research_summary,
                },
            )

        if not run_vuln_checks:
            experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
            target = db.query(Target).filter(Target.id == target_id).first()
            if experiment:
                updated_limits = dict(_experiment_limits(experiment))
                experiment.limits = updated_limits
                experiment.status = ExperimentStatus.COMPLETED
                experiment.completed_at = datetime.now(UTC)
            if target:
                target.status = TargetStatus.RECON_ONLY
            db.commit()
            try:
                RunStateService.claim_stage(db, experiment_id, RunStageName.REPORTING, stage_owner)
                from backend_api.services.campaign_report_service import CampaignReportService
                CampaignReportService.generate_report(db, experiment_id)
                RunStateService.complete_stage(
                    db, experiment_id, RunStageName.REPORTING, {"recon_only": True}
                )
            except Exception as rep_err:
                logger.error(f"Failed to generate campaign report for recon: {rep_err}", exc_info=True)
            logger.info(
                f"Recon-only scan completed for target {target_id}: "
                f"{_target_endpoint_count(db, target_id)} endpoint(s), {_target_param_count(db, target_id)} parameter(s)."
            )
            return

        RunStateService.claim_stage(db, experiment_id, RunStageName.PROFILING, stage_owner)
        _record_scan_progress(
            db,
            experiment_id,
            phase="profiling",
            tool="context profiler",
            message="Classifying parameters, reflection contexts, filters, and sinks",
            overall_percent=20,
        )
        fuzzer = FuzzingService(db)
        result = fuzzer.run_experiment(experiment_id)
        if result.get("status") == ExperimentStatus.FAILED.value:
            raise RuntimeError(result.get("message") or "Vulnerability checks failed")
        RunStateService.complete_stage(
            db,
            experiment_id,
            RunStageName.PROFILING,
            {"test_cases_created": result.get("test_cases_created", 0)},
        )
        RunStateService.claim_stage(db, experiment_id, RunStageName.EXECUTION, stage_owner, lease_seconds=3600)

        experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
        limits = _experiment_limits(experiment) if experiment else {}
        if (
            result.get("test_cases_created", 0) == 0
            and not limits.get("query_probes_seeded")
            and not parse_qs(urlparse(url).query, keep_blank_values=True)
        ):
            seeded_endpoint_ids = _seed_query_probe_endpoints(db, target_id, url)
            if seeded_endpoint_ids and experiment:
                updated_limits = dict(limits)
                updated_limits["query_probes_seeded"] = True
                updated_limits["query_probe_names"] = list(COMMON_QUERY_PROBE_NAMES)
                updated_limits["endpoint_ids"] = sorted(set((updated_limits.get("endpoint_ids") or []) + seeded_endpoint_ids))
                experiment.limits = updated_limits
                experiment.status = ExperimentStatus.RUNNING
                experiment.completed_at = None
                db.commit()
                logger.info(
                    f"Initial run created no test cases; retrying experiment {experiment_id} with {len(seeded_endpoint_ids)} query probe endpoint(s)."
                )
                retry_result = fuzzer.run_experiment(experiment_id)
                if retry_result.get("status") == ExperimentStatus.FAILED.value:
                    raise RuntimeError(retry_result.get("message") or "Vulnerability check retry failed")
    except Exception as err:
        logger.error(f"Scan task failed for experiment {experiment_id}: {err}", exc_info=True)
        try:
            db.rollback()
            _fail_scan(db, experiment_id, err)
        except Exception as state_err:
            logger.error(f"Failed to persist terminal state for experiment {experiment_id}: {state_err}", exc_info=True)
    finally:
        db.close()


@router.get("/{experiment_id}/interventions")
def list_scan_interventions(experiment_id: int, db: Session = Depends(get_db)):
    """Return open MFA/CAPTCHA/login/workflow actions for a paused campaign."""
    from backend_api.services.human_intervention_service import HumanInterventionService

    try:
        return {"items": HumanInterventionService.list_open(db, experiment_id)}
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@router.post("/{experiment_id}/interventions/{intervention_id}/resolve")
def resolve_scan_intervention(
    experiment_id: int,
    intervention_id: str,
    request: InterventionResolution,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Apply refreshed auth state and resume the exact paused one-shot campaign."""
    from backend_api.services.human_intervention_service import HumanInterventionService

    experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
    if not experiment:
        raise HTTPException(status_code=404, detail=f"Experiment {experiment_id} not found")
    if request.auth_info is not None:
        experiment.target.auth_info = request.auth_info
        db.commit()
    try:
        resolved = HumanInterventionService.resolve(
            db, experiment_id, intervention_id, request.resolution
        )
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error

    open_items = HumanInterventionService.list_open(db, experiment_id)
    if not open_items:
        limits = _experiment_limits(experiment)
        request_url = str(limits.get("request_url") or experiment.target.base_url)
        background_tasks.add_task(
            _run_scan_task,
            experiment.id,
            experiment.target_id,
            request_url,
            bool(limits.get("crawl", True)),
            bool(limits.get("passive_recon", False)),
            int(limits.get("max_depth", 1)),
            int(limits.get("max_pages", 100)),
            bool(limits.get("vuln_checks_enabled", True)),
        )
    return {"resolved": resolved, "remaining_open": len(open_items), "resumed": not open_items}


@router.post("/", response_model=ScanResponse, status_code=201)
def create_scan(scan: ScanCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Create a target from a URL and start recon-only or full vuln scanning."""
    if not scan.authorized:
        raise HTTPException(
            status_code=400,
            detail="Confirm you own this target or have explicit permission to test it.",
        )

    origin = _origin_for_url(scan.url)
    host = _host_for_url(scan.url)

    target = (
        db.query(Target)
        .filter(Target.base_url == origin)
        .order_by(Target.updated_at.desc())
        .first()
    )
    reused_target = target is not None

    is_recon_only = scan.mode == ScanMode.RECON
    target_status = TargetStatus.RECON_ONLY if is_recon_only else TargetStatus.FUZZING
    crawl_enabled = scan.crawl

    if target:
        target.status = target_status
        target.scope_tags = target.scope_tags or {"allowed_hosts": [host]}
        if scan.auth_info is not None:
            target.auth_info = scan.auth_info
        db.commit()
        db.refresh(target)
    else:
        target = TargetService.create_target(
            db,
            {
                "name": scan.name or host or origin,
                "base_url": origin,
                "notes": "Created from one-shot scan.",
                "bounty_platform": "manual",
                "scope_tags": {"allowed_hosts": [host]},
                "auth_info": scan.auth_info or {},
                "status": target_status,
            },
        )

    recent_experiment = None if scan.force_new else _find_recent_same_url_experiment(db, target.id, scan.url)
    if recent_experiment:
        return ScanResponse(
            target_id=target.id,
            experiment_id=recent_experiment.id,
            endpoint_count=db.query(Endpoint).filter(Endpoint.target_id == target.id).count(),
            status=recent_experiment.status.value,
            message=(
                f"Reusing active or paused scan for {host}. "
                "Resume that run, or submit force_new=true to retain it and launch a separate diagnostic run."
            ),
        )

    endpoint = ReconService.create_endpoint_from_request(
        db,
        target.id,
        "GET",
        scan.url,
        _request_from_url(scan.url),
    )

    experiment = ExperimentService.create_experiment(
        db,
        {
            "target_id": target.id,
            "name": f"{'Recon only' if is_recon_only else 'Recon + vuln scan'} - {host}",
            "strategy": scan.strategy,
            "limits": {
                "source": "one_shot_scan",
                "scan_mode": scan.mode.value,
                "vuln_checks_enabled": not is_recon_only,
                "request_url": _normalize_scan_url(scan.url),
                "endpoint_ids": [endpoint.id],
                "crawl": crawl_enabled,
                "passive_recon": scan.passive_recon,
                "autonomous_research": scan.autonomous_research,
                "max_depth": scan.max_depth,
                "max_pages": scan.max_pages,
                "reused_target": reused_target,
                "auth_identity": scan.auth_identity,
            },
        },
    )
    RunStateService.ensure_pipeline(db, experiment.id)
    RunStateService.add_endpoints(db, experiment.id, [endpoint.id], "submitted_url")
    experiment = ExperimentService.start_experiment(db, experiment.id)
    _record_scan_progress(
        db,
        experiment.id,
        phase="queued",
        tool="scan orchestrator",
        message="Scan accepted and queued for discovery",
        state="waiting",
        completed=0,
        total=1,
        overall_percent=0,
        detail="The first crawler heartbeat should appear shortly.",
    )

    scan_payload = {
        "experiment_id": experiment.id,
        "target_id": target.id,
        "url": scan.url,
        "crawl": crawl_enabled,
        "passive_recon": scan.passive_recon,
        "max_depth": scan.max_depth,
        "max_pages": scan.max_pages,
        "run_vuln_checks": not is_recon_only,
    }
    if settings.ORCHESTRATION_MODE.lower() == "celery":
        from backend_api.task_queue import scan_pipeline_task

        scan_pipeline_task.apply_async(args=[scan_payload], queue="orchestration")
    else:
        background_tasks.add_task(_run_scan_task, **scan_payload)

    endpoint_count = _target_endpoint_count(db, target.id)
    if is_recon_only:
        message = f"Recon started for {host}. Burp, crawler, and script/parameter discovery are live on this page."
    else:
        message_prefix = "Scan started" if not reused_target else "Scan started using existing recon"
        message = f"{message_prefix} for {host}. Recon and vulnerability monitoring are live on this page."
    return ScanResponse(
        target_id=target.id,
        experiment_id=experiment.id,
        endpoint_count=endpoint_count,
        status=experiment.status.value,
        message=message,
    )


@router.get("/live-screen")
def get_live_browser_screen():
    """Get the current live browser vision preview frame and active execution telemetry."""
    import json
    import time
    from pathlib import Path
    
    screenshots_dir = Path(__file__).resolve().parent.parent.parent / "screenshots"
    live_img = screenshots_dir / "live_latest.png"
    meta_path = screenshots_dir / "live_metadata.json"
    
    metadata: Dict[str, Any] = {}
    if meta_path.exists():
        try:
            metadata = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            metadata = {}
            
    available = live_img.exists()
    ts = int(time.time() * 1000)
    image_url = f"/screenshots/live_latest.png?t={ts}" if available else None
    
    return {
        "available": available,
        "image_url": image_url,
        "metadata": metadata,
    }
