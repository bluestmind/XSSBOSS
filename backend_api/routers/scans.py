"""One-shot scan router."""
from datetime import UTC, datetime, timedelta
from threading import Lock
import os
import socket
import time
from urllib.parse import parse_qs, parse_qsl, urlencode, urlparse

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
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
from backend_api.utils.logger import logger
from recon_engine.crawler import Crawler

router = APIRouter(prefix="/scans", tags=["scans"])

BURP_TRIGGER_DEDUPE_SECONDS = 600
COMMON_QUERY_PROBE_NAMES = ("q", "s", "search", "query", "keyword", "redirect", "url", "next")
_burp_trigger_lock = Lock()
_recent_burp_triggers = {}


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
    # Auto-trigger Burp active scan
    try:
        RunStateService.ensure_pipeline(db, experiment_id)
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
            else:
                logger.info("Burp Active Scan was not started; continuing with the local one-shot pipeline")
    except Exception as burp_scan_err:
        logger.warning(f"Auto Burp active scan trigger failed (is Burp REST running?): {burp_scan_err}")
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
                crawler = Crawler(
                    base_url=url,
                    max_depth=max_depth,
                    max_pages=max_pages,
                    delay=0.25,
                    follow_external=False,
                )
                crawled = crawler.crawl_to_database(target_id, db)
                imported += crawled
                run_endpoint_ids.update(crawler.saved_endpoint_ids)
                recon_signals.extend(crawler.research_signals)
                logger.info(f"Imported {crawled} endpoint(s) from crawler for target {target_id}")
            except Exception as crawl_err:
                logger.warning(f"Crawler failed for scan target {target_id}: {crawl_err}", exc_info=True)

            if passive_recon:
                try:
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
            research_summary = {}
            if bool(_experiment_limits(experiment).get("autonomous_research", True)):
                try:
                    from backend_api.services.research_service import ResearchService

                    research_summary = ResearchService.plan_experiment(
                        db, experiment_id, recon_signals=recon_signals
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
                "auth_info": {},
                "status": target_status,
            },
        )

    recent_experiment = _find_recent_same_url_experiment(db, target.id, scan.url)
    if recent_experiment:
        return ScanResponse(
            target_id=target.id,
            experiment_id=recent_experiment.id,
            endpoint_count=db.query(Endpoint).filter(Endpoint.target_id == target.id).count(),
            status=recent_experiment.status.value,
            message=(
                f"Reusing recent scan for {host}. "
                "Wait a few minutes or remove the previous run before launching another Burp crawl for the same URL."
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
            },
        },
    )
    RunStateService.ensure_pipeline(db, experiment.id)
    RunStateService.add_endpoints(db, experiment.id, [endpoint.id], "submitted_url")
    experiment = ExperimentService.start_experiment(db, experiment.id)

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
