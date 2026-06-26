"""One-shot scan router."""
from datetime import datetime, timedelta
from threading import Lock
import time
from urllib.parse import parse_qs, urlparse

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from backend_api.db.session import SessionLocal, get_db
from backend_api.config import settings
from backend_api.models.endpoint import Endpoint
from backend_api.models.experiment import Experiment, ExperimentStatus
from backend_api.models.param import Param
from backend_api.models.target import Target
from backend_api.models.target import TargetStatus
from backend_api.schemas.scan import ScanCreate, ScanMode, ScanResponse
from backend_api.services.experiment_service import ExperimentService
from backend_api.services.fuzzing_service import FuzzingService
from backend_api.services.recon_service import ReconService
from backend_api.services.target_service import TargetService
from backend_api.utils.logger import logger
from recon_engine.crawler import Crawler

router = APIRouter(prefix="/scans", tags=["scans"])

RECENT_SCAN_REUSE_SECONDS = 600
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
    return f"{scheme}://{netloc}{path}?{parsed.query}" if parsed.query else f"{scheme}://{netloc}{path}"


def _experiment_limits(experiment: Experiment) -> dict:
    return experiment.limits if isinstance(experiment.limits, dict) else {}


def _find_recent_same_url_experiment(db: Session, target_id: int, scan_url: str):
    cutoff = datetime.utcnow() - timedelta(seconds=RECENT_SCAN_REUSE_SECONDS)
    normalized_url = _normalize_scan_url(scan_url)
    experiments = (
        db.query(Experiment)
        .filter(Experiment.target_id == target_id)
        .filter(Experiment.created_at >= cutoff)
        .order_by(Experiment.updated_at.desc())
        .all()
    )
    for experiment in experiments:
        limits = _experiment_limits(experiment)
        if (
            limits.get("source") == "one_shot_scan"
            and limits.get("request_url") == normalized_url
            and experiment.status in [ExperimentStatus.RUNNING, ExperimentStatus.PAUSED, ExperimentStatus.PENDING]
        ):
            return experiment
    return None


def _claim_burp_trigger(scan_url: str) -> bool:
    now = datetime.utcnow()
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


def _target_recon_counts(db: Session, target_id: int) -> dict:
    return {
        "endpoints": _target_endpoint_count(db, target_id),
        "params": _target_param_count(db, target_id),
    }


def _seed_query_probe_endpoints(db: Session, target_id: int, url: str) -> list[int]:
    if parse_qs(urlparse(url).query, keep_blank_values=True):
        return []

    endpoint_ids = []
    for name in COMMON_QUERY_PROBE_NAMES:
        probe_url = _url_with_query_param(url, name, "xssboss")
        before = _target_param_count(db, target_id)
        endpoint = ReconService.create_endpoint_from_request(
            db,
            target_id,
            "GET",
            probe_url,
            _request_from_url(probe_url),
        )
        endpoint_ids.append(endpoint.id)
        after = _target_param_count(db, target_id)
    unique_endpoint_ids = sorted(set(endpoint_ids))
    if unique_endpoint_ids:
        logger.info(f"Seeded {len(unique_endpoint_ids)} same-host query probe endpoint(s) for bare URL {url}")
    return unique_endpoint_ids


def _run_scan_task(
    experiment_id: int,
    target_id: int,
    url: str,
    crawl: bool,
    max_depth: int,
    max_pages: int,
    run_vuln_checks: bool,
):
    db = SessionLocal()
    # Auto-trigger Burp active scan
    try:
        experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
        limits = _experiment_limits(experiment) if experiment else {}
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
            if experiment:
                updated_limits = dict(limits)
                updated_limits["burp_scan_started_at"] = datetime.utcnow().isoformat()
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
    except Exception as burp_scan_err:
        logger.warning(f"Auto Burp active scan trigger failed (is Burp REST running?): {burp_scan_err}")
    try:
        imported = 0
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
                logger.info(f"Imported {crawled} endpoint(s) from crawler for target {target_id}")
            except Exception as crawl_err:
                logger.warning(f"Crawler failed for scan target {target_id}: {crawl_err}", exc_info=True)

            try:
                from recon_engine.advanced_recon import AdvancedRecon
                adv = AdvancedRecon(db, target_id)
                adv_crawled = adv.run_all(url)
                imported += adv_crawled
                logger.info(f"Imported {adv_crawled} endpoint(s) from advanced recon for target {target_id}")
            except Exception as adv_err:
                logger.warning(f"Advanced recon failed for target {target_id}: {adv_err}", exc_info=True)

        if imported == 0:
            logger.info(f"Running scan for target {target_id} using the submitted URL only")

        if _target_param_count(db, target_id) == 0:
            imported += len(_seed_query_probe_endpoints(db, target_id, url))

        if not run_vuln_checks:
            experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
            target = db.query(Target).filter(Target.id == target_id).first()
            if experiment:
                recon_counts = _target_recon_counts(db, target_id)
                updated_limits = dict(_experiment_limits(experiment))
                updated_limits["recon_completed_at"] = datetime.utcnow().isoformat()
                updated_limits["recon_imported_count"] = imported
                updated_limits["recon_endpoint_count"] = recon_counts["endpoints"]
                updated_limits["recon_param_count"] = recon_counts["params"]
                experiment.limits = updated_limits
                experiment.status = ExperimentStatus.COMPLETED
                experiment.completed_at = datetime.utcnow()
            if target:
                target.status = TargetStatus.RECON_ONLY
            db.commit()
            try:
                from backend_api.services.campaign_report_service import CampaignReportService
                CampaignReportService.generate_report(db, experiment_id)
            except Exception as rep_err:
                logger.error(f"Failed to generate campaign report for recon: {rep_err}", exc_info=True)
            logger.info(
                f"Recon-only scan completed for target {target_id}: "
                f"{_target_endpoint_count(db, target_id)} endpoint(s), {_target_param_count(db, target_id)} parameter(s)."
            )
            return

        fuzzer = FuzzingService(db)
        result = fuzzer.run_experiment(experiment_id)

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
                fuzzer.run_experiment(experiment_id)
    except Exception as err:
        logger.error(f"Scan task failed for experiment {experiment_id}: {err}", exc_info=True)
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
    crawl_enabled = scan.crawl if is_recon_only else (scan.crawl and not reused_target)

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

    active_experiment = (
        db.query(Experiment)
        .filter(Experiment.target_id == target.id)
        .filter(Experiment.status.in_([ExperimentStatus.RUNNING, ExperimentStatus.PAUSED, ExperimentStatus.PENDING]))
        .order_by(Experiment.updated_at.desc())
        .first()
    )

    if active_experiment:
        return ScanResponse(
            target_id=target.id,
            experiment_id=active_experiment.id,
            endpoint_count=db.query(Endpoint).filter(Endpoint.target_id == target.id).count(),
            status=active_experiment.status.value,
            message=f"Reusing existing {active_experiment.status.value} scan for {host}.",
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
                "max_depth": scan.max_depth,
                "max_pages": scan.max_pages,
                "reused_target": reused_target,
            },
        },
    )
    experiment = ExperimentService.start_experiment(db, experiment.id)

    background_tasks.add_task(
        _run_scan_task,
        experiment.id,
        target.id,
        scan.url,
        crawl_enabled,
        scan.max_depth,
        scan.max_pages,
        not is_recon_only,
    )

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
