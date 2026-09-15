"""Program dashboard API — ranked program profiles + one-click autonomous hunt.

Surfaces synced HackerOne programs best-first (``GET /programs``), a full profile per program
(``GET /programs/{id}`` — scope summary + prioritized worklist + live run status), and a single
"start find on program" trigger (``POST /programs/{id}/hunt``) that launches the
``ProgramRunOrchestrator`` in the background. Run state is tracked in-memory (single-operator tool),
polled via ``GET /programs/{id}/hunt/status``.
"""
from datetime import UTC, datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend_api.config import settings
from backend_api.db.session import SessionLocal, get_db
from backend_api.models.target import Target
from backend_api.services.program_ranker import ProgramRanker
from backend_api.services.program_scope import ProgramScope
from backend_api.services.program_run_orchestrator import ProgramRunOrchestrator, RunBudget
from backend_api.utils.logger import logger
from backend_api.utils.scope_guard import scope_rule_matches_url

router = APIRouter(prefix="/programs", tags=["programs"])

from sqlalchemy import func
from backend_api.models.endpoint import Endpoint
from backend_api.models.finding import Finding
from backend_api.models.experiment import Experiment, ExperimentStatus, ExperimentStrategy

# In-memory run registry: target_id -> {status, started_at, finished_at, report, error}
_program_runs: Dict[int, Dict[str, Any]] = {}


@router.get("")
def list_programs(
    limit: int = Query(1000, ge=1, le=2000),
    bounty_only: bool = Query(False),
    query: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """Ranked program profiles for the dashboard (best expected-value programs first)."""
    ranks = ProgramRanker.rank_from_db(db, limit=limit, bounty_only=bounty_only, query=query)
    
    # Fast grouped database aggregations across all targets
    findings_by_target = dict(
        db.query(Endpoint.target_id, func.count(Finding.id))
        .join(Finding, Finding.endpoint_id == Endpoint.id)
        .group_by(Endpoint.target_id)
        .all()
    )
    endpoints_by_target = dict(
        db.query(Endpoint.target_id, func.count(Endpoint.id))
        .group_by(Endpoint.target_id)
        .all()
    )
    exp_rows = (
        db.query(
            Experiment.target_id,
            func.count(Experiment.id),
            func.max(Experiment.started_at),
        )
        .group_by(Experiment.target_id)
        .all()
    )
    exp_summary = {r[0]: {"count": r[1], "latest_started_at": r[2]} for r in exp_rows}
    
    running_exps = dict(
        db.query(Experiment.target_id, Experiment.id)
        .filter(Experiment.status == ExperimentStatus.RUNNING)
        .all()
    )
    paused_exps = dict(
        db.query(Experiment.target_id, Experiment.id)
        .filter(Experiment.status == ExperimentStatus.PAUSED)
        .all()
    )

    programs = []
    for r in ranks:
        d = r.to_dict()
        tid = r.target_id or -1
        in_memory_run = _program_runs.get(tid, {})
        mem_status = in_memory_run.get("status")
        
        # Determine actual computed status
        if mem_status in ("queued", "running"):
            computed_status = mem_status
        elif tid in running_exps:
            computed_status = "running"
        elif tid in paused_exps:
            computed_status = "paused"
        elif mem_status == "completed" or tid in exp_summary:
            computed_status = "completed"
        elif mem_status == "failed":
            computed_status = "failed"
        else:
            computed_status = "idle"

        last_hunted = (
            exp_summary.get(tid, {}).get("latest_started_at")
            or in_memory_run.get("finished_at")
            or in_memory_run.get("started_at")
        )
        if isinstance(last_hunted, datetime):
            last_hunted = last_hunted.isoformat()

        d["run_status"] = computed_status
        d["findings_count"] = findings_by_target.get(tid, 0)
        d["endpoints_count"] = endpoints_by_target.get(tid, 0)
        d["experiments_count"] = exp_summary.get(tid, {}).get("count", 0)
        d["last_hunted_at"] = last_hunted
        d["active_experiment_id"] = running_exps.get(tid) or paused_exps.get(tid)
        
        programs.append(d)

    # Calculate global program stats
    active_count = sum(1 for p in programs if p["run_status"] in ("running", "queued"))
    hunted_count = sum(1 for p in programs if p["run_status"] == "completed" or p["experiments_count"] > 0)
    with_findings_count = sum(1 for p in programs if p["findings_count"] > 0)
    paused_count = sum(1 for p in programs if p["run_status"] == "paused")
    idle_count = sum(1 for p in programs if p["run_status"] == "idle" and p["experiments_count"] == 0)
    total_findings = sum(p["findings_count"] for p in programs)

    return {
        "count": len(programs),
        "stats": {
            "total": len(programs),
            "active": active_count,
            "hunted": hunted_count,
            "with_findings": with_findings_count,
            "paused": paused_count,
            "idle": idle_count,
            "total_findings": total_findings,
        },
        "programs": programs,
    }


@router.get("/{target_id}")
def program_profile(target_id: int, db: Session = Depends(get_db)):
    """Full program profile: priority, scope summary, prioritized worklist, and run status."""
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Program (target) not found")
    scope = ProgramScope.from_target(target)
    rank = ProgramRanker.score(scope, name=target.name, target_id=target.id)
    run = _program_runs.get(target_id, {})
    
    # Check DB experiments for persistent state
    latest_exp = (
        db.query(Experiment)
        .filter(Experiment.target_id == target_id)
        .order_by(Experiment.id.desc())
        .first()
    )
    status = run.get("status")
    if not status or status == "idle":
        if latest_exp:
            status = latest_exp.status.value.lower()
        else:
            status = "idle"

    findings_count = (
        db.query(Finding)
        .join(Endpoint, Finding.endpoint_id == Endpoint.id)
        .filter(Endpoint.target_id == target_id)
        .count()
    )
    endpoints_count = db.query(Endpoint).filter(Endpoint.target_id == target_id).count()

    from backend_api.services.security_profile_service import SecurityProfileService
    sec_profile = SecurityProfileService.get_program_security_profile(db, target_id)

    return {
        "target_id": target_id,
        "rank": rank.to_dict(),
        "summary": scope.summary(),
        "worklist": [a.to_dict() for a in scope.worklist()],
        "security_profile": sec_profile,
        "run": {
            "status": status,
            "started_at": run.get("started_at") or (latest_exp.started_at.isoformat() if latest_exp and latest_exp.started_at else None),
            "finished_at": run.get("finished_at") or (latest_exp.completed_at.isoformat() if latest_exp and latest_exp.completed_at else None),
            "report": run.get("report"),
            "error": run.get("error"),
            "findings_count": findings_count,
            "endpoints_count": endpoints_count,
            "active_experiment_id": latest_exp.id if latest_exp else None,
        },
    }


@router.get("/{target_id}/security-profile")
def get_security_profile(target_id: int, db: Session = Depends(get_db)):
    """Get full security defense profile: WAF, CSP, Sinks, Character Filtering Matrix, and Tech Stack."""
    from backend_api.services.security_profile_service import SecurityProfileService
    sec_profile = SecurityProfileService.get_program_security_profile(db, target_id)
    if not sec_profile:
        raise HTTPException(status_code=404, detail="Target not found")
    return sec_profile


@router.post("/{target_id}/hunt")
def start_program_hunt(
    target_id: int,
    background_tasks: BackgroundTasks,
    max_assets: int = Query(10, ge=1, le=200),
    budget: int = Query(1500, ge=1, le=100_000),
    strategy: str = Query("smart_adaptive"),
    db: Session = Depends(get_db),
):
    """One-click 'Start find on program' — launch the autonomous hunt in the background."""
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Program (target) not found")
    current = _program_runs.get(target_id)
    if current and current.get("status") in ("queued", "running"):
        raise HTTPException(status_code=409, detail="A hunt is already in progress for this program")
    try:
        ExperimentStrategy(strategy)
    except ValueError as exc:
        allowed = ", ".join(item.value for item in ExperimentStrategy)
        raise HTTPException(status_code=422, detail=f"Unknown strategy. Choose one of: {allowed}") from exc

    _program_runs[target_id] = {
        "status": "queued", "started_at": datetime.now(UTC).isoformat(),
        "finished_at": None, "report": None, "error": None,
    }
    background_tasks.add_task(_run_program_hunt, target_id, max_assets, budget, strategy)
    logger.info(f"Queued program hunt for target_id={target_id} (max_assets={max_assets}, budget={budget})")
    return {"status": "queued", "target_id": target_id, "message": "Program hunt started"}


@router.get("/{target_id}/hunt/status")
def program_hunt_status(target_id: int):
    """Poll the current run status/report for the dashboard."""
    return _program_runs.get(target_id, {"status": "idle"})


def _run_program_hunt(target_id: int, max_assets: int, budget: int, strategy: str) -> None:
    """Background worker: hunt the whole program via the orchestrator. Owns its own DB session."""
    state = _program_runs.setdefault(target_id, {})
    state["status"] = "running"
    db = SessionLocal()
    try:
        target = db.query(Target).filter(Target.id == target_id).first()
        if not target:
            state.update({"status": "failed", "error": "target not found"})
            return
        scope = ProgramScope.from_target(target)
        budget_obj = RunBudget(max_assets=max_assets, max_requests_total=budget)

        from recon_engine.crawler import Crawler
        from backend_api.models.endpoint import Endpoint
        from backend_api.models.finding import Finding
        from backend_api.services.run_budget_service import RunBudgetService
        from backend_api.services.fuzzing_service import FuzzingService
        from backend_api.services.burp_service import BurpService
        from backend_api.services.burp_runtime_service import BurpRuntimeService
        from backend_api.utils.rate_limiter import rate_limiter

        # Ensure Burp Suite Desktop is running if auto-start is configured
        if getattr(settings, "BURP_ENABLED", True) and getattr(settings, "BURP_AUTO_START", False):
            try:
                BurpRuntimeService.ensure_available(settings.BURP_API_URL, settings.BURP_API_KEY)
                logger.info(f"Burp Suite runtime active on {settings.BURP_API_URL}")
            except Exception as burp_err:
                logger.warning(f"Burp Suite runtime auto-launch skipped/failed: {burp_err}")

        def hunt_asset(asset, cap):
            seed = asset.seed_url or asset.identifier
            if not seed or not scope.contains_url(seed):
                raise ValueError(f"Refusing unresolved or out-of-scope asset seed: {asset.identifier}")
            before = db.query(Finding).join(Endpoint).filter(Endpoint.target_id == target.id).count()
            
            with rate_limiter.request_budget(cap) as recon_budget:
                # 1. Advanced Recon: Passive OSINT, subdomains, robots.txt, sitemaps, SPA routes, API specs
                try:
                    from recon_engine.advanced_recon import AdvancedRecon
                    adv_count = AdvancedRecon(db, target.id).run_all(seed)
                    logger.info(f"Advanced recon for {seed} imported {adv_count} endpoints.")
                except Exception as adv_e:
                    logger.warning(f"Advanced recon on {seed} encountered error: {adv_e}")

                # 2. Active Browser Crawler: CDP interception, forms, and dynamic SPA routes
                try:
                    crawl_count = Crawler(base_url=seed, max_depth=2, max_pages=15).crawl_to_database(target.id, db)
                    logger.info(f"Active crawl for {seed} imported {crawl_count} endpoints.")
                except Exception as ce:
                    logger.warning(f"Crawl on {seed} encountered error: {ce}")

            recon_requests = recon_budget.used

            asset_endpoints = [
                endpoint
                for endpoint in db.query(Endpoint).filter(Endpoint.target_id == target.id).all()
                if scope.contains_url(endpoint.url_pattern)
                and scope_rule_matches_url(asset.source_identifier or asset.identifier, endpoint.url_pattern)
            ]
            if not asset_endpoints:
                existing_ep = db.query(Endpoint).filter(Endpoint.target_id == target.id, Endpoint.url_pattern == seed).first()
                if not existing_ep:
                    try:
                        new_ep = Endpoint(target_id=target.id, url_pattern=seed, method="GET")
                        db.add(new_ep)
                        db.commit()
                        db.refresh(new_ep)
                        asset_endpoints = [new_ep]
                    except Exception:
                        db.rollback()
                else:
                    asset_endpoints = [existing_ep]

            ep_count = len(asset_endpoints)
            fuzz_cap = max(0, int(cap) - recon_requests)

            if fuzz_cap <= 0:
                after = db.query(Finding).join(Endpoint).filter(Endpoint.target_id == target.id).count()
                return {
                    "endpoints": ep_count,
                    "findings": max(0, after - before),
                    "requests_used": recon_requests,
                    "requests_actual": recon_requests,
                }

            # Trigger background Burp Scan for asset if Burp REST API is available
            if (
                getattr(settings, "BURP_ENABLED", False)
                and getattr(settings, "BURP_PROGRAM_AUTO_SCAN", False)
                and not asset.is_path_scoped
                and not scope.has_host_exclusions(seed)
            ):
                try:
                    if BurpRuntimeService.api_ready(settings.BURP_API_URL, settings.BURP_API_KEY):
                        burp_res = BurpService.trigger_scan(
                            api_url=settings.BURP_API_URL,
                            target_urls=[seed],
                            api_key=settings.BURP_API_KEY,
                        )
                        logger.info(f"Burp Scan Task #{burp_res.get('task_id')} launched for {seed}")
                except Exception as b_err:
                    logger.warning(f"Burp scan dispatch for {seed} failed: {b_err}")

            exp = Experiment(
                target_id=target.id,
                name=f"Hunt: {target.name} - {asset.host}",
                strategy=ExperimentStrategy(strategy),
                status=ExperimentStatus.RUNNING,
                started_at=datetime.now(UTC),
                limits={
                    "endpoint_ids": [endpoint.id for endpoint in asset_endpoints],
                    "max_requests": fuzz_cap,
                    "max_test_cases": min(
                        fuzz_cap,
                        max(1, int(settings.MAX_TEST_CASES_PER_EXPERIMENT)),
                    ),
                    "program_scope_rule": asset.source_identifier or asset.identifier,
                    "program_seed_url": seed,
                },
            )
            try:
                db.add(exp)
                db.commit()
                db.refresh(exp)
                FuzzingService(db).run_experiment(exp.id)
            except Exception as fe:
                logger.warning(f"Fuzzing on {asset.host} encountered error: {fe}")
                db.rollback()

            after = db.query(Finding).join(Endpoint).filter(Endpoint.target_id == target.id).count()
            usage = RunBudgetService.snapshot(db, exp.id)
            try:
                db.refresh(exp)
            except Exception:
                pass
            # Browser execution is asynchronous in production. Reserve the
            # experiment's whole cap while work is still active so subsequent
            # assets cannot each allocate the same global program budget.
            requests_reserved = RunBudgetService.program_allocation(usage, exp.status, fuzz_cap)
            return {
                "endpoints": ep_count,
                "findings": max(0, after - before),
                "requests_used": recon_requests + requests_reserved,
                "requests_actual": recon_requests + usage.requests_reserved,
            }

        observed_urls = [
            row[0]
            for row in db.query(Endpoint.url_pattern)
            .filter(Endpoint.target_id == target.id)
            .all()
            if row[0] and scope.contains_url(row[0])
        ]
        if scope.contains_url(target.base_url) and target.base_url not in observed_urls:
            observed_urls.insert(0, target.base_url)
        report = ProgramRunOrchestrator.run(
            scope,
            hunt_asset,
            budget_obj,
            candidate_urls=observed_urls,
        )
        state.update({"status": "completed", "finished_at": datetime.now(UTC).isoformat(), "report": report.to_dict()})
        logger.info(f"Program hunt complete target_id={target_id}: {report.total_findings} findings")
    except Exception as e:
        logger.error(f"Program hunt failed target_id={target_id}: {e}", exc_info=True)
        state.update({"status": "failed", "finished_at": datetime.now(UTC).isoformat(), "error": str(e)})
    finally:
        db.close()
