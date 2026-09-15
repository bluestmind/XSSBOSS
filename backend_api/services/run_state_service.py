"""Transactional helpers for restart-safe scan orchestration."""
from datetime import UTC, datetime, timedelta
from typing import Any, Iterable, Optional

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from backend_api.models.run_state import (
    FindingObservation,
    RunEndpoint,
    RunStage,
    RunStageName,
    RunStageStatus,
)


PIPELINE_STAGES = tuple(RunStageName)


def normalize_river_stage(phase: str) -> str:
    """Map raw phase names to standard River-to-Sea stages."""
    p = str(phase or "").lower()
    if any(k in p for k in ("preflight", "scope", "auth", "target", "init")):
        return "springs"
    if any(k in p for k in ("recon", "crawl", "spider", "burp", "discovery")):
        return "recon"
    if any(k in p for k in ("param", "surface", "expand", "seed")):
        return "params"
    if any(k in p for k in ("context", "reflection", "sink", "taint")):
        return "contexts"
    if any(k in p for k in ("filter", "waf", "sanitiz", "bypass")):
        return "filters"
    if any(k in p for k in ("auditor", "cors", "crlf", "ssrf", "sqli", "markup", "cache", "pollution", "redirect")):
        return "auditors"
    if any(k in p for k in ("browser", "execut", "payload", "playwright", "chromium", "fuzz")):
        return "browser"
    if any(k in p for k in ("sea", "finding", "vuln", "report", "complete")):
        return "sea"
    return "recon"


RIVER_STAGE_METADATA = {
    "springs": {
        "name": "The Springs",
        "subtitle": "Source & Authorization Scope",
        "icon": "Compass",
        "order": 1,
    },
    "recon": {
        "name": "Recon Rapids",
        "subtitle": "Crawler, Spider & Route Mapping",
        "icon": "Waves",
        "order": 2,
    },
    "params": {
        "name": "Param Tributaries",
        "subtitle": "Surface & Injection Point Expansion",
        "icon": "GitFork",
        "order": 3,
    },
    "contexts": {
        "name": "Context Confluence",
        "subtitle": "Reflection Mapping & Sink Analysis",
        "icon": "Eye",
        "order": 4,
    },
    "filters": {
        "name": "Filter Channels",
        "subtitle": "WAF Profiling & Character Bypass",
        "icon": "ShieldAlert",
        "order": 5,
    },
    "auditors": {
        "name": "Auditor Cascades",
        "subtitle": "Focused Specialized Web Probes",
        "icon": "Crosshair",
        "order": 6,
    },
    "browser": {
        "name": "Browser Whirlpool",
        "subtitle": "Headless Chromium Execution Oracle",
        "icon": "Zap",
        "order": 7,
    },
    "sea": {
        "name": "The Sea of Findings",
        "subtitle": "Confirmed Vulnerabilities & PoC Evidence",
        "icon": "Anchor",
        "order": 8,
    },
}


class RunStateService:
    """Owns all mutations of run membership and pipeline checkpoints."""

    @staticmethod
    def record_progress(
        db: Session,
        experiment_id: int,
        *,
        phase: str,
        tool: str,
        message: str,
        state: str = "working",
        completed: Optional[int] = None,
        total: Optional[int] = None,
        overall_percent: Optional[float] = None,
        detail: Optional[str] = None,
        doing_status: Optional[str] = None,
        micro_state: Optional[dict[str, Any]] = None,
        river_stage: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        """Persist a compact operator heartbeat for long-running work with micro-state."""
        from backend_api.models.experiment import Experiment

        experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
        if experiment is None:
            return None

        now = datetime.now(UTC)
        limits = dict(experiment.limits) if isinstance(experiment.limits, dict) else {}
        previous = limits.get("live_progress") if isinstance(limits.get("live_progress"), dict) else {}
        inferred_stage = river_stage or normalize_river_stage(phase)
        computed_doing = doing_status or (
            f"{message} - {micro_state.get('substep')}" if (micro_state and micro_state.get("substep")) else message
        )
        
        event = {
            "sequence": int(previous.get("sequence") or 0) + 1,
            "phase": str(phase),
            "tool": str(tool),
            "message": str(message),
            "detail": str(detail) if detail else None,
            "state": str(state),
            "completed": int(completed) if completed is not None else None,
            "total": int(total) if total is not None else None,
            "overall_percent": (
                max(0.0, min(100.0, round(float(overall_percent), 1)))
                if overall_percent is not None else None
            ),
            "doing_status": computed_doing,
            "river_stage": inferred_stage,
            "micro_state": micro_state,
            "updated_at": now.isoformat(),
        }
        history = list(limits.get("progress_history") or [])
        history.append(event)
        limits["live_progress"] = event
        limits["progress_history"] = history[-80:]
        limits["doing_status"] = computed_doing
        if micro_state:
            limits["micro_state"] = micro_state
        limits["current_river_stage"] = inferred_stage

        # Also add as a micro_event to the live event stream
        micro_events = list(limits.get("micro_events") or [])
        stage_meta = RIVER_STAGE_METADATA.get(inferred_stage, {})
        micro_events.append({
            "sequence": event["sequence"],
            "timestamp": now.isoformat(),
            "river_stage": inferred_stage,
            "stage_label": stage_meta.get("name", inferred_stage.capitalize()),
            "title": message,
            "detail": detail or (micro_state.get("substep") if micro_state else None),
            "status": "error" if state == "error" else ("success" if state == "done" else ("warning" if state == "waiting" else "running")),
            "outcome": micro_state.get("result") if micro_state else None,
            "endpoint": micro_state.get("endpoint") if micro_state else None,
            "param": micro_state.get("param") if micro_state else None,
            "tool": tool,
        })
        limits["micro_events"] = micro_events[-100:]

        experiment.limits = limits
        db.commit()
        try:
            from backend_api.services.log_service import LogService

            event_level = (
                "ERROR" if state == "error"
                else "WARNING" if state in {"warning", "waiting"}
                else "HIT" if "hit" in str((micro_state or {}).get("action", "")).lower()
                else "INFO"
            )
            LogService.emit(
                event_level,
                f"progress.{phase}",
                message,
                detail=detail,
                experiment_id=experiment_id,
                target_id=experiment.target_id,
                data={
                    "event_type": "progress",
                    "tool": tool,
                    "state": state,
                    "completed": completed,
                    "total": total,
                    "overall_percent": event.get("overall_percent"),
                    "doing_status": computed_doing,
                    "river_stage": inferred_stage,
                    "micro_state": micro_state,
                },
                db=db,
            )
        except Exception:
            pass
        return event

    @staticmethod
    def record_micro_step(
        db: Session,
        experiment_id: int,
        *,
        title: str,
        river_stage: str,
        action: str,
        status: str = "info",
        outcome: Optional[str] = None,
        detail: Optional[str] = None,
        endpoint: Optional[str] = None,
        param: Optional[str] = None,
        context: Optional[str] = None,
        technique: Optional[str] = None,
        doing_status: Optional[str] = None,
        tool: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        """Record a granular micro-event into the live stream buffer without displacing progress heartbeats."""
        from backend_api.models.experiment import Experiment

        experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
        if experiment is None:
            return None

        now = datetime.now(UTC)
        limits = dict(experiment.limits) if isinstance(experiment.limits, dict) else {}
        stage = normalize_river_stage(river_stage)
        stage_meta = RIVER_STAGE_METADATA.get(stage, {})

        micro_events = list(limits.get("micro_events") or [])
        seq = (micro_events[-1]["sequence"] + 1) if micro_events else 1

        active_doing = doing_status or f"[{stage_meta.get('name', stage)}] {title}"
        current_micro = {
            "action": action,
            "substep": title,
            "endpoint": endpoint,
            "param": param,
            "context": context,
            "technique": technique,
            "result": outcome,
            "status": status,
            "timestamp": now.isoformat(),
        }

        entry = {
            "sequence": seq,
            "timestamp": now.isoformat(),
            "river_stage": stage,
            "stage_label": stage_meta.get("name", stage.capitalize()),
            "title": title,
            "detail": detail,
            "status": status,
            "outcome": outcome,
            "endpoint": endpoint,
            "param": param,
            "context": context,
            "technique": technique,
            "tool": tool or "fuzzer engine",
        }
        micro_events.append(entry)
        limits["micro_events"] = micro_events[-100:]
        limits["doing_status"] = active_doing
        limits["micro_state"] = current_micro
        limits["current_river_stage"] = stage

        # Keep live_progress in sync if available
        if isinstance(limits.get("live_progress"), dict):
            limits["live_progress"]["doing_status"] = active_doing
            limits["live_progress"]["micro_state"] = current_micro
            limits["live_progress"]["updated_at"] = now.isoformat()

        experiment.limits = limits
        db.commit()
        try:
            from backend_api.services.log_service import LogService

            LogService.emit(
                "ERROR" if status == "error" else "WARNING" if status == "warning" else "INFO",
                f"micro.{stage}",
                title,
                detail=detail,
                experiment_id=experiment_id,
                target_id=experiment.target_id,
                data={
                    "event_type": "micro_step",
                    "action": action,
                    "status": status,
                    "outcome": outcome,
                    "endpoint": endpoint,
                    "param": param,
                    "context": context,
                    "technique": technique,
                    "tool": tool or "fuzzer engine",
                },
                db=db,
            )
        except Exception:
            pass
        return entry

    @staticmethod
    def get_river_flow_snapshot(db: Session, experiment_id: int) -> dict[str, Any]:
        """Generate a complete River-to-Sea progress snapshot with milestone states."""
        from backend_api.models.experiment import Experiment, ExperimentStatus
        from backend_api.models.endpoint import Endpoint
        from backend_api.models.param import Param
        from backend_api.models.context import Context
        from backend_api.models.filter_profile import FilterProfile
        from backend_api.models.test_case import TestCase, TestCaseStatus
        from backend_api.models.finding import Finding

        experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
        if not experiment:
            return {}

        limits = dict(experiment.limits) if isinstance(experiment.limits, dict) else {}
        current_stage = limits.get("current_river_stage") or normalize_river_stage(
            (limits.get("live_progress") or {}).get("phase") or experiment.status.value
        )
        doing_status = limits.get("doing_status") or (limits.get("live_progress") or {}).get("message") or "Pipeline initialized"
        is_completed = experiment.status == ExperimentStatus.COMPLETED
        is_failed = experiment.status == ExperimentStatus.FAILED
        is_running = experiment.status == ExperimentStatus.RUNNING

        # Metric counts for stages
        endpoint_count = db.query(Endpoint.id).filter(Endpoint.target_id == experiment.target_id).count()
        param_count = db.query(Param.id).join(Endpoint).filter(Endpoint.target_id == experiment.target_id).count()
        context_count = db.query(Context.id).join(Endpoint).filter(Endpoint.target_id == experiment.target_id).count()
        filter_count = db.query(FilterProfile.id).join(Endpoint).filter(Endpoint.target_id == experiment.target_id).count()
        test_case_total = db.query(TestCase.id).filter(TestCase.experiment_id == experiment_id).count()
        test_case_finished = db.query(TestCase.id).filter(
            TestCase.experiment_id == experiment_id,
            TestCase.status.in_([TestCaseStatus.COMPLETED, TestCaseStatus.FAILED, TestCaseStatus.SKIPPED, TestCaseStatus.CANCELLED])
        ).count()
        finding_count = db.query(Finding.id).join(Endpoint).filter(Endpoint.target_id == experiment.target_id).count()

        stage_order = ["springs", "recon", "params", "contexts", "filters", "auditors", "browser", "sea"]
        current_idx = stage_order.index(current_stage) if current_stage in stage_order else 0

        milestones = []
        counts_map = {
            "springs": 1,
            "recon": endpoint_count,
            "params": param_count,
            "contexts": context_count,
            "filters": filter_count,
            "auditors": 9 if (current_idx > stage_order.index("auditors") or is_completed) else 0,
            "browser": test_case_finished if test_case_total > 0 else 0,
            "sea": finding_count,
        }

        for idx, key in enumerate(stage_order):
            meta = RIVER_STAGE_METADATA.get(key, {})
            if is_completed:
                m_status = "settled"
                water_pct = 100
            elif is_failed and idx == current_idx:
                m_status = "eddied"
                water_pct = 50
            elif idx < current_idx:
                m_status = "settled"
                water_pct = 100
            elif idx == current_idx:
                m_status = "flowing" if is_running else "eddied"
                if key == "browser" and test_case_total > 0:
                    water_pct = round((test_case_finished / test_case_total) * 100, 1)
                else:
                    water_pct = 50
            else:
                m_status = "pending"
                water_pct = 0

            milestones.append({
                "key": key,
                "name": meta.get("name", key.capitalize()),
                "subtitle": meta.get("subtitle", ""),
                "icon": meta.get("icon", "Circle"),
                "status": m_status,
                "count": counts_map.get(key, 0),
                "water_percent": water_pct,
                "order": idx + 1,
            })

        return {
            "current_stage": current_stage,
            "doing_status": doing_status,
            "milestones": milestones,
            "micro_state": limits.get("micro_state"),
            "water_velocity": "Smooth Flow" if is_running else ("Settled in Sea" if is_completed else "Idle"),
        }

    @staticmethod
    def ensure_pipeline(db: Session, experiment_id: int) -> list[RunStage]:
        existing = {
            stage.name: stage
            for stage in db.query(RunStage).filter(RunStage.experiment_id == experiment_id).all()
        }
        for name in PIPELINE_STAGES:
            if name not in existing:
                try:
                    with db.begin_nested():
                        stage = RunStage(experiment_id=experiment_id, name=name)
                        db.add(stage)
                        db.flush()
                        existing[name] = stage
                except IntegrityError:
                    existing[name] = db.query(RunStage).filter_by(
                        experiment_id=experiment_id, name=name
                    ).one()
        db.commit()
        return [existing[name] for name in PIPELINE_STAGES]

    @staticmethod
    def claim_stage(
        db: Session,
        experiment_id: int,
        name: RunStageName,
        owner: str,
        lease_seconds: int = 900,
    ) -> bool:
        """Claim a stage unless it is complete or has a live lease."""
        RunStateService.ensure_pipeline(db, experiment_id)
        now = datetime.now(UTC)
        now_naive = now.replace(tzinfo=None)
        stage = (
            db.query(RunStage)
            .filter(RunStage.experiment_id == experiment_id, RunStage.name == name)
            .with_for_update()
            .one()
        )
        if stage.status == RunStageStatus.COMPLETED:
            db.rollback()
            return False
        
        expires = stage.lease_expires_at
        if expires and expires.tzinfo:
            expires = expires.astimezone(UTC).replace(tzinfo=None)

        if (
            stage.status == RunStageStatus.RUNNING
            and expires
            and expires > now_naive
            and stage.lease_owner != owner
        ):
            db.rollback()
            return False
        stage.status = RunStageStatus.RUNNING
        stage.attempt_count += 1
        stage.lease_owner = owner
        stage.lease_expires_at = now + timedelta(seconds=max(30, lease_seconds))
        stage.started_at = stage.started_at or now
        stage.completed_at = None
        stage.error = None
        db.commit()
        return True

    @staticmethod
    def complete_stage(
        db: Session,
        experiment_id: int,
        name: RunStageName,
        output: Optional[dict[str, Any]] = None,
    ) -> None:
        RunStateService.ensure_pipeline(db, experiment_id)
        stage = db.query(RunStage).filter_by(experiment_id=experiment_id, name=name).first()
        if not stage:
            return
        stage.status = RunStageStatus.COMPLETED
        stage.completed_at = datetime.now(UTC)
        stage.lease_owner = None
        stage.lease_expires_at = None
        stage.output = output
        stage.error = None
        db.commit()

    @staticmethod
    def fail_stage(db: Session, experiment_id: int, name: RunStageName, error: Exception) -> None:
        RunStateService.ensure_pipeline(db, experiment_id)
        stage = db.query(RunStage).filter_by(experiment_id=experiment_id, name=name).first()
        if not stage:
            return
        stage.status = RunStageStatus.FAILED
        stage.completed_at = datetime.now(UTC)
        stage.lease_owner = None
        stage.lease_expires_at = None
        stage.error = str(error)[:8000]
        db.commit()

    @staticmethod
    def add_endpoints(
        db: Session,
        experiment_id: int,
        endpoint_ids: Iterable[int],
        source: str,
    ) -> None:
        existing = {
            endpoint_id for (endpoint_id,) in db.query(RunEndpoint.endpoint_id)
            .filter(RunEndpoint.experiment_id == experiment_id)
            .all()
        }
        for endpoint_id in {int(value) for value in endpoint_ids} - existing:
            db.add(RunEndpoint(
                experiment_id=experiment_id,
                endpoint_id=endpoint_id,
                discovery_source=source,
            ))
        db.commit()

    @staticmethod
    def endpoint_ids(db: Session, experiment_id: int) -> list[int]:
        return [
            endpoint_id for (endpoint_id,) in db.query(RunEndpoint.endpoint_id)
            .filter(RunEndpoint.experiment_id == experiment_id)
            .order_by(RunEndpoint.endpoint_id)
            .all()
        ]

    @staticmethod
    def observe_finding(
        db: Session,
        experiment_id: int,
        finding_id: int,
        test_case_id: Optional[int] = None,
        execution_id: Optional[int] = None,
        evidence: Optional[dict[str, Any]] = None,
    ) -> FindingObservation:
        observation = db.query(FindingObservation).filter_by(
            experiment_id=experiment_id, finding_id=finding_id
        ).first()
        if observation is None:
            observation = FindingObservation(
                experiment_id=experiment_id,
                finding_id=finding_id,
            )
            db.add(observation)
        observation.test_case_id = test_case_id or observation.test_case_id
        observation.execution_id = execution_id or observation.execution_id
        observation.evidence = evidence or observation.evidence
        db.commit()
        return observation
