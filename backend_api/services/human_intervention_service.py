"""Durable operator-intervention queue stored with an autonomous campaign."""
from __future__ import annotations

from datetime import UTC, datetime
from copy import deepcopy
from typing import Any, Dict, Optional
import uuid

from sqlalchemy.orm import Session

from backend_api.models.experiment import Experiment, ExperimentStatus
from backend_api.models.run_state import RunStage, RunStageName, RunStageStatus


class HumanInterventionService:
    """Pause safely on MFA/CAPTCHA/login/workflow barriers and support resumption."""

    @staticmethod
    def raise_intervention(
        db: Session,
        experiment_id: int,
        *,
        kind: str,
        reason: str,
        identity: Optional[str] = None,
        url: Optional[str] = None,
        workflow: Optional[str] = None,
    ) -> Dict[str, Any]:
        experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
        if not experiment:
            raise ValueError(f"Experiment {experiment_id} not found")
        limits = dict(experiment.limits) if isinstance(experiment.limits, dict) else {}
        queue = deepcopy(limits.get("human_interventions") or [])
        duplicate = next((
            item for item in queue
            if item.get("status") == "open"
            and item.get("kind") == kind
            and item.get("identity") == identity
            and item.get("workflow") == workflow
        ), None)
        if duplicate:
            return duplicate
        item = {
            "id": str(uuid.uuid4()),
            "status": "open",
            "kind": str(kind)[:80],
            "reason": str(reason)[:1000],
            "identity": str(identity)[:80] if identity else None,
            "url": str(url)[:2048] if url else None,
            "workflow": str(workflow)[:160] if workflow else None,
            "created_at": datetime.now(UTC).isoformat(),
        }
        queue.append(item)
        limits["human_interventions"] = queue[-50:]
        warnings = list(limits.get("warnings") or [])
        warnings.append({
            "level": "warning",
            "phase": "authentication",
            "message": "Campaign paused for operator authentication intervention.",
            "detail": item["reason"],
        })
        limits["warnings"] = warnings[-12:]
        experiment.limits = limits
        experiment.status = ExperimentStatus.PAUSED

        stage = db.query(RunStage).filter_by(
            experiment_id=experiment_id, name=RunStageName.RECON
        ).first()
        if stage and stage.status == RunStageStatus.RUNNING:
            stage.status = RunStageStatus.PENDING
            stage.lease_owner = None
            stage.lease_expires_at = None
            stage.error = "Paused for human authentication intervention"
        db.commit()
        return item

    @staticmethod
    def list_open(db: Session, experiment_id: int) -> list[Dict[str, Any]]:
        experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
        if not experiment:
            raise ValueError(f"Experiment {experiment_id} not found")
        limits = experiment.limits if isinstance(experiment.limits, dict) else {}
        return [item for item in limits.get("human_interventions", []) if item.get("status") == "open"]

    @staticmethod
    def resolve(
        db: Session,
        experiment_id: int,
        intervention_id: str,
        resolution: Optional[str] = None,
    ) -> Dict[str, Any]:
        experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
        if not experiment:
            raise ValueError(f"Experiment {experiment_id} not found")
        limits = dict(experiment.limits) if isinstance(experiment.limits, dict) else {}
        queue = deepcopy(limits.get("human_interventions") or [])
        matched = None
        for item in queue:
            if item.get("id") == intervention_id:
                item["status"] = "resolved"
                item["resolved_at"] = datetime.now(UTC).isoformat()
                item["resolution"] = str(resolution or "operator resolved")[:500]
                matched = item
                break
        if not matched:
            raise ValueError(f"Intervention {intervention_id} not found")
        limits["human_interventions"] = queue
        experiment.limits = limits
        if not any(item.get("status") == "open" for item in queue):
            experiment.status = ExperimentStatus.RUNNING
        db.commit()
        return matched
