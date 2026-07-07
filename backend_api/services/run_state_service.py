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


class RunStateService:
    """Owns all mutations of run membership and pipeline checkpoints."""

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
        stage = (
            db.query(RunStage)
            .filter(RunStage.experiment_id == experiment_id, RunStage.name == name)
            .with_for_update()
            .one()
        )
        if stage.status == RunStageStatus.COMPLETED:
            db.rollback()
            return False
        if (
            stage.status == RunStageStatus.RUNNING
            and stage.lease_expires_at
            and stage.lease_expires_at > (
                now if stage.lease_expires_at.tzinfo else now.replace(tzinfo=None)
            )
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
