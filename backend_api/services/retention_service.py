"""Tenant-aware retention for terminal runs and content-addressed evidence."""
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from backend_api.config import settings
from backend_api.models.evidence import EvidenceArtifact
from backend_api.models.experiment import Experiment, ExperimentStatus
from backend_api.models.target import Target
from backend_api.models.tenant import Tenant


class RetentionService:
    @staticmethod
    def sweep(db: Session, *, apply: bool = False, now: datetime | None = None) -> dict:
        now = now or datetime.now(UTC)
        candidates: list[Experiment] = []
        by_tenant: dict[str, int] = {}
        for tenant in db.query(Tenant).filter(Tenant.is_active.is_(True)).all():
            cutoff = now - timedelta(days=max(1, tenant.retention_days))
            expired = (
                db.query(Experiment)
                .join(Target, Experiment.target_id == Target.id)
                .filter(
                    Target.tenant_id == tenant.id,
                    Experiment.status.in_([ExperimentStatus.COMPLETED, ExperimentStatus.FAILED]),
                    or_(
                        Experiment.completed_at < cutoff,
                        and_(Experiment.completed_at.is_(None), Experiment.created_at < cutoff),
                    ),
                )
                .all()
            )
            candidates.extend(expired)
            by_tenant[tenant.slug] = len(expired)

        artifact_uris = [
            row[0]
            for row in db.query(EvidenceArtifact.uri).filter(
                EvidenceArtifact.experiment_id.in_([experiment.id for experiment in candidates])
            ).all()
            if row[0]
        ] if candidates else []

        deleted_files = 0
        if apply and candidates:
            for experiment in candidates:
                db.delete(experiment)
            db.commit()
            root = Path(settings.EVIDENCE_DIR).resolve()
            for uri in set(artifact_uris):
                path = Path(uri)
                path = path.resolve() if path.is_absolute() else (root / path).resolve()
                if path == root or root not in path.parents:
                    continue
                if path.is_file():
                    path.unlink()
                    deleted_files += 1

        return {
            "apply": apply,
            "candidate_runs": len(candidates),
            "candidate_artifacts": len(set(artifact_uris)),
            "deleted_runs": len(candidates) if apply else 0,
            "deleted_files": deleted_files,
            "by_tenant": by_tenant,
        }
