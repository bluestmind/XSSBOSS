"""Durable, database-serialized experiment budget accounting."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Optional

from sqlalchemy import func, update
from sqlalchemy.orm import Session

from backend_api.models.execution import Execution
from backend_api.models.experiment import Experiment
from backend_api.models.test_case import TestCase, TestCaseStatus


@dataclass(frozen=True)
class RunBudgetSnapshot:
    max_requests: Optional[int]
    max_test_cases: Optional[int]
    test_cases: int
    request_attempts: int
    additional_requests: int
    executions: int

    @property
    def requests_reserved(self) -> int:
        return self.request_attempts + self.additional_requests

    @property
    def requests_remaining(self) -> Optional[int]:
        if self.max_requests is None:
            return None
        return max(0, self.max_requests - self.requests_reserved)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["requests_reserved"] = self.requests_reserved
        result["requests_remaining"] = self.requests_remaining
        return result


class RunBudgetService:
    """Serialize reservations on the experiment row and derive usage from DB rows.

    ``request_attempts`` counts atomic browser leases. A reservation is charged
    before Chromium can touch the target, so crashes can under-use but never
    overspend the declared logical-request budget.
    """

    @staticmethod
    def _limit(experiment: Experiment, key: str) -> Optional[int]:
        limits = experiment.limits if isinstance(experiment.limits, dict) else {}
        if key not in limits or limits.get(key) is None:
            return None
        try:
            value = int(limits[key])
        except (TypeError, ValueError, OverflowError):
            return 0  # a malformed declared limit fails closed
        return max(0, value)

    @staticmethod
    def _additional_requests(db: Session, experiment_id: int) -> int:
        rows = db.query(TestCase.research_metadata).filter(
            TestCase.experiment_id == experiment_id
        ).all()
        total = 0
        for (metadata,) in rows:
            reservations = (
                metadata.get("budget_request_reservations", {})
                if isinstance(metadata, dict) else {}
            )
            if not isinstance(reservations, dict):
                continue
            for value in reservations.values():
                try:
                    total += max(0, int(value))
                except (TypeError, ValueError, OverflowError):
                    continue
        return total

    @classmethod
    def snapshot(cls, db: Session, experiment_id: int) -> RunBudgetSnapshot:
        experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
        if not experiment:
            raise ValueError(f"Experiment {experiment_id} not found")
        test_cases = db.query(func.count(TestCase.id)).filter(
            TestCase.experiment_id == experiment_id
        ).scalar() or 0
        attempts = db.query(func.coalesce(func.sum(TestCase.attempt_count), 0)).filter(
            TestCase.experiment_id == experiment_id
        ).scalar() or 0
        executions = db.query(func.count(Execution.id)).join(TestCase).filter(
            TestCase.experiment_id == experiment_id
        ).scalar() or 0
        return RunBudgetSnapshot(
            max_requests=cls._limit(experiment, "max_requests"),
            max_test_cases=cls._limit(experiment, "max_test_cases"),
            test_cases=int(test_cases),
            request_attempts=int(attempts),
            additional_requests=cls._additional_requests(db, experiment_id),
            executions=int(executions),
        )

    @staticmethod
    def program_allocation(
        snapshot: RunBudgetSnapshot,
        status: Any,
        request_cap: int,
    ) -> int:
        """Return spend for a program scheduler without reusing async capacity."""
        status_value = getattr(status, "value", status)
        if status_value in {"completed", "failed"} or snapshot.test_cases == 0:
            return snapshot.requests_reserved
        return max(snapshot.requests_reserved, max(0, int(request_cap)))

    @staticmethod
    def _lock_experiment(db: Session, experiment_id: int) -> Experiment:
        # The no-op write obtains a SQLite write lock and a PostgreSQL row lock,
        # serializing claims for different test-case rows in the same run.
        db.execute(
            update(Experiment)
            .where(Experiment.id == experiment_id)
            .values(updated_at=Experiment.updated_at)
            .execution_options(synchronize_session=False)
        )
        experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
        if not experiment:
            raise ValueError(f"Experiment {experiment_id} not found")
        return experiment

    @classmethod
    def allow_primary_request(cls, db: Session, test_case: TestCase) -> bool:
        """Lock the run and fail closed when its next browser attempt would exceed cap."""
        experiment = cls._lock_experiment(db, test_case.experiment_id)
        maximum = cls._limit(experiment, "max_requests")
        if maximum is None:
            return True
        used = int(db.query(func.coalesce(func.sum(TestCase.attempt_count), 0)).filter(
            TestCase.experiment_id == test_case.experiment_id
        ).scalar() or 0)
        used += cls._additional_requests(db, test_case.experiment_id)
        if used < maximum:
            return True

        db.query(TestCase).filter(
            TestCase.experiment_id == test_case.experiment_id,
            TestCase.status.in_([TestCaseStatus.PENDING, TestCaseStatus.QUEUED]),
        ).update({"status": TestCaseStatus.SKIPPED}, synchronize_session=False)
        db.commit()
        return False

    @classmethod
    def reserve_runtime_lineage_probe(cls, db: Session, test_case: TestCase) -> bool:
        """Atomically reserve the optional three-request A/A/B follow-up."""
        experiment = cls._lock_experiment(db, test_case.experiment_id)
        fresh = db.query(TestCase).filter(TestCase.id == test_case.id).first()
        if not fresh or fresh.runtime_lineage_probe_reserved_at is not None:
            db.rollback()
            return False

        maximum = cls._limit(experiment, "max_requests")
        used = int(db.query(func.coalesce(func.sum(TestCase.attempt_count), 0)).filter(
            TestCase.experiment_id == test_case.experiment_id
        ).scalar() or 0)
        used += cls._additional_requests(db, test_case.experiment_id)
        if maximum is not None and used + 3 > maximum:
            db.rollback()
            return False

        from datetime import UTC, datetime

        metadata = dict(fresh.research_metadata) if isinstance(fresh.research_metadata, dict) else {}
        if isinstance(metadata.get("runtime_lineage_aab_attempt"), dict):
            db.rollback()
            return False
        reservations = (
            dict(metadata.get("budget_request_reservations"))
            if isinstance(metadata.get("budget_request_reservations"), dict) else {}
        )
        reservations["runtime_lineage_aab"] = 3
        metadata["budget_request_reservations"] = reservations
        metadata["runtime_lineage_aab_attempt"] = {
            "schema_version": "runtime-lineage-probe-attempt/v1",
            "attempt_no": int(getattr(fresh, "attempt_count", 0) or 0),
            "reserved_requests": 3,
        }
        changed = db.execute(
            update(TestCase)
            .where(
                TestCase.id == fresh.id,
                TestCase.runtime_lineage_probe_reserved_at.is_(None),
            )
            .values(
                runtime_lineage_probe_reserved_at=datetime.now(UTC),
                research_metadata=metadata,
            )
            .execution_options(synchronize_session=False)
        ).rowcount
        if changed != 1:
            db.rollback()
            return False
        db.commit()
        db.expire_all()
        return True
