"""Atomic, expiring ownership for browser test-case execution."""
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, func, or_, update
from sqlalchemy.orm import Session

from backend_api.models.test_case import TestCase, TestCaseStatus


@dataclass(frozen=True)
class LeaseClaim:
    test_case_id: int
    attempt_count: int
    owner: str
    expires_at: datetime


class TestCaseLeaseService:
    """Claim browser work safely across duplicate delivery and worker loss."""

    @staticmethod
    def claim(
        db: Session,
        test_case_id: int,
        owner: str,
        lease_seconds: int,
    ) -> TestCase | None:
        claim = TestCaseLeaseService.claim_snapshot(
            db, test_case_id, owner, lease_seconds
        )
        if claim is None:
            return None
        return db.query(TestCase).filter(TestCase.id == claim.test_case_id).one()

    @staticmethod
    def claim_snapshot(
        db: Session,
        test_case_id: int,
        owner: str,
        lease_seconds: int,
    ) -> LeaseClaim | None:
        """Commit an atomic claim and return only the fields hot-path workers need."""
        candidate = db.query(TestCase).filter(TestCase.id == test_case_id).first()
        if candidate is None:
            return None
        from backend_api.services.run_budget_service import RunBudgetService

        if not RunBudgetService.allow_primary_request(db, candidate):
            return None

        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=max(1, lease_seconds))
        normalized_owner = owner[:120]
        claimable = or_(
            TestCase.status.in_([TestCaseStatus.PENDING, TestCaseStatus.QUEUED]),
            and_(
                TestCase.status == TestCaseStatus.RUNNING,
                # A legacy/in-flight RUNNING row with no lease is not proof that
                # ownership was abandoned. Reclaim only an explicitly expired
                # lease; the queue's stuck-work recovery handles old null rows.
                TestCase.lease_expires_at.is_not(None),
                TestCase.lease_expires_at <= now,
            ),
        )
        row = db.execute(
            update(TestCase)
            .where(TestCase.id == test_case_id, claimable)
            .values(
                status=TestCaseStatus.RUNNING,
                lease_owner=normalized_owner,
                lease_expires_at=expires_at,
                first_claimed_at=func.coalesce(TestCase.first_claimed_at, now),
                attempt_count=func.coalesce(TestCase.attempt_count, 0) + 1,
            )
            .returning(TestCase.id, TestCase.attempt_count)
            .execution_options(synchronize_session=False)
        ).one_or_none()
        db.commit()
        if row is None:
            return None
        return LeaseClaim(
            test_case_id=int(row.id),
            attempt_count=int(row.attempt_count),
            owner=normalized_owner,
            expires_at=expires_at,
        )

    @staticmethod
    def finish(db: Session, test_case: TestCase, status: TestCaseStatus) -> None:
        """Move owned work to its next state and release its execution lease."""
        try:
            test_case.status = status
            test_case.lease_owner = None
            test_case.lease_expires_at = None
            db.commit()
        except Exception:
            try:
                db.rollback()
                db.execute(
                    update(TestCase)
                    .where(TestCase.id == test_case.id)
                    .values(
                        status=status,
                        lease_owner=None,
                        lease_expires_at=None,
                    )
                    .execution_options(synchronize_session=False)
                )
                db.commit()
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
