"""Recovery/load probe built on the real browser execution contract."""
import time

from sqlalchemy import update
from sqlalchemy.orm import Session

from backend_api.config import settings
from backend_api.models.execution import Execution, OracleStatus
from backend_api.models.test_case import TestCase, TestCaseStatus
from backend_api.services.test_case_lease_service import TestCaseLeaseService


class ScaleProbeService:
    @staticmethod
    def process(
        db: Session,
        test_case_id: int,
        owner: str,
        delay_ms: int = 25,
    ) -> dict:
        claimed = TestCaseLeaseService.claim_snapshot(
            db,
            test_case_id,
            owner,
            settings.BROWSER_LEASE_SECONDS,
        )
        if claimed is None:
            status = db.query(TestCase.status).filter(TestCase.id == test_case_id).scalar()
            if status is None:
                return {"status": "missing", "test_case_id": test_case_id}
            if status == TestCaseStatus.COMPLETED:
                return {"status": "already_completed", "test_case_id": test_case_id}
            return {"status": "already_claimed", "test_case_id": test_case_id}

        if delay_ms > 0:
            time.sleep(delay_ms / 1000)

        execution = Execution(
            test_case_id=claimed.test_case_id,
            attempt_no=claimed.attempt_count,
            idempotency_key=f"scale:{claimed.test_case_id}:{claimed.attempt_count}",
            browser_worker_id=owner[:100],
            oracle_status=OracleStatus.MISSED,
            logs="scale-recovery-probe",
            duration_ms=max(0, delay_ms),
        )
        db.add(execution)
        finished = db.execute(
            update(TestCase)
            .where(
                TestCase.id == claimed.test_case_id,
                TestCase.status == TestCaseStatus.RUNNING,
                TestCase.lease_owner == claimed.owner,
            )
            .values(
                status=TestCaseStatus.COMPLETED,
                lease_owner=None,
                lease_expires_at=None,
            )
            .execution_options(synchronize_session=False)
        ).rowcount
        if finished != 1:
            db.rollback()
            return {"status": "lease_lost", "test_case_id": test_case_id}
        db.commit()
        return {
            "status": "completed",
            "test_case_id": test_case_id,
            "attempt_no": claimed.attempt_count,
        }
