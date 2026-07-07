import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
import tempfile
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

import backend_api.models  # noqa: F401
from backend_api.models.base import BaseModel
from backend_api.models.endpoint import Endpoint
from backend_api.models.execution import Execution, OracleStatus
from backend_api.models.experiment import Experiment, ExperimentStatus, ExperimentStrategy
from backend_api.models.param import Param
from backend_api.models.run_state import RunEndpoint, RunStage, RunStageName, RunStageStatus
from backend_api.models.target import Target, TargetStatus
from backend_api.models.test_case import TestCase
from backend_api.services.run_state_service import RunStateService
from backend_api.services.test_case_lease_service import TestCaseLeaseService
from backend_api.services.scale_probe_service import ScaleProbeService
from backend_api.models.evidence import EvidenceArtifact
from backend_api.services.evidence_service import EvidenceService
from backend_api.config import settings


class RunStateTests(unittest.TestCase):
    def setUp(self):
        self.evidence_temp = tempfile.TemporaryDirectory()
        self.evidence_patch = patch.object(settings, "EVIDENCE_DIR", self.evidence_temp.name)
        self.evidence_patch.start()
        self.engine = create_engine("sqlite:///:memory:")
        BaseModel.metadata.create_all(self.engine)
        self.db = sessionmaker(bind=self.engine)()
        target = Target(
            name="owned",
            base_url="https://owned.test",
            status=TargetStatus.FUZZING,
            scope_tags={"allowed_hosts": ["owned.test"]},
        )
        self.db.add(target)
        self.db.flush()
        self.endpoint = Endpoint(
            target_id=target.id,
            method="GET",
            url_pattern="https://owned.test/?q=",
        )
        self.db.add(self.endpoint)
        self.db.flush()
        self.param = Param(endpoint_id=self.endpoint.id, name="q", location="query")
        self.db.add(self.param)
        self.db.flush()
        self.experiment = Experiment(
            target_id=target.id,
            name="durable",
            strategy=ExperimentStrategy.QUICK_LIGHT,
            status=ExperimentStatus.RUNNING,
        )
        self.db.add(self.experiment)
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()
        self.evidence_patch.stop()
        self.evidence_temp.cleanup()

    def test_pipeline_claims_are_leased_and_terminal(self):
        stages = RunStateService.ensure_pipeline(self.db, self.experiment.id)
        self.assertEqual(len(stages), 5)
        self.assertTrue(RunStateService.claim_stage(
            self.db, self.experiment.id, RunStageName.RECON, "worker-a"
        ))
        self.assertFalse(RunStateService.claim_stage(
            self.db, self.experiment.id, RunStageName.RECON, "worker-b"
        ))
        RunStateService.complete_stage(
            self.db, self.experiment.id, RunStageName.RECON, {"endpoint_count": 1}
        )
        self.assertFalse(RunStateService.claim_stage(
            self.db, self.experiment.id, RunStageName.RECON, "worker-b"
        ))
        stage = self.db.query(RunStage).filter_by(
            experiment_id=self.experiment.id, name=RunStageName.RECON
        ).one()
        self.assertEqual(stage.status, RunStageStatus.COMPLETED)
        self.assertEqual(stage.output["endpoint_count"], 1)

    def test_expired_stage_lease_is_recovered_by_another_worker(self):
        RunStateService.ensure_pipeline(self.db, self.experiment.id)
        self.assertTrue(RunStateService.claim_stage(
            self.db, self.experiment.id, RunStageName.RECON, "dead-worker"
        ))
        stage = self.db.query(RunStage).filter_by(
            experiment_id=self.experiment.id, name=RunStageName.RECON
        ).one()
        stage.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        self.db.commit()

        self.assertTrue(RunStateService.claim_stage(
            self.db, self.experiment.id, RunStageName.RECON, "replacement-worker"
        ))
        self.db.refresh(stage)
        self.assertEqual(stage.lease_owner, "replacement-worker")
        self.assertEqual(stage.attempt_count, 2)

    def test_endpoint_membership_is_database_idempotent(self):
        RunStateService.add_endpoints(
            self.db, self.experiment.id, [self.endpoint.id, self.endpoint.id], "crawler"
        )
        RunStateService.add_endpoints(
            self.db, self.experiment.id, [self.endpoint.id], "crawler"
        )
        self.assertEqual(self.db.query(RunEndpoint).count(), 1)
        self.assertEqual(
            RunStateService.endpoint_ids(self.db, self.experiment.id), [self.endpoint.id]
        )

    def test_browser_attempt_number_is_unique_per_test_case(self):
        test_case = TestCase(
            experiment_id=self.experiment.id,
            endpoint_id=self.endpoint.id,
            param_id=self.param.id,
            payload="payload",
            token="attempt-unique-token",
        )
        self.db.add(test_case)
        self.db.flush()
        self.db.add(Execution(
            test_case_id=test_case.id,
            attempt_no=1,
            idempotency_key=f"browser:{test_case.id}:1",
            oracle_status=OracleStatus.MISSED,
        ))
        self.db.commit()
        self.db.add(Execution(
            test_case_id=test_case.id,
            attempt_no=1,
            idempotency_key="different-key",
            oracle_status=OracleStatus.MISSED,
        ))
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

    def test_active_browser_lease_blocks_duplicate_and_expired_lease_recovers(self):
        test_case = TestCase(
            experiment_id=self.experiment.id,
            endpoint_id=self.endpoint.id,
            param_id=self.param.id,
            payload="payload",
            token="lease-recovery-token",
        )
        self.db.add(test_case)
        self.db.commit()

        first = TestCaseLeaseService.claim(self.db, test_case.id, "worker-a", 300)
        self.assertIsNotNone(first)
        self.assertEqual(first.attempt_count, 1)
        first_claimed_at = first.first_claimed_at
        self.assertIsNotNone(first_claimed_at)
        self.assertIsNone(TestCaseLeaseService.claim(self.db, test_case.id, "worker-b", 300))

        first.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        self.db.commit()
        recovered = TestCaseLeaseService.claim(self.db, test_case.id, "worker-b", 300)

        self.assertIsNotNone(recovered)
        self.assertEqual(recovered.lease_owner, "worker-b")
        self.assertEqual(recovered.attempt_count, 2)
        self.assertEqual(recovered.first_claimed_at, first_claimed_at)

    def test_scale_probe_duplicate_delivery_has_one_completed_execution(self):
        test_case = TestCase(
            experiment_id=self.experiment.id,
            endpoint_id=self.endpoint.id,
            param_id=self.param.id,
            payload="payload",
            token="scale-probe-token",
        )
        self.db.add(test_case)
        self.db.commit()

        first = ScaleProbeService.process(self.db, test_case.id, "worker-a", 0)
        duplicate = ScaleProbeService.process(self.db, test_case.id, "worker-b", 0)

        self.assertEqual(first["status"], "completed")
        self.assertEqual(duplicate["status"], "already_completed")
        self.assertEqual(
            self.db.query(Execution).filter_by(test_case_id=test_case.id).count(),
            1,
        )

    def test_dom_evidence_is_content_addressed_and_deduplicated(self):
        test_case = TestCase(
            experiment_id=self.experiment.id,
            endpoint_id=self.endpoint.id,
            param_id=self.param.id,
            payload="payload",
            token="evidence-token",
        )
        self.db.add(test_case)
        self.db.flush()
        execution = Execution(
            test_case_id=test_case.id,
            oracle_status=OracleStatus.HIT,
            logs="proof log",
            dom_snapshot="<html>proof</html>",
        )
        self.db.add(execution)
        self.db.commit()

        first = EvidenceService.register_execution(
            self.db,
            execution,
            request_data={
                "url": "https://owned.test/?q=payload",
                "headers": {"Authorization": "Bearer secret", "Accept": "text/html"},
                "cookies": {"session": "secret"},
            },
            result={"status_code": 200, "headers": {"content-type": "text/html"}, "oracle_hit": True},
        )
        second = EvidenceService.register_execution(self.db, execution)

        self.assertEqual(len(first[0].sha256), 64)
        self.assertIn(second[0].sha256, {artifact.sha256 for artifact in first})
        self.assertEqual(self.db.query(EvidenceArtifact).count(), 4)
        verification = EvidenceService.verify_all(self.db)
        self.assertTrue(verification["passed"])
        request_artifact = self.db.query(EvidenceArtifact).filter_by(kind="request").one()
        request_content = (Path(settings.EVIDENCE_DIR) / request_artifact.uri).read_text(encoding="utf-8")
        self.assertNotIn("Bearer secret", request_content)
        self.assertNotIn('"session":"secret"', request_content)


if __name__ == "__main__":
    unittest.main()
