import unittest
from unittest.mock import patch

from fastapi import BackgroundTasks
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import backend_api.models  # noqa: F401 - register every relationship target
from backend_api.models.base import BaseModel
from backend_api.models.endpoint import Endpoint
from backend_api.models.execution import Execution, OracleStatus
from backend_api.models.experiment import Experiment, ExperimentStatus, ExperimentStrategy
from backend_api.models.finding import Finding, FindingStatus, Severity
from backend_api.models.param import Param
from backend_api.models.target import Target, TargetStatus
from backend_api.models.test_case import TestCase, TestCaseStatus
from backend_api.routers.scans import _fail_scan, _persist_run_scope, create_scan
from backend_api.schemas.scan import ScanCreate
from backend_api.services.campaign_report_service import CampaignReportService
from browser_workers.worker import execute_test_case_task
from recon_engine.utils.request_signature import RequestSignature


class OneShotFlowTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        BaseModel.metadata.create_all(self.engine)
        self.db = sessionmaker(bind=self.engine)()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def _target(self) -> Target:
        target = Target(
            name="example",
            base_url="https://example.test",
            scope_tags={"allowed_hosts": ["example.test"]},
            status=TargetStatus.RECON_ONLY,
        )
        self.db.add(target)
        self.db.commit()
        return target

    def _experiment(self, target_id: int, request_url: str) -> Experiment:
        experiment = Experiment(
            target_id=target_id,
            name="one flow",
            strategy=ExperimentStrategy.QUICK_LIGHT,
            status=ExperimentStatus.RUNNING,
            limits={"source": "one_shot_scan", "request_url": request_url},
        )
        self.db.add(experiment)
        self.db.commit()
        return experiment

    def test_query_values_do_not_create_distinct_endpoint_identity(self):
        first = RequestSignature.normalize_url("https://example.test/search?q=first&page=1")
        second = RequestSignature.normalize_url("https://example.test/search?page=99&q=second")
        self.assertEqual(first, second)
        self.assertEqual(first, "https://example.test/search?page=&q=")

    def test_persisted_scope_contains_only_run_endpoints(self):
        target = self._target()
        run_endpoint = Endpoint(target_id=target.id, method="GET", url_pattern="https://example.test/run?q=")
        stale_endpoint = Endpoint(target_id=target.id, method="GET", url_pattern="https://example.test/old?q=")
        self.db.add_all([run_endpoint, stale_endpoint])
        self.db.flush()
        self.db.add(Param(endpoint_id=run_endpoint.id, name="q", location="query"))
        experiment = self._experiment(target.id, "https://example.test/run?q=x")

        _persist_run_scope(self.db, experiment, {run_endpoint.id}, imported_count=1)
        self.db.refresh(experiment)

        self.assertEqual(experiment.limits["endpoint_ids"], [run_endpoint.id])
        self.assertEqual(experiment.limits["recon_endpoint_count"], 1)
        self.assertEqual(experiment.limits["recon_param_count"], 1)

    def test_background_failure_is_terminal_and_visible(self):
        target = self._target()
        experiment = self._experiment(target.id, "https://example.test/")

        with patch("backend_api.services.campaign_report_service.CampaignReportService.generate_report"):
            _fail_scan(self.db, experiment.id, RuntimeError("browser crashed"))
        self.db.refresh(experiment)
        self.db.refresh(target)

        self.assertEqual(experiment.status, ExperimentStatus.FAILED)
        self.assertIsNotNone(experiment.completed_at)
        self.assertEqual(target.status, TargetStatus.RECON_ONLY)
        self.assertIn("browser crashed", experiment.limits["warnings"][-1]["detail"])

    def test_different_url_on_same_origin_gets_its_own_run(self):
        target = self._target()
        active = self._experiment(target.id, "https://example.test/first?q=x")

        result = create_scan(
            ScanCreate(url="https://example.test/second?q=x", authorized=True, crawl=True),
            BackgroundTasks(),
            self.db,
        )

        self.assertNotEqual(result.experiment_id, active.id)
        created = self.db.query(Experiment).filter(Experiment.id == result.experiment_id).one()
        self.assertEqual(created.limits["request_url"], "https://example.test/second?q=x")
        self.assertTrue(created.limits["crawl"])

    def test_same_url_reuses_its_active_run(self):
        target = self._target()
        active = self._experiment(target.id, "https://example.test/search?q=x")

        result = create_scan(
            ScanCreate(url="https://example.test/search?q=x", authorized=True),
            BackgroundTasks(),
            self.db,
        )

        self.assertEqual(result.experiment_id, active.id)
        self.assertEqual(self.db.query(Experiment).count(), 1)

    def test_campaign_findings_are_not_leaked_between_runs(self):
        target = self._target()
        endpoint = Endpoint(target_id=target.id, method="GET", url_pattern="https://example.test/?q=")
        self.db.add(endpoint)
        self.db.flush()
        param = Param(endpoint_id=endpoint.id, name="q", location="query")
        self.db.add(param)
        self.db.flush()
        first = self._experiment(target.id, "https://example.test/?q=one")
        second = self._experiment(target.id, "https://example.test/?q=two")
        test_case = TestCase(
            experiment_id=first.id,
            endpoint_id=endpoint.id,
            param_id=param.id,
            payload="<svg/onload=alert(1)>",
            token="one-shot-owned-finding",
        )
        self.db.add(test_case)
        self.db.flush()
        finding = Finding(
            endpoint_id=endpoint.id,
            param_id=param.id,
            best_payload=test_case.payload,
            severity=Severity.HIGH,
            status=FindingStatus.DRAFT,
            evidence_refs={"test_case_id": test_case.id},
        )
        self.db.add(finding)
        self.db.commit()

        self.assertEqual(CampaignReportService.get_findings_for_experiment(self.db, first.id), [finding])
        self.assertEqual(CampaignReportService.get_findings_for_experiment(self.db, second.id), [])

        target.name = '<img src=x onerror="alert(1)">' 
        finding.report_text = '<script>alert("report")</script> **safe bold**'
        finding.screenshot_path = "screenshots/private.png"
        self.db.commit()
        rendered = CampaignReportService._build_html(
            first, [finding], 1, 1, 0,
            {"critical": 0, "high": 1, "medium": 0, "low": 0}, "1s",
        )
        self.assertNotIn("<script>alert", rendered)
        self.assertNotIn("<img src=x onerror", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("&lt;svg/onload=alert(1)&gt;", rendered)
        self.assertIn(f"/api/v1/results/findings/{finding.id}/screenshot", rendered)

    def test_completed_worker_delivery_is_idempotent(self):
        target = self._target()
        endpoint = Endpoint(target_id=target.id, method="GET", url_pattern="https://example.test/?q=")
        self.db.add(endpoint)
        self.db.flush()
        param = Param(endpoint_id=endpoint.id, name="q", location="query")
        self.db.add(param)
        self.db.flush()
        experiment = self._experiment(target.id, "https://example.test/?q=x")
        test_case = TestCase(
            experiment_id=experiment.id,
            endpoint_id=endpoint.id,
            param_id=param.id,
            payload="<svg/onload=alert(1)>",
            token="completed-delivery-token",
            status=TestCaseStatus.COMPLETED,
        )
        self.db.add(test_case)
        self.db.flush()
        execution = Execution(
            test_case_id=test_case.id,
            oracle_status=OracleStatus.HIT,
            oracle_token=test_case.token,
        )
        self.db.add(execution)
        self.db.commit()

        with patch("browser_workers.worker.get_db", return_value=iter([self.db])):
            result = execute_test_case_task.run(test_case.id)

        self.assertEqual(result["status"], "already_completed")
        self.assertEqual(self.db.query(Execution).filter(Execution.test_case_id == test_case.id).count(), 1)

    def test_running_worker_delivery_cannot_be_claimed_twice(self):
        target = self._target()
        endpoint = Endpoint(target_id=target.id, method="GET", url_pattern="https://example.test/?q=")
        self.db.add(endpoint)
        self.db.flush()
        param = Param(endpoint_id=endpoint.id, name="q", location="query")
        self.db.add(param)
        self.db.flush()
        experiment = self._experiment(target.id, "https://example.test/?q=x")
        test_case = TestCase(
            experiment_id=experiment.id,
            endpoint_id=endpoint.id,
            param_id=param.id,
            payload="payload",
            token="already-running-token",
            status=TestCaseStatus.RUNNING,
        )
        self.db.add(test_case)
        self.db.commit()

        with patch("browser_workers.worker.get_db", return_value=iter([self.db])):
            result = execute_test_case_task.run(test_case.id)

        self.assertEqual(result["status"], "already_claimed")
        self.assertEqual(self.db.query(Execution).count(), 0)


if __name__ == "__main__":
    unittest.main()
