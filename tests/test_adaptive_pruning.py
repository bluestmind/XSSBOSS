"""Unit tests for adaptive dead parameter pruning and hit confirmation pruning."""
import unittest
from unittest.mock import MagicMock, patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend_api.models.base import Base
from backend_api.models.target import Target
from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from backend_api.models.experiment import Experiment, ExperimentStatus, ExperimentStrategy
from backend_api.models.test_case import TestCase, TestCaseStatus
from backend_api.models.context import Context, ContextType


class TestAdaptivePruning(unittest.TestCase):

    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()

        # Seed target, endpoint, param, experiment
        self.target = Target(name="example", base_url="https://example.com")
        self.db.add(self.target)
        self.db.flush()

        self.endpoint = Endpoint(target_id=self.target.id, url_pattern="https://example.com/search", method="GET")
        self.db.add(self.endpoint)
        self.db.flush()

        self.param = Param(endpoint_id=self.endpoint.id, name="dead_param", location="query")
        self.db.add(self.param)
        self.db.flush()

        self.experiment = Experiment(name="test-exp", target_id=self.target.id, status=ExperimentStatus.RUNNING, strategy=ExperimentStrategy.SMART_ADAPTIVE)
        self.db.add(self.experiment)
        self.db.flush()

    def tearDown(self):
        self.db.close()

    # A real rendered mega-polyglot (variant 2) — matches PolyglotTriageEngine.is_triage_payload.
    def _triage_case(self, token="TOKEN1"):
        return TestCase(
            experiment_id=self.experiment.id,
            endpoint_id=self.endpoint.id,
            param_id=self.param.id,
            payload=f"-->'\"><script src=data:,__XSS__('{token}')></script>",
            token=token,
            priority=100,
            status=TestCaseStatus.RUNNING,
        )

    def _spec_cases(self, n=5):
        return [
            TestCase(
                experiment_id=self.experiment.id,
                endpoint_id=self.endpoint.id,
                param_id=self.param.id,
                payload=f"speculative_payload_{i}",
                token=f"TOKEN_SPEC_{i}",
                priority=10,
                status=TestCaseStatus.PENDING,
            )
            for i in range(n)
        ]

    def test_zero_reflection_triage_pruning(self):
        """Zero reflection triage cancels remaining pending test cases for the dead parameter."""
        from backend_api.services.adaptive_pruning_service import AdaptivePruningService

        triage_case = self._triage_case()
        self.db.add(triage_case)
        self.db.add_all(self._spec_cases(5))
        self.db.commit()

        # Execution result with ZERO reflection and a clean 200 (not WAF-blocked).
        result = {
            "oracle_hit": False,
            "status_code": 200,
            "dom_snapshot": "<html><body><h1>Search Results: None</h1></body></html>",
            "logs": {"console": [], "errors": []},
        }

        trace = AdaptivePruningService.apply_triage_verdict(self.db, triage_case, result)

        self.assertEqual(trace["action"], "prune")
        self.assertEqual(trace["pruned"], 5)
        cancelled_cases = self.db.query(TestCase).filter(TestCase.status == TestCaseStatus.CANCELLED).count()
        self.assertEqual(cancelled_cases, 5)

    def test_waf_blocked_polyglot_does_not_prune(self):
        """A 403 on the (big, obvious) polyglot must NOT prune — a stealth payload might still hit."""
        from backend_api.services.adaptive_pruning_service import AdaptivePruningService

        triage_case = self._triage_case()
        self.db.add(triage_case)
        self.db.add_all(self._spec_cases(4))
        self.db.commit()

        result = {"oracle_hit": False, "status_code": 403, "dom_snapshot": "", "logs": {}}
        trace = AdaptivePruningService.apply_triage_verdict(self.db, triage_case, result)

        self.assertEqual(trace["action"], "keep")
        self.assertTrue(trace["blocked"])
        self.assertEqual(trace["pruned"], 0)
        self.assertEqual(self.db.query(TestCase).filter(TestCase.status == TestCaseStatus.CANCELLED).count(), 0)

    def test_taint_signal_blocks_prune(self):
        """A DOM taint flow in the logs keeps the parameter even with zero server reflection."""
        from backend_api.services.adaptive_pruning_service import AdaptivePruningService

        triage_case = self._triage_case()
        self.db.add(triage_case)
        self.db.add_all(self._spec_cases(3))
        self.db.commit()

        result = {
            "oracle_hit": False,
            "status_code": 200,
            "dom_snapshot": "<html>no reflection</html>",
            "logs": {"console": ["[TaintFlow] location.hash -> innerHTML"]},
        }
        trace = AdaptivePruningService.apply_triage_verdict(self.db, triage_case, result)

        self.assertEqual(trace["action"], "keep")
        self.assertEqual(trace["pruned"], 0)
        self.assertEqual(self.db.query(TestCase).filter(TestCase.status == TestCaseStatus.CANCELLED).count(), 0)

    def test_non_triage_case_is_ignored(self):
        """A normal single-context payload must never trigger parameter-wide pruning."""
        from backend_api.services.adaptive_pruning_service import AdaptivePruningService

        normal = TestCase(
            experiment_id=self.experiment.id, endpoint_id=self.endpoint.id, param_id=self.param.id,
            payload="<img src=x onerror=__XSS__('T')>", token="T", priority=10,
            status=TestCaseStatus.RUNNING,
        )
        self.db.add(normal)
        self.db.add_all(self._spec_cases(2))
        self.db.commit()

        trace = AdaptivePruningService.apply_triage_verdict(
            self.db, normal, {"oracle_hit": False, "status_code": 200, "dom_snapshot": ""}
        )
        self.assertFalse(trace["applied"])
        self.assertEqual(self.db.query(TestCase).filter(TestCase.status == TestCaseStatus.CANCELLED).count(), 0)

    def test_hit_confirmation_prunes_redundant_cases(self):
        """Confirmed execution hit immediately cancels remaining pending test cases for the parameter."""
        hit_case = TestCase(
            experiment_id=self.experiment.id,
            endpoint_id=self.endpoint.id,
            param_id=self.param.id,
            payload="<script>__XSS__('HIT')</script>",
            token="HIT",
            priority=80,
            status=TestCaseStatus.RUNNING
        )
        spec_cases = [
            TestCase(
                experiment_id=self.experiment.id,
                endpoint_id=self.endpoint.id,
                param_id=self.param.id,
                payload=f"extra_probe_{i}",
                token=f"TOKEN_EXTRA_{i}",
                priority=10,
                status=TestCaseStatus.PENDING
            )
            for i in range(3)
        ]
        self.db.add(hit_case)
        self.db.add_all(spec_cases)
        self.db.commit()

        # Hit confirmed
        pruned = (
            self.db.query(TestCase)
            .filter(
                TestCase.experiment_id == hit_case.experiment_id,
                TestCase.param_id == hit_case.param_id,
                TestCase.id != hit_case.id,
                TestCase.status.in_([TestCaseStatus.PENDING, TestCaseStatus.QUEUED])
            )
            .update({"status": TestCaseStatus.CANCELLED}, synchronize_session=False)
        )
        self.db.commit()

        self.assertEqual(pruned, 3)


if __name__ == "__main__":
    unittest.main()
