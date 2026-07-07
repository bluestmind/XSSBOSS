"""Acceptance tests for the persistent hypothesis-driven research loop."""
import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import backend_api.models  # noqa: F401
import backend_api.tenancy  # noqa: F401
from backend_api.models.base import BaseModel
from backend_api.models.context import Context
from backend_api.models.endpoint import Endpoint
from backend_api.models.execution import Execution, OracleStatus
from backend_api.models.experiment import Experiment, ExperimentStatus, ExperimentStrategy
from backend_api.models.finding import Finding, FindingStatus, Severity
from backend_api.models.param import Param
from backend_api.models.research import (
    AttackSurfaceEdge,
    AttackSurfaceNode,
    ResearchHypothesis,
    ResearchObservation,
    ResearchTechniqueStat,
)
from backend_api.models.sink import DetectedVia, Sink
from backend_api.models.target import Target, TargetStatus
from backend_api.models.tenant import Tenant
from backend_api.models.test_case import TestCase, TestCaseStatus
from backend_api.services.research_service import ResearchService
from backend_api.services.run_state_service import RunStateService
from fuzzer.strategy import Strategy


class ResearchServiceTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        BaseModel.metadata.create_all(self.engine)
        self.db = sessionmaker(bind=self.engine)()
        tenant = Tenant(slug="research", name="Research")
        self.db.add(tenant)
        self.db.flush()
        target = Target(
            tenant_id=tenant.id,
            name="research-target",
            base_url="https://research.test",
            scope_tags={"allowed_hosts": ["research.test"]},
            status=TargetStatus.FUZZING,
        )
        self.db.add(target)
        self.db.flush()
        self.endpoint = Endpoint(
            target_id=target.id,
            method="GET",
            url_pattern="https://research.test/oauth/callback?redirect=",
        )
        self.db.add(self.endpoint)
        self.db.flush()
        self.param = Param(
            endpoint_id=self.endpoint.id,
            name="redirect_url",
            location="query",
            sample_value="/home",
        )
        self.db.add(self.param)
        self.db.flush()
        self.context = Context(
            endpoint_id=self.endpoint.id,
            param_id=self.param.id,
            context_type="JS_STRING_LITERAL",
            snippet='const next = "MARKER"',
        )
        self.db.add(self.context)
        self.db.flush()
        self.sink = Sink(
            context_id=self.context.id,
            sink_type="innerHTML",
            taint_path=["redirect_url", "next", "innerHTML"],
            detected_via=DetectedVia.DYNAMIC,
        )
        self.db.add(self.sink)
        self.experiment = Experiment(
            target_id=target.id,
            name="autonomous-research",
            strategy=ExperimentStrategy.SMART_ADAPTIVE,
            status=ExperimentStatus.RUNNING,
            limits={"autonomous_research": True},
        )
        self.db.add(self.experiment)
        self.db.commit()
        RunStateService.add_endpoints(self.db, self.experiment.id, [self.endpoint.id], "test")

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def test_planner_builds_idempotent_graph_and_ranked_hypotheses(self):
        first = ResearchService.plan_experiment(self.db, self.experiment.id)
        second = ResearchService.plan_experiment(self.db, self.experiment.id)

        self.assertEqual(first, second)
        self.assertGreaterEqual(first["surface_nodes"], 5)
        self.assertGreaterEqual(first["surface_edges"], 4)
        hypothesis_types = {
            row.hypothesis_type
            for row in self.db.query(ResearchHypothesis).filter_by(experiment_id=self.experiment.id)
        }
        self.assertIn("open_redirect", hypothesis_types)
        self.assertIn("dom_xss", hypothesis_types)
        self.assertEqual(
            self.db.query(AttackSurfaceNode).filter_by(experiment_id=self.experiment.id).count(),
            first["surface_nodes"],
        )
        self.assertEqual(
            self.db.query(AttackSurfaceEdge).filter_by(experiment_id=self.experiment.id).count(),
            first["surface_edges"],
        )

    def test_execution_feedback_updates_hypothesis_and_cross_run_technique_stat(self):
        ResearchService.plan_experiment(self.db, self.experiment.id)
        hypothesis = ResearchService.hypothesis_for_context(
            self.db, self.experiment.id, self.endpoint.id, self.param.id, self.context.id
        )
        self.assertEqual(hypothesis.hypothesis_type, "dom_xss")
        technique = ResearchService.select_technique(self.db, hypothesis, self.context, None)
        strategy = ResearchService.recommended_strategy(
            hypothesis, self.context, None, Strategy.QUICK_LIGHT
        )
        self.assertEqual(strategy, Strategy.JS_STRING_SPECIALIST)

        test_case = TestCase(
            experiment_id=self.experiment.id,
            endpoint_id=self.endpoint.id,
            param_id=self.param.id,
            context_id=self.context.id,
            payload='<svg onload=__XSS__("token")>',
            token="research-feedback-token",
            priority=100,
            status=TestCaseStatus.COMPLETED,
        )
        profile = {"waf_detected": True, "csp_rules": {}}
        fingerprint = ResearchService.context_fingerprint(hypothesis, self.context, profile)
        ResearchService.attach_test_case(
            self.db, test_case, hypothesis, technique, fingerprint
        )
        self.db.add(test_case)
        self.db.flush()
        execution = Execution(
            test_case_id=test_case.id,
            oracle_status=OracleStatus.HIT,
            oracle_token=test_case.token,
            logs='{"sink":"Element.innerHTML"}',
        )
        self.db.add(execution)
        self.db.commit()

        learned = ResearchService.learn_from_execution(
            self.db, execution, {"oracle_hit": True, "logs": {"sink": "Element.innerHTML"}}
        )
        duplicate = ResearchService.learn_from_execution(self.db, execution, {})

        self.assertEqual(learned["outcome"], "supported")
        self.assertEqual(learned["technique"], "svg-event")
        self.assertTrue(duplicate["deduplicated"])
        self.assertEqual(hypothesis.status, "supported")
        self.assertGreaterEqual(hypothesis.confidence, 0.99)
        self.assertEqual(self.db.query(ResearchObservation).count(), 1)
        stat = self.db.query(ResearchTechniqueStat).one()
        self.assertEqual(stat.technique, "svg-event")
        self.assertEqual(stat.successes, 1)
        self.assertEqual(stat.failures, 0)
        self.assertEqual(stat.context_fingerprint, fingerprint)
        self.assertIn(":waf:no-csp", stat.context_fingerprint)

    def test_bundle_signals_become_sanitized_graph_evidence_and_hypotheses(self):
        summary = ResearchService.plan_experiment(
            self.db,
            self.experiment.id,
            recon_signals=[{
                "kind": "client_bundle",
                "script_url": "https://research.test/assets/app.js",
                "size_bytes": 8192,
                "discovered_endpoints": ["/oauth/callback"],
                "counts": {
                    "dom_sources": 2,
                    "dom_sinks": 1,
                    "navigation_sinks": 1,
                    "eval_sinks": 0,
                    "postmessage_listeners": 1,
                    "sensitive_tokens": 1,
                    "prototype_pollution": 1,
                    "sanitizers": 1,
                },
            }],
        )

        self.assertEqual(summary["recon_signals"]["bundles"], 1)
        hypothesis_types = {
            row.hypothesis_type for row in self.db.query(ResearchHypothesis).all()
        }
        self.assertTrue({
            "client_side_taint", "postmessage_boundary",
            "prototype_pollution", "client_secret_exposure",
        }.issubset(hypothesis_types))
        script = self.db.query(AttackSurfaceNode).filter_by(node_type="client_script").one()
        self.assertNotIn("secret", str(script.attributes).lower())
        self.assertTrue(
            self.db.query(AttackSurfaceEdge).filter_by(relation="references").count()
        )

    def test_direct_auditor_finding_promotes_matching_hypothesis(self):
        ResearchService.plan_experiment(self.db, self.experiment.id)
        finding = Finding(
            endpoint_id=self.endpoint.id,
            param_id=self.param.id,
            vuln_type="cors",
            scanner_module="cors_auditor",
            confidence="firm",
            best_payload="Origin: https://research-canary.invalid",
            severity=Severity.MEDIUM,
            status=FindingStatus.CONFIRMED,
        )
        self.db.add(finding)
        self.db.commit()

        self.assertEqual(
            ResearchService.learn_from_findings(self.db, self.experiment.id, [finding]), 1
        )
        hypothesis = self.db.query(ResearchHypothesis).filter_by(
            experiment_id=self.experiment.id,
            endpoint_id=self.endpoint.id,
            hypothesis_type="cors",
        ).one()
        self.assertEqual(hypothesis.status, "supported")
        self.assertGreaterEqual(hypothesis.confidence, 0.99)
        self.assertEqual(hypothesis.observations[0].finding_id, finding.id)


if __name__ == "__main__":
    unittest.main()
