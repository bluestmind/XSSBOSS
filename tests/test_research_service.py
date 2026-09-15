"""Acceptance tests for the persistent hypothesis-driven research loop."""
import hashlib
import json
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
from backend_api.utils.runtime_lineage_evidence import (
    seal_runtime_lineage_probe_evidence,
)
from fuzzer.strategy import Strategy


def _runtime_candidate_id(
    source_category: str,
    source_fingerprint: str,
    sink_category: str,
    sink_fingerprint: str,
) -> str:
    canonical = json.dumps({
        "source_category": source_category,
        "source_fingerprint": source_fingerprint,
        "sink_category": sink_category,
        "sink_fingerprint": sink_fingerprint,
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


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
        hypothesis.evidence = {
            **(hypothesis.evidence or {}),
            "llm_advice": {
                "model": "local-test-model",
                "priority_adjustment": 3,
                "technique": "svg-event",
                "rationale": "test attribution",
            },
        }
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
        test_case.research_metadata = {
            **test_case.research_metadata,
            "llm_pivot": {
                "model": "local-test-model",
                "trigger_test_case_id": 999,
                "priority_boost": 10,
                "llm_changed_decision": True,
            },
        }
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
        performance = self.experiment.limits["campaign_brain"]["llm_advisor_performance"]
        self.assertEqual(performance["executions"], 1)
        self.assertEqual(performance["hits"], 1)
        self.assertEqual(performance["reward_sum"], 1.0)
        self.assertEqual(performance["model"], "local-test-model")
        pivot_performance = self.experiment.limits["campaign_brain"]["llm_pivot_performance"]
        self.assertEqual(pivot_performance["executions"], 1)
        self.assertEqual(pivot_performance["hits"], 1)
        self.assertEqual(pivot_performance["reward_sum"], 1.0)
        self.assertEqual(pivot_performance["overrides"], 1)

        baseline_case = TestCase(
            experiment_id=self.experiment.id,
            endpoint_id=self.endpoint.id,
            param_id=self.param.id,
            context_id=self.context.id,
            payload="plain-baseline-probe",
            token="research-baseline-token",
            priority=50,
            status=TestCaseStatus.COMPLETED,
        )
        ResearchService.attach_test_case(
            self.db, baseline_case, hypothesis, "script-element", fingerprint
        )
        self.db.add(baseline_case)
        self.db.flush()
        limits = dict(self.experiment.limits)
        memory = dict(limits["campaign_brain"])
        memory["llm_pivots"] = {
            "shadow": {
                "llm_changed_decision": True,
                "selected_candidate_id": test_case.id,
                "deterministic_candidate_id": baseline_case.id,
            }
        }
        limits["campaign_brain"] = memory
        self.experiment.limits = limits
        baseline_execution = Execution(
            test_case_id=baseline_case.id,
            oracle_status=OracleStatus.MISSED,
            oracle_token=baseline_case.token,
            logs="{}",
        )
        self.db.add(baseline_execution)
        self.db.commit()
        ResearchService.learn_from_execution(self.db, baseline_execution, {"logs": {}})
        pivot_performance = self.experiment.limits["campaign_brain"]["llm_pivot_performance"]
        self.assertEqual(pivot_performance["baseline_executions"], 1)
        self.assertEqual(pivot_performance["baseline_reward_sum"], 0.0)
        self.assertEqual(pivot_performance["observed_reward_lift"], 1.0)

        ranked = ResearchService.rank_payloads(
            self.db,
            hypothesis,
            self.context,
            profile,
            [
                '<script>__XSS__("token")</script>',
                '<svg onload=__XSS__("token")>',
                '<img onerror=__XSS__("token")>',
                '<svg onfocus=__XSS__("token")>',
            ],
        )
        self.assertTrue(ranked[0].startswith("<svg"))
        self.assertNotEqual(
            ResearchService.classify_payload(ranked[0]),
            ResearchService.classify_payload(ranked[1]),
        )

    def test_runtime_activation_and_dom_differential_raise_priority_without_confirmation(self):
        ResearchService.plan_experiment(self.db, self.experiment.id)
        hypothesis = ResearchService.hypothesis_for_context(
            self.db, self.experiment.id, self.endpoint.id, self.param.id, self.context.id
        )
        self.assertEqual(hypothesis.hypothesis_type, "dom_xss")
        prior_confidence = hypothesis.confidence
        test_case = TestCase(
            experiment_id=self.experiment.id,
            endpoint_id=self.endpoint.id,
            param_id=self.param.id,
            context_id=self.context.id,
            payload="inert-alphanumeric-canary",
            token="runtime-correlation-token",
            priority=80,
            status=TestCaseStatus.COMPLETED,
        )
        ResearchService.attach_test_case(
            self.db, test_case, hypothesis, "marker-differential", "runtime-context"
        )
        self.db.add(test_case)
        self.db.flush()
        logs = {
            "runtime_code_coverage": {
                "available": True,
                "findings": [{
                    "category": "dom_sink",
                    "runtime_reached": True,
                    "site_kind": "innerHTML",
                }],
            },
            "dom_marker_differential": {
                "available": True,
                "differential_available": True,
                "summary": {"new_marker_sites": 1},
            },
        }
        execution = Execution(
            test_case_id=test_case.id,
            oracle_status=OracleStatus.MISSED,
            logs="{}",
        )
        self.db.add(execution)
        self.db.commit()

        learned = ResearchService.learn_from_execution(
            self.db, execution, {"logs": logs, "status_code": 200}
        )

        observation = self.db.query(ResearchObservation).filter_by(
            execution_id=execution.id
        ).one()
        self.assertEqual(learned["outcome"], "signal")
        self.assertEqual(observation.signal_type, "runtime_marker_correlation")
        self.assertEqual(observation.strength, 0.5)
        self.assertEqual(observation.details["runtime_activation_categories"], ["dom_sink"])
        self.assertEqual(observation.details["marker_materialized_sites"], 1)
        self.assertEqual(hypothesis.status, "testing")
        self.assertGreater(hypothesis.confidence, prior_confidence)
        self.assertLess(hypothesis.confidence, 0.99)

    def test_irrelevant_runtime_category_does_not_support_dom_hypothesis(self):
        ResearchService.plan_experiment(self.db, self.experiment.id)
        hypothesis = ResearchService.hypothesis_for_context(
            self.db, self.experiment.id, self.endpoint.id, self.param.id, self.context.id
        )
        prior_confidence = hypothesis.confidence
        test_case = TestCase(
            experiment_id=self.experiment.id,
            endpoint_id=self.endpoint.id,
            param_id=self.param.id,
            context_id=self.context.id,
            payload="inert-canary",
            token="irrelevant-runtime-token",
            status=TestCaseStatus.COMPLETED,
        )
        ResearchService.attach_test_case(
            self.db, test_case, hypothesis, "context-differential", "runtime-context-2"
        )
        self.db.add(test_case)
        self.db.flush()
        execution = Execution(
            test_case_id=test_case.id,
            oracle_status=OracleStatus.MISSED,
            logs="{}",
        )
        self.db.add(execution)
        self.db.commit()

        ResearchService.learn_from_execution(self.db, execution, {"logs": {
            "runtime_code_coverage": {
                "available": True,
                "findings": [{
                    "category": "postmessage_wildcard_target",
                    "runtime_reached": True,
                }],
            },
        }})

        observation = self.db.query(ResearchObservation).filter_by(
            execution_id=execution.id
        ).one()
        self.assertEqual(observation.signal_type, "negative_probe")
        self.assertEqual(observation.strength, 0.0)
        self.assertLess(hypothesis.confidence, prior_confidence)

    def test_runtime_lineage_weights_value_influence_above_causal_ordering(self):
        ResearchService.plan_experiment(self.db, self.experiment.id)
        hypothesis = ResearchService.hypothesis_for_context(
            self.db, self.experiment.id, self.endpoint.id, self.param.id, self.context.id
        )
        prior_confidence = hypothesis.confidence
        observations = {}

        for index, (classification, expected_signal) in enumerate((
            ("causal_only", "runtime_causal_only"),
            ("value_influence", "runtime_value_influence"),
        ), start=1):
            test_case = TestCase(
                experiment_id=self.experiment.id,
                endpoint_id=self.endpoint.id,
                param_id=self.param.id,
                context_id=self.context.id,
                payload=f"inert-lineage-canary-{index}",
                token=f"runtime-lineage-token-{index}",
                status=TestCaseStatus.COMPLETED,
            )
            ResearchService.attach_test_case(
                self.db,
                test_case,
                hypothesis,
                "runtime-lineage-correlation",
                f"runtime-lineage-context-{index}",
            )
            self.db.add(test_case)
            self.db.flush()
            execution = Execution(
                test_case_id=test_case.id,
                attempt_no=1,
                oracle_status=OracleStatus.MISSED,
                logs="{}",
            )
            self.db.add(execution)
            self.db.commit()
            observation_count = 3 if classification == "value_influence" else 0
            summary = {
                "events_seen": 2,
                "events_accepted": 2,
                "events_rejected": 0,
                "observations_seen": observation_count,
                "observations_accepted": observation_count,
                "observations_rejected": 0,
                "candidates": 1,
                "causal_only": int(classification == "causal_only"),
                "value_influence": int(classification == "value_influence"),
            }
            candidate_id = _runtime_candidate_id(
                "location_hash", "a" * 64, "innerhtml", "b" * 64
            )
            flow = {
                "candidate_id": candidate_id,
                "classification": classification,
                "source_id": "source:1",
                "source_category": "location_hash",
                "source_fingerprint": "a" * 64,
                "sink_id": "sink:1",
                "sink_category": "innerhtml",
                "sink_fingerprint": "b" * 64,
                "relation": "direct",
                "depth": 1,
                "latency_ms": 1,
            }
            if classification == "value_influence":
                flow["aab"] = {
                    "pattern": "A/A/B",
                    "runs": 3,
                    "stable_a": True,
                    "b_changed": True,
                    "inert": True,
                }

            lineage = {
                "schema_version": "1.0",
                "limits": {
                    "max_depth": 8,
                    "ttl_ms": 5000,
                    "max_events": 256,
                    "max_candidates": 8,
                    "max_observations": 24,
                    "max_runs": 24,
                    "events_truncated": False,
                    "candidates_truncated": False,
                    "observations_truncated": False,
                    "runs_truncated": False,
                },
                "budget_exhausted": [],
                "summary": summary,
                "causal_flows": [flow] if classification == "causal_only" else [],
                "value_influences": [flow] if classification == "value_influence" else [],
                "raw_value": "must-not-be-persisted",
            }
            if classification == "value_influence":
                series_id = f"{index + 6}" * 64
                run_prefix = f"rlp:{series_id[:16]}:0123456789abcdef"
                lineage["probe_observations"] = [
                    {
                        "run_id": f"{run_prefix}:1",
                        "arm": "A",
                        "inert": True,
                        "candidate_id": candidate_id,
                        "sink_fingerprint": "b" * 64,
                        "stimulus_fingerprint": "c" * 64,
                        "observation_fingerprint": "d" * 64,
                    },
                    {
                        "run_id": f"{run_prefix}:2",
                        "arm": "A",
                        "inert": True,
                        "candidate_id": candidate_id,
                        "sink_fingerprint": "b" * 64,
                        "stimulus_fingerprint": "c" * 64,
                        "observation_fingerprint": "d" * 64,
                    },
                    {
                        "run_id": f"{run_prefix}:3",
                        "arm": "B",
                        "inert": True,
                        "candidate_id": candidate_id,
                        "sink_fingerprint": "b" * 64,
                        "stimulus_fingerprint": "e" * 64,
                        "observation_fingerprint": "f" * 64,
                    },
                ]
                lineage = seal_runtime_lineage_probe_evidence(
                    lineage,
                    test_case_id=test_case.id,
                    attempt_no=1,
                    series_id=series_id,
                    accepted_observations=lineage["probe_observations"],
                )
                self.assertIsNotNone(lineage)

            learned = ResearchService.learn_from_execution(
                self.db,
                execution,
                {"logs": {
                    (
                        "runtime_lineage"
                        if classification == "value_influence"
                        else "runtime_causal_lineage"
                    ): lineage,
                }},
            )
            observation = self.db.query(ResearchObservation).filter_by(
                execution_id=execution.id
            ).one()
            self.assertEqual(learned["outcome"], "signal")
            self.assertEqual(observation.signal_type, expected_signal)
            self.assertEqual(
                observation.details["runtime_lineage_classification"], classification
            )
            self.assertNotIn("must-not-be-persisted", repr(observation.details))
            observations[classification] = observation

        self.assertLess(
            observations["causal_only"].strength,
            observations["value_influence"].strength,
        )
        self.assertEqual(hypothesis.status, "testing")
        self.assertGreater(hypothesis.confidence, prior_confidence)
        self.assertLess(hypothesis.confidence, 0.99)

    def test_targeted_sanitizer_boundary_learns_runtime_evidence_without_confirmation(self):
        ResearchService.plan_experiment(
            self.db,
            self.experiment.id,
            recon_signals=[{
                "kind": "client_bundle",
                "script_url": "https://research.test/assets/boundary.js?token=discarded",
                "discovered_endpoints": ["/oauth/callback"],
                "counts": {
                    "sanitizer_boundary_findings": 1,
                    "sanitizer_context_mismatch": 1,
                },
                "sanitizer_boundary_findings": [{
                    "category": "sanitizer_context_mismatch",
                    "source_kind": "url_param",
                    "source_param": "redirect_url",
                    "sink_kind": "innerHTML",
                    "required_context": "HTML",
                    "transform_kind": "url_encoding",
                    "protection_state": "ineffective",
                    "reason_codes": ["known_transform", "output_context_mismatch"],
                    "source_offset": 10,
                    "transform_offset": 20,
                    "sink_offset": 30,
                    "confidence": 0.9,
                    "fingerprint": "f" * 64,
                    "details": {
                        "hops": 2,
                        "compatible_context": False,
                        "raw_snippet": "must not be persisted",
                    },
                }],
            }],
        )
        hypothesis = ResearchService.hypothesis_for_context(
            self.db,
            self.experiment.id,
            self.endpoint.id,
            self.param.id,
            self.context.id,
        )
        self.assertEqual(hypothesis.hypothesis_type, "sanitizer_boundary")
        self.assertEqual(hypothesis.endpoint_id, self.endpoint.id)
        self.assertEqual(hypothesis.param_id, self.param.id)
        self.assertEqual(hypothesis.context_id, self.context.id)
        self.assertNotIn("raw_snippet", str(hypothesis.evidence))
        prior_confidence = hypothesis.confidence

        test_case = TestCase(
            experiment_id=self.experiment.id,
            endpoint_id=self.endpoint.id,
            param_id=self.param.id,
            context_id=self.context.id,
            payload="inert-boundary-canary",
            token="sanitizer-runtime-token",
            status=TestCaseStatus.COMPLETED,
        )
        ResearchService.attach_test_case(
            self.db, test_case, hypothesis, "sanitizer-boundary-differential",
            "sanitizer-runtime-context",
        )
        self.db.add(test_case)
        self.db.flush()
        execution = Execution(
            test_case_id=test_case.id,
            oracle_status=OracleStatus.MISSED,
            logs="{}",
        )
        self.db.add(execution)
        self.db.commit()

        learned = ResearchService.learn_from_execution(self.db, execution, {"logs": {
            "runtime_code_coverage": {
                "available": True,
                "findings": [{
                    "category": "dom_sink",
                    "runtime_reached": True,
                    "site_kind": "innerHTML",
                }],
            },
            "dom_marker_differential": {
                "available": True,
                "differential_available": True,
                "summary": {"new_marker_sites": 1},
            },
        }})

        observation = self.db.query(ResearchObservation).filter_by(
            execution_id=execution.id
        ).one()
        self.assertEqual(learned["outcome"], "signal")
        self.assertEqual(observation.signal_type, "runtime_marker_correlation")
        self.assertEqual(hypothesis.status, "testing")
        self.assertGreater(hypothesis.confidence, prior_confidence)
        self.assertLess(hypothesis.confidence, 0.99)

    def test_bundle_signals_become_sanitized_graph_evidence_and_hypotheses(self):
        summary = ResearchService.plan_experiment(
            self.db,
            self.experiment.id,
            recon_signals=[{
                "kind": "client_bundle",
                "script_url": (
                    "https://user:TOP_SECRET_URL@research.test/assets/app.js"
                    "?token=TOP_SECRET_URL#TOP_SECRET_URL"
                ),
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
                    "client_trust_findings": 3,
                    "postmessage_unvalidated_sink": 1,
                    "dom_named_property_to_sink": 1,
                    "trusted_types_identity_policy": 1,
                    "property_integrity_chains": 2,
                    "dom_clobbering_chain": 1,
                    "prototype_property_injection_chain": 1,
                    "sanitizer_boundary_findings": 2,
                    "sanitizer_context_mismatch": 1,
                    "trusted_types_unvalidated_flow": 1,
                    "effective_sanitizer_boundary": 1,
                },
                "client_trust_findings": [{
                    "category": "postmessage_unvalidated_sink",
                    "confidence": 0.92,
                    "severity_hint": "high",
                    "offset": 120,
                    "code_fingerprint": "a" * 64,
                    "required_confirmation": "must not be persisted from untrusted input",
                    "details": {
                        "event_parameter": "evt",
                        "sink": "innerHTML",
                        "raw_snippet": "must not be persisted",
                    },
                }],
                "property_integrity_chains": [
                    {
                        "kind": "dom_clobbering_chain",
                        "fingerprint": "b" * 64,
                        "confidence": 0.9,
                        "metadata": {
                            "named_property": "appConfig",
                            "base": "window",
                            "relationship": "direct_named_property",
                            "definition_fingerprints": ["c" * 64],
                            "sink_kind": "innerHTML",
                        },
                    },
                    {
                        "kind": "prototype_property_injection_chain",
                        "fingerprint": "d" * 64,
                        "confidence": 0.94,
                        "metadata": {
                            "source_kind": "message_data",
                            "mutation_operation": "deep_merge",
                            "mutation_target": "options",
                            "gadget_property": "html",
                            "sink_kind": "innerHTML",
                        },
                    },
                ],
                "sanitizer_boundary_findings": [{
                    "category": "trusted_types_unvalidated_flow",
                    "source_kind": "url_param",
                    "source_param": "redirect_url",
                    "sink_kind": "innerHTML",
                    "required_context": "HTML",
                    "transform_kind": "trusted_types_policy",
                    "protection_state": "ineffective",
                    "reason_codes": ["content_preserving_policy_method"],
                    "source_offset": 40,
                    "transform_offset": 80,
                    "sink_offset": 120,
                    "confidence": 0.91,
                    "fingerprint": "e" * 64,
                    "details": {
                        "hops": 2,
                        "policy_method": "createHTML",
                        "compatible_context": True,
                        "raw_snippet": "must not be persisted",
                    },
                }],
            }],
        )

        self.assertEqual(summary["recon_signals"]["bundles"], 1)
        hypothesis_types = {
            row.hypothesis_type for row in self.db.query(ResearchHypothesis).all()
        }
        self.assertTrue({
            "client_side_taint", "postmessage_boundary",
            "prototype_pollution", "client_secret_exposure", "dom_clobbering",
            "trusted_types_policy",
            "sanitizer_boundary",
        }.issubset(hypothesis_types))
        script = self.db.query(AttackSurfaceNode).filter_by(node_type="client_script").one()
        self.assertEqual(script.label, "https://research.test/assets/app.js")
        self.assertNotIn("TOP_SECRET_URL", str(script.attributes))
        self.assertNotIn("secret", str(script.attributes).lower())
        self.assertNotIn("raw_snippet", str(script.attributes))
        self.assertNotIn("required_confirmation", str(script.attributes))
        self.assertGreaterEqual(script.risk_score, 40)
        self.assertEqual(
            script.attributes["client_trust_findings"][0]["details"]["sink"],
            "innerHTML",
        )
        self.assertEqual(len(script.attributes["property_integrity_chains"]), 2)
        self.assertEqual(len(script.attributes["sanitizer_boundary_findings"]), 1)
        self.assertNotIn("raw_snippet", str(script.attributes["sanitizer_boundary_findings"]))
        targeted_boundary = self.db.query(ResearchHypothesis).filter_by(
            hypothesis_type="sanitizer_boundary",
            endpoint_id=self.endpoint.id,
            param_id=self.param.id,
            context_id=self.context.id,
        ).one()
        self.assertTrue(targeted_boundary.evidence["targeted"])
        self.assertEqual(targeted_boundary.evidence["parameter_name"], "redirect_url")
        self.assertEqual(targeted_boundary.evidence["sink_kinds"], ["innerHTML"])
        self.assertNotIn("raw_snippet", str(targeted_boundary.evidence))
        self.assertEqual(
            ResearchService.hypothesis_for_context(
                self.db,
                self.experiment.id,
                self.endpoint.id,
                self.param.id,
                self.context.id,
            ).id,
            targeted_boundary.id,
        )
        self.assertEqual(
            self.db.query(AttackSurfaceNode).filter(
                AttackSurfaceNode.node_type.in_([
                    "dom_clobbering_chain", "prototype_property_injection_chain",
                ])
            ).count(),
            2,
        )
        self.assertEqual(
            self.db.query(AttackSurfaceEdge).filter_by(relation="supports").count(),
            2,
        )
        self.assertTrue(
            self.db.query(AttackSurfaceEdge).filter_by(relation="references").count()
        )

    def test_malformed_recon_numbers_are_bounded_instead_of_aborting_planning(self):
        summary = ResearchService.plan_experiment(
            self.db,
            self.experiment.id,
            recon_signals=[{
                "kind": "client_bundle",
                "script_url": "https://research.test/assets/malformed.js",
                "size_bytes": "not-a-number",
                "counts": {"dom_sinks": "not-a-number", "eval_sinks": float("inf")},
                "client_trust_findings": [{
                    "category": "postmessage_unvalidated_sink",
                    "confidence": "unknown",
                    "offset": "unknown",
                }],
                "property_integrity_chains": [{
                    "kind": "dom_clobbering_chain",
                    "confidence": float("nan"),
                }],
            }],
        )

        assert summary["recon_signals"]["bundles"] == 1
        script = self.db.query(AttackSurfaceNode).filter_by(node_type="client_script").one()
        assert script.attributes["size_bytes"] == 0
        assert script.attributes["counts"]["dom_sinks"] == 0
        assert script.attributes["client_trust_findings"][0]["confidence"] == 0.0

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
