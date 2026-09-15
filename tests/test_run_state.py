import unittest
from datetime import UTC, datetime, timedelta
import hashlib
import json
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
from backend_api.models.finding import Finding, FindingStatus, Severity
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
from backend_api.utils.response_security import analyze_response


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


def _raw_causal_lineage() -> dict:
    source_fingerprint = "deadbeef" * 8
    sink_fingerprint = "e" * 64
    return {
        "schema_version": "runtime-causal-lineage/v1",
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
        "summary": {
            "events_seen": 2,
            "events_accepted": 2,
            "events_rejected": 0,
            "observations_seen": 0,
            "observations_accepted": 0,
            "observations_rejected": 0,
            "candidates": 1,
            "causal_only": 1,
            "value_influence": 0,
        },
        "causal_flows": [{
            "candidate_id": _runtime_candidate_id(
                "location_hash", source_fingerprint, "innerhtml", sink_fingerprint
            ),
            "classification": "causal_only",
            "source_id": "RAW-SOURCE-ID-SECRET",
            "source_category": "location_hash",
            "source_fingerprint": source_fingerprint,
            "sink_id": "RAW-SINK-ID-SECRET",
            "sink_category": "innerhtml",
            "sink_fingerprint": sink_fingerprint,
            "relation": "direct",
            "depth": 1,
            "latency_ms": 1,
        }],
        "value_influences": [],
    }


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

    def test_progress_heartbeat_is_persisted_capped_and_monotonic(self):
        for index in range(85):
            event = RunStateService.record_progress(
                self.db,
                self.experiment.id,
                phase="browser",
                tool="Chromium",
                message=f"Executing payload {index + 1}",
                completed=index + 1,
                total=85,
                overall_percent=55 + index,
            )

        self.db.refresh(self.experiment)
        live = self.experiment.limits["live_progress"]
        history = self.experiment.limits["progress_history"]
        self.assertEqual(event["sequence"], 85)
        self.assertEqual(live["sequence"], 85)
        self.assertEqual(live["overall_percent"], 100.0)
        self.assertEqual(len(history), 80)
        self.assertEqual(history[0]["sequence"], 6)
        self.assertEqual(history[-1]["message"], "Executing payload 85")

    def test_monitor_handles_sqlite_timestamps_with_progress_heartbeat(self):
        from backend_api.routers.experiments import get_experiment_monitor

        RunStateService.ensure_pipeline(self.db, self.experiment.id)
        RunStateService.record_progress(
            self.db,
            self.experiment.id,
            phase="profiling",
            tool="context profiler",
            message="Classifying reflection context",
            completed=1,
            total=2,
            overall_percent=45,
        )

        monitor = get_experiment_monitor(self.experiment.id, self.db)

        self.assertEqual(monitor["live_progress"]["tool"], "context profiler")
        self.assertEqual(monitor["stage"], "profiling")
        self.assertGreaterEqual(monitor["elapsed_seconds"], 0)
        self.assertFalse(monitor["progress_stale"])

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
            attempt_no=1,
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
            result={
                "status_code": 200,
                "headers": {"content-type": "text/html"},
                "oracle_hit": True,
                "logs": {
                    "response_posture": {
                        **analyze_response(
                            url="https://owned.test/account?token=secret",
                            status_code=200,
                            headers={"Content-Security-Policy": "default-src 'self'"},
                        ),
                        "nested_evidence": {
                            "runtime_lineage": {
                                "raw_value": "RESULT-SUBARTIFACT-RAW-LINEAGE-8D20",
                            },
                        },
                    },
                    "runtime_code_coverage": {
                        "schema_version": "runtime-code-coverage/v1",
                        "available": True,
                        "summary": {"scripts_analyzed": 1, "runtime_reached_sites": 1},
                        "scripts": [{
                            "url": "https://owned.test/app.js",
                            "source_fingerprint": "a" * 64,
                        }],
                        "findings": [],
                        "nested_evidence": {
                            "runtime_lineage": {
                                "raw_value": "RESULT-SUBARTIFACT-RAW-LINEAGE-8D20",
                            },
                        },
                    },
                    "runtime_lineage": {
                        "schema_version": "runtime-causal-lineage/v1",
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
                        "summary": {
                            "events_seen": 2,
                            "events_accepted": 2,
                            "events_rejected": 0,
                            "observations_seen": 0,
                            "observations_accepted": 0,
                            "observations_rejected": 0,
                            "candidates": 1,
                            "causal_only": 1,
                            "value_influence": 0,
                        },
                        "causal_flows": [{
                            "candidate_id": _runtime_candidate_id(
                                "location_hash", "d" * 64, "innerhtml", "e" * 64
                            ),
                            "classification": "causal_only",
                            "source_id": "source:1",
                            "source_category": "location_hash",
                            "source_fingerprint": "d" * 64,
                            "sink_id": "sink:1",
                            "sink_category": "innerhtml",
                            "sink_fingerprint": "e" * 64,
                            "relation": "direct",
                            "depth": 1,
                            "latency_ms": 1,
                            "raw_value": "lineage-secret-must-not-survive",
                        }],
                        "value_influences": [],
                    },
                    "dom_marker_differential": {
                        "schema_version": "dom-marker-differential/v1",
                        "available": True,
                        "differential_available": True,
                        "summary": {"new_marker_sites": 1},
                        "sites": [{
                            "context": "text",
                            "structural_path_fingerprint": "b" * 64,
                        }],
                        "nested_evidence": {
                            "runtime_lineage": {
                                "raw_value": "RESULT-SUBARTIFACT-RAW-LINEAGE-8D20",
                            },
                        },
                    },
                },
            },
        )
        second = EvidenceService.register_execution(self.db, execution)

        self.assertEqual(len(first[0].sha256), 64)
        self.assertIn(second[0].sha256, {artifact.sha256 for artifact in first})
        self.assertEqual(self.db.query(EvidenceArtifact).count(), 8)
        verification = EvidenceService.verify_all(self.db)
        self.assertTrue(verification["passed"])
        request_artifact = self.db.query(EvidenceArtifact).filter_by(kind="request").one()
        request_content = (Path(settings.EVIDENCE_DIR) / request_artifact.uri).read_text(encoding="utf-8")
        self.assertNotIn("Bearer secret", request_content)
        self.assertNotIn('"session":"secret"', request_content)
        posture_artifact = self.db.query(EvidenceArtifact).filter_by(kind="response_posture").one()
        posture_content = (Path(settings.EVIDENCE_DIR) / posture_artifact.uri).read_text(encoding="utf-8")
        self.assertNotIn("token=secret", posture_content)
        self.assertIn("response-security-posture/v1", posture_content)
        runtime_artifact = self.db.query(EvidenceArtifact).filter_by(
            kind="runtime_code_coverage"
        ).one()
        runtime_content = (Path(settings.EVIDENCE_DIR) / runtime_artifact.uri).read_text(
            encoding="utf-8"
        )
        self.assertIn("runtime-code-coverage/v1", runtime_content)
        self.assertTrue(runtime_artifact.artifact_metadata["source_free"])
        lineage_artifact = self.db.query(EvidenceArtifact).filter_by(
            kind="runtime_lineage"
        ).one()
        lineage_content = (
            Path(settings.EVIDENCE_DIR) / lineage_artifact.uri
        ).read_text(encoding="utf-8")
        self.assertIn("runtime-causal-lineage/v1", lineage_content)
        self.assertNotIn("lineage-secret-must-not-survive", lineage_content)
        self.assertTrue(lineage_artifact.artifact_metadata["value_free"])
        differential_artifact = self.db.query(EvidenceArtifact).filter_by(
            kind="dom_marker_differential"
        ).one()
        differential_content = (
            Path(settings.EVIDENCE_DIR) / differential_artifact.uri
        ).read_text(encoding="utf-8")
        self.assertIn("dom-marker-differential/v1", differential_content)
        self.assertTrue(differential_artifact.artifact_metadata["content_free"])
        for artifact_content in (
            posture_content,
            runtime_content,
            differential_content,
        ):
            self.assertNotIn(
                "RESULT-SUBARTIFACT-RAW-LINEAGE-8D20",
                artifact_content,
            )

    def test_legacy_raw_lineage_is_sanitized_across_read_and_evidence_paths(self):
        from backend_api.routers.experiments import (
            get_experiment_audit,
            get_experiment_monitor,
        )
        from backend_api.routers.results import _safe_execution_response

        test_case = TestCase(
            experiment_id=self.experiment.id,
            endpoint_id=self.endpoint.id,
            param_id=self.param.id,
            payload="legacy",
            token="legacy-lineage-token",
        )
        self.db.add(test_case)
        self.db.flush()
        execution = Execution(
            test_case_id=test_case.id,
            attempt_no=1,
            oracle_status=OracleStatus.MISSED,
            logs=json.dumps({
                "console": ["keep"],
                "runtime_lineage": _raw_causal_lineage(),
            }),
        )
        self.db.add(execution)
        self.db.commit()
        RunStateService.ensure_pipeline(self.db, self.experiment.id)

        monitor = get_experiment_monitor(self.experiment.id, self.db)
        row = next(
            item for item in monitor["recent_executions"]
            if item["id"] == execution.id
        )
        result_row = _safe_execution_response(execution)
        audit = get_experiment_audit(self.experiment.id, self.db)
        audit_execution = next(
            item
            for case in audit["test_cases"]
            if case["id"] == test_case.id
            for item in case["executions"]
            if item["id"] == execution.id
        )
        EvidenceService.register_execution(self.db, execution)
        artifact = self.db.query(EvidenceArtifact).filter_by(
            execution_id=execution.id,
            kind="execution_log",
        ).one()
        artifact_text = (Path(settings.EVIDENCE_DIR) / artifact.uri).read_text(
            encoding="utf-8"
        )

        combined = "\n".join((
            row["raw_logs"],
            result_row["logs"],
            json.dumps(audit_execution["logs"]),
            artifact_text,
        ))
        assert "RAW-SOURCE-ID-SECRET" not in combined
        assert "RAW-SINK-ID-SECRET" not in combined
        assert "deadbeef" * 8 not in combined
        assert row["runtime_lineage"]["summary"]["causal_only"] == 1
        assert "projection_version" in row["runtime_lineage"]

    def test_non_mapping_lineage_text_is_omitted_from_all_fallback_surfaces(self):
        from backend_api.routers.experiments import (
            get_experiment_audit,
            get_experiment_monitor,
        )
        from backend_api.routers.results import _safe_execution_response

        secret = "MALFORMED-LINEAGE-SECRET"
        non_mapping = json.dumps([{
            "runtime_lineage": {
                "classification": "value_influence",
                "raw_value": secret,
            },
        }])
        test_case = TestCase(
            experiment_id=self.experiment.id,
            endpoint_id=self.endpoint.id,
            param_id=self.param.id,
            payload="malformed-lineage",
            token="malformed-lineage-token",
        )
        self.db.add(test_case)
        self.db.flush()
        execution = Execution(
            test_case_id=test_case.id,
            attempt_no=1,
            oracle_status=OracleStatus.HIT,
            logs=non_mapping,
        )
        finding = Finding(
            endpoint_id=self.endpoint.id,
            param_id=self.param.id,
            best_payload=test_case.payload,
            severity=Severity.HIGH,
            status=FindingStatus.CONFIRMED,
            evidence_refs={"test_case_id": test_case.id},
        )
        self.db.add_all((execution, finding))
        self.db.commit()
        RunStateService.ensure_pipeline(self.db, self.experiment.id)

        monitor = get_experiment_monitor(self.experiment.id, self.db)
        monitor_execution = next(
            item for item in monitor["recent_executions"]
            if item["id"] == execution.id
        )
        monitor_finding = next(
            item for item in monitor["recent_findings"]
            if item["id"] == finding.id
        )
        result_row = _safe_execution_response(execution)
        audit = get_experiment_audit(self.experiment.id, self.db)
        audit_execution = next(
            item
            for case in audit["test_cases"]
            if case["id"] == test_case.id
            for item in case["executions"]
            if item["id"] == execution.id
        )
        EvidenceService.register_execution(self.db, execution)
        artifact = self.db.query(EvidenceArtifact).filter_by(
            execution_id=execution.id,
            kind="execution_log",
        ).one()
        artifact_text = (Path(settings.EVIDENCE_DIR) / artifact.uri).read_text(
            encoding="utf-8"
        )

        combined = json.dumps({
            "monitor_execution": monitor_execution,
            "monitor_finding": monitor_finding,
            "result": result_row["logs"],
            "audit": audit_execution["logs"],
            "artifact": artifact_text,
        }, default=str)
        assert secret not in combined
        assert "unparsed execution log omitted" in combined

    def test_nested_and_case_variant_lineage_is_removed_from_all_surfaces(self):
        from backend_api.routers.experiments import (
            get_experiment_audit,
            get_experiment_monitor,
        )
        from backend_api.routers.results import _safe_execution_response

        secrets = (
            "NESTED-LINEAGE-SECRET",
            "CASE-VARIANT-LINEAGE-SECRET",
            "ROOT-CASE-LINEAGE-SECRET",
        )
        nested_logs = json.dumps({
            "errors": [{
                "message": "keep",
                "runtime_lineage": {
                    "classification": "value_influence",
                    "raw_value": secrets[0],
                },
            }],
            "nested": {
                "RUNTIME_CAUSAL_LINEAGE": {
                    "classification": "value_influence",
                    "raw_value": secrets[1],
                },
            },
            "Runtime_Lineage": {
                "classification": "value_influence",
                "raw_value": secrets[2],
            },
        })
        test_case = TestCase(
            experiment_id=self.experiment.id,
            endpoint_id=self.endpoint.id,
            param_id=self.param.id,
            payload="nested-lineage",
            token="nested-lineage-token",
        )
        self.db.add(test_case)
        self.db.flush()
        execution = Execution(
            test_case_id=test_case.id,
            attempt_no=1,
            oracle_status=OracleStatus.HIT,
            logs=nested_logs,
        )
        finding = Finding(
            endpoint_id=self.endpoint.id,
            param_id=self.param.id,
            best_payload=test_case.payload,
            severity=Severity.HIGH,
            status=FindingStatus.CONFIRMED,
            evidence_refs={"test_case_id": test_case.id},
        )
        self.db.add_all((execution, finding))
        self.db.commit()
        RunStateService.ensure_pipeline(self.db, self.experiment.id)

        monitor = get_experiment_monitor(self.experiment.id, self.db)
        monitor_execution = next(
            item for item in monitor["recent_executions"]
            if item["id"] == execution.id
        )
        monitor_finding = next(
            item for item in monitor["recent_findings"]
            if item["id"] == finding.id
        )
        result_row = _safe_execution_response(execution)
        audit = get_experiment_audit(self.experiment.id, self.db)
        audit_execution = next(
            item
            for case in audit["test_cases"]
            if case["id"] == test_case.id
            for item in case["executions"]
            if item["id"] == execution.id
        )
        EvidenceService.register_execution(self.db, execution)
        artifact = self.db.query(EvidenceArtifact).filter_by(
            execution_id=execution.id,
            kind="execution_log",
        ).one()
        artifact_text = (Path(settings.EVIDENCE_DIR) / artifact.uri).read_text(
            encoding="utf-8"
        )

        combined = json.dumps({
            "monitor_execution": monitor_execution,
            "monitor_finding": monitor_finding,
            "result": result_row["logs"],
            "audit": audit_execution["logs"],
            "artifact": artifact_text,
        }, default=str)
        for secret in secrets:
            assert secret not in combined
        assert "keep" in combined

    def test_legacy_bytes_lineage_keys_are_removed_from_audit_and_artifact(self):
        from backend_api.routers.experiments import get_experiment_audit

        secret = "BYTES-KEY-RAW-VALUE-7C2A"
        legacy_logs = repr({
            "console": ["keep"],
            b"runtime_lineage": {
                "classification": "value_influence",
                "raw_value": secret,
            },
            "nested": {
                b"runtime_causal_lineage": {
                    "classification": "value_influence",
                    "raw_value": f"{secret}-NESTED",
                },
            },
        })
        test_case = TestCase(
            experiment_id=self.experiment.id,
            endpoint_id=self.endpoint.id,
            param_id=self.param.id,
            payload="bytes-key-lineage",
            token="bytes-key-lineage-token",
        )
        self.db.add(test_case)
        self.db.flush()
        execution = Execution(
            test_case_id=test_case.id,
            attempt_no=1,
            oracle_status=OracleStatus.MISSED,
            logs=legacy_logs,
        )
        self.db.add(execution)
        self.db.commit()

        audit = get_experiment_audit(self.experiment.id, self.db)
        audit_execution = next(
            item
            for case in audit["test_cases"]
            if case["id"] == test_case.id
            for item in case["executions"]
            if item["id"] == execution.id
        )
        EvidenceService.register_execution(self.db, execution)
        artifact = self.db.query(EvidenceArtifact).filter_by(
            execution_id=execution.id,
            kind="execution_log",
        ).one()
        artifact_text = (Path(settings.EVIDENCE_DIR) / artifact.uri).read_text(
            encoding="utf-8"
        )

        combined = json.dumps({
            "audit": audit_execution["logs"],
            "artifact": artifact_text,
        }, default=str)
        assert secret not in combined
        assert "keep" in combined

    def test_micro_state_and_river_flow_snapshot(self):
        # 1. Record progress with micro-state
        progress_event = RunStateService.record_progress(
            self.db,
            self.experiment.id,
            phase="contexts",
            tool="reflection engine",
            message="Found reflection in ATTRIBUTE_VALUE",
            doing_status="Context Confluence: Probing parameter 'q'",
            micro_state={"action": "reflection", "param": "q", "result": "reflected"},
            river_stage="contexts",
        )
        self.assertIsNotNone(progress_event)
        self.assertEqual(progress_event["doing_status"], "Context Confluence: Probing parameter 'q'")
        self.assertEqual(progress_event["river_stage"], "contexts")

        # 2. Record granular micro-steps
        micro_step = RunStateService.record_micro_step(
            self.db,
            self.experiment.id,
            title="Filter test on 'q'",
            river_stage="filters",
            action="waf_profiling",
            status="success",
            outcome="allowed",
            endpoint="https://example.com/search",
            param="q",
        )
        self.assertIsNotNone(micro_step)
        self.assertEqual(micro_step["river_stage"], "filters")

        # 3. Verify snapshot
        snapshot = RunStateService.get_river_flow_snapshot(self.db, self.experiment.id)
        self.assertIn("milestones", snapshot)
        self.assertEqual(len(snapshot["milestones"]), 8)
        self.assertIn("doing_status", snapshot)
        self.assertEqual(snapshot["current_stage"], "filters")


if __name__ == "__main__":
    unittest.main()
