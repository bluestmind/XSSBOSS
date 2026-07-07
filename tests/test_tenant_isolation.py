import unittest
from tempfile import TemporaryDirectory
from unittest.mock import patch

from fastapi import HTTPException

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import backend_api.models  # noqa: F401
import backend_api.tenancy  # noqa: F401 - register session hooks
from backend_api.models.base import BaseModel
from backend_api.models.endpoint import Endpoint
from backend_api.models.execution import Execution, OracleStatus
from backend_api.models.evidence import EvidenceArtifact
from backend_api.models.experiment import Experiment, ExperimentStatus, ExperimentStrategy
from backend_api.models.param import Param
from backend_api.models.research import (
    AttackSurfaceEdge,
    AttackSurfaceNode,
    ResearchHypothesis,
    ResearchObservation,
    ResearchTechniqueStat,
)
from backend_api.models.target import Target, TargetStatus
from backend_api.models.tenant import Tenant
from backend_api.models.test_case import TestCase
from backend_api.config import settings
from backend_api.routers.artifacts import download_artifact
from backend_api.services.evidence_service import EvidenceService


class TenantIsolationTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        BaseModel.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        admin = self.Session()
        self.tenants = [
            Tenant(slug="alpha", name="Alpha"),
            Tenant(slug="beta", name="Beta"),
        ]
        admin.add_all(self.tenants)
        admin.flush()
        self.rows = []
        self.research_ids = []
        for index, tenant in enumerate(self.tenants):
            target = Target(
                tenant_id=tenant.id,
                name=f"target-{index}",
                base_url=f"https://tenant-{index}.test",
                status=TargetStatus.FUZZING,
            )
            admin.add(target)
            admin.flush()
            endpoint = Endpoint(target_id=target.id, method="GET", url_pattern=f"{target.base_url}/?q=")
            admin.add(endpoint)
            admin.flush()
            param = Param(endpoint_id=endpoint.id, name="q", location="query")
            admin.add(param)
            admin.flush()
            experiment = Experiment(
                target_id=target.id,
                name=f"experiment-{index}",
                strategy=ExperimentStrategy.QUICK_LIGHT,
                status=ExperimentStatus.RUNNING,
            )
            admin.add(experiment)
            admin.flush()
            test_case = TestCase(
                experiment_id=experiment.id,
                endpoint_id=endpoint.id,
                param_id=param.id,
                payload="payload",
                token=f"tenant-token-{index}",
            )
            admin.add(test_case)
            admin.flush()
            execution = Execution(test_case_id=test_case.id, oracle_status=OracleStatus.MISSED)
            admin.add(execution)
            admin.flush()
            target_node = AttackSurfaceNode(
                experiment_id=experiment.id,
                node_type="target",
                natural_key=f"target-{index}",
                label=target.base_url,
            )
            endpoint_node = AttackSurfaceNode(
                experiment_id=experiment.id,
                node_type="endpoint",
                natural_key=f"endpoint-{index}",
                label=endpoint.url_pattern,
            )
            admin.add_all([target_node, endpoint_node])
            admin.flush()
            edge = AttackSurfaceEdge(
                experiment_id=experiment.id,
                source_node_id=target_node.id,
                target_node_id=endpoint_node.id,
                relation="exposes",
            )
            hypothesis = ResearchHypothesis(
                experiment_id=experiment.id,
                endpoint_id=endpoint.id,
                fingerprint=f"{index:064x}",
                hypothesis_type="cors",
                title=f"tenant hypothesis {index}",
                rationale="tenant boundary test",
                technique_candidates=["origin-differential"],
            )
            admin.add_all([edge, hypothesis])
            admin.flush()
            observation = ResearchObservation(
                hypothesis_id=hypothesis.id,
                execution_id=execution.id,
                signal_type="test",
                outcome="inconclusive",
            )
            technique_stat = ResearchTechniqueStat(
                tenant_id=tenant.id,
                context_fingerprint="cors:none:no-waf:no-csp",
                technique=f"origin-differential-{index}",
            )
            admin.add_all([observation, technique_stat])
            admin.flush()
            self.rows.append((target, endpoint, param, experiment, test_case, execution))
            self.research_ids.append({
                AttackSurfaceNode: target_node.id,
                AttackSurfaceEdge: edge.id,
                ResearchHypothesis: hypothesis.id,
                ResearchObservation: observation.id,
                ResearchTechniqueStat: technique_stat.id,
            })
        admin.commit()
        self.tenant_ids = [tenant.id for tenant in self.tenants]
        self.row_ids = [tuple(row.id for row in group) for group in self.rows]
        admin.close()

    def tearDown(self):
        self.engine.dispose()

    def _session(self, tenant_index: int):
        db = self.Session()
        db.info["tenant_id"] = self.tenant_ids[tenant_index]
        return db

    def test_every_core_entity_is_hidden_from_other_tenant(self):
        models = (Target, Endpoint, Param, Experiment, TestCase, Execution)
        alpha = self._session(0)
        try:
            for model, own_id, other_id in zip(models, self.row_ids[0], self.row_ids[1]):
                self.assertIsNotNone(alpha.query(model).filter(model.id == own_id).first())
                self.assertIsNone(alpha.query(model).filter(model.id == other_id).first())
                self.assertEqual(alpha.query(model).count(), 1)
        finally:
            alpha.close()

    def test_cross_tenant_update_is_filtered(self):
        alpha = self._session(0)
        try:
            changed = alpha.query(Target).filter(Target.id == self.row_ids[1][0]).update(
                {Target.name: "stolen"}, synchronize_session=False
            )
            alpha.commit()
            self.assertEqual(changed, 0)
        finally:
            alpha.close()

        admin = self.Session()
        try:
            self.assertEqual(admin.query(Target).filter_by(id=self.row_ids[1][0]).one().name, "target-1")
        finally:
            admin.close()

    def test_research_graph_learning_and_observations_are_tenant_scoped(self):
        alpha = self._session(0)
        try:
            for model in (
                AttackSurfaceNode,
                AttackSurfaceEdge,
                ResearchHypothesis,
                ResearchObservation,
                ResearchTechniqueStat,
            ):
                own_id = self.research_ids[0][model]
                other_id = self.research_ids[1][model]
                self.assertIsNotNone(alpha.query(model).filter(model.id == own_id).first())
                self.assertIsNone(alpha.query(model).filter(model.id == other_id).first())
            self.assertEqual(alpha.query(ResearchHypothesis).count(), 1)
            self.assertEqual(alpha.query(ResearchObservation).count(), 1)
            self.assertEqual(alpha.query(ResearchTechniqueStat).count(), 1)
        finally:
            alpha.close()

    def test_new_target_is_forced_to_authenticated_tenant(self):
        alpha = self._session(0)
        try:
            target = Target(
                name="new-alpha",
                base_url="https://new-alpha.test",
                status=TargetStatus.RECON_ONLY,
            )
            alpha.add(target)
            alpha.commit()
            self.assertEqual(target.tenant_id, self.tenant_ids[0])

            forbidden = Target(
                tenant_id=self.tenant_ids[1],
                name="cross-tenant",
                base_url="https://cross.test",
                status=TargetStatus.RECON_ONLY,
            )
            alpha.add(forbidden)
            with self.assertRaises(PermissionError):
                alpha.commit()
            alpha.rollback()
        finally:
            alpha.close()

    def test_artifact_download_is_hash_verified_and_tenant_scoped(self):
        with TemporaryDirectory() as evidence_dir, patch.object(settings, "EVIDENCE_DIR", evidence_dir):
            admin = self.Session()
            own = EvidenceService.register_bytes(
                admin, self.row_ids[0][3], None, "campaign_report_html", b"alpha report"
            )
            other = EvidenceService.register_bytes(
                admin, self.row_ids[1][3], None, "campaign_report_html", b"beta report"
            )
            own_id, other_id, own_hash = own.id, other.id, own.sha256
            admin.close()

            alpha = self._session(0)
            try:
                response = download_artifact(own_id, alpha)
                self.assertTrue(str(response.path).startswith(evidence_dir))
                self.assertEqual(response.headers["etag"], f'"{own_hash}"')
                with self.assertRaises(HTTPException) as denied:
                    download_artifact(other_id, alpha)
                self.assertEqual(denied.exception.status_code, 404)

                artifact = alpha.query(EvidenceArtifact).filter_by(id=own_id).one()
                artifact.sha256 = "0" * 64
                alpha.commit()
                with self.assertRaises(HTTPException) as tampered:
                    download_artifact(own_id, alpha)
                self.assertEqual(tampered.exception.status_code, 409)
            finally:
                alpha.close()


if __name__ == "__main__":
    unittest.main()
