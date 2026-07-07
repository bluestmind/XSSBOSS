import unittest
from unittest.mock import patch
from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import backend_api.models  # noqa: F401
import backend_api.tenancy  # noqa: F401 - register tenant session hooks
from backend_api.config import settings
from backend_api.models.audit import AuditEvent
from backend_api.models.base import BaseModel
from backend_api.models.tenant import Tenant
from backend_api.models.target import Target, TargetStatus
from backend_api.models.experiment import Experiment, ExperimentStatus, ExperimentStrategy
from backend_api.services.audit_service import AuditService
from backend_api.services.retention_service import RetentionService
from backend_api.services.tenant_service import TenantService


class TenantOperationsTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        BaseModel.metadata.create_all(self.engine)
        self.db = sessionmaker(bind=self.engine)()
        self.tenant = Tenant(slug="audit-tenant", name="Audit Tenant")
        self.db.add(self.tenant)
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def test_audit_chain_is_valid_and_orm_append_only(self):
        first = AuditService.record(
            self.db,
            tenant_id=self.tenant.id,
            request_id="request-1",
            actor="audit-tenant",
            method="POST",
            path="/api/v1/scans/",
            status_code=201,
            duration_ms=12.3456,
            client_ip="127.0.0.1",
        )
        second = AuditService.record(
            self.db,
            tenant_id=self.tenant.id,
            request_id="request-2",
            actor="audit-tenant",
            method="GET",
            path="/api/v1/targets/",
            status_code=200,
            duration_ms=4.2,
        )

        self.assertEqual(second.previous_hash, first.event_hash)
        self.assertEqual(AuditService.verify_chain(self.db, self.tenant.id)["checked"], 2)
        first.path = "/tampered"
        with self.assertRaises(PermissionError):
            self.db.commit()
        self.db.rollback()

    def test_configured_tenant_tokens_are_hashed_and_authenticate(self):
        token = "tenant-token-with-more-than-thirty-two-characters"
        with (
            patch.object(settings, "API_AUTH_TOKEN", None),
            patch.object(settings, "TENANT_API_TOKENS", '{"customer-a":"' + token + '"}'),
        ):
            TenantService.provision_configured(self.db)
            tenant = TenantService.authenticate(self.db, token)

        self.assertIsNotNone(tenant)
        self.assertEqual(tenant.slug, "customer-a")
        self.assertNotEqual(tenant.api_token_hash, token)
        self.assertEqual(len(tenant.api_token_hash), 64)
        self.assertIsNone(TenantService.authenticate(self.db, "wrong-token"))

    def test_tenant_scoped_session_filters_audit_events(self):
        other = Tenant(slug="other", name="Other")
        self.db.add(other)
        self.db.commit()
        AuditService.record(
            self.db, tenant_id=self.tenant.id, request_id="own", actor="own",
            method="GET", path="/own", status_code=200, duration_ms=1,
        )
        AuditService.record(
            self.db, tenant_id=other.id, request_id="other", actor="other",
            method="GET", path="/other", status_code=200, duration_ms=1,
        )
        self.db.info["tenant_id"] = self.tenant.id

        self.assertEqual(self.db.query(AuditEvent).count(), 1)
        self.assertEqual(self.db.query(AuditEvent).one().request_id, "own")

    def test_retention_deletes_only_expired_terminal_runs_and_keeps_audit(self):
        self.tenant.retention_days = 1
        target = Target(
            tenant_id=self.tenant.id,
            name="retention-target",
            base_url="https://retention.test",
            status=TargetStatus.DONE,
        )
        self.db.add(target)
        self.db.flush()
        old = Experiment(
            target_id=target.id,
            name="expired",
            strategy=ExperimentStrategy.QUICK_LIGHT,
            status=ExperimentStatus.COMPLETED,
            completed_at=datetime.now(UTC) - timedelta(days=2),
        )
        current = Experiment(
            target_id=target.id,
            name="current",
            strategy=ExperimentStrategy.QUICK_LIGHT,
            status=ExperimentStatus.COMPLETED,
            completed_at=datetime.now(UTC),
        )
        self.db.add_all([old, current])
        self.db.commit()
        AuditService.record(
            self.db, tenant_id=self.tenant.id, request_id="retention-audit",
            actor="audit-tenant", method="DELETE", path="/retention",
            status_code=200, duration_ms=1,
        )

        dry_run = RetentionService.sweep(self.db, apply=False)
        applied = RetentionService.sweep(self.db, apply=True)

        self.assertEqual(dry_run["candidate_runs"], 1)
        self.assertEqual(applied["deleted_runs"], 1)
        self.assertEqual(self.db.query(Experiment).filter_by(name="current").count(), 1)
        self.assertEqual(self.db.query(Experiment).filter_by(name="expired").count(), 0)
        self.assertEqual(self.db.query(AuditEvent).filter_by(request_id="retention-audit").count(), 1)


if __name__ == "__main__":
    unittest.main()
