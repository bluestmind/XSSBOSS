"""Append-only, hash-chained API audit log."""
import hashlib
import json

from sqlalchemy.orm import Session

from backend_api.models.audit import AuditEvent
from backend_api.models.tenant import Tenant


class AuditService:
    @staticmethod
    def _hash(payload: dict) -> str:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def record(
        db: Session,
        *,
        tenant_id: int,
        request_id: str,
        actor: str,
        method: str,
        path: str,
        status_code: int,
        duration_ms: float,
        client_ip: str | None = None,
        event_type: str = "api_request",
        details: dict | None = None,
    ) -> AuditEvent:
        existing = db.query(AuditEvent).filter(AuditEvent.request_id == request_id).first()
        if existing is not None:
            return existing
        # Serialize each tenant's hash-chain head. SELECT FOR UPDATE is a real
        # row lock in PostgreSQL and harmless in SQLite tests.
        db.query(Tenant).filter(Tenant.id == tenant_id).with_for_update().one()
        previous = (
            db.query(AuditEvent)
            .filter(AuditEvent.tenant_id == tenant_id)
            .order_by(AuditEvent.id.desc())
            .first()
        )
        previous_hash = previous.event_hash if previous else ""
        client_ip_hash = hashlib.sha256(client_ip.encode("utf-8")).hexdigest() if client_ip else None
        hash_payload = {
            "tenant_id": tenant_id,
            "request_id": request_id,
            "actor": actor,
            "method": method,
            "path": path,
            "status_code": status_code,
            "duration_ms": round(duration_ms, 3),
            "client_ip_hash": client_ip_hash,
            "event_type": event_type,
            "details": details,
            "previous_hash": previous_hash,
        }
        event = AuditEvent(
            **hash_payload,
            event_hash=AuditService._hash(hash_payload),
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event

    @staticmethod
    def enqueue(**event) -> None:
        """Durably enqueue audit persistence outside request latency."""
        from backend_api.task_queue import task_app

        task_app.send_task(
            "append_audit_event",
            kwargs=event,
            queue="audit",
            ignore_result=True,
        )

    @staticmethod
    def verify_chain(db: Session, tenant_id: int) -> dict:
        previous_hash = ""
        checked = 0
        for event in db.query(AuditEvent).filter(
            AuditEvent.tenant_id == tenant_id
        ).order_by(AuditEvent.id).all():
            payload = {
                "tenant_id": event.tenant_id,
                "request_id": event.request_id,
                "actor": event.actor,
                "method": event.method,
                "path": event.path,
                "status_code": event.status_code,
                "duration_ms": round(event.duration_ms, 3),
                "client_ip_hash": event.client_ip_hash,
                "event_type": event.event_type,
                "details": event.details,
                "previous_hash": event.previous_hash,
            }
            if event.previous_hash != previous_hash or event.event_hash != AuditService._hash(payload):
                return {"passed": False, "checked": checked, "failed_event_id": event.id}
            previous_hash = event.event_hash
            checked += 1
        return {"passed": True, "checked": checked, "head": previous_hash}
