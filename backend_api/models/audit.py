"""Tamper-evident tenant audit events."""
from sqlalchemy import Column, Float, ForeignKey, Integer, JSON, String, event
from sqlalchemy.orm import relationship

from .base import BaseModel


class AuditEvent(BaseModel):
    __tablename__ = "audit_events"

    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=True, index=True)
    request_id = Column(String(64), nullable=False, unique=True, index=True)
    actor = Column(String(160), nullable=False)
    method = Column(String(16), nullable=False)
    path = Column(String(512), nullable=False)
    status_code = Column(Integer, nullable=False)
    duration_ms = Column(Float, nullable=False)
    client_ip_hash = Column(String(64), nullable=True)
    event_type = Column(String(80), nullable=False, default="api_request")
    details = Column(JSON, nullable=True)
    previous_hash = Column(String(64), nullable=False, default="")
    event_hash = Column(String(64), nullable=False, unique=True, index=True)

    tenant = relationship("Tenant", back_populates="audit_events")


@event.listens_for(AuditEvent, "before_update")
@event.listens_for(AuditEvent, "before_delete")
def _reject_orm_mutation(_mapper, _connection, _target):
    raise PermissionError("audit_events is append-only")
