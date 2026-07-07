"""Tenant boundary and per-tenant operational policy."""
from sqlalchemy import Boolean, Column, Integer, JSON, String
from sqlalchemy.orm import relationship

from .base import BaseModel


class Tenant(BaseModel):
    __tablename__ = "tenants"

    slug = Column(String(80), nullable=False, unique=True, index=True)
    name = Column(String(255), nullable=False)
    api_token_hash = Column(String(64), nullable=True, unique=True, index=True)
    is_active = Column(Boolean, nullable=False, default=True)
    quotas = Column(JSON, nullable=True)
    retention_days = Column(Integer, nullable=False, default=90)

    targets = relationship("Target", back_populates="tenant")
    audit_events = relationship("AuditEvent", back_populates="tenant")
