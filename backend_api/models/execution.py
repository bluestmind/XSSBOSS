"""Execution model."""
from sqlalchemy import Column, String, Text, Integer, ForeignKey, DateTime, Enum as SQLEnum, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum
from .base import BaseModel


class OracleStatus(str, enum.Enum):
    """Oracle status enum."""
    HIT = "hit"
    MISSED = "missed"
    ERROR = "error"


class Execution(BaseModel):
    """Execution result model."""
    
    __tablename__ = "executions"
    __table_args__ = (
        UniqueConstraint("test_case_id", "attempt_no", name="uq_execution_attempt"),
    )
    
    test_case_id = Column(Integer, ForeignKey("test_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    browser_worker_id = Column(String(100), nullable=True)
    oracle_status = Column(SQLEnum(OracleStatus), nullable=False)
    oracle_token = Column(String(64), nullable=True)
    logs = Column(Text, nullable=True)
    screenshot_path = Column(String(512), nullable=True)
    dom_snapshot = Column(Text, nullable=True)
    executed_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    duration_ms = Column(Integer, nullable=True)  # Execution duration in milliseconds
    # NULL retains compatibility for legacy/manual records. Browser deliveries
    # always set both fields, giving retries an enforceable idempotency contract.
    attempt_no = Column(Integer, nullable=True)
    idempotency_key = Column(String(180), nullable=True, unique=True, index=True)
    
    # Relationships
    test_case = relationship("TestCase", back_populates="executions")
    evidence_artifacts = relationship("EvidenceArtifact", back_populates="execution")
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        return f"<Execution(id={self.id}, test_case_id={self.test_case_id}, oracle_status='{self.oracle_status.value}')>"
