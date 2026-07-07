"""Test case model."""
from sqlalchemy import Column, String, Text, Integer, ForeignKey, Enum as SQLEnum, DateTime, JSON
from sqlalchemy.orm import relationship
import enum
from datetime import datetime, timedelta, UTC
from .base import BaseModel


class TestCaseStatus(str, enum.Enum):
    """Test case status enum."""
    __test__ = False
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class TestCase(BaseModel):
    """Test case model."""
    __test__ = False
    
    __tablename__ = "test_cases"
    
    experiment_id = Column(Integer, ForeignKey("experiments.id", ondelete="CASCADE"), nullable=False, index=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True)
    param_id = Column(Integer, ForeignKey("params.id", ondelete="CASCADE"), nullable=False, index=True)
    context_id = Column(Integer, ForeignKey("contexts.id", ondelete="CASCADE"), nullable=True, index=True)
    payload = Column(Text, nullable=False)
    token = Column(String(64), nullable=False, unique=True, index=True)  # Unique token for Oracle
    priority = Column(Integer, default=0, nullable=False)  # Higher = more important
    status = Column(SQLEnum(TestCaseStatus), default=TestCaseStatus.PENDING, nullable=False)
    token_expires_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC) + timedelta(hours=24), nullable=True)
    token_consumed_at = Column(DateTime(timezone=True), nullable=True)
    # A Celery acknowledgement is not an execution lock. These fields let a
    # redelivered task reclaim work after a browser process dies mid-run while
    # preventing concurrent workers from executing the same case.
    lease_owner = Column(String(120), nullable=True, index=True)
    lease_expires_at = Column(DateTime(timezone=True), nullable=True, index=True)
    first_claimed_at = Column(DateTime(timezone=True), nullable=True, index=True)
    attempt_count = Column(Integer, default=0, nullable=False)
    research_hypothesis_id = Column(Integer, ForeignKey("research_hypotheses.id", ondelete="SET NULL"), nullable=True, index=True)
    technique = Column(String(80), nullable=True, index=True)
    research_metadata = Column(JSON, nullable=True)
    
    # Relationships
    experiment = relationship("Experiment", back_populates="test_cases")
    endpoint = relationship("Endpoint", back_populates="test_cases")
    param = relationship("Param", back_populates="test_cases")
    context = relationship("Context", back_populates="test_cases")
    executions = relationship("Execution", back_populates="test_case", cascade="all, delete-orphan")
    research_hypothesis = relationship("ResearchHypothesis", back_populates="test_cases")
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        return f"<TestCase(id={self.id}, payload='{self.payload[:30]}...', status='{self.status.value}')>"
