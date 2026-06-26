"""Test case model."""
from sqlalchemy import Column, String, Text, Integer, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import relationship
import enum
from .base import BaseModel


class TestCaseStatus(str, enum.Enum):
    """Test case status enum."""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class TestCase(BaseModel):
    """Test case model."""
    
    __tablename__ = "test_cases"
    
    experiment_id = Column(Integer, ForeignKey("experiments.id", ondelete="CASCADE"), nullable=False, index=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True)
    param_id = Column(Integer, ForeignKey("params.id", ondelete="CASCADE"), nullable=False, index=True)
    context_id = Column(Integer, ForeignKey("contexts.id", ondelete="CASCADE"), nullable=True, index=True)
    payload = Column(Text, nullable=False)
    token = Column(String(64), nullable=False, unique=True, index=True)  # Unique token for Oracle
    priority = Column(Integer, default=0, nullable=False)  # Higher = more important
    status = Column(SQLEnum(TestCaseStatus), default=TestCaseStatus.PENDING, nullable=False)
    
    # Relationships
    experiment = relationship("Experiment", back_populates="test_cases")
    endpoint = relationship("Endpoint", back_populates="test_cases")
    param = relationship("Param", back_populates="test_cases")
    context = relationship("Context", back_populates="test_cases")
    executions = relationship("Execution", back_populates="test_case", cascade="all, delete-orphan")
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        return f"<TestCase(id={self.id}, payload='{self.payload[:30]}...', status='{self.status.value}')>"
