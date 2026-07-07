"""Durable ownership and pipeline state for scan runs."""
import enum

from sqlalchemy import (
    Column,
    DateTime,
    Enum as SQLEnum,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from .base import BaseModel


class RunStageName(str, enum.Enum):
    RECON = "recon"
    PROFILING = "profiling"
    EXECUTION = "execution"
    CORRELATION = "correlation"
    REPORTING = "reporting"


class RunStageStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class RunEndpoint(BaseModel):
    """An endpoint observed by one run, independent of shared target inventory."""

    __tablename__ = "run_endpoints"
    __table_args__ = (
        UniqueConstraint("experiment_id", "endpoint_id", name="uq_run_endpoint"),
    )

    experiment_id = Column(
        Integer, ForeignKey("experiments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    endpoint_id = Column(
        Integer, ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    discovery_source = Column(String(80), nullable=False, default="unknown")

    experiment = relationship("Experiment", back_populates="run_endpoints")
    endpoint = relationship("Endpoint", back_populates="run_memberships")


class FindingObservation(BaseModel):
    """A run-scoped observation of a deduplicated global finding."""

    __tablename__ = "finding_observations"
    __table_args__ = (
        UniqueConstraint("experiment_id", "finding_id", name="uq_run_finding"),
    )

    experiment_id = Column(
        Integer, ForeignKey("experiments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id = Column(
        Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    test_case_id = Column(
        Integer, ForeignKey("test_cases.id", ondelete="SET NULL"), nullable=True, index=True
    )
    execution_id = Column(
        Integer, ForeignKey("executions.id", ondelete="SET NULL"), nullable=True, index=True
    )
    evidence = Column(JSON, nullable=True)

    experiment = relationship("Experiment", back_populates="finding_observations")
    finding = relationship("Finding", back_populates="observations")
    test_case = relationship("TestCase")
    execution = relationship("Execution")


class RunStage(BaseModel):
    """A restart-safe state machine checkpoint for one pipeline stage."""

    __tablename__ = "run_stages"
    __table_args__ = (
        UniqueConstraint("experiment_id", "name", name="uq_run_stage"),
    )

    experiment_id = Column(
        Integer, ForeignKey("experiments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name = Column(SQLEnum(RunStageName), nullable=False)
    status = Column(
        SQLEnum(RunStageStatus), nullable=False, default=RunStageStatus.PENDING, index=True
    )
    attempt_count = Column(Integer, nullable=False, default=0)
    lease_owner = Column(String(160), nullable=True)
    lease_expires_at = Column(DateTime(timezone=True), nullable=True, index=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error = Column(Text, nullable=True)
    output = Column(JSON, nullable=True)

    experiment = relationship("Experiment", back_populates="stages")
