"""Experiment model."""
from sqlalchemy import Column, String, JSON, Integer, ForeignKey, DateTime, Enum as SQLEnum
from sqlalchemy.orm import relationship
import enum
from .base import BaseModel


class ExperimentStrategy(str, enum.Enum):
    """Experiment strategy enum."""
    QUICK_LIGHT = "quick_light"
    SMART_ADAPTIVE = "smart_adaptive"
    POLYGLOT_FIRST = "polyglot_first"
    UNICODE_HUNT = "unicode_hunt"
    JS_STRING_SPECIALIST = "js_string_specialist"
    CSP_AWARE = "csp_aware"
    MAX_COVERAGE = "max_coverage"
    GENETIC_EVOLUTIONARY = "genetic_evolutionary"


class ExperimentStatus(str, enum.Enum):
    """Experiment status enum."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class Experiment(BaseModel):
    """Experiment model."""
    
    __tablename__ = "experiments"
    
    target_id = Column(Integer, ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    strategy = Column(SQLEnum(ExperimentStrategy), nullable=False)
    status = Column(SQLEnum(ExperimentStatus), default=ExperimentStatus.PENDING, nullable=False)
    limits = Column(JSON, nullable=True)  # {max_requests, time_limit, concurrency, rate_limit}
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    target = relationship("Target", back_populates="experiments")
    test_cases = relationship("TestCase", back_populates="experiment", cascade="all, delete-orphan")
    run_endpoints = relationship("RunEndpoint", back_populates="experiment", cascade="all, delete-orphan")
    finding_observations = relationship(
        "FindingObservation", back_populates="experiment", cascade="all, delete-orphan"
    )
    stages = relationship("RunStage", back_populates="experiment", cascade="all, delete-orphan")
    evidence_artifacts = relationship("EvidenceArtifact", back_populates="experiment", cascade="all, delete-orphan")
    surface_nodes = relationship("AttackSurfaceNode", back_populates="experiment", cascade="all, delete-orphan")
    surface_edges = relationship("AttackSurfaceEdge", back_populates="experiment", cascade="all, delete-orphan")
    research_hypotheses = relationship("ResearchHypothesis", back_populates="experiment", cascade="all, delete-orphan")
