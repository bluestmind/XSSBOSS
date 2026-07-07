"""Persistent attack-surface graph and hypothesis-driven research state."""
from sqlalchemy import Column, Float, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from .base import BaseModel


class AttackSurfaceNode(BaseModel):
    __tablename__ = "attack_surface_nodes"
    __table_args__ = (
        UniqueConstraint("experiment_id", "node_type", "natural_key", name="uq_surface_node"),
    )

    experiment_id = Column(Integer, ForeignKey("experiments.id", ondelete="CASCADE"), nullable=False, index=True)
    node_type = Column(String(40), nullable=False, index=True)
    natural_key = Column(String(180), nullable=False)
    label = Column(String(500), nullable=False)
    risk_score = Column(Integer, default=0, nullable=False, index=True)
    attributes = Column(JSON, nullable=True)

    experiment = relationship("Experiment", back_populates="surface_nodes")
    outgoing_edges = relationship(
        "AttackSurfaceEdge", foreign_keys="AttackSurfaceEdge.source_node_id",
        back_populates="source", cascade="all, delete-orphan",
    )
    incoming_edges = relationship(
        "AttackSurfaceEdge", foreign_keys="AttackSurfaceEdge.target_node_id",
        back_populates="target", cascade="all, delete-orphan",
    )


class AttackSurfaceEdge(BaseModel):
    __tablename__ = "attack_surface_edges"
    __table_args__ = (
        UniqueConstraint("experiment_id", "source_node_id", "target_node_id", "relation", name="uq_surface_edge"),
    )

    experiment_id = Column(Integer, ForeignKey("experiments.id", ondelete="CASCADE"), nullable=False, index=True)
    source_node_id = Column(Integer, ForeignKey("attack_surface_nodes.id", ondelete="CASCADE"), nullable=False, index=True)
    target_node_id = Column(Integer, ForeignKey("attack_surface_nodes.id", ondelete="CASCADE"), nullable=False, index=True)
    relation = Column(String(60), nullable=False, index=True)
    confidence = Column(Float, default=1.0, nullable=False)
    evidence = Column(JSON, nullable=True)

    experiment = relationship("Experiment", back_populates="surface_edges")
    source = relationship("AttackSurfaceNode", foreign_keys=[source_node_id], back_populates="outgoing_edges")
    target = relationship("AttackSurfaceNode", foreign_keys=[target_node_id], back_populates="incoming_edges")


class ResearchHypothesis(BaseModel):
    __tablename__ = "research_hypotheses"
    __table_args__ = (
        UniqueConstraint("experiment_id", "fingerprint", name="uq_research_hypothesis"),
    )

    experiment_id = Column(Integer, ForeignKey("experiments.id", ondelete="CASCADE"), nullable=False, index=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=True, index=True)
    param_id = Column(Integer, ForeignKey("params.id", ondelete="CASCADE"), nullable=True, index=True)
    context_id = Column(Integer, ForeignKey("contexts.id", ondelete="SET NULL"), nullable=True, index=True)
    fingerprint = Column(String(64), nullable=False)
    hypothesis_type = Column(String(60), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    rationale = Column(Text, nullable=False)
    status = Column(String(24), default="proposed", nullable=False, index=True)
    confidence = Column(Float, default=0.5, nullable=False)
    impact_score = Column(Integer, default=0, nullable=False)
    priority = Column(Float, default=0.0, nullable=False, index=True)
    technique_candidates = Column(JSON, nullable=True)
    evidence = Column(JSON, nullable=True)

    experiment = relationship("Experiment", back_populates="research_hypotheses")
    observations = relationship("ResearchObservation", back_populates="hypothesis", cascade="all, delete-orphan")
    test_cases = relationship("TestCase", back_populates="research_hypothesis")


class ResearchObservation(BaseModel):
    __tablename__ = "research_observations"

    hypothesis_id = Column(Integer, ForeignKey("research_hypotheses.id", ondelete="CASCADE"), nullable=False, index=True)
    execution_id = Column(Integer, ForeignKey("executions.id", ondelete="SET NULL"), nullable=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True)
    signal_type = Column(String(60), nullable=False, index=True)
    outcome = Column(String(24), nullable=False, index=True)
    strength = Column(Float, default=0.0, nullable=False)
    details = Column(JSON, nullable=True)

    hypothesis = relationship("ResearchHypothesis", back_populates="observations")


class ResearchTechniqueStat(BaseModel):
    __tablename__ = "research_technique_stats"
    __table_args__ = (
        UniqueConstraint("tenant_id", "context_fingerprint", "technique", name="uq_research_technique_stat"),
    )

    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    context_fingerprint = Column(String(180), nullable=False, index=True)
    technique = Column(String(80), nullable=False, index=True)
    successes = Column(Integer, default=0, nullable=False)
    failures = Column(Integer, default=0, nullable=False)
    reward_sum = Column(Float, default=0.0, nullable=False)
    evidence = Column(JSON, nullable=True)
