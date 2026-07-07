"""Content-addressed evidence metadata."""
from sqlalchemy import Column, ForeignKey, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import relationship

from .base import BaseModel


class EvidenceArtifact(BaseModel):
    __tablename__ = "evidence_artifacts"
    __table_args__ = (
        UniqueConstraint("experiment_id", "kind", "sha256", name="uq_run_evidence_hash"),
    )

    experiment_id = Column(Integer, ForeignKey("experiments.id", ondelete="CASCADE"), nullable=False, index=True)
    execution_id = Column(Integer, ForeignKey("executions.id", ondelete="SET NULL"), nullable=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True)
    kind = Column(String(40), nullable=False, index=True)
    uri = Column(String(1024), nullable=True)
    sha256 = Column(String(64), nullable=False, index=True)
    size_bytes = Column(Integer, nullable=False)
    artifact_metadata = Column(JSON, nullable=True)

    experiment = relationship("Experiment", back_populates="evidence_artifacts")
    execution = relationship("Execution", back_populates="evidence_artifacts")
    finding = relationship("Finding", back_populates="evidence_artifacts")
