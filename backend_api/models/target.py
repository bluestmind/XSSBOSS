"""Target model."""
from sqlalchemy import Column, String, Text, JSON, Enum as SQLEnum
from sqlalchemy.orm import relationship
import enum
from .base import BaseModel


class TargetStatus(str, enum.Enum):
    """Target status enum."""
    RECON_ONLY = "recon_only"
    FUZZING = "fuzzing"
    TRIAGE = "triage"
    DONE = "done"


class Target(BaseModel):
    """Target program/model."""
    
    __tablename__ = "targets"
    
    name = Column(String(255), nullable=False, index=True)
    base_url = Column(String(2048), nullable=False)
    notes = Column(Text, nullable=True)
    bounty_platform = Column(String(100), nullable=True)  # intigriti, hackerone, etc.
    scope_tags = Column(JSON, nullable=True)  # List of scope-related tags
    auth_info = Column(JSON, nullable=True)  # Auth credentials/headers/cookies
    status = Column(SQLEnum(TargetStatus), default=TargetStatus.RECON_ONLY, nullable=False)
    
    # Relationships
    endpoints = relationship("Endpoint", back_populates="target", cascade="all, delete-orphan")
    experiments = relationship("Experiment", back_populates="target", cascade="all, delete-orphan")
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        return f"<Target(id={self.id}, name='{self.name}', status='{self.status.value}')>"
