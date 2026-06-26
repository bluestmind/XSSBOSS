"""Endpoint model."""
from sqlalchemy import Column, String, Text, JSON, Integer, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .base import BaseModel


class Endpoint(BaseModel):
    """HTTP endpoint model."""
    
    __tablename__ = "endpoints"
    
    target_id = Column(Integer, ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    method = Column(String(10), nullable=False)  # GET, POST, PUT, DELETE, etc.
    url_pattern = Column(String(2048), nullable=False, index=True)  # Normalized URL pattern
    sample_request_body = Column(JSON, nullable=True)
    sample_response_body = Column(Text, nullable=True)
    auth_context = Column(JSON, nullable=True)  # Cookies/headers used for this endpoint
    custom_steps = Column(JSON, nullable=True)  # Custom stateful sequence steps
    discovered_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    target = relationship("Target", back_populates="endpoints")
    params = relationship("Param", back_populates="endpoint", cascade="all, delete-orphan")
    contexts = relationship("Context", back_populates="endpoint", cascade="all, delete-orphan")
    filter_profiles = relationship("FilterProfile", back_populates="endpoint", cascade="all, delete-orphan")
    test_cases = relationship("TestCase", back_populates="endpoint")
    findings = relationship("Finding", back_populates="endpoint")
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        return f"<Endpoint(id={self.id}, method='{self.method}', url_pattern='{self.url_pattern[:50]}...')>"
