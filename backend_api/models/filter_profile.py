"""Filter profile model."""
from sqlalchemy import Column, Text, JSON, Boolean, String, Integer, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .base import BaseModel


class FilterProfile(BaseModel):
    """Filter behavior profile model."""
    
    __tablename__ = "filter_profiles"
    
    endpoint_id = Column(Integer, ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True)
    summary = Column(Text, nullable=True)  # Human-readable summary
    blocked_tokens = Column(JSON, nullable=True)  # List of blocked tokens/patterns
    allowed_tokens = Column(JSON, nullable=True)  # List of allowed tokens/patterns
    normalization_behavior = Column(JSON, nullable=True)  # How input is normalized
    waf_detected = Column(Boolean, default=False, nullable=False)
    sanitizer_detected = Column(String(100), nullable=True)  # e.g., "DOMPurify", "sanitize-html"
    csp_rules = Column(JSON, nullable=True)  # Parsed Content-Security-Policy rules
    probe_results = Column(JSON, nullable=True)  # Raw probe test results
    profiled_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    endpoint = relationship("Endpoint", back_populates="filter_profiles")
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        return f"<FilterProfile(id={self.id}, endpoint_id={self.endpoint_id}, waf_detected={self.waf_detected})>"
