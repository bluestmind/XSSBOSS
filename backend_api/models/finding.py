"""Finding model."""
from sqlalchemy import Column, String, Text, Integer, ForeignKey, JSON, Enum as SQLEnum
from sqlalchemy.orm import relationship
import enum
from .base import BaseModel


class Severity(str, enum.Enum):
    """Severity enum."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingStatus(str, enum.Enum):
    """Finding status enum."""
    DRAFT = "draft"
    CONFIRMED = "confirmed"
    REPORTED = "reported"
    DUPLICATE = "duplicate"


class Finding(BaseModel):
    """XSS finding model."""
    
    __tablename__ = "findings"
    
    endpoint_id = Column(Integer, ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True)
    param_id = Column(Integer, ForeignKey("params.id", ondelete="CASCADE"), nullable=False, index=True)
    context_id = Column(Integer, ForeignKey("contexts.id", ondelete="CASCADE"), nullable=True, index=True)
    sink_id = Column(Integer, ForeignKey("sinks.id", ondelete="CASCADE"), nullable=True, index=True)
    vuln_type = Column(String(80), default="xss", nullable=False, index=True)
    scanner_module = Column(String(120), default="xss_fuzzer", nullable=False)
    confidence = Column(String(40), default="firm", nullable=False)
    evidence_summary = Column(Text, nullable=True)
    best_payload = Column(Text, nullable=False)
    severity = Column(SQLEnum(Severity), default=Severity.MEDIUM, nullable=False)
    status = Column(SQLEnum(FindingStatus), default=FindingStatus.DRAFT, nullable=False)
    report_text = Column(Text, nullable=True)  # Human-readable report text
    evidence_refs = Column(JSON, nullable=True)  # References to execution IDs, screenshots, etc.
    poc_request = Column(JSON, nullable=True)  # PoC HTTP request
    poc_html = Column(Text, nullable=True)  # PoC HTML file content
    screenshot_path = Column(String(512), nullable=True)
    
    # Relationships
    endpoint = relationship("Endpoint", back_populates="findings")
    param = relationship("Param", back_populates="findings")
    context = relationship("Context", back_populates="findings")
    sink = relationship("Sink", back_populates="findings")
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        return f"<Finding(id={self.id}, severity='{self.severity.value}', status='{self.status.value}')>"
