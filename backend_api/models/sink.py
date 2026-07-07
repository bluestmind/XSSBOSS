"""Sink model."""
from sqlalchemy import Column, String, Text, Integer, ForeignKey, JSON, Enum as SQLEnum
from sqlalchemy.orm import relationship
import enum
from .base import BaseModel


class SinkType(str, enum.Enum):
    """Sink type enum."""
    INNERHTML = "innerHTML"
    OUTERHTML = "outerHTML"
    INSERT_ADJACENT_HTML = "insertAdjacentHTML"
    EVAL = "eval"
    FUNCTION = "Function"
    SET_TIMEOUT = "setTimeout"
    SET_INTERVAL = "setInterval"
    DOCUMENT_WRITE = "document.write"
    HREF = "href"
    SRC = "src"
    JQUERY_HTML = "jQuery_html"
    ELEMENT_INNERHTML = "Element_innerHTML"


class DetectedVia(str, enum.Enum):
    """Detection method enum."""
    STATIC = "static"
    DYNAMIC = "dynamic"


class Sink(BaseModel):
    """Dangerous sink model."""
    
    __tablename__ = "sinks"
    
    context_id = Column(Integer, ForeignKey("contexts.id", ondelete="CASCADE"), nullable=False, index=True)
    sink_type = Column(String(50), nullable=False)  # innerHTML, eval, etc.
    js_location = Column(String(2048), nullable=True)  # JS file path or inline location
    taint_path = Column(JSON, nullable=True)  # Path from param to sink (variable names, etc.)
    detected_via = Column(SQLEnum(DetectedVia), nullable=False)  # static or dynamic
    notes = Column(Text, nullable=True)
    
    # Relationships
    context = relationship("Context", back_populates="sinks")
    findings = relationship("Finding", back_populates="sink")
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        return f"<Sink(id={self.id}, sink_type='{self.sink_type}', context_id={self.context_id})>"
