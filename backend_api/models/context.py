"""Context model."""
from sqlalchemy import Column, String, Text, Integer, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum
from .base import BaseModel


class ContextType(str, enum.Enum):
    """Context type enum."""
    HTML_TEXT = "HTML_TEXT"
    ATTR_QUOTED = "ATTR_QUOTED"
    ATTR_UNQUOTED = "ATTR_UNQUOTED"
    EVENT_HANDLER_ATTR = "EVENT_HANDLER_ATTR"
    JS_STRING_LITERAL = "JS_STRING_LITERAL"
    JS_IDENTIFIER = "JS_IDENTIFIER"
    URL_FRAGMENT = "URL_FRAGMENT"
    URL_QUERY = "URL_QUERY"
    JSON_VALUE = "JSON_VALUE"


class Context(BaseModel):
    """Reflection context model."""
    
    __tablename__ = "contexts"
    
    param_id = Column(Integer, ForeignKey("params.id", ondelete="CASCADE"), nullable=False, index=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True)
    context_type = Column(String(50), nullable=False)  # HTML_TEXT, ATTR_QUOTED, etc.
    tag = Column(String(100), nullable=True)  # HTML tag name where reflection occurs
    attribute = Column(String(100), nullable=True)  # Attribute name if in attribute context
    script_path = Column(String(2048), nullable=True)  # JS file path if in JS context
    snippet = Column(Text, nullable=True)  # HTML/JS snippet showing reflection
    detected_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    param = relationship("Param", back_populates="contexts")
    endpoint = relationship("Endpoint", back_populates="contexts")
    sinks = relationship("Sink", back_populates="context", cascade="all, delete-orphan")
    test_cases = relationship("TestCase", back_populates="context")
    findings = relationship("Finding", back_populates="context")
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        return f"<Context(id={self.id}, context_type='{self.context_type}', param_id={self.param_id})>"
