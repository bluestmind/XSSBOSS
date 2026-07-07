"""Context model and taxonomy definitions."""
from sqlalchemy import Column, String, Text, Integer, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum
from typing import Dict, Any, Optional
from .base import BaseModel


class ContextType(str, enum.Enum):
    """Fine-grained reflection context taxonomy."""
    # HTML contexts
    HTML_TEXT = "HTML_TEXT"
    HTML_COMMENT = "HTML_COMMENT"
    HTML_RCDATA = "HTML_RCDATA"              # <title>, <textarea>
    HTML_RAW_TEXT = "HTML_RAW_TEXT"          # <xmp>, <iframe>, <noembed>, <noframes>
    HTML_NOSCRIPT = "HTML_NOSCRIPT"

    # Attribute contexts
    ATTR_QUOTED = "ATTR_QUOTED"
    ATTR_UNQUOTED = "ATTR_UNQUOTED"
    ATTR_NAME = "ATTR_NAME"
    EVENT_HANDLER_ATTR = "EVENT_HANDLER_ATTR"  # onclick, onload, onerror
    URL_QUERY = "URL_QUERY"                  # href, src, action, url parameters
    URL_FRAGMENT = "URL_FRAGMENT"
    SRC_DOC_ATTR = "SRC_DOC_ATTR"            # <iframe srcdoc="..."> (double HTML decoding)

    # JavaScript contexts
    JS_STRING_LITERAL = "JS_STRING_LITERAL"
    JS_TEMPLATE_LITERAL = "JS_TEMPLATE_LITERAL"  # `...`
    JS_IDENTIFIER = "JS_IDENTIFIER"
    JS_COMMENT = "JS_COMMENT"                    # // or /* ... */
    JSON_IN_SCRIPT = "JSON_IN_SCRIPT"            # <script type="application/json">
    JSON_VALUE = "JSON_VALUE"

    # XML / SVG / MathML namespace contexts (mXSS Crucial)
    SVG_TEXT = "SVG_TEXT"
    SVG_SCRIPT = "SVG_SCRIPT"
    MATHML_TEXT = "MATHML_TEXT"
    FOREIGN_OBJECT = "FOREIGN_OBJECT"
    ANNOTATION_XML = "ANNOTATION_XML"

    # CSS contexts
    CSS_STYLE_BLOCK = "CSS_STYLE_BLOCK"
    CSS_INLINE_STYLE = "CSS_INLINE_STYLE"
    CSS_URL = "CSS_URL"

    # Client-Side Template Injections (CSTI)
    CSTI_ANGULAR = "CSTI_ANGULAR"
    CSTI_VUE = "CSTI_VUE"
    CSTI_GENERIC = "CSTI_GENERIC"

    def is_js_executable(self) -> bool:
        """Return True if this context executes directly as JavaScript."""
        return self in (
            ContextType.JS_STRING_LITERAL,
            ContextType.JS_TEMPLATE_LITERAL,
            ContextType.JS_IDENTIFIER,
            ContextType.EVENT_HANDLER_ATTR,
            ContextType.SVG_SCRIPT,
        )

    def is_html_entity_decoded(self) -> bool:
        """Return True if the browser decodes HTML entities before evaluation."""
        return self in (
            ContextType.HTML_TEXT,
            ContextType.HTML_RCDATA,
            ContextType.ATTR_QUOTED,
            ContextType.EVENT_HANDLER_ATTR,
            ContextType.URL_QUERY,
            ContextType.SRC_DOC_ATTR,
            ContextType.SVG_TEXT,
            ContextType.MATHML_TEXT,
        )

    def requires_closing_tag(self) -> bool:
        """Return True if breakout requires closing an enclosing container tag."""
        return self in (
            ContextType.HTML_RCDATA,
            ContextType.HTML_RAW_TEXT,
            ContextType.HTML_COMMENT,
            ContextType.JS_STRING_LITERAL,
            ContextType.JS_TEMPLATE_LITERAL,
            ContextType.JSON_IN_SCRIPT,
            ContextType.CSS_STYLE_BLOCK,
        )

    def get_breakout_template(self, tag: Optional[str] = None, quote: str = '"') -> str:
        """Return recommended breakout prefix for this context."""
        t = (tag or "").lower()
        if self == ContextType.HTML_COMMENT:
            return "-->"
        if self == ContextType.HTML_RCDATA:
            return f"</{t}>" if t else "</title>"
        if self == ContextType.HTML_RAW_TEXT:
            return f"</{t}>" if t else "</style>"
        if self == ContextType.ATTR_QUOTED:
            return f"{quote}>"
        if self == ContextType.ATTR_UNQUOTED:
            return " >"
        if self == ContextType.JS_STRING_LITERAL:
            return f"{quote};"
        if self == ContextType.JS_TEMPLATE_LITERAL:
            return "${"
        if self == ContextType.JS_COMMENT:
            return "\n"
        if self in (ContextType.JSON_IN_SCRIPT, ContextType.JS_STRING_LITERAL) and t == "script":
            return "</script>"
        return ""


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
