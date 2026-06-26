"""Parameter model."""
from sqlalchemy import Column, String, Boolean, Integer, ForeignKey
from sqlalchemy.orm import relationship
import enum
from .base import BaseModel


class ParamLocation(str, enum.Enum):
    """Parameter location enum."""
    QUERY = "query"
    BODY = "body"
    JSON = "json"
    PATH = "path"
    HEADER = "header"
    COOKIE = "cookie"


class Param(BaseModel):
    """HTTP parameter model."""
    
    __tablename__ = "params"
    
    endpoint_id = Column(Integer, ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    location = Column(String(20), nullable=False)  # query, body, json, path, header, cookie
    sample_value = Column(String(2048), nullable=True)
    is_controllable = Column(Boolean, default=True, nullable=False)
    burp_flagged = Column(Boolean, default=False, nullable=False)
    
    # Relationships
    endpoint = relationship("Endpoint", back_populates="params")
    contexts = relationship("Context", back_populates="param", cascade="all, delete-orphan")
    test_cases = relationship("TestCase", back_populates="param")
    findings = relationship("Finding", back_populates="param")
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        return f"<Param(id={self.id}, name='{self.name}', location='{self.location}')>"
