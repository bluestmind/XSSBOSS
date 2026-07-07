"""Payload knowledge model."""
from sqlalchemy import Column, String, Text, JSON, DateTime
from sqlalchemy.sql import func
from .base import BaseModel


class PayloadKnowledge(BaseModel):
    """Payload knowledge base model."""
    
    __tablename__ = "payload_knowledge"
    
    pattern = Column(Text, nullable=False)  # Payload pattern
    tag = Column(String(255), nullable=True, index=True)  # e.g., "bypass_modsecurity_3.x"
    context_types = Column(JSON, nullable=True)  # List of context types this works in
    success_history = Column(JSON, nullable=True)  # History of successful uses
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        return f"<PayloadKnowledge(id={self.id}, tag='{self.tag}', pattern='{self.pattern[:30]}...')>"
