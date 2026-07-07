"""Payload service - payload generation coordination."""
from datetime import datetime
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional
from backend_api.models.payload_knowledge import PayloadKnowledge
from backend_api.models.context import Context, ContextType


class PayloadService:
    """Service for payload generation operations."""
    
    @staticmethod
    def get_payloads_for_context(
        db: Session,
        context_type: ContextType,
        tag: Optional[str] = None
    ) -> List[PayloadKnowledge]:
        """Get payloads that work for a specific context type."""
        query = db.query(PayloadKnowledge)
        
        # Filter by context types (JSON array contains context_type)
        # This is a simplified version - in production, use proper JSON queries
        all_payloads = query.all()
        
        matching = []
        for payload in all_payloads:
            if payload.context_types and context_type.value in payload.context_types:
                if tag is None or payload.tag == tag:
                    matching.append(payload)
        
        return matching
    
    @staticmethod
    def record_successful_payload(
        db: Session,
        pattern: str,
        context_types: List[str],
        tag: Optional[str] = None
    ) -> PayloadKnowledge:
        """Record a successful payload pattern."""
        # Check if pattern already exists
        existing = db.query(PayloadKnowledge).filter(
            PayloadKnowledge.pattern == pattern
        ).first()
        
        if existing:
            # Update success history
            if existing.success_history is None:
                existing.success_history = []
            existing.success_history.append({
                'timestamp': str(datetime.utcnow()),
                'context_types': context_types
            })
            existing.last_used_at = datetime.utcnow()
            db.commit()
            db.refresh(existing)
            return existing
        else:
            # Create new
            payload = PayloadKnowledge(
                pattern=pattern,
                tag=tag,
                context_types=context_types,
                success_history=[{
                    'timestamp': str(datetime.utcnow()),
                    'context_types': context_types
                }],
                last_used_at=datetime.utcnow()
            )
            db.add(payload)
            db.commit()
            db.refresh(payload)
            return payload

