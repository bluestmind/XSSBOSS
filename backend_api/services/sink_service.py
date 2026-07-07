"""Sink service - sink mapping coordination."""
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from backend_api.models.sink import Sink, SinkType, DetectedVia
from backend_api.models.context import Context


class SinkService:
    """Service for sink mapping operations."""
    
    @staticmethod
    def create_sink(
        db: Session,
        context_id: int,
        sink_type: str,
        js_location: Optional[str] = None,
        taint_path: Optional[Dict[str, Any]] = None,
        detected_via: str = DetectedVia.STATIC.value,
        notes: Optional[str] = None
    ) -> Sink:
        """Create a sink record.
        
        Args:
            db: Database session
            context_id: Context ID
            sink_type: Sink type (string value)
            js_location: JavaScript file location with line/column
            taint_path: Taint path dictionary
            detected_via: Detection method (static/dynamic)
            notes: Additional notes
            
        Returns:
            Created Sink record
        """
        # Handle enum or string
        if isinstance(sink_type, SinkType):
            sink_type_str = sink_type.value
        else:
            sink_type_str = str(sink_type)
        
        if isinstance(detected_via, DetectedVia):
            detected_via_str = detected_via.value
        else:
            detected_via_str = str(detected_via)
        
        sink = Sink(
            context_id=context_id,
            sink_type=sink_type_str,
            js_location=js_location,
            taint_path=taint_path or {},
            detected_via=detected_via_str,
            notes=notes
        )
        db.add(sink)
        db.commit()
        db.refresh(sink)
        return sink
    
    @staticmethod
    def get_sinks_for_context(
        db: Session,
        context_id: int
    ) -> List[Sink]:
        """Get all sinks for a context."""
        return db.query(Sink).filter(Sink.context_id == context_id).all()
    
    @staticmethod
    def get_sinks_for_endpoint(
        db: Session,
        endpoint_id: int
    ) -> List[Sink]:
        """Get all sinks for an endpoint (via contexts)."""
        return (
            db.query(Sink)
            .join(Context)
            .filter(Context.endpoint_id == endpoint_id)
            .all()
        )

