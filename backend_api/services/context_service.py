"""Context service - context detection coordination."""
from sqlalchemy.orm import Session
from typing import List, Optional
from backend_api.models.context import Context, ContextType
from backend_api.models.param import Param
from backend_api.models.endpoint import Endpoint


class ContextService:
    """Service for context detection operations."""
    
    @staticmethod
    def create_context(
        db: Session,
        param_id: int,
        endpoint_id: int,
        context_type: ContextType,
        tag: Optional[str] = None,
        attribute: Optional[str] = None,
        script_path: Optional[str] = None,
        snippet: Optional[str] = None
    ) -> Context:
        """Create a context record.
        
        Args:
            db: Database session
            param_id: Parameter ID
            endpoint_id: Endpoint ID
            context_type: ContextType enum
            tag: HTML tag name
            attribute: Attribute name
            script_path: JavaScript file path
            snippet: HTML/JS snippet
            
        Returns:
            Created Context record
        """
        # Handle both enum and string
        if isinstance(context_type, ContextType):
            context_type_str = context_type.value
        else:
            context_type_str = str(context_type)
        
        context = Context(
            param_id=param_id,
            endpoint_id=endpoint_id,
            context_type=context_type_str,
            tag=tag,
            attribute=attribute,
            script_path=script_path,
            snippet=snippet
        )
        db.add(context)
        db.commit()
        db.refresh(context)
        return context
    
    @staticmethod
    def get_contexts_for_param(
        db: Session,
        param_id: int
    ) -> List[Context]:
        """Get all contexts for a parameter."""
        return db.query(Context).filter(Context.param_id == param_id).all()
    
    @staticmethod
    def get_contexts_for_endpoint(
        db: Session,
        endpoint_id: int
    ) -> List[Context]:
        """Get all contexts for an endpoint."""
        return db.query(Context).filter(Context.endpoint_id == endpoint_id).all()

