"""Endpoint service."""
from sqlalchemy.orm import Session
from typing import List, Optional
from backend_api.models.endpoint import Endpoint
from backend_api.models.target import Target
from backend_api.utils.errors import NotFoundError, ValidationError
from backend_api.utils.scope_guard import is_url_in_scope


class EndpointService:
    """Service for endpoint operations."""
    
    @staticmethod
    def create_endpoint(db: Session, endpoint_data: dict) -> Endpoint:
        """Create a new endpoint."""
        # Verify target exists
        target = db.query(Target).filter(Target.id == endpoint_data['target_id']).first()
        if not target:
            raise NotFoundError("Target", endpoint_data['target_id'])

        if not is_url_in_scope(target, endpoint_data.get("url_pattern", "")):
            raise ValidationError("Endpoint URL is outside the target's configured bug bounty scope")
        
        endpoint = Endpoint(**endpoint_data)
        db.add(endpoint)
        db.commit()
        db.refresh(endpoint)
        return endpoint
    
    @staticmethod
    def get_endpoint(db: Session, endpoint_id: int) -> Endpoint:
        """Get endpoint by ID."""
        endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id).first()
        if not endpoint:
            raise NotFoundError("Endpoint", endpoint_id)
        return endpoint
    
    @staticmethod
    def list_endpoints(
        db: Session,
        target_id: Optional[int] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[Endpoint]:
        """List endpoints, optionally filtered by target."""
        query = db.query(Endpoint)
        if target_id:
            query = query.filter(Endpoint.target_id == target_id)
        return query.offset(skip).limit(limit).all()
    
    @staticmethod
    def delete_endpoint(db: Session, endpoint_id: int) -> None:
        """Delete an endpoint."""
        endpoint = EndpointService.get_endpoint(db, endpoint_id)
        db.delete(endpoint)
        db.commit()

