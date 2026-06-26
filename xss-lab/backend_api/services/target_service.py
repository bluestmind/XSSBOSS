"""Target service."""
from sqlalchemy.orm import Session
from typing import List, Optional
from backend_api.models.target import Target, TargetStatus
from backend_api.utils.errors import NotFoundError, ValidationError


class TargetService:
    """Service for target operations."""
    
    @staticmethod
    def create_target(db: Session, target_data: dict) -> Target:
        """Create a new target."""
        target = Target(**target_data)
        db.add(target)
        db.commit()
        db.refresh(target)
        return target
    
    @staticmethod
    def get_target(db: Session, target_id: int) -> Target:
        """Get target by ID."""
        target = db.query(Target).filter(Target.id == target_id).first()
        if not target:
            raise NotFoundError("Target", target_id)
        return target
    
    @staticmethod
    def list_targets(
        db: Session,
        skip: int = 0,
        limit: int = 100
    ) -> List[Target]:
        """List all targets."""
        return db.query(Target).offset(skip).limit(limit).all()
    
    @staticmethod
    def update_target(
        db: Session,
        target_id: int,
        update_data: dict
    ) -> Target:
        """Update a target."""
        target = TargetService.get_target(db, target_id)
        
        for field, value in update_data.items():
            if hasattr(target, field):
                setattr(target, field, value)
        
        db.commit()
        db.refresh(target)
        return target
    
    @staticmethod
    def delete_target(db: Session, target_id: int) -> None:
        """Delete a target."""
        target = TargetService.get_target(db, target_id)
        db.delete(target)
        db.commit()

