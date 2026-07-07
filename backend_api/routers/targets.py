"""Targets router."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from backend_api.db.session import get_db
from backend_api.schemas.target import TargetCreate, TargetUpdate, TargetResponse
from backend_api.services.target_service import TargetService

router = APIRouter(prefix="/targets", tags=["targets"])


@router.post("/", response_model=TargetResponse, status_code=201)
def create_target(target: TargetCreate, db: Session = Depends(get_db)):
    """Create a new target."""
    try:
        target_data = target.dict()
        db_target = TargetService.create_target(db, target_data)
        return db_target
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/", response_model=List[TargetResponse])
def list_targets(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """List all targets."""
    targets = TargetService.list_targets(db, skip=skip, limit=limit)
    return targets


@router.get("/{target_id}", response_model=TargetResponse)
def get_target(target_id: int, db: Session = Depends(get_db)):
    """Get a target by ID."""
    try:
        target = TargetService.get_target(db, target_id)
        return target
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{target_id}", response_model=TargetResponse)
def update_target(
    target_id: int,
    target_update: TargetUpdate,
    db: Session = Depends(get_db)
):
    """Update a target."""
    try:
        update_data = target_update.dict(exclude_unset=True)
        target = TargetService.update_target(db, target_id, update_data)
        return target
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{target_id}", status_code=204)
def delete_target(target_id: int, db: Session = Depends(get_db)):
    """Delete a target."""
    try:
        TargetService.delete_target(db, target_id)
        return None
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
