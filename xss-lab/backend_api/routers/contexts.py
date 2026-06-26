"""Contexts router."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional

from backend_api.db.session import get_db
from backend_api.models.context import Context
from backend_api.schemas.context import ContextResponse

router = APIRouter(prefix="/contexts", tags=["contexts"])


@router.get("/", response_model=List[ContextResponse])
def list_contexts(
    param_id: Optional[int] = None,
    endpoint_id: Optional[int] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """List reflection contexts with optional filters."""
    query = db.query(Context)
    if param_id:
        query = query.filter(Context.param_id == param_id)
    if endpoint_id:
        query = query.filter(Context.endpoint_id == endpoint_id)
    return query.order_by(Context.detected_at.desc()).offset(skip).limit(limit).all()


@router.get("/{context_id}", response_model=ContextResponse)
def get_context(context_id: int, db: Session = Depends(get_db)):
    """Get a reflection context by ID."""
    context = db.query(Context).filter(Context.id == context_id).first()
    if not context:
        raise HTTPException(status_code=404, detail=f"Context {context_id} not found")
    return context
