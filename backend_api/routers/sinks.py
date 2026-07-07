"""Sinks router."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional

from backend_api.db.session import get_db
from backend_api.models.context import Context
from backend_api.models.sink import Sink
from backend_api.schemas.sink import SinkResponse

router = APIRouter(prefix="/sinks", tags=["sinks"])


@router.get("/", response_model=List[SinkResponse])
def list_sinks(
    context_id: Optional[int] = None,
    endpoint_id: Optional[int] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """List sinks with optional context or endpoint filters."""
    query = db.query(Sink)
    if context_id:
        query = query.filter(Sink.context_id == context_id)
    if endpoint_id:
        query = query.join(Context).filter(Context.endpoint_id == endpoint_id)
    return query.order_by(Sink.id.asc()).offset(skip).limit(limit).all()


@router.get("/{sink_id}", response_model=SinkResponse)
def get_sink(sink_id: int, db: Session = Depends(get_db)):
    """Get a sink by ID."""
    sink = db.query(Sink).filter(Sink.id == sink_id).first()
    if not sink:
        raise HTTPException(status_code=404, detail=f"Sink {sink_id} not found")
    return sink
