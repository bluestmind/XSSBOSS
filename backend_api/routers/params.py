"""Parameters router."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional

from backend_api.db.session import get_db
from backend_api.models.param import Param
from backend_api.schemas.param import ParamResponse

router = APIRouter(prefix="/params", tags=["params"])


@router.get("/", response_model=List[ParamResponse])
def list_params(
    endpoint_id: Optional[int] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """List parameters, optionally filtered by endpoint."""
    query = db.query(Param)
    if endpoint_id:
        query = query.filter(Param.endpoint_id == endpoint_id)
    return query.order_by(Param.id.asc()).offset(skip).limit(limit).all()


@router.get("/{param_id}", response_model=ParamResponse)
def get_param(param_id: int, db: Session = Depends(get_db)):
    """Get a parameter by ID."""
    param = db.query(Param).filter(Param.id == param_id).first()
    if not param:
        raise HTTPException(status_code=404, detail=f"Param {param_id} not found")
    return param
