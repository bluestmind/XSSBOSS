"""Endpoints router."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from backend_api.db.session import get_db
from backend_api.schemas.endpoint import EndpointCreate, EndpointResponse
from backend_api.services.endpoint_service import EndpointService

router = APIRouter(prefix="/endpoints", tags=["endpoints"])


@router.post("/", response_model=EndpointResponse, status_code=201)
def create_endpoint(endpoint: EndpointCreate, db: Session = Depends(get_db)):
    """Create a new endpoint."""
    try:
        endpoint_data = endpoint.dict()
        db_endpoint = EndpointService.create_endpoint(db, endpoint_data)
        return db_endpoint
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/", response_model=List[EndpointResponse])
def list_endpoints(
    target_id: Optional[int] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """List endpoints, optionally filtered by target."""
    endpoints = EndpointService.list_endpoints(db, target_id=target_id, skip=skip, limit=limit)
    return endpoints


@router.get("/{endpoint_id}", response_model=EndpointResponse)
def get_endpoint(endpoint_id: int, db: Session = Depends(get_db)):
    """Get an endpoint by ID."""
    try:
        endpoint = EndpointService.get_endpoint(db, endpoint_id)
        return endpoint
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{endpoint_id}", status_code=204)
def delete_endpoint(endpoint_id: int, db: Session = Depends(get_db)):
    """Delete an endpoint."""
    try:
        EndpointService.delete_endpoint(db, endpoint_id)
        return None
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
