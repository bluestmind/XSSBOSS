"""Filter profiles router."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend_api.db.session import get_db
from backend_api.models.filter_profile import FilterProfile
from backend_api.schemas.filter_profile import FilterProfileResponse
from backend_api.services.filter_service import FilterService

router = APIRouter(prefix="/filters", tags=["filters"])


@router.get("/endpoint/{endpoint_id}", response_model=FilterProfileResponse)
def get_filter_profile_for_endpoint(endpoint_id: int, db: Session = Depends(get_db)):
    """Get the latest filter profile for an endpoint."""
    profile = FilterService.get_filter_profile_for_endpoint(db, endpoint_id)
    if not profile:
        raise HTTPException(status_code=404, detail=f"Filter profile for endpoint {endpoint_id} not found")
    return profile


@router.get("/{profile_id}", response_model=FilterProfileResponse)
def get_filter_profile(profile_id: int, db: Session = Depends(get_db)):
    """Get a filter profile by ID."""
    profile = db.query(FilterProfile).filter(FilterProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail=f"Filter profile {profile_id} not found")
    return profile
