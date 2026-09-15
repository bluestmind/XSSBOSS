"""Target schemas."""
from pydantic import BaseModel, ConfigDict, field_serializer
from typing import Optional, Dict, Any
from datetime import datetime
from backend_api.models.target import TargetStatus


class TargetCreate(BaseModel):
    """Target creation schema."""
    name: str
    base_url: str
    notes: Optional[str] = None
    bounty_platform: Optional[str] = None
    scope_tags: Optional[Dict[str, Any]] = None
    auth_info: Optional[Dict[str, Any]] = None
    status: Optional[TargetStatus] = TargetStatus.RECON_ONLY


class TargetUpdate(BaseModel):
    """Target update schema."""
    name: Optional[str] = None
    base_url: Optional[str] = None
    notes: Optional[str] = None
    bounty_platform: Optional[str] = None
    scope_tags: Optional[Dict[str, Any]] = None
    auth_info: Optional[Dict[str, Any]] = None
    status: Optional[TargetStatus] = None


class TargetResponse(BaseModel):
    """Target response schema."""
    id: int
    name: str
    base_url: str
    notes: Optional[str]
    bounty_platform: Optional[str]
    scope_tags: Optional[Dict[str, Any]]
    auth_info: Optional[Dict[str, Any]]
    status: TargetStatus
    created_at: datetime
    updated_at: datetime

    @field_serializer("auth_info")
    def redact_auth_info(self, value: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if value is None:
            return None
        from backend_api.services.auth_session_service import AuthSessionService

        return AuthSessionService.sanitize_public(value)

    model_config = ConfigDict(from_attributes=True)

