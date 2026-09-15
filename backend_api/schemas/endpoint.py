"""Endpoint schemas."""
from pydantic import BaseModel, ConfigDict, field_serializer
from typing import Optional, Dict, Any
from datetime import datetime


class EndpointCreate(BaseModel):
    """Endpoint creation schema."""
    target_id: int
    method: str
    url_pattern: str
    sample_request_body: Optional[Dict[str, Any]] = None
    sample_response_body: Optional[str] = None
    auth_context: Optional[Dict[str, Any]] = None


class EndpointResponse(BaseModel):
    """Endpoint response schema."""
    id: int
    target_id: int
    method: str
    url_pattern: str
    sample_request_body: Optional[Dict[str, Any]]
    sample_response_body: Optional[str]
    auth_context: Optional[Dict[str, Any]]
    discovered_at: datetime
    created_at: datetime
    updated_at: datetime

    @field_serializer("auth_context")
    def redact_auth_context(self, value: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if value is None:
            return None
        from backend_api.services.auth_session_service import AuthSessionService

        return AuthSessionService.sanitize_public(value)

    model_config = ConfigDict(from_attributes=True)

