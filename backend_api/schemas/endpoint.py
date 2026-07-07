"""Endpoint schemas."""
from pydantic import BaseModel
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

    class Config:
        from_attributes = True

