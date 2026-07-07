"""Sink schemas."""
from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel


class SinkResponse(BaseModel):
    """Dangerous sink response schema."""

    id: int
    context_id: int
    sink_type: str
    js_location: Optional[str]
    taint_path: Optional[Dict[str, Any]]
    detected_via: str
    notes: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
