"""Context schemas."""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class ContextResponse(BaseModel):
    """Reflection context response schema."""

    id: int
    param_id: int
    endpoint_id: int
    context_type: str
    tag: Optional[str]
    attribute: Optional[str]
    script_path: Optional[str]
    snippet: Optional[str]
    detected_at: datetime
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
