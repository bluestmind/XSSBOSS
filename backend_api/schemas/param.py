"""Parameter schemas."""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class ParamResponse(BaseModel):
    """Parameter response schema."""

    id: int
    endpoint_id: int
    name: str
    location: str
    sample_value: Optional[str]
    is_controllable: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
