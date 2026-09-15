"""Filter profile schemas."""
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict


class FilterProfileResponse(BaseModel):
    """Filter profile response schema."""

    id: int
    endpoint_id: int
    summary: Optional[str]
    blocked_tokens: Optional[List[str]]
    allowed_tokens: Optional[List[str]]
    normalization_behavior: Optional[List[str]]
    waf_detected: bool
    sanitizer_detected: Optional[str]
    csp_rules: Optional[Dict[str, Any]]
    probe_results: Optional[List[Dict[str, Any]]]
    profiled_at: datetime
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
