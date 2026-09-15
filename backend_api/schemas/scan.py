"""One-shot scan schemas."""
import enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

from backend_api.models.experiment import ExperimentStrategy


class ScanMode(str, enum.Enum):
    """Top-level workflow mode for the one-page scanner."""
    RECON = "recon"
    FULL = "full"


class ScanCreate(BaseModel):
    """Request to create a target and start a scoped scan workflow."""
    url: str
    authorized: bool = Field(
        default=False,
        description="Must be true for targets the operator owns or is authorized to test.",
    )
    name: Optional[str] = None
    crawl: bool = True
    passive_recon: bool = False
    max_depth: int = Field(default=3, ge=0, le=5)
    max_pages: int = Field(
        default=150,
        ge=1,
        le=500,
        description="Maximum representative pages after route-template deduplication.",
    )
    strategy: ExperimentStrategy = ExperimentStrategy.SMART_ADAPTIVE
    autonomous_research: bool = True
    force_new: bool = Field(
        default=False,
        description="Start a separate run even when the same URL already has an active or paused experiment.",
    )
    mode: ScanMode = ScanMode.FULL
    auth_info: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Structured authorized identities, static session state, and login/workflow definitions.",
    )
    auth_identity: Optional[str] = Field(default=None, max_length=80)


class ScanResponse(BaseModel):
    """Response returned after queueing a scan."""
    target_id: int
    experiment_id: int
    endpoint_count: int
    status: str
    message: str
