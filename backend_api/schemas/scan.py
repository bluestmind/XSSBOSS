"""One-shot scan schemas."""
import enum
from typing import Optional
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
    max_depth: int = Field(default=1, ge=0, le=3)
    max_pages: int = Field(default=15, ge=1, le=100)
    strategy: ExperimentStrategy = ExperimentStrategy.QUICK_LIGHT
    mode: ScanMode = ScanMode.FULL


class ScanResponse(BaseModel):
    """Response returned after queueing a scan."""
    target_id: int
    experiment_id: int
    endpoint_count: int
    status: str
    message: str
