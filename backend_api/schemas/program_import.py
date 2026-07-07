"""Schemas for bug bounty program imports."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ProgramImportRequest(BaseModel):
    """Request to import programs from supported bug bounty platforms."""

    platforms: List[str] = Field(default_factory=lambda: ["hackerone", "yeswehack"])
    handles: Optional[List[str]] = None
    slugs: Optional[List[str]] = None
    limit_per_platform: int = Field(default=25, ge=1, le=100)
    max_scopes_per_program: int = Field(default=500, ge=1, le=10000)
    yeswehack_types: List[str] = Field(
        default_factory=lambda: ["bug-bounty", "vdp", "pentest", "vdp-in-app"]
    )
    update_existing: bool = True
    dry_run: bool = False
    browser_profile_path: Optional[str] = None
    browser_profile_name: str = "Default"


class ProgramImportTarget(BaseModel):
    """Summary of one imported or previewed target."""

    action: str
    platform: str
    program_key: str
    name: str
    base_url: str
    target_id: Optional[int] = None
    in_scope_count: int = 0
    out_of_scope_count: int = 0
    notes: Optional[str] = None
    scope_tags: Optional[Dict[str, Any]] = None


class ProgramImportError(BaseModel):
    """Import error for one platform or program."""

    platform: str
    program_key: Optional[str] = None
    message: str


class ProgramImportResponse(BaseModel):
    """Import result summary."""

    requested_platforms: List[str]
    dry_run: bool
    imported: int = 0
    updated: int = 0
    skipped: int = 0
    errors: List[ProgramImportError] = Field(default_factory=list)
    targets: List[ProgramImportTarget] = Field(default_factory=list)
