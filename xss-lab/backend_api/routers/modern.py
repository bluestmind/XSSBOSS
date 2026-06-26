"""Modern DOM XSS probe routes."""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend_api.db.session import get_db
from backend_api.services.modern_dom_probe_service import ModernDOMProbeService
from backend_api.services.modern_dom_probe_executor import ModernDOMProbeExecutor

router = APIRouter(prefix="/modern", tags=["modern"])


class ModernProbeRequest(BaseModel):
    """Request for opt-in modern DOM XSS probes."""

    endpoint_id: int
    payload_template: Optional[str] = Field(
        default=None,
        description="Payload template. Use {{TOKEN}} as the oracle placeholder.",
    )
    token: Optional[str] = Field(default=None, max_length=64)
    include_live_fingerprint: bool = True


class ModernProbeExecuteRequest(BaseModel):
    """Request to execute opt-in modern DOM XSS probes in a browser."""

    endpoint_id: int
    param_id: Optional[int] = None
    context_id: Optional[int] = None
    payload_template: Optional[str] = Field(
        default=None,
        description="Payload template. Use {{TOKEN}} as the oracle placeholder.",
    )
    families: Optional[list[str]] = Field(
        default=None,
        description="Optional families: post_message, prototype_pollution, dom_clobbering, sanitizer_mxss.",
    )
    max_probes: int = Field(default=50, ge=1, le=100)
    post_message_origin_modes: Optional[list[str]] = Field(
        default=None,
        description=(
            "Optional postMessage origin modes: none, starts_ends, exact. "
            "Defaults to none and starts_ends; exact is triage-only."
        ),
    )
    serve_post_message_poc_http: bool = Field(
        default=True,
        description="Serve postMessage PoC HTML from an ephemeral 127.0.0.1 HTTP origin instead of a data: URL.",
    )


@router.post("/dom-probes")
def build_modern_dom_probes(
    request: ModernProbeRequest,
    db: Session = Depends(get_db),
):
    """Generate postMessage, prototype pollution, clobbering, and mXSS probe families."""
    try:
        return ModernDOMProbeService.build_probes(
            db=db,
            endpoint_id=request.endpoint_id,
            payload_template=request.payload_template,
            token=request.token,
            include_live_fingerprint=request.include_live_fingerprint,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/dom-probes/execute")
def execute_modern_dom_probes(
    request: ModernProbeExecuteRequest,
    db: Session = Depends(get_db),
):
    """Run modern DOM XSS probes in a real browser and persist evidence."""
    try:
        return ModernDOMProbeExecutor.execute(
            db=db,
            endpoint_id=request.endpoint_id,
            param_id=request.param_id,
            context_id=request.context_id,
            payload_template=request.payload_template,
            families=request.families,
            max_probes=request.max_probes,
            post_message_origin_modes=request.post_message_origin_modes,
            serve_post_message_poc_http=request.serve_post_message_poc_http,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
