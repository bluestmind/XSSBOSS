"""Verification routes for higher-impact XSS proof."""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend_api.db.session import get_db
from backend_api.services.stored_xss_verifier import StoredXSSVerifier

router = APIRouter(prefix="/verification", tags=["verification"])


class RoleContext(BaseModel):
    """Authorized role/session context for revisit verification."""

    label: str = Field(default="same-session", max_length=80)
    auth_context: Dict[str, Any] = Field(default_factory=dict)


class StoredXSSVerificationRequest(BaseModel):
    """Request to verify stored or cross-session XSS execution."""

    submit_endpoint_id: int
    param_id: int
    payload_template: str = Field(..., min_length=1)
    context_id: Optional[int] = None
    revisit_endpoint_ids: Optional[List[int]] = None
    role_contexts: List[RoleContext] = Field(default_factory=list)
    max_revisits: int = Field(default=20, ge=1, le=100)


@router.post("/stored-xss")
def verify_stored_xss(
    request: StoredXSSVerificationRequest,
    db: Session = Depends(get_db),
):
    """Submit a payload, revisit pages, and record stored/cross-role proof."""
    try:
        return StoredXSSVerifier.verify(
            db=db,
            submit_endpoint_id=request.submit_endpoint_id,
            param_id=request.param_id,
            context_id=request.context_id,
            payload_template=request.payload_template,
            revisit_endpoint_ids=request.revisit_endpoint_ids,
            role_contexts=[role.model_dump() for role in request.role_contexts],
            max_revisits=request.max_revisits,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
