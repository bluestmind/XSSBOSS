"""Oracle callback router."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from datetime import UTC, datetime
from backend_api.db.session import get_db
from backend_api.models.test_case import TestCase
from backend_api.models.execution import Execution, OracleStatus
from backend_api.utils.logger import logger
from backend_api.services.oracle_service import process_oracle_callback

router = APIRouter(prefix="/oracle", tags=["oracle"])


class OracleCallback(BaseModel):
    """Oracle callback schema."""
    token: str
    msg: Optional[str] = None
    sink: Optional[str] = None
    data: Optional[str] = None


@router.get("/")
def oracle_callback(
    token: str = Query(..., description="Oracle token"),
    msg: Optional[str] = Query(None, description="Optional message"),
    sink: Optional[str] = Query(None, description="Optional sink type"),
    kind: Optional[str] = Query(None, description="Telemetry classification kind (execution vs taint)"),
    data: Optional[str] = Query(None, description="Optional trace metadata"),
    db: Session = Depends(get_db)
):
    """Handle Oracle callbacks (GET request from browser).

    Delegates to the shared authoritative classifier so this endpoint behaves identically to the
    standalone oracle server: unknown/expired/consumed tokens are rejected, taint/source-read
    callbacks are recorded as telemetry (not a HIT), and only ``kind=execution`` proof consumes
    the token and promotes a Finding.
    """
    logger.info("Received oracle callback")
    result = process_oracle_callback(
        db, token, kind=kind, sink=sink, data=data, msg=msg, create_finding=True
    )
    return {
        "status": "success",
        "message": "Oracle callback recorded" if result["is_execution"] else "Telemetry recorded",
        "is_execution": result["is_execution"],
        "test_case_id": result["test_case_id"],
        "execution_id": result["execution_id"],
        "finding_id": result["finding_id"],
    }
