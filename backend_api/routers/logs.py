"""Diagnostic Logs API Router."""
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
import json
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend_api.db.session import get_db
from backend_api.models.experiment import Experiment
from backend_api.models.log_event import LogEvent
from backend_api.models.target import Target
from backend_api.services.log_service import LogService
from backend_api.tenancy import current_tenant_id

router = APIRouter(prefix="/logs", tags=["Diagnostic Logs"])


class LogCreate(BaseModel):
    level: str = Field(default="INFO", max_length=20)
    module: str = Field(default="custom", max_length=50)
    message: str = ""
    detail: Optional[str] = None
    experiment_id: Optional[int] = Field(default=None, ge=1)
    target_id: Optional[int] = Field(default=None, ge=1)
    data: Optional[Dict[str, Any]] = None


@router.get("", response_model=Dict[str, Any])
def get_logs(
    level: Optional[str] = Query(None, description="Log level filter: ALL, HIT, ERROR, WARNING, INFO, DEBUG"),
    module: Optional[str] = Query(None, description="Subsystem/module filter: crawler, profiler, fuzzer, browser, auditor, burp, rate_limiter"),
    experiment_id: Optional[int] = Query(None, description="Filter by experiment ID"),
    target_id: Optional[int] = Query(None, description="Filter by target ID"),
    search: Optional[str] = Query(None, description="Keyword search in messages and details"),
    since_id: Optional[int] = Query(None, description="Fetch logs created after this ID"),
    limit: int = Query(150, ge=1, le=1000, description="Max log items to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
):
    """Retrieve filtered pipeline diagnostic logs."""
    return LogService.get_logs(
        db=db,
        level=level,
        module=module,
        experiment_id=experiment_id,
        target_id=target_id,
        search=search,
        since_id=since_id,
        limit=limit,
        offset=offset,
    )


@router.get("/stats", response_model=Dict[str, Any])
def get_log_stats(
    experiment_id: Optional[int] = Query(None, description="Filter stats by experiment ID"),
    db: Session = Depends(get_db),
):
    """Get aggregate log statistics across pipeline stages."""
    return LogService.get_stats(db=db, experiment_id=experiment_id)


@router.get("/export")
def export_experiment_logs(
    experiment_id: int = Query(..., ge=1, description="Experiment ID to export"),
    db: Session = Depends(get_db),
):
    """Download the entire durable event stream as chronological JSON Lines."""
    rows = (
        LogService.query_events(db)
        .filter(LogEvent.experiment_id == experiment_id)
        .order_by(LogEvent.id.asc())
        .all()
    )

    def generate():
        for row in rows:
            yield json.dumps(row.to_dict(), ensure_ascii=False, default=str) + "\n"

    return StreamingResponse(
        generate(),
        media_type="application/x-ndjson",
        headers={
            "Content-Disposition": f'attachment; filename="experiment-{experiment_id}-events.jsonl"',
            "X-Event-Count": str(len(rows)),
        },
    )


@router.get("/stream")
async def stream_logs():
    """Stream live diagnostic logs via Server-Sent Events (SSE)."""
    return StreamingResponse(
        LogService.stream_logs(current_tenant_id.get()),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.delete("/clear")
def clear_logs(
    experiment_id: Optional[int] = Query(None, description="Optional experiment ID to clear logs for"),
    db: Session = Depends(get_db),
):
    """Clear diagnostic log entries."""
    deleted_count = LogService.clear_logs(db=db, experiment_id=experiment_id)
    return {"status": "ok", "deleted_count": deleted_count}


@router.post("/emit")
def emit_custom_log(
    payload: LogCreate,
    db: Session = Depends(get_db),
):
    """Emit a custom diagnostic log entry."""
    if db.info.get("tenant_id") is not None:
        if payload.experiment_id is None and payload.target_id is None:
            raise HTTPException(422, "Specify an experiment or target for the log entry")
        if payload.target_id is not None and db.get(Target, payload.target_id) is None:
            raise HTTPException(404, "Target not found")
        if payload.experiment_id is not None:
            experiment = db.get(Experiment, payload.experiment_id)
            if experiment is None:
                raise HTTPException(404, "Experiment not found")
            if payload.target_id is not None and payload.target_id != experiment.target_id:
                raise HTTPException(422, "The experiment belongs to a different target")

    event = LogService.emit(db=db, **payload.model_dump())
    return {"status": "ok", "event": event}
