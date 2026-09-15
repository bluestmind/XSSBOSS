"""Oracle server - receives XSS execution callbacks."""
from fastapi import FastAPI, Query, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import Optional
from datetime import UTC, datetime

from backend_api.db.session import get_db
from backend_api.utils.logger import logger, setup_logging
from backend_api.config import settings
from backend_api.services.oracle_service import process_oracle_callback

# Setup logging
setup_logging()

app = FastAPI(title="XSS Oracle Server")

# CORS middleware - allows callbacks from any scanned target origin
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://.*$",
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/v1/oracle")
def oracle_callback(
    token: str = Query(..., description="Oracle token"),
    msg: Optional[str] = Query(None, description="Optional message"),
    sink: Optional[str] = Query(None, description="Sink type"),
    kind: Optional[str] = Query(None, description="Telemetry classification kind"),
    data: Optional[str] = Query(None, description="Additional data"),
    db: Session = Depends(get_db)
):
    """Receive an XSS Oracle callback. Classification is delegated to the shared
    authoritative service (unknown/expired/consumed rejection, taint-vs-execution,
    atomic single-consume)."""
    result = process_oracle_callback(db, token, kind=kind, sink=sink, data=data, msg=msg)
    return {
        "status": "ok",
        "token": token[:8] + "...",  # Don't expose full token
        "execution_id": result["execution_id"],
        "test_case_id": result["test_case_id"],
        "message": "XSS execution detected" if result["is_execution"] else "Telemetry recorded",
        "is_execution": result["is_execution"],
        "sink": sink,
        "dynamic_sink_id": result["dynamic_sink_id"],
    }


@app.post("/api/v1/oracle")
def oracle_callback_post(
    token: str = Query(..., description="Oracle token"),
    msg: Optional[str] = Query(None, description="Optional message"),
    sink: Optional[str] = Query(None, description="Sink type"),
    kind: Optional[str] = Query(None, description="Telemetry classification kind"),
    data: Optional[str] = Query(None, description="Additional data"),
    db: Session = Depends(get_db)
):
    """Receive XSS Oracle callback via POST."""
    return oracle_callback(token=token, msg=msg, sink=sink, kind=kind, data=data, db=db)


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "XSS Oracle Server"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "oracle_server.main:app",
        host=settings.API_HOST,
        port=8001,
        reload=True
    )
