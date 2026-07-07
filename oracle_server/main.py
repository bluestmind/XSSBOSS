"""Oracle server - receives XSS execution callbacks."""
from fastapi import FastAPI, Query, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import Optional
from datetime import UTC, datetime

from backend_api.db.session import get_db
from backend_api.models.test_case import TestCase
from backend_api.models.execution import Execution, OracleStatus
from backend_api.utils.logger import logger, setup_logging
from backend_api.config import settings
from backend_api.utils.log_serializer import parse_execution_logs, serialize_execution_logs

# Setup logging
setup_logging()

app = FastAPI(title="XSS Oracle Server")


def _legacy_callback_confirms_execution(token: str, sink: Optional[str], data: Optional[str]) -> bool:
    """Conservatively classify callbacks from pre-``kind`` oracle scripts.

    Reaching innerHTML, setAttribute, or another taint sink is not proof that code
    executed. Legacy callbacks are accepted only when they contain direct execution
    evidence tied to this test token.
    """
    if not sink:
        return False
    normalized_sink = str(sink).strip()
    sink_lower = normalized_sink.lower()
    if normalized_sink == token or token in normalized_sink:
        return True
    if sink_lower in {"taggedtemplateliteral", "directexecution"}:
        return True
    if sink_lower in {"alert", "prompt", "confirm"}:
        return bool(data and token in data)
    return False

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
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
    """Receive XSS Oracle callback when payload executes.
    
    Args:
        token: Oracle token from test case
        msg: Optional message
        sink: Sink type (if from dynamic sink tracking)
        data: Additional data (JSON string)
        db: Database session
        
    Returns:
        Response dictionary
    """
    # Find test case by token
    test_case = db.query(TestCase).filter(TestCase.token == token).first()
    if not test_case:
        logger.warning("Oracle callback used an unknown token")
        raise HTTPException(status_code=404, detail="Token not found")
    expiry_now = datetime.now(UTC)
    if test_case.token_expires_at and test_case.token_expires_at < (
        expiry_now if test_case.token_expires_at.tzinfo else expiry_now.replace(tzinfo=None)
    ):
        logger.warning("Rejected expired oracle callback")
        raise HTTPException(status_code=410, detail="Token expired")
    logger.info(f"Oracle callback received for test_case_id={test_case.id}, sink={sink}")
    
    # Find or create execution record
    execution = (
        db.query(Execution)
        .filter(Execution.test_case_id == test_case.id)
        .order_by(Execution.executed_at.desc())
        .first()
    )
    
    # Distinguish between a source read trace callback and a real sink execution
    if kind:
        is_xss_hit = str(kind).strip().lower() == "execution"
    else:
        is_xss_hit = _legacy_callback_confirms_execution(token, sink, data)

    if not execution:
        # Create new execution record
        execution = Execution(
            test_case_id=test_case.id,
            oracle_status=OracleStatus.HIT if is_xss_hit else OracleStatus.MISSED,
            oracle_token=token if is_xss_hit else None,
            executed_at=datetime.now(UTC)
        )
        db.add(execution)
        logger.info(f"Created new execution record for test_case_id={test_case.id} (is_xss_hit={is_xss_hit})")
    else:
        # Update existing execution
        if is_xss_hit:
            execution.oracle_status = OracleStatus.HIT
            execution.oracle_token = token
            logger.info(f"Updated execution record id={execution.id} to HIT")
        execution.executed_at = datetime.now(UTC)
    if is_xss_hit:
        test_case.token_consumed_at = datetime.now(UTC)
    
    # Store additional data if provided
    dynamic_sink_id = None
    if sink or data:
        logs = parse_execution_logs(execution.logs)
        logs['sink'] = sink
        logs['data'] = data
        execution.logs = serialize_execution_logs(logs)
        
        # Try to resolve or create a dynamic Sink record in the database
        if test_case.context_id:
            try:
                import json
                from backend_api.models.sink import Sink, DetectedVia
                
                # Parse trace metadata if present
                js_location = "unknown"
                notes_trace = ""
                if data:
                    try:
                        parsed_data = json.loads(data)
                        if isinstance(parsed_data, dict):
                            filename = parsed_data.get("filename", "unknown")
                            line_num = parsed_data.get("line", 0)
                            col_num = parsed_data.get("column", 0)
                            js_location = f"{filename}:{line_num}:{col_num}"
                            notes_trace = f"Value: {parsed_data.get('value', '')[:200]}\nStack: {parsed_data.get('stack', '')}"
                    except Exception as parse_err:
                        logger.error(f"Error parsing data payload for dynamic sink: {parse_err}")
                
                # Check if this dynamic sink already exists
                existing_dynamic_sink = (
                    db.query(Sink)
                    .filter(Sink.context_id == test_case.context_id)
                    .filter(Sink.sink_type == sink)
                    .filter(Sink.detected_via == DetectedVia.DYNAMIC)
                    .first()
                )
                
                if not existing_dynamic_sink:
                    dynamic_sink = Sink(
                        context_id=test_case.context_id,
                        sink_type=sink,
                        js_location=js_location,
                        detected_via=DetectedVia.DYNAMIC,
                        notes=f"Dynamically hit during browser fuzzing.\n{notes_trace}"
                    )
                    db.add(dynamic_sink)
                    db.commit()
                    db.refresh(dynamic_sink)
                    dynamic_sink_id = dynamic_sink.id
                    logger.info(f"Dynamically registered new Sink id={dynamic_sink_id} for context_id={test_case.context_id}")
                else:
                    dynamic_sink_id = existing_dynamic_sink.id
                    # Update location and stack details
                    existing_dynamic_sink.js_location = js_location
                    existing_dynamic_sink.notes = f"Dynamically hit during browser fuzzing.\n{notes_trace}"
                    db.commit()
            except Exception as sink_err:
                logger.error(f"Failed to record dynamic sink: {sink_err}", exc_info=True)
    
    db.commit()
    db.refresh(execution)
    
    return {
        "status": "ok",
        "token": token[:8] + "...",  # Don't expose full token
        "execution_id": execution.id,
        "test_case_id": test_case.id,
        "message": "XSS execution detected",
        "sink": sink,
        "dynamic_sink_id": dynamic_sink_id
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
