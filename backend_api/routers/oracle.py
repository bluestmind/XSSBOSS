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
from backend_api.utils.log_serializer import parse_execution_logs, serialize_execution_logs

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
    data: Optional[str] = Query(None, description="Optional trace metadata"),
    db: Session = Depends(get_db)
):
    """Handle Oracle callbacks (GET request from browser).
    
    This endpoint is called by the payload when executed in the browser.
    It marks the test case as executed with an oracle hit.
    """
    logger.info(f"Received oracle callback with token: {token}")
    
    # Find test case by token
    test_case = db.query(TestCase).filter(TestCase.token == token).first()
    if not test_case:
        logger.warning(f"Unknown oracle token received: {token}")
        raise HTTPException(status_code=404, detail="Invalid token")
    if test_case.token_consumed_at:
        logger.warning(f"Replay attempt for already consumed token: {token}")
        raise HTTPException(status_code=410, detail="Token already consumed")
    if test_case.token_expires_at and test_case.token_expires_at < datetime.now(UTC):
        logger.warning(f"Expired token received: {token}")
        raise HTTPException(status_code=410, detail="Token expired")
    logger.info(f"Oracle callback matched test case {test_case.id}")
    
    # Find or create execution record
    execution = (
        db.query(Execution)
        .filter(Execution.test_case_id == test_case.id)
        .order_by(Execution.executed_at.desc())
        .first()
    )
    
    if not execution:
        # Create new execution record
        execution = Execution(
            test_case_id=test_case.id,
            oracle_status=OracleStatus.HIT,
            oracle_token=token,
            executed_at=datetime.now(UTC)
        )
        db.add(execution)
        logger.info(f"Created new execution record for test_case_id={test_case.id}")
    else:
        # Update existing execution
        execution.oracle_status = OracleStatus.HIT
        execution.oracle_token = token
        execution.executed_at = datetime.now(UTC)
        logger.info(f"Updated execution record id={execution.id} to HIT")
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
                logger.error(f"Failed to register dynamic sink: {sink_err}")

    # Commit changes
    db.commit()
    db.refresh(execution)
    
    # Auto-generate Finding on successful XSS execution
    finding_id = None
    try:
        from backend_api.services.result_service import ResultService
        finding = ResultService.create_finding_from_execution(
            db,
            execution_id=execution.id,
            sink_id=dynamic_sink_id
        )
        if finding:
            finding_id = finding.id
            logger.info(f"Auto-generated Finding id={finding.id} (Severity: {finding.severity}) for hit on test_case={test_case.id}")
    except Exception as finding_err:
        logger.error(f"Failed to auto-generate Finding for execution {execution.id}: {finding_err}")
    
    return {
        "status": "success",
        "message": "Oracle callback recorded",
        "test_case_id": test_case.id,
        "execution_id": execution.id,
        "finding_id": finding_id
    }
