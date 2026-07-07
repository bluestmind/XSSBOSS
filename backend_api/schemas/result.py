"""Result schemas."""
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime
from backend_api.models.finding import Severity, FindingStatus
from backend_api.models.execution import OracleStatus


class FindingResponse(BaseModel):
    """Finding response schema."""
    id: int
    endpoint_id: int
    param_id: int
    context_id: Optional[int]
    sink_id: Optional[int]
    vuln_type: str
    scanner_module: str
    confidence: str
    evidence_summary: Optional[str]
    best_payload: str
    severity: Severity
    status: FindingStatus
    report_text: Optional[str]
    evidence_refs: Optional[Dict[str, Any]]
    poc_request: Optional[Dict[str, Any]]
    poc_html: Optional[str]
    screenshot_path: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ExecutionResponse(BaseModel):
    """Execution response schema."""
    id: int
    test_case_id: int
    browser_worker_id: Optional[str]
    oracle_status: OracleStatus
    oracle_token: Optional[str]
    logs: Optional[str]
    screenshot_path: Optional[str]
    dom_snapshot: Optional[str]
    executed_at: datetime
    duration_ms: Optional[int]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

