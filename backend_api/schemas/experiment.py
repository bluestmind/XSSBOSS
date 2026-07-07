"""Experiment schemas."""
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from datetime import datetime
from backend_api.models.experiment import ExperimentStrategy, ExperimentStatus


class ExperimentCreate(BaseModel):
    """Experiment creation schema."""
    target_id: int
    name: str
    strategy: ExperimentStrategy
    limits: Optional[Dict[str, Any]] = None


class ExperimentUpdate(BaseModel):
    """Experiment update schema."""
    name: Optional[str] = None
    strategy: Optional[ExperimentStrategy] = None
    status: Optional[ExperimentStatus] = None
    limits: Optional[Dict[str, Any]] = None


class ExperimentResponse(BaseModel):
    """Experiment response schema."""
    id: int
    target_id: int
    name: str
    strategy: ExperimentStrategy
    status: ExperimentStatus
    limits: Optional[Dict[str, Any]]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class MonitorCheckResponse(BaseModel):
    """Recent payload-check row for the live monitor."""
    id: int
    status: str
    priority: int
    payload_preview: str
    token_preview: str
    endpoint_id: int
    endpoint_method: str
    endpoint_url: str
    param_name: str
    param_location: str
    context_type: Optional[str] = None
    updated_at: datetime


class MonitorExecutionResponse(BaseModel):
    """Recent browser execution row for the live monitor."""
    id: int
    test_case_id: int
    oracle_status: str
    duration_ms: Optional[int]
    logs: Optional[str] = None
    screenshot_path: Optional[str]
    executed_at: datetime
    endpoint_url: Optional[str] = None
    param_name: Optional[str] = None
    payload: Optional[str] = None


class MonitorFindingResponse(BaseModel):
    """Recent finding row for the live monitor."""
    id: int
    severity: str
    status: str
    vuln_type: str
    scanner_module: str
    confidence: str
    evidence_summary: Optional[str] = None
    endpoint_url: str
    param_name: str
    payload_preview: str
    created_at: datetime
    poc_request: Optional[Dict[str, Any]] = None
    screenshot_path: Optional[str] = None
    execution_logs: Optional[str] = None
    dom_snapshot: Optional[str] = None


class MonitorEventResponse(BaseModel):
    """Operator-readable event row for the one-page monitor."""
    timestamp: datetime
    level: str
    phase: str
    message: str
    detail: Optional[str] = None


class ExperimentMonitorResponse(BaseModel):
    """Aggregated live monitor response."""
    experiment: ExperimentResponse
    target: Dict[str, Any]
    stats: Dict[str, int]
    stage: str
    stage_detail: str
    progress_percent: float
    recent_checks: List[MonitorCheckResponse]
    recent_executions: List[MonitorExecutionResponse]
    recent_findings: List[MonitorFindingResponse]
    activity_log: List[MonitorEventResponse]
    throttle_status: Optional[Dict[str, Any]] = None

