"""Experiment schemas."""
from pydantic import BaseModel, ConfigDict, Field
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
    limits: Optional[Dict[str, Any]] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    target_name: Optional[str] = None
    target_handle: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class MonitorCheckResponse(BaseModel):
    """Recent payload-check row for the live monitor."""
    id: int
    status: str
    priority: int
    payload_preview: str
    payload: Optional[str] = None
    token_preview: str
    token: Optional[str] = None
    technique: Optional[str] = None
    attempt_count: Optional[int] = 0
    endpoint_id: int
    endpoint_method: str
    endpoint_url: str
    param_name: str
    param_location: str
    context_type: Optional[str] = None
    context_tag: Optional[str] = None
    context_attribute: Optional[str] = None
    context_snippet: Optional[str] = None
    sinks: Optional[List[str]] = None
    updated_at: datetime


class MonitorExecutionResponse(BaseModel):
    """Recent browser execution row for the live monitor."""
    id: int
    test_case_id: int
    oracle_status: str
    duration_ms: Optional[int]
    logs: Optional[str] = None
    raw_logs: Optional[str] = None
    dom_snapshot: Optional[str] = None
    browser_worker_id: Optional[str] = None
    attempt_no: Optional[int] = None
    screenshot_path: Optional[str] = None
    executed_at: datetime
    endpoint_url: Optional[str] = None
    endpoint_method: Optional[str] = None
    param_name: Optional[str] = None
    param_location: Optional[str] = None
    context_type: Optional[str] = None
    context_tag: Optional[str] = None
    context_attribute: Optional[str] = None
    sinks: Optional[List[str]] = None
    payload: Optional[str] = None
    token: Optional[str] = None
    status_code: Optional[int] = None
    response_headers: Optional[Dict[str, Any]] = None
    response_posture: Optional[Dict[str, Any]] = None
    runtime_code_coverage: Optional[Dict[str, Any]] = None
    runtime_lineage: Optional[Dict[str, Any]] = None
    dom_marker_differential: Optional[Dict[str, Any]] = None
    final_url: Optional[str] = None
    taint_flows: Optional[List[Dict[str, Any]]] = None


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


class MonitorStageResponse(BaseModel):
    name: str
    status: str
    attempt_count: int
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None


class ExperimentMonitorResponse(BaseModel):
    """Aggregated live monitor response."""
    experiment: ExperimentResponse
    target: Dict[str, Any]
    stats: Dict[str, int]
    stage: str
    stage_detail: str
    doing_status: Optional[str] = None
    micro_state: Optional[Dict[str, Any]] = None
    micro_events: List[Dict[str, Any]] = Field(default_factory=list)
    river_flow: Optional[Dict[str, Any]] = None
    progress_percent: float
    live_progress: Optional[Dict[str, Any]] = None
    progress_history: List[Dict[str, Any]] = Field(default_factory=list)
    elapsed_seconds: float = 0
    idle_seconds: float = 0
    progress_stale: bool = False
    pipeline_stages: List[MonitorStageResponse] = Field(default_factory=list)
    recent_checks: List[MonitorCheckResponse]
    recent_executions: List[MonitorExecutionResponse]
    recent_findings: List[MonitorFindingResponse]
    activity_log: List[MonitorEventResponse]
    throttle_status: Optional[Dict[str, Any]] = None
    context_distribution: Optional[Dict[str, int]] = None
    performance_metrics: Optional[Dict[str, Any]] = None
    waf_status: Optional[Dict[str, Any]] = None
    attack_surface: Optional[Dict[str, Any]] = None
