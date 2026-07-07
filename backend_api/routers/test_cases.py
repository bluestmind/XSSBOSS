"""Manual test case router."""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend_api.db.session import get_db
from backend_api.models.context import Context
from backend_api.models.endpoint import Endpoint
from backend_api.models.experiment import Experiment, ExperimentStatus, ExperimentStrategy
from backend_api.models.param import Param
from backend_api.models.test_case import TestCase, TestCaseStatus
from backend_api.utils.scope_guard import is_endpoint_in_scope
from backend_api.utils.tokenizer import Tokenizer

router = APIRouter(prefix="/test-cases", tags=["test-cases"])


class ManualTestCaseExecute(BaseModel):
    """Manual payload execution request."""

    endpoint_id: int
    param_id: int
    context_id: Optional[int] = None
    payload: str = Field(..., min_length=1)
    token: Optional[str] = Field(default=None, max_length=64)


def _get_or_create_manual_experiment(db: Session, endpoint: Endpoint) -> Experiment:
    """Return a reusable manual testing experiment for the endpoint target."""
    experiment = (
        db.query(Experiment)
        .filter(Experiment.target_id == endpoint.target_id)
        .filter(Experiment.name == "Manual Payloads")
        .first()
    )

    if experiment:
        experiment.status = ExperimentStatus.RUNNING
        if not experiment.started_at:
            experiment.started_at = datetime.utcnow()
        db.flush()
        return experiment

    experiment = Experiment(
        target_id=endpoint.target_id,
        name="Manual Payloads",
        strategy=ExperimentStrategy.QUICK_LIGHT,
        status=ExperimentStatus.RUNNING,
        limits={"mode": "manual", "bug_bounty_guardrails": True},
        started_at=datetime.utcnow(),
    )
    db.add(experiment)
    db.flush()
    return experiment


@router.post("/execute")
def execute_manual_test_case(
    request: ManualTestCaseExecute,
    db: Session = Depends(get_db)
):
    """Create and queue a manual payload execution after scope checks."""
    endpoint = db.query(Endpoint).filter(Endpoint.id == request.endpoint_id).first()
    if not endpoint:
        raise HTTPException(status_code=404, detail=f"Endpoint {request.endpoint_id} not found")

    param = db.query(Param).filter(Param.id == request.param_id).first()
    if not param or param.endpoint_id != endpoint.id:
        raise HTTPException(status_code=400, detail="Parameter does not belong to the selected endpoint")

    if request.context_id is not None:
        context = db.query(Context).filter(Context.id == request.context_id).first()
        if not context or context.endpoint_id != endpoint.id or context.param_id != param.id:
            raise HTTPException(status_code=400, detail="Context does not belong to the selected endpoint/parameter")

    if not is_endpoint_in_scope(endpoint):
        raise HTTPException(
            status_code=403,
            detail="Endpoint URL is outside the target's configured bug bounty scope"
        )

    token = request.token or Tokenizer.generate_token()
    if len(token) > 64:
        raise HTTPException(status_code=400, detail="Oracle token is too long")

    experiment = _get_or_create_manual_experiment(db, endpoint)
    test_case = TestCase(
        experiment_id=experiment.id,
        endpoint_id=endpoint.id,
        param_id=param.id,
        context_id=request.context_id,
        payload=request.payload,
        token=token,
        priority=100,
        status=TestCaseStatus.QUEUED,
    )
    db.add(test_case)
    db.commit()
    db.refresh(test_case)

    try:
        from browser_workers.worker import execute_test_case_task

        async_result = execute_test_case_task.delay(test_case.id)
        response = {
            "status": "queued",
            "queued": True,
            "test_case_id": test_case.id,
            "experiment_id": experiment.id,
            "token": token,
            "task_id": getattr(async_result, "id", None),
        }

        if getattr(async_result, "ready", lambda: False)():
            result = getattr(async_result, "result", None)
            if isinstance(result, dict):
                response.update(result)
                response["status"] = "completed"
                response["queued"] = False

        return response
    except Exception as exc:
        test_case.status = TestCaseStatus.FAILED
        db.commit()
        raise HTTPException(status_code=500, detail=f"Failed to queue manual execution: {exc}") from exc
