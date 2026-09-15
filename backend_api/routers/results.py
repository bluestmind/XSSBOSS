"""Results router."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from backend_api.db.session import get_db
from backend_api.schemas.result import FindingResponse, ExecutionResponse
from backend_api.models.finding import FindingStatus, Severity
from backend_api.models.execution import OracleStatus
from backend_api.services.result_service import ResultService
from backend_api.services.bounty_report_service import BountyReportService
from backend_api.models.evidence import EvidenceArtifact
from backend_api.models.execution import Execution
from backend_api.routers.artifacts import _download_response
from backend_api.utils.log_serializer import (
    parse_execution_logs,
    safe_unparsed_execution_log_text,
    serialize_execution_logs,
)

router = APIRouter(prefix="/results", tags=["results"])


def _safe_execution_response(execution: Execution) -> dict:
    parsed = parse_execution_logs(execution.logs)
    safe_logs = (
        serialize_execution_logs(
            parsed,
            test_case_id=execution.test_case_id,
            attempt_no=execution.attempt_no,
        )
        if parsed
        else safe_unparsed_execution_log_text(execution.logs)
    )
    return {
        "id": execution.id,
        "test_case_id": execution.test_case_id,
        "browser_worker_id": execution.browser_worker_id,
        "oracle_status": execution.oracle_status,
        "oracle_token": execution.oracle_token,
        "logs": safe_logs,
        "screenshot_path": execution.screenshot_path,
        "dom_snapshot": execution.dom_snapshot,
        "executed_at": execution.executed_at,
        "duration_ms": execution.duration_ms,
        "created_at": execution.created_at,
        "updated_at": execution.updated_at,
    }


@router.get("/sarif/{experiment_id}")
def experiment_sarif(experiment_id: int, db: Session = Depends(get_db)):
    """Findings as SARIF 2.1.0 — drops straight into GitHub code-scanning / DefectDojo / CI."""
    from backend_api.services.sarif_report_service import SarifReportService
    return SarifReportService.build_for_experiment(db, experiment_id)


@router.get("/bug-classes")
def bug_classes():
    """The vulnerability-class subsystems this tool covers (XSS + the auditor suite)."""
    from backend_api.services.bug_class_registry import BugClassRegistry
    classes = [{"key": b.key, "name": b.name, "kind": b.kind, "severity": b.default_severity,
                "description": b.description} for b in BugClassRegistry.all()]
    return {"count": len(classes), "bug_classes": classes}


@router.get("/coverage/{experiment_id}")
def experiment_coverage(experiment_id: int, db: Session = Depends(get_db)):
    """Epistemic coverage verdict for an experiment — the 'never falsely report clean' report.

    Returns the decided fraction, confirmed vulnerabilities, and the ranked undecided surface
    (inconclusive/unreached) that a human must close to push winrate toward 100%.
    """
    from backend_api.services.ledger_service import LedgerService
    return LedgerService.coverage_for_experiment(db, experiment_id)


@router.get("/findings", response_model=List[FindingResponse])
def list_findings(
    target_id: Optional[int] = None,
    endpoint_id: Optional[int] = None,
    status: Optional[FindingStatus] = None,
    severity: Optional[Severity] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """List findings with optional filters."""
    findings = ResultService.list_findings(
        db,
        target_id=target_id,
        endpoint_id=endpoint_id,
        status=status,
        severity=severity,
        skip=skip,
        limit=limit
    )
    return [ResultService.enrich_finding(f, db=db) for f in findings]


@router.get("/findings/{finding_id}", response_model=FindingResponse)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    """Get a finding by ID."""
    try:
        finding = ResultService.get_finding(db, finding_id)
        return ResultService.enrich_finding(finding, db=db)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/findings/{finding_id}/screenshot")
def get_finding_screenshot(finding_id: int, db: Session = Depends(get_db)):
    """Return hash-verified screenshot evidence owned by this finding's tenant."""
    finding = ResultService.get_finding(db, finding_id)
    artifact = (
        db.query(EvidenceArtifact)
        .filter(EvidenceArtifact.finding_id == finding.id, EvidenceArtifact.kind == "screenshot")
        .order_by(EvidenceArtifact.id.desc())
        .first()
    )
    if artifact is None and isinstance(finding.evidence_refs, dict):
        test_case_id = finding.evidence_refs.get("test_case_id")
        if test_case_id:
            artifact = (
                db.query(EvidenceArtifact)
                .join(Execution, EvidenceArtifact.execution_id == Execution.id)
                .filter(Execution.test_case_id == test_case_id, EvidenceArtifact.kind == "screenshot")
                .order_by(EvidenceArtifact.id.desc())
                .first()
            )
    if artifact is None:
        raise HTTPException(status_code=404, detail="Screenshot evidence not found")
    return _download_response(artifact)


@router.get("/executions/{execution_id}/screenshot")
def get_execution_screenshot(execution_id: int, db: Session = Depends(get_db)):
    """Return hash-verified screenshot evidence for a tenant-owned execution."""
    execution = ResultService.get_execution(db, execution_id)
    artifact = (
        db.query(EvidenceArtifact)
        .filter(EvidenceArtifact.execution_id == execution.id, EvidenceArtifact.kind == "screenshot")
        .order_by(EvidenceArtifact.id.desc())
        .first()
    )
    if artifact is None:
        raise HTTPException(status_code=404, detail="Screenshot evidence not found")
    return _download_response(artifact)


@router.get("/executions", response_model=List[ExecutionResponse])
def list_executions(
    test_case_id: Optional[int] = None,
    oracle_status: Optional[OracleStatus] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """List executions with optional filters."""
    executions = ResultService.list_executions(
        db,
        test_case_id=test_case_id,
        oracle_status=oracle_status,
        skip=skip,
        limit=limit
    )
    return [_safe_execution_response(execution) for execution in executions]


@router.get("/executions/{execution_id}", response_model=ExecutionResponse)
def get_execution(execution_id: int, db: Session = Depends(get_db)):
    """Get an execution by ID."""
    try:
        execution = ResultService.get_execution(db, execution_id)
        return _safe_execution_response(execution)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/findings/{finding_id}/replay")
def replay_finding_poc(finding_id: int, db: Session = Depends(get_db)):
    """Replay finding's proof of concept by triggering browser execution."""
    try:
        finding = ResultService.get_finding(db, finding_id)
        if not finding.evidence_refs or 'test_case_id' not in finding.evidence_refs:
            raise HTTPException(status_code=400, detail="Finding does not contain a valid test case reference.")
        
        test_case_id = finding.evidence_refs['test_case_id']
        
        # Trigger Celery/Worker execution task
        from browser_workers.worker import execute_test_case_task
        execute_test_case_task.delay(test_case_id)
        
        return {"status": "success", "message": f"Replay task queued for test case {test_case_id}."}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/findings/{finding_id}/bounty-report")
def get_bounty_report(finding_id: int, db: Session = Depends(get_db)):
    """Build a bounty-platform-ready report for a finding."""
    try:
        finding = ResultService.get_finding(db, finding_id)
        return BountyReportService.build_report(db, finding)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/findings/{finding_id}/bounty-report/refresh")
def refresh_bounty_report(finding_id: int, db: Session = Depends(get_db)):
    """Regenerate and store markdown report text for a finding."""
    try:
        finding = ResultService.get_finding(db, finding_id)
        report = BountyReportService.build_report(db, finding)
        finding.report_text = report["markdown"]
        db.commit()
        db.refresh(finding)
        return report
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/findings/{finding_id}/patch-fix")
def generate_patch_fix(
    finding_id: int,
    vulnerable_code: Optional[str] = None,
    language: str = "javascript",
    db: Session = Depends(get_db),
):
    """Generate an AI remediation patch for a confirmed finding via the LLM agent.

    Optionally accepts the vulnerable source snippet to patch in place; otherwise the
    agent infers the likely sink from the reflection context.
    """
    try:
        from backend_api.services.llm_service import LLMService

        finding = ResultService.get_finding(db, finding_id)
        patch = LLMService.generate_patch_fix(
            endpoint=finding.endpoint,
            param=finding.param,
            context=finding.context,
            payload=finding.best_payload,
            vulnerable_code=vulnerable_code,
            language=language,
        )
        return {"finding_id": finding_id, "patch": patch}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
