"""Burp Suite Integration endpoints."""
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from pydantic import BaseModel

from backend_api.db.session import get_db
from backend_api.config import settings
from backend_api.services.burp_service import BurpService
from backend_api.services.recon_service import ReconService
from backend_api.utils.logger import logger

router = APIRouter(prefix="/burp", tags=["burp"])

# Global queue for sending requests to Burp Suite Repeater
repeater_queue = []
findings_queue = []

class SendToRepeaterRequest(BaseModel):
    finding_id: int
    tool: Optional[str] = "repeater"

class RestImportRequest(BaseModel):
    target_id: int
    api_url: str
    api_key: Optional[str] = None
    task_id: Optional[str] = None

class TriggerScanRequest(BaseModel):
    api_url: str
    target_urls: List[str]
    api_key: Optional[str] = None

class ExtensionPushRequest(BaseModel):
    target_id: int
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str] = None
    response: Optional[Dict[str, Any]] = None

@router.post("/xml")
async def import_burp_xml(
    target_id: int = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Import endpoints from a Burp Suite XML export file."""
    try:
        content = await file.read()
        xml_content = content.decode("utf-8", errors="ignore")
        count = BurpService.import_xml(db, target_id, xml_content)
        return {
            "status": "success",
            "message": f"Successfully imported {count} endpoint(s) from Burp XML.",
            "imported_count": count
        }
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as e:
        logger.error(f"Error handling XML upload: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to process XML: {str(e)}")

@router.post("/rest-import")
def import_burp_rest(
    request: RestImportRequest,
    db: Session = Depends(get_db)
):
    """Import sitemap and scan results directly from Burp REST API."""
    try:
        result = BurpService.import_from_rest(
            db=db,
            target_id=request.target_id,
            api_url=request.api_url,
            api_key=request.api_key,
            task_id=request.task_id
        )
        return result
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as e:
        logger.error(f"Error executing Burp REST API import: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/auto-sync/{target_id}")
def auto_sync_burp_target(
    target_id: int,
    db: Session = Depends(get_db)
):
    """Start a Burp scan for the target and sync findings without manual inputs."""
    try:
        return BurpService.auto_scan_and_sync(
            db=db,
            target_id=target_id,
            api_url=settings.BURP_API_URL,
            api_key=settings.BURP_API_KEY,
        )
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as e:
        logger.error(f"Error executing automatic Burp sync: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/trigger-scan")
def trigger_burp_scan(
    request: TriggerScanRequest
):
    """Trigger a new scan on Burp Suite Pro/DAST using the REST API."""
    try:
        result = BurpService.trigger_scan(
            api_url=request.api_url,
            target_urls=request.target_urls,
            api_key=request.api_key
        )
        return result
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as e:
        logger.error(f"Error triggering Burp REST API scan: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/extension-push")
def receive_extension_push(
    request: ExtensionPushRequest,
    db: Session = Depends(get_db)
):
    """Receive real-time push from XSS Boss Burp Suite Montoya Extension."""
    try:
        # Construct request dict matching ReconService format
        request_data = {
            "method": request.method,
            "url": request.url,
            "headers": request.headers,
            "query": {},
            "body": request.body,
            "json": None
        }
        
        # Extract query parameters from URL if present
        if "?" in request.url:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(request.url)
            request_data["query"] = {
                k: v[0] if len(v) == 1 else v
                for k, v in parse_qs(parsed.query, keep_blank_values=True).items()
            }

        response_data = None
        if request.response:
            response_data = {
                "body": request.response.get("body", "")
            }

        endpoint = ReconService.create_endpoint_from_request(
            db=db,
            target_id=request.target_id,
            method=request.method,
            url=request.url,
            request_data=request_data,
            response_data=response_data
        )
        
        return {
            "status": "success",
            "endpoint_id": endpoint.id,
            "url_pattern": endpoint.url_pattern
        }
    except Exception as e:
        logger.error(f"Error receiving live Montoya extension push: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/send-to-repeater")
def send_to_repeater(
    request: SendToRepeaterRequest,
    db: Session = Depends(get_db)
):
    """Add a request corresponding to a finding to the Burp Repeater queue."""
    from backend_api.models.finding import Finding
    from urllib.parse import urlparse
    import json
    
    finding = db.query(Finding).filter(Finding.id == request.finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    poc = finding.poc_request or {}
    url = poc.get("url") or finding.endpoint.url_pattern
    method = poc.get("method") or finding.endpoint.method
    headers = poc.get("headers") or finding.endpoint.auth_context or {}
    
    # Determine body based on parameter location
    body = None
    if finding.param.location == "body":
        body = f"{finding.param.name}={finding.best_payload}"
    elif finding.param.location == "json":
        body_dict = finding.endpoint.sample_request_body or {}
        if isinstance(body_dict, dict):
            body_dict = body_dict.copy()
        else:
            body_dict = {}
        body_dict[finding.param.name] = finding.best_payload
        body = json.dumps(body_dict)
        headers["Content-Type"] = "application/json"
        
    parsed = urlparse(url)
    secure = parsed.scheme == 'https'
    host = parsed.hostname or ''
    port = parsed.port or (443 if secure else 80)
    
    path_with_query = parsed.path
    if parsed.query:
        path_with_query += f"?{parsed.query}"
    if not path_with_query:
        path_with_query = "/"
        
    # Standardize Host header
    headers_copy = {k: v for k, v in headers.items() if k.lower() != 'host'}
    headers_copy['Host'] = parsed.netloc
    
    raw_lines = [f"{method} {path_with_query} HTTP/1.1"]
    for k, v in headers_copy.items():
        raw_lines.append(f"{k}: {v}")
    raw_lines.append("")
    if body:
        raw_lines.append(body)
    else:
        raw_lines.append("")
        
    raw_request = "\r\n".join(raw_lines)
    label = f"XSSBoss {finding.id} ({finding.param.name})"
    
    repeater_queue.append({
        "host": host,
        "port": port,
        "secure": secure,
        "raw_request": raw_request,
        "label": label,
        "tool": request.tool or "repeater"
    })

    # Also push as finding for Burp Issues dashboard
    raw_resp_body = finding.poc_html or f"<html><body>XSS Boss Verified Finding: {finding.best_payload}</body></html>"
    raw_response_lines = [
        "HTTP/1.1 200 OK",
        "Content-Type: text/html; charset=utf-8",
        f"Content-Length: {len(raw_resp_body)}",
        "",
        raw_resp_body
    ]
    raw_response = "\r\n".join(raw_response_lines)

    evidence_refs = finding.evidence_refs or {}
    sink_details = evidence_refs.get('sink_details', {})
    sink_type = sink_details.get('sink_type', 'unknown')
    js_location = sink_details.get('js_location', 'unknown')
    notes = sink_details.get('notes', '')

    vuln_label = _vuln_label(getattr(finding, "vuln_type", None))
    findings_queue.append({
        "id": finding.id,
        "name": f"XSS Boss: Verified {vuln_label} ({finding.param.location} parameter '{finding.param.name}')",
        "severity": finding.severity.value,
        "confidence": "Certain",
        "url": url,
        "detail": finding.report_text or f"Verified {vuln_label} vulnerability found by XSS Boss.",
        "remediation": "Validate user-controlled input, restrict trust decisions to allowlisted values, and apply the remediation guidance in the report detail.",
        "host": host,
        "port": port,
        "secure": secure,
        "raw_request": raw_request,
        "raw_response": raw_response,
        "sink_type": sink_type,
        "js_location": js_location,
        "notes": notes
    })
    
    return {"status": "queued", "queue_length": len(repeater_queue), "findings_queue_length": len(findings_queue)}

@router.get("/repeater-queue")
def get_repeater_queue():
    """Retrieve and clear the pending requests queue for Burp Repeater."""
    global repeater_queue
    temp = list(repeater_queue)
    repeater_queue.clear()
    return temp

@router.get("/findings-queue")
def get_findings_queue():
    """Retrieve and clear the pending findings queue for Burp SiteMap/Issues dashboard."""
    global findings_queue
    temp = list(findings_queue)
    findings_queue.clear()
    return temp

@router.get("/scan-tasks")
def get_burp_scan_tasks(
    api_url: str = Query(...),
    api_key: Optional[str] = Query(None)
):
    """Retrieve list of scan tasks from Burp REST API."""
    try:
        return BurpService.get_scan_tasks(api_url=api_url, api_key=api_key)
    except Exception as e:
        logger.error(f"Error listing Burp scans: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scan-tasks/{task_id}")
def get_burp_scan_task_details(
    task_id: str,
    api_url: str = Query(...),
    api_key: Optional[str] = Query(None)
):
    """Retrieve details of a specific scan task."""
    try:
        return BurpService.get_scan_task(api_url=api_url, task_id=task_id, api_key=api_key)
    except Exception as e:
        logger.error(f"Error fetching Burp scan status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/scan-tasks/{task_id}")
def cancel_burp_scan_task(
    task_id: str,
    api_url: str = Query(...),
    api_key: Optional[str] = Query(None)
):
    """Cancel/delete a specific scan task in Burp Suite."""
    try:
        success = BurpService.cancel_scan_task(api_url=api_url, task_id=task_id, api_key=api_key)
        return {"status": "success", "canceled": success}
    except Exception as e:
        logger.error(f"Error canceling Burp scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/issue-definitions")
def get_burp_issue_definitions(
    api_url: str = Query(...),
    api_key: Optional[str] = Query(None)
):
    """Retrieve issue definitions from Burp Suite REST API knowledge base."""
    try:
        return BurpService.get_issue_definitions(api_url=api_url, api_key=api_key)
    except Exception as e:
        logger.error(f"Error fetching Burp knowledge base: {e}")
        return {"issues": [], "error": "Burp Suite not reachable"}

# Active Collaborator Payloads Registry
active_collaborator_payloads = []

@router.post("/collaborator-register")
def register_collaborator(data: Dict[str, Any]):
    """Register an active Burp Collaborator payload from the Montoya extension."""
    payload = data.get("payload")
    if payload:
        if payload not in active_collaborator_payloads:
            active_collaborator_payloads.append(payload)
            logger.info(f"Registered active Burp Collaborator payload: {payload}")
    return {"status": "ok", "registered": payload}

@router.get("/collaborator-payload")
def get_collaborator_payload():
    """Retrieve the latest registered active Burp Collaborator payload domain."""
    if active_collaborator_payloads:
        return {"payload": active_collaborator_payloads[-1]}
    return {"payload": None}


def _is_ssrf_canary_test_case(test_case) -> bool:
    """Return whether a collaborator-backed test case was created by the SSRF auditor."""
    from urllib.parse import urlparse

    payload = (getattr(test_case, "payload", "") or "").strip()
    if not payload.startswith(("http://", "https://")):
        return False
    parsed = urlparse(payload)
    host = (parsed.hostname or "").lower()
    if not host.startswith(f"t{test_case.token}".lower()):
        return False
    if (parsed.path or "").startswith("/ssrf"):
        return True
    return any(host.endswith(str(domain).lower()) for domain in active_collaborator_payloads)


def _vuln_label(value: Optional[str]) -> str:
    labels = {
        "xss": "XSS",
        "blind_xss": "Blind XSS",
        "ssrf_oob": "SSRF",
        "open_redirect": "Open Redirect",
        "cors_misconfiguration": "CORS Misconfiguration",
        "path_traversal_lfi": "Path Traversal / LFI",
        "sqli_error_based": "SQL Injection",
    }
    normalized = str(value or "xss").lower()
    return labels.get(normalized, normalized.replace("_", " ").title())

@router.post("/collaborator-interaction")
def report_collaborator_interaction(data: Dict[str, Any], db: Session = Depends(get_db)):
    """Report an out-of-band interaction from Burp Collaborator and create verified findings."""
    token = data.get("test_case_id")  # In our system design, the Montoya extension reports the extracted token in 'test_case_id' parameter
    if not token or token == -1 or token == "-1":
        logger.warning("Collaborator interaction received but token was not extracted or invalid.")
        return {"status": "unmatched"}
        
    from backend_api.models.test_case import TestCase
    # Try querying the test case by its unique token
    test_case = db.query(TestCase).filter(TestCase.token == str(token)).first()
    if not test_case:
        logger.warning(f"Collaborator interaction matched token='{token}' but test case not found in database.")
        return {"status": "test_case_not_found"}
        
    from backend_api.models.finding import Finding, FindingStatus
    from backend_api.models.execution import Execution, OracleStatus
    import base64
    
    is_ssrf_canary = _is_ssrf_canary_test_case(test_case)
    vuln_type = "ssrf_oob" if is_ssrf_canary else "blind_xss"

    # Check if a confirmed finding already exists for this endpoint parameter and vulnerability type
    existing = (
        db.query(Finding)
        .filter(Finding.endpoint_id == test_case.endpoint_id)
        .filter(Finding.param_id == test_case.param_id)
        .filter(Finding.vuln_type == vuln_type)
        .filter(Finding.status == FindingStatus.CONFIRMED.value)
        .first()
    )
    if existing:
        return {"status": "finding_already_exists"}
        
    interaction_type = data.get("type", "unknown")
    client_ip = data.get("client_ip", "unknown")
    timestamp_str = data.get("timestamp", "unknown")
    
    raw_req_b64 = data.get("request")
    raw_query_b64 = data.get("raw_query")
    
    detail_parts = [
        f"Type: {interaction_type}",
        f"Client IP: {client_ip}",
        f"Time: {timestamp_str}"
    ]
    
    if raw_req_b64:
        try:
            decoded_req = base64.b64decode(raw_req_b64).decode(errors="ignore")
            detail_parts.append(f"\n\n**Raw HTTP Request Received by Collaborator:**\n```http\n{decoded_req}\n```")
        except Exception:
            pass
    elif raw_query_b64:
        try:
            decoded_query = base64.b64decode(raw_query_b64).decode(errors="ignore")
            detail_parts.append(f"\n\n**DNS Query details:**\n{decoded_query}")
        except Exception:
            pass
            
    detail_text = "\n".join(detail_parts)
    
    # Register execution record
    execution = Execution(
        test_case_id=test_case.id,
        browser_worker_id=f"burp-collaborator:{interaction_type.lower()}",
        oracle_status=OracleStatus.HIT,
        oracle_token=test_case.token,
        logs=detail_text,
        screenshot_path=None,
        dom_snapshot=None,
        duration_ms=0
    )
    db.add(execution)
    db.flush()
    
    title = "SSRF confirmed via Burp Collaborator" if is_ssrf_canary else "Blind XSS confirmed via Burp Collaborator"
    evidence_summary = (
        f"Out-of-band {interaction_type} interaction received after injecting collaborator URL into "
        f"{test_case.param.name if test_case.param else 'parameter'}."
        if is_ssrf_canary
        else f"Out-of-band {interaction_type} interaction received for collaborator-backed script payload."
    )
    report_text = (
        f"**SSRF CONFIRMED via Burp Collaborator out-of-band callback!**\n\n"
        f"A {interaction_type} interaction was received from client IP {client_ip} at {timestamp_str}. "
        f"This confirms the application or backend infrastructure made an outbound request to the injected canary URL."
        if is_ssrf_canary
        else
        f"**BLIND XSS CONFIRMED via Burp Collaborator out-of-band callback!**\n\n"
        f"An out-of-band {interaction_type} interaction was received from client IP {client_ip} "
        f"at {timestamp_str}. This confirms that the injected script payload has executed in a separate backend/admin context."
    )

    # Create verified collaborator finding record
    finding = Finding(
        endpoint_id=test_case.endpoint_id,
        param_id=test_case.param_id,
        context_id=test_case.context_id,
        sink_id=None,
        vuln_type=vuln_type,
        scanner_module="ssrf_canary_auditor" if is_ssrf_canary else "blind_xss_collaborator",
        confidence="certain",
        evidence_summary=evidence_summary,
        best_payload=test_case.payload,
        severity="high" if is_ssrf_canary else ("critical" if interaction_type == "HTTP" else "high"),
        status=FindingStatus.CONFIRMED.value,
        report_text=report_text,
        evidence_refs={
            "execution_ids": [execution.id],
            "test_case_id": test_case.id,
            "vuln_type": vuln_type,
            "verification": {
                "stored": not is_ssrf_canary,
                "blind": not is_ssrf_canary,
                "ssrf": is_ssrf_canary,
                "title": title,
                "type": interaction_type,
                "client_ip": client_ip,
                "timestamp": timestamp_str
            }
        },
        poc_request={
            "url": test_case.endpoint.url_pattern,
            "method": test_case.endpoint.method,
            "headers": test_case.endpoint.auth_context or {}
        },
        poc_html=detail_text,
        screenshot_path=None
    )
    db.add(finding)
    db.flush()
    db.commit()
    
    # Auto-forward findings back to Burp dashboard
    try:
        BurpService.auto_forward_finding(db, finding)
    except Exception as e:
        logger.error(f"Failed to auto-forward blind finding to Burp: {e}")
        
    return {"status": "created", "finding_id": finding.id}
