"""Path traversal and local file inclusion auditor."""
import re
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy.orm import Session

from backend_api.models.endpoint import Endpoint
from backend_api.models.finding import Finding, FindingStatus, Severity
from backend_api.models.param import Param
from backend_api.services.auditors.http_param import benign_value, curl_command, send_param_probe
from backend_api.utils.logger import logger


LFI_PARAM_HINTS = {
    "file",
    "filepath",
    "filename",
    "path",
    "page",
    "template",
    "include",
    "view",
    "download",
    "document",
    "doc",
    "image",
    "img",
    "avatar",
    "attachment",
    "resource",
}


class PathTraversalAuditor:
    """Detect high-confidence file-read behavior from controllable params."""

    PAYLOADS = [
        "../../../../../../../../etc/passwd",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "../../../../../../../../windows/win.ini",
    ]

    @staticmethod
    def audit_endpoints(db: Session, endpoints: Iterable[Endpoint], param_limit: int = 30) -> List[Finding]:
        findings: List[Finding] = []
        checked = 0

        for endpoint in endpoints:
            candidate_params = [
                param for param in (endpoint.params or [])
                if param.location in {"query", "body", "json", "path"}
                and PathTraversalAuditor._is_candidate_param(param.name)
            ]
            for param in candidate_params:
                if checked >= param_limit:
                    break
                checked += 1
                try:
                    finding = PathTraversalAuditor._audit_param(db, endpoint, param)
                    if finding:
                        findings.append(finding)
                except Exception as err:
                    logger.debug(f"Path traversal audit skipped param {getattr(param, 'id', '?')}: {err}")
            if checked >= param_limit:
                break

        if findings:
            db.commit()
            for finding in findings:
                db.refresh(finding)
        return findings

    @staticmethod
    def _is_candidate_param(name: str) -> bool:
        normalized = (name or "").strip().lower().replace("-", "_")
        return normalized in LFI_PARAM_HINTS or any(hint in normalized for hint in LFI_PARAM_HINTS)

    @staticmethod
    def _detect_signature(text: str, baseline: str) -> Optional[Dict[str, str]]:
        lowered = text.lower()
        baseline_lowered = baseline.lower()

        passwd_match = re.search(r"(?m)^root:[^:\n]*:0:0:", text)
        if passwd_match and not re.search(r"(?m)^root:[^:\n]*:0:0:", baseline):
            return {
                "file": "/etc/passwd",
                "signature": passwd_match.group(0)[:120],
                "description": "Unix passwd file content signature appeared in the response.",
            }

        win_markers = ["[fonts]", "[extensions]"]
        if all(marker in lowered for marker in win_markers) and not all(marker in baseline_lowered for marker in win_markers):
            return {
                "file": "windows/win.ini",
                "signature": "[fonts] and [extensions]",
                "description": "Windows win.ini marker sections appeared in the response.",
            }

        return None

    @staticmethod
    def _audit_param(db: Session, endpoint: Endpoint, param: Param) -> Optional[Finding]:
        baseline = send_param_probe(endpoint, param, benign_value(param))
        baseline_text = baseline.get("text") or ""

        for payload in PathTraversalAuditor.PAYLOADS:
            probe = send_param_probe(endpoint, param, payload)
            signature = PathTraversalAuditor._detect_signature(probe.get("text") or "", baseline_text)
            if not signature:
                continue
            return PathTraversalAuditor._upsert_finding(db, endpoint, param, payload, probe, signature)

        return None

    @staticmethod
    def _upsert_finding(
        db: Session,
        endpoint: Endpoint,
        param: Param,
        payload: str,
        probe: Dict[str, Any],
        signature: Dict[str, str],
    ) -> Finding:
        existing = (
            db.query(Finding)
            .filter(Finding.endpoint_id == endpoint.id)
            .filter(Finding.param_id == param.id)
            .filter(Finding.vuln_type == "path_traversal_lfi")
            .first()
        )

        evidence_summary = f"Response contained {signature['file']} content markers after path traversal payload injection."
        report_text = f"""Path Traversal / Local File Inclusion

**Summary:**
{evidence_summary}

**Affected Endpoint:**
- Method: {endpoint.method}
- URL: {endpoint.url_pattern}
- Parameter: {param.name} ({param.location})

**Payload:**
```
{payload}
```

**Evidence:**
- File signature: `{signature['signature']}`
- HTTP status: `{probe['status_code']}`

**Impact:**
An attacker may be able to read local files from the server or application runtime environment.

**Recommendation:**
Do not pass user-controlled paths directly to filesystem APIs. Use fixed file identifiers, normalize paths, and enforce an allowlisted base directory.
"""
        poc_request = {
            "command": curl_command(probe["request"]),
            "method": probe["request"]["method"],
            "url": probe["request"]["url"],
            "headers": probe["request"].get("headers") or {},
            "payload": payload,
            "param_location": param.location,
        }
        evidence_refs = {
            "path_traversal": {
                "payload": payload,
                "signature": signature,
                "status_code": probe["status_code"],
                "response_headers": probe.get("headers") or {},
            }
        }

        if existing:
            existing.best_payload = payload
            existing.severity = Severity.HIGH.value
            existing.status = FindingStatus.DRAFT.value
            existing.scanner_module = "path_traversal_auditor"
            existing.confidence = "certain"
            existing.evidence_summary = evidence_summary
            existing.report_text = report_text
            existing.evidence_refs = evidence_refs
            existing.poc_request = poc_request
            return existing

        finding = Finding(
            endpoint_id=endpoint.id,
            param_id=param.id,
            context_id=None,
            sink_id=None,
            vuln_type="path_traversal_lfi",
            scanner_module="path_traversal_auditor",
            confidence="certain",
            evidence_summary=evidence_summary,
            best_payload=payload,
            severity=Severity.HIGH.value,
            status=FindingStatus.DRAFT.value,
            report_text=report_text,
            evidence_refs=evidence_refs,
            poc_request=poc_request,
            poc_html=None,
            screenshot_path=None,
        )
        db.add(finding)
        db.flush()
        return finding
