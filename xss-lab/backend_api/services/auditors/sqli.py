"""Error-based SQL injection auditor."""
import re
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy.orm import Session

from backend_api.models.endpoint import Endpoint
from backend_api.models.finding import Finding, FindingStatus, Severity
from backend_api.models.param import Param
from backend_api.services.auditors.http_param import benign_value, curl_command, send_param_probe
from backend_api.utils.logger import logger


SQL_ERROR_SIGNATURES = [
    ("mysql", re.compile(r"(sql syntax.*mysql|mysql_fetch_|mysql_num_rows|you have an error in your sql syntax)", re.I)),
    ("postgresql", re.compile(r"(postgresql.*error|pg_query|pg_exec|unterminated quoted string|syntax error at or near)", re.I)),
    ("sqlite", re.compile(r"(sqlite3?::|sqlite error|sqliteexception|near \".+\": syntax error)", re.I)),
    ("mssql", re.compile(r"(microsoft ole db provider for sql server|odbc sql server driver|sql server.*driver|unclosed quotation mark)", re.I)),
    ("oracle", re.compile(r"(ora-\d{5}|oracle error|quoted string not properly terminated)", re.I)),
    ("generic", re.compile(r"(sqlstate\[[^\]]+\]|database error|db error|jdbc exception|driver exception)", re.I)),
]


class ErrorBasedSqliAuditor:
    """Detect SQL injection through newly introduced DB error signatures."""

    PAYLOADS = [
        "'",
        "\"",
        "')",
        "\")",
        "' OR '1'='1",
        "1' ORDER BY 1--",
    ]

    @staticmethod
    def audit_endpoints(db: Session, endpoints: Iterable[Endpoint], param_limit: int = 40) -> List[Finding]:
        findings: List[Finding] = []
        checked = 0

        for endpoint in endpoints:
            candidate_params = [
                param for param in (endpoint.params or [])
                if param.location in {"query", "body", "json", "path"}
            ]
            for param in candidate_params:
                if checked >= param_limit:
                    break
                checked += 1
                try:
                    finding = ErrorBasedSqliAuditor._audit_param(db, endpoint, param)
                    if finding:
                        findings.append(finding)
                except Exception as err:
                    logger.debug(f"SQLi audit skipped param {getattr(param, 'id', '?')}: {err}")
            if checked >= param_limit:
                break

        if findings:
            db.commit()
            for finding in findings:
                db.refresh(finding)
        return findings

    @staticmethod
    def _find_signature(text: str, baseline: str) -> Optional[Dict[str, str]]:
        for engine, pattern in SQL_ERROR_SIGNATURES:
            match = pattern.search(text or "")
            if not match:
                continue
            if pattern.search(baseline or ""):
                continue
            return {
                "engine": engine,
                "signature": match.group(0)[:160],
            }
        return None

    @staticmethod
    def _audit_param(db: Session, endpoint: Endpoint, param: Param) -> Optional[Finding]:
        baseline = send_param_probe(endpoint, param, benign_value(param))
        baseline_text = baseline.get("text") or ""

        for payload in ErrorBasedSqliAuditor.PAYLOADS:
            probe = send_param_probe(endpoint, param, payload)
            signature = ErrorBasedSqliAuditor._find_signature(probe.get("text") or "", baseline_text)
            if not signature:
                continue
            return ErrorBasedSqliAuditor._upsert_finding(db, endpoint, param, payload, probe, signature)

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
            .filter(Finding.vuln_type == "sqli_error_based")
            .first()
        )

        evidence_summary = f"Database error signature for {signature['engine']} appeared only after SQL metacharacter injection."
        report_text = f"""Error-Based SQL Injection

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
- Database family: `{signature['engine']}`
- Error signature: `{signature['signature']}`
- HTTP status: `{probe['status_code']}`

**Impact:**
The application appears to pass user-controlled input into a SQL query without safe parameterization, causing database errors to leak.

**Recommendation:**
Use parameterized queries/prepared statements, validate input type and range, and suppress detailed database errors from HTTP responses.
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
            "sqli": {
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
            existing.scanner_module = "sqli_error_auditor"
            existing.confidence = "firm"
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
            vuln_type="sqli_error_based",
            scanner_module="sqli_error_auditor",
            confidence="firm",
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
