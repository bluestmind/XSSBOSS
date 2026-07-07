"""CRLF & HTTP Header Injection / Response Splitting Auditor.

Audits candidate parameters for carriage return / line feed (%0d%0a, \r\n, and Unicode CRLF)
injections reflected in HTTP response headers (Location, Set-Cookie, Content-Disposition, etc.)
that allow header injection or HTTP response splitting into reflected XSS.
"""
import re
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional
import httpx
from sqlalchemy.orm import Session

from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from backend_api.models.finding import Finding, FindingStatus, Severity
from backend_api.utils.logger import logger
from backend_api.utils.request_builder import RequestBuilder


class CRLFInjectionAuditor:
    """Audits endpoints for HTTP header injection and response splitting."""

    CANDIDATE_PARAMS = {
        'url', 'redirect', 'next', 'return', 'dest', 'lang', 'language',
        'theme', 'locale', 'country', 'currency', 'session', 'ref', 'view'
    }

    # High-signal CRLF test probes
    PROBES = [
        # Standard URL-encoded CRLF injecting a canary header
        ("%0d%0aX-XSSBoss-Injected:%20canary_header_ok", "header_injection", Severity.MEDIUM),
        # CRLF with Set-Cookie injection
        ("%0d%0aSet-Cookie:%20xssboss_canary=1;%20Path=/;%20HttpOnly", "cookie_injection", Severity.MEDIUM),
        # Response splitting with double CRLF injecting HTML body
        ("%0d%0a%0d%0a<svg/onload=__XSS__('crlf_split')>", "response_splitting_xss", Severity.HIGH),
        # Unicode CRLF bypass (%E5%98%8D%E5%98%8A -> \r\n after normalization)
        ("%E5%98%8D%E5%98%8AX-Unicode-CRLF:%20canary_ok", "unicode_crlf_injection", Severity.MEDIUM),
        # Raw / tab space variant
        ("%0d%0a%20X-Folded-Header:%20canary_ok", "header_folding_injection", Severity.LOW)
    ]

    @staticmethod
    def audit_endpoints(db: Session, endpoints: Iterable[Endpoint], limit: int = 30) -> List[Finding]:
        """Audit candidate endpoints and parameters for CRLF and header injection."""
        findings: List[Finding] = []
        checked = 0

        for endpoint in endpoints:
            if checked >= limit:
                break
            if not endpoint or not endpoint.url_pattern.startswith(("http://", "https://")):
                continue

            checked += 1
            for param in endpoint.params:
                if param.location not in ("query", "body", "json"):
                    continue
                norm_name = re.sub(r'[^a-z0-9]', '', param.name.lower())
                if norm_name not in CRLFInjectionAuditor.CANDIDATE_PARAMS and not any(cand in norm_name for cand in ['url', 'red', 'lang', 'loc', 'cookie', 'next']):
                    continue

                for payload, vuln_type, severity in CRLFInjectionAuditor.PROBES:
                    try:
                        hit = CRLFInjectionAuditor._test_payload(endpoint, param, payload)
                        if hit:
                            finding = CRLFInjectionAuditor._upsert_finding(
                                db=db,
                                endpoint=endpoint,
                                param=param,
                                payload=payload,
                                vuln_type=hit.get("type", vuln_type),
                                severity=hit.get("severity", severity),
                                details=hit
                            )
                            if finding:
                                findings.append(finding)
                                break  # Move to next param on verified hit
                    except Exception as err:
                        logger.debug(f"CRLF probe failed on {param.name}: {err}")
                        continue

        if findings:
            db.commit()
            for f in findings:
                db.refresh(f)
        return findings

    @staticmethod
    def _test_payload(endpoint: Endpoint, param: Param, payload: str) -> Optional[Dict[str, Any]]:
        """Send probe request and check HTTP response headers and body."""
        target_url = RequestBuilder.url_with_query_param(endpoint.url_pattern, param.name, payload)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

        try:
            with httpx.Client(timeout=4.0, follow_redirects=False, verify=False) as client:
                resp = client.get(target_url, headers=headers)
                
                # Check 1: Injected header present in response headers
                for h_name, h_val in resp.headers.items():
                    if "x-xssboss-injected" in h_name.lower() or "x-unicode-crlf" in h_name.lower() or "x-folded-header" in h_name.lower():
                        return {
                            "type": "header_injection",
                            "injected_header": h_name,
                            "header_value": h_val,
                            "status_code": resp.status_code
                        }
                    if h_name.lower() == "set-cookie" and "xssboss_canary=1" in h_val:
                        return {
                            "type": "cookie_injection",
                            "injected_cookie": h_val,
                            "status_code": resp.status_code
                        }

                # Check 2: Response splitting body reflection
                if "<svg/onload=__XSS__('crlf_split')>" in resp.text:
                    return {
                        "type": "response_splitting_xss",
                        "severity": Severity.HIGH,
                        "status_code": resp.status_code,
                        "evidence": "Injected HTML body confirmed after response splitting headers."
                    }
        except Exception:
            pass

        return None

    @staticmethod
    def _upsert_finding(
        db: Session,
        endpoint: Endpoint,
        param: Param,
        payload: str,
        vuln_type: str,
        severity: Severity,
        details: Dict[str, Any]
    ) -> Optional[Finding]:
        """Save or update finding in database."""
        try:
            evidence_summary = f"HTTP Header Injection ({vuln_type}) detected via parameter '{param.name}'. Evidence: {details}"
            finding = Finding(
                endpoint_id=endpoint.id,
                param_id=param.id,
                context_id=None,
                sink_id=None,
                vuln_type=vuln_type,
                scanner_module="crlf_auditor",
                confidence="firm",
                severity=severity,
                status=FindingStatus.CONFIRMED,
                best_payload=payload,
                evidence_summary=evidence_summary,
                report_text=evidence_summary,
            )
            db.add(finding)
            return finding
        except Exception as e:
            logger.debug(f"Failed to upsert CRLF finding: {e}")
            return None
