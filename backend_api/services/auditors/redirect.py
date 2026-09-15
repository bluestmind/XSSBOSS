"""Open Redirect and Client-Side URL Scheme Hijacking Auditor."""
import re
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional
import httpx
from sqlalchemy.orm import Session

from backend_api.config import settings
from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from backend_api.models.finding import Finding, FindingStatus, Severity
from backend_api.utils.logger import logger
from backend_api.utils.request_builder import RequestBuilder
from backend_api.utils.rate_limiter import rate_limited_call

class RedirectAuditor:
    """Detect Open Redirect and protocol scheme hijacking (escalating to DOM XSS)."""

    CANDIDATE_PARAMS = {
        'url', 'target', 'redirect', 'returnurl', 'return_to', 'returnto',
        'next', 'dest', 'destination', 'originurl', 'callback', 'checkout_url',
        'continue', 'forward', 'to', 'nocache', 'link', 'out', 'view', 'r'
    }

    CANARY_HOST = "xssboss.invalid"

    PAYLOADS = [
        ("https://xssboss.invalid/redirect-canary", "open_redirect", Severity.MEDIUM),
        ("//xssboss.invalid/redirect-canary", "open_redirect", Severity.MEDIUM),
        ("/\\xssboss.invalid/redirect-canary", "open_redirect", Severity.MEDIUM),
        ("javascript:alert(document.domain)", "dom_xss", Severity.HIGH),
        ("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "dom_xss", Severity.HIGH)
    ]

    @staticmethod
    def audit_endpoints(db: Session, endpoints: Iterable[Endpoint], limit: int = 30) -> List[Finding]:
        """Audit candidate endpoints and parameters for open redirect and scheme execution."""
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
                if norm_name not in RedirectAuditor.CANDIDATE_PARAMS and not any(cand in norm_name for cand in ['redirect', 'return', 'dest', 'url', 'target']):
                    continue

                for payload, vuln_type, severity in RedirectAuditor.PAYLOADS:
                    try:
                        hit = RedirectAuditor._test_payload(endpoint, param, payload)
                        if hit:
                            finding = RedirectAuditor._upsert_finding(
                                db=db,
                                endpoint=endpoint,
                                param=param,
                                payload=payload,
                                vuln_type=vuln_type,
                                severity=severity,
                                details=hit
                            )
                            if finding:
                                findings.append(finding)
                                break  # Move to next param on verified hit
                    except Exception as err:
                        logger.debug(f"Redirect probe failed on {param.name}: {err}")
                        continue

        if findings:
            db.commit()
            for f in findings:
                db.refresh(f)
        return findings

    @staticmethod
    def _test_payload(endpoint: Endpoint, param: Param, payload: str) -> Optional[Dict[str, Any]]:
        """Send probe without following redirects to inspect 3xx Location header or reflection."""
        target_url = RequestBuilder.url_with_query_param(endpoint.url_pattern, param.name, payload)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
        from backend_api.utils.stealth import get_http_proxy_kwargs
        proxy_kwargs = get_http_proxy_kwargs(rotated=True)

        try:
            with httpx.Client(
                timeout=httpx.Timeout(2.5, connect=1.5),
                verify=not settings.ALLOW_INSECURE_TLS,
                follow_redirects=False,
                **proxy_kwargs,
            ) as client:
                res = rate_limited_call(
                    target_url,
                    lambda: client.get(target_url, headers=headers),
                )
                loc = res.headers.get("Location", "")
                if loc:
                    parsed_loc = urllib.parse.urlparse(loc)
                    is_canary_netloc = parsed_loc.netloc.lower() == RedirectAuditor.CANARY_HOST.lower() or parsed_loc.netloc.lower().endswith("." + RedirectAuditor.CANARY_HOST.lower())
                    is_proto_rel = loc.startswith(f"//{RedirectAuditor.CANARY_HOST}") or loc.startswith(f"/\\{RedirectAuditor.CANARY_HOST}")
                    if is_canary_netloc or is_proto_rel:
                        return {"type": "header_redirect", "location": loc, "status_code": res.status_code}
                    if loc.strip().lower().startswith("javascript:") and "alert" in loc:
                        return {"type": "javascript_scheme", "location": loc, "status_code": res.status_code}
                
                # Check for client-side meta refresh or script redirect reflection
                if payload in res.text:
                    if f'content="0;url={payload}' in res.text or f"window.location='{payload}'" in res.text or f'window.location="{payload}"' in res.text:
                        return {"type": "meta_or_js_redirect", "snippet": payload, "status_code": res.status_code}
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
        """Record or update confirmed redirect / scheme execution finding."""
        existing = db.query(Finding).filter(
            Finding.endpoint_id == endpoint.id,
            Finding.param_id == param.id,
            Finding.vuln_type == vuln_type
        ).first()

        evidence_summary = (
            f"Parameter `{param.name}` on `{endpoint.method} {endpoint.url_pattern}` is vulnerable to {vuln_type.replace('_', ' ').title()}. "
            f"The application accepts arbitrary redirect targets and responds with HTTP {details.get('status_code')} redirecting to: `{details.get('location') or details.get('snippet')}`."
        )

        if existing:
            existing.best_payload = payload
            existing.evidence_summary = evidence_summary
            existing.status = FindingStatus.CONFIRMED
            return existing

        finding = Finding(
            endpoint_id=endpoint.id,
            param_id=param.id,
            context_id=None,
            sink_id=None,
            vuln_type=vuln_type,
            scanner_module="redirect_auditor",
            confidence="firm",
            severity=severity,
            status=FindingStatus.CONFIRMED,
            best_payload=payload,
            evidence_summary=evidence_summary,
            report_text=evidence_summary
        )
        finding.evidence_refs = {
            "verification": {
                "steps": [
                    f"Send a `{endpoint.method}` request to `{endpoint.url_pattern}`.",
                    f"Place the redirect payload in `{param.name}`.",
                    f"Observe server redirect or client execution pointing to the payload target."
                ],
                "impact_summary": "Unvalidated redirects facilitate phishing, credential harvesting, and OAuth authorization code theft.",
                "stored": False,
                "cross_role": False,
                "authenticated": False
            }
        }
        db.add(finding)
        return finding
