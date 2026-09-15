"""CORS misconfiguration auditor."""
from typing import Any, Dict, Iterable, List, Optional

import httpx
from sqlalchemy.orm import Session

from backend_api.config import settings
from backend_api.models.endpoint import Endpoint
from backend_api.models.finding import Finding, FindingStatus, Severity
from backend_api.models.param import Param
from backend_api.utils.logger import logger
from backend_api.utils.rate_limiter import rate_limited_call


class CorsAuditor:
    """Detect high-confidence CORS trust mistakes from recon endpoints."""

    TEST_ORIGIN = "https://xssboss.invalid"
    TIMEOUT = httpx.Timeout(8.0, connect=3.0)

    @staticmethod
    def audit_endpoints(db: Session, endpoints: Iterable[Endpoint], limit: int = 25) -> List[Finding]:
        """Create findings for endpoints that trust arbitrary credentialed origins."""
        findings: List[Finding] = []
        checked = 0
        for endpoint in endpoints:
            if checked >= limit:
                break
            if not endpoint or not endpoint.url_pattern.startswith(("http://", "https://")):
                continue

            checked += 1
            try:
                result = CorsAuditor._probe_endpoint(endpoint)
            except Exception as err:
                logger.debug(f"CORS audit skipped endpoint {getattr(endpoint, 'id', '?')}: {err}")
                continue

            if not result:
                continue

            finding = CorsAuditor._upsert_finding(db, endpoint, result)
            if finding:
                findings.append(finding)

        if findings:
            db.commit()
            for finding in findings:
                db.refresh(finding)
        return findings

    @staticmethod
    def _probe_endpoint(endpoint: Endpoint) -> Optional[Dict[str, Any]]:
        method = endpoint.method.upper()
        probe_method = "GET" if method in {"GET", "HEAD"} else "OPTIONS"
        headers = {
            "Origin": CorsAuditor.TEST_ORIGIN,
            "User-Agent": "XSSBoss-CORS-Auditor/1.0",
        }
        if probe_method == "OPTIONS":
            headers["Access-Control-Request-Method"] = method if method else "GET"

        from backend_api.utils.stealth import get_http_proxy_kwargs

        request_kwargs: Dict[str, Any] = {
            "timeout": CorsAuditor.TIMEOUT,
            "headers": headers,
            "follow_redirects": False,
            "verify": not settings.ALLOW_INSECURE_TLS,
            "trust_env": False,
        }
        request_kwargs.update(get_http_proxy_kwargs(rotated=True))

        with httpx.Client(**request_kwargs) as client:
            response = rate_limited_call(
                endpoint.url_pattern,
                lambda: client.request(probe_method, endpoint.url_pattern),
            )

        response_headers = {key.lower(): value for key, value in response.headers.items()}
        allow_origin = response_headers.get("access-control-allow-origin", "").strip()
        allow_credentials = response_headers.get("access-control-allow-credentials", "").strip().lower()

        arbitrary_origin_trusted = allow_origin == CorsAuditor.TEST_ORIGIN
        credentialed = allow_credentials == "true"

        if arbitrary_origin_trusted and credentialed:
            # If probe was preflight (OPTIONS), perform a Phase 2 data-read verification probe
            # to verify that the server actually returns data and ACAO on GET/POST requests.
            if probe_method == "OPTIONS":
                data_method = method if method in {"GET", "POST", "PUT"} else "GET"
                data_headers = {
                    "Origin": CorsAuditor.TEST_ORIGIN,
                    "User-Agent": "XSSBoss-CORS-Auditor/1.0",
                    "Accept": "application/json, text/plain, */*"
                }
                if endpoint.auth_context and isinstance(endpoint.auth_context, dict):
                    data_headers.update(endpoint.auth_context)

                try:
                    data_kwargs = {
                        "timeout": CorsAuditor.TIMEOUT,
                        "verify": not settings.ALLOW_INSECURE_TLS,
                        "follow_redirects": False,
                        "trust_env": False,
                    }
                    data_kwargs.update(get_http_proxy_kwargs(rotated=True))
                    with httpx.Client(**data_kwargs) as client:
                        data_res = rate_limited_call(
                            endpoint.url_pattern,
                            lambda: client.request(
                                data_method,
                                endpoint.url_pattern,
                                headers=data_headers,
                            ),
                        )
                        data_headers_map = {k.lower(): v for k, v in data_res.headers.items()}
                        data_acao = data_headers_map.get("access-control-allow-origin", "").strip()
                        data_acac = data_headers_map.get("access-control-allow-credentials", "").strip().lower()

                        # If the actual data response blocks the origin or fails to return ACAO: true, it's a false positive
                        if data_acao != CorsAuditor.TEST_ORIGIN or data_acac != "true":
                            logger.info(f"CORS preflight reflected origin on {endpoint.url_pattern}, but data response dropped ACAO/ACAC. Suppressing false positive.")
                            return None

                        if "cors policy violation" in data_res.text.lower() or "origin not on the allowlist" in data_res.text.lower():
                            logger.info(f"CORS policy violation thrown on data request for {endpoint.url_pattern}. Suppressing false positive.")
                            return None
                except Exception as ex:
                    logger.debug(f"CORS data verification probe failed for {endpoint.url_pattern}: {ex}")
                    return None

            return {
                "severity": Severity.HIGH.value,
                "confidence": "certain",
                "evidence_summary": (
                    "Endpoint reflects an arbitrary Origin into Access-Control-Allow-Origin "
                    "and allows credentialed reads on actual data responses."
                ),
                "headers": response_headers,
                "status_code": response.status_code,
                "probe_method": probe_method,
            }

        return None

    @staticmethod
    def _origin_param(db: Session, endpoint: Endpoint) -> Param:
        param = (
            db.query(Param)
            .filter(Param.endpoint_id == endpoint.id)
            .filter(Param.name == "Origin")
            .filter(Param.location == "header")
            .first()
        )
        if param:
            return param

        param = Param(
            endpoint_id=endpoint.id,
            name="Origin",
            location="header",
            sample_value=CorsAuditor.TEST_ORIGIN,
            is_controllable=True,
        )
        db.add(param)
        db.flush()
        return param

    @staticmethod
    def _upsert_finding(db: Session, endpoint: Endpoint, result: Dict[str, Any]) -> Optional[Finding]:
        param = CorsAuditor._origin_param(db, endpoint)
        existing = (
            db.query(Finding)
            .filter(Finding.endpoint_id == endpoint.id)
            .filter(Finding.param_id == param.id)
            .filter(Finding.vuln_type == "cors_misconfiguration")
            .first()
        )

        report_text = f"""CORS Misconfiguration

**Summary:**
The endpoint trusts an arbitrary cross-origin requester and allows credentialed browser reads.

**Affected Endpoint:**
- Method: {endpoint.method}
- URL: {endpoint.url_pattern}
- Header: Origin

**Evidence:**
- Sent Origin: `{CorsAuditor.TEST_ORIGIN}`
- Access-Control-Allow-Origin: `{result["headers"].get("access-control-allow-origin", "")}`
- Access-Control-Allow-Credentials: `{result["headers"].get("access-control-allow-credentials", "")}`
- Probe Method: `{result["probe_method"]}`
- HTTP Status: `{result["status_code"]}`

**Impact:**
If this endpoint returns user-specific or sensitive data, a malicious website can read it from a victim browser with credentials attached.

**Recommendation:**
Allow only trusted origins, avoid reflecting arbitrary Origin values, and do not combine credentialed CORS with broad origin trust.
"""

        poc_request = {
            "command": (
                f"curl -i -X {result['probe_method']} "
                f"-H \"Origin: {CorsAuditor.TEST_ORIGIN}\" "
                f"-H \"Access-Control-Request-Method: {endpoint.method}\" "
                f"\"{endpoint.url_pattern}\""
            ),
            "method": result["probe_method"],
            "url": endpoint.url_pattern,
            "headers": {"Origin": CorsAuditor.TEST_ORIGIN},
            "payload": CorsAuditor.TEST_ORIGIN,
            "param_location": "header",
        }

        if existing:
            existing.severity = result["severity"]
            existing.status = FindingStatus.DRAFT.value
            existing.best_payload = CorsAuditor.TEST_ORIGIN
            existing.scanner_module = "cors_auditor"
            existing.confidence = result["confidence"]
            existing.evidence_summary = result["evidence_summary"]
            existing.report_text = report_text
            existing.evidence_refs = {"cors": result}
            existing.poc_request = poc_request
            return existing

        finding = Finding(
            endpoint_id=endpoint.id,
            param_id=param.id,
            context_id=None,
            sink_id=None,
            vuln_type="cors_misconfiguration",
            scanner_module="cors_auditor",
            confidence=result["confidence"],
            evidence_summary=result["evidence_summary"],
            best_payload=CorsAuditor.TEST_ORIGIN,
            severity=result["severity"],
            status=FindingStatus.DRAFT.value,
            report_text=report_text,
            evidence_refs={"cors": result},
            poc_request=poc_request,
            poc_html=None,
            screenshot_path=None,
        )
        db.add(finding)
        db.flush()
        return finding
