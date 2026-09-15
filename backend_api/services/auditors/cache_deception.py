"""Web Cache Deception & Relative Path Overwrite (RPO) Auditor.

Audits endpoints for:
1. Web Cache Deception: Path confusion suffixes (e.g. /account/settings/test.css) caching authenticated dynamic bodies.
2. Relative Path Overwrite (RPO): Loading a page's own reflected content as a stylesheet via relative CSS path confusion.
"""
import re
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional
import httpx
from sqlalchemy.orm import Session

from backend_api.config import settings
from backend_api.models.endpoint import Endpoint
from backend_api.models.finding import Finding, FindingStatus, Severity
from backend_api.utils.logger import logger
from backend_api.utils.rate_limiter import rate_limited_call


class CacheDeceptionAuditor:
    """Audits endpoints for Web Cache Deception and Relative Path Overwrite vulnerabilities."""

    PATH_SUFFIXES = [
        "/nonexistent_canary.css",
        "/test_static.js",
        "/fake_avatar.png",
        ";/canary.css",
        "%2Fcanary.css"
    ]

    @staticmethod
    def audit_endpoints(db: Session, endpoints: Iterable[Endpoint], limit: int = 25) -> List[Finding]:
        """Audit endpoints for cache deception and RPO vulnerabilities."""
        findings: List[Finding] = []
        checked = 0

        for endpoint in endpoints:
            if checked >= limit:
                break
            if not endpoint or not endpoint.url_pattern.startswith(("http://", "https://")):
                continue
            if endpoint.method and endpoint.method.upper() != "GET":
                continue

            checked += 1
            for suffix in CacheDeceptionAuditor.PATH_SUFFIXES:
                try:
                    hit = CacheDeceptionAuditor._test_cache_deception(endpoint, suffix)
                    if hit:
                        finding = CacheDeceptionAuditor._upsert_finding(
                            db=db,
                            endpoint=endpoint,
                            vuln_type=hit["vuln_type"],
                            severity=hit["severity"],
                            details=hit
                        )
                        if finding:
                            findings.append(finding)
                            break
                except Exception as err:
                    logger.debug(f"Cache deception probe failed on {endpoint.url_pattern}: {err}")
                    continue

        if findings:
            db.commit()
            for f in findings:
                db.refresh(f)
        return findings

    @staticmethod
    def _test_cache_deception(endpoint: Endpoint, suffix: str) -> Optional[Dict[str, Any]]:
        """Send path-confusion request and analyze caching response headers."""
        parsed = urllib.parse.urlparse(endpoint.url_pattern)
        base_path = parsed.path.rstrip("/")
        test_path = f"{base_path}{suffix}"
        test_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, test_path, parsed.params, parsed.query, parsed.fragment))
        from backend_api.utils.stealth import get_http_proxy_kwargs
        proxy_kwargs = get_http_proxy_kwargs(rotated=True)

        with httpx.Client(
            timeout=4.0,
            follow_redirects=True,
            verify=not settings.ALLOW_INSECURE_TLS,
            **proxy_kwargs,
        ) as client:
            resp = rate_limited_call(test_url, lambda: client.get(test_url))
            headers_lower = {k.lower(): str(v).lower() for k, v in resp.headers.items()}
            
            # Check 1: Did the server return 200 OK with dynamic/HTML body?
            if resp.status_code == 200 and len(resp.text) > 50:
                cache_control = headers_lower.get("cache-control", "")
                cf_cache = headers_lower.get("cf-cache-status", "")
                x_cache = headers_lower.get("x-cache", "")
                age = headers_lower.get("age", "")

                # Check if response has public caching directive or CDN caching headers
                is_publicly_cached = (
                    "public" in cache_control or
                    "max-age" in cache_control and "no-store" not in cache_control and "private" not in cache_control or
                    cf_cache in ("hit", "eligible") or
                    "hit" in x_cache or
                    bool(age and age != "0")
                )

                if is_publicly_cached:
                    return {
                        "vuln_type": "web_cache_deception",
                        "severity": Severity.HIGH,
                        "test_url": test_url,
                        "cache_control": cache_control,
                        "cf_cache_status": cf_cache,
                        "evidence": f"Path confusion '{suffix}' returned HTTP 200 with dynamic body and public cache headers: {cache_control}"
                    }

                # Check 2: Relative Path Overwrite (RPO) reflection
                if "text/html" in headers_lower.get("content-type", "") and re.search(r'<link[^>]+rel=[\'"]stylesheet[\'"][^>]+href=[\'"][^/][^\'"]*\.css[\'"]', resp.text, re.IGNORECASE):
                    return {
                        "vuln_type": "relative_path_overwrite",
                        "severity": Severity.MEDIUM,
                        "test_url": test_url,
                        "evidence": "Relative stylesheet link detected in path-confused HTML document."
                    }

        return None

    @staticmethod
    def _upsert_finding(
        db: Session,
        endpoint: Endpoint,
        vuln_type: str,
        severity: Severity,
        details: Dict[str, Any]
    ) -> Optional[Finding]:
        try:
            param_id = endpoint.params[0].id if endpoint.params else 0
            evidence_summary = f"Cache Vulnerability ({vuln_type}) detected on endpoint '{endpoint.url_pattern}'. Evidence: {details}"
            finding = Finding(
                endpoint_id=endpoint.id,
                param_id=param_id,
                context_id=None,
                sink_id=None,
                vuln_type=vuln_type,
                scanner_module="cache_deception_auditor",
                confidence="firm",
                severity=severity,
                status=FindingStatus.CONFIRMED,
                best_payload=details.get("test_url", endpoint.url_pattern),
                evidence_summary=evidence_summary,
                report_text=evidence_summary,
            )
            db.add(finding)
            return finding
        except Exception as e:
            logger.debug(f"Failed to upsert Cache Deception finding: {e}")
            return None
