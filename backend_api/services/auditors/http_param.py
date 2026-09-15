"""Small HTTP probing helpers for recon-driven vulnerability auditors."""
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx
from sqlalchemy.orm import Session

from backend_api.config import settings
from backend_api.models.endpoint import Endpoint
from backend_api.models.finding import Finding, FindingStatus, Severity
from backend_api.models.param import Param
from backend_api.utils.logger import logger
from backend_api.utils.rate_limiter import rate_limited_call


HTTP_AUDIT_TIMEOUT = httpx.Timeout(10.0, connect=3.0)


def benign_value(param: Param) -> str:
    """Return a stable non-attack value for baseline requests."""
    sample = (param.sample_value or "").strip()
    if sample:
        return sample[:200]
    name = (param.name or "").lower()
    if "id" in name:
        return "1"
    if "url" in name or "uri" in name or "redirect" in name:
        return "https://example.com/"
    if "file" in name or "path" in name or "page" in name:
        return "index"
    return "xssboss"


from backend_api.utils.stealth import get_http_proxy_kwargs


def _request_kwargs() -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {
        "timeout": HTTP_AUDIT_TIMEOUT,
        "follow_redirects": False,
        "verify": not settings.ALLOW_INSECURE_TLS,
        "trust_env": False,
    }
    kwargs.update(get_http_proxy_kwargs(rotated=True))
    return kwargs


def _split_headers_and_cookies(endpoint: Endpoint) -> tuple[Dict[str, str], Dict[str, str]]:
    headers = {
        str(key): str(value)
        for key, value in (endpoint.auth_context or {}).items()
        if str(key).lower() not in {"content-length", "host"}
    }
    cookies: Dict[str, str] = {}
    cookie_header = headers.pop("Cookie", None)
    if cookie_header:
        for pair in cookie_header.split(";"):
            if "=" in pair:
                key, value = pair.split("=", 1)
                cookies[key.strip()] = value.strip()
    return headers, cookies


def build_request(endpoint: Endpoint, param: Param, value: str) -> Dict[str, Any]:
    """Build an httpx request from an endpoint, replacing one parameter value."""
    method = (endpoint.method or "GET").upper()
    url = endpoint.url_pattern
    headers, cookies = _split_headers_and_cookies(endpoint)
    body = None
    json_data = None

    all_params = list(endpoint.params or [])

    path_params = {
        item.name: (value if item.id == param.id else benign_value(item))
        for item in all_params
        if item.location == "path"
    }
    for name, path_value in path_params.items():
        url = url.replace(f"{{{name}}}", str(path_value))

    parsed = list(urlparse(url))
    query = dict(parse_qsl(parsed[4], keep_blank_values=True))

    if endpoint.sample_request_body and isinstance(endpoint.sample_request_body, dict):
        if any(item.location == "json" for item in all_params) or param.location == "json":
            json_data = dict(endpoint.sample_request_body)
        elif any(item.location == "body" for item in all_params) or param.location == "body":
            body = dict(endpoint.sample_request_body)

    for item in all_params:
        item_value = value if item.id == param.id else benign_value(item)
        if item.location == "query":
            query[item.name] = item_value
        elif item.location == "body":
            if body is None:
                body = {}
            body[item.name] = item_value
        elif item.location == "json":
            if json_data is None:
                json_data = {}
            keys = item.name.split(".")
            current = json_data
            for key in keys[:-1]:
                if key not in current or not isinstance(current[key], dict):
                    current[key] = {}
                current = current[key]
            current[keys[-1]] = item_value
        elif item.location == "header":
            headers[item.name] = item_value
        elif item.location == "cookie":
            cookies[item.name] = item_value

    parsed[4] = urlencode(query, doseq=True)
    url = urlunparse(parsed)

    return {
        "method": method,
        "url": url,
        "headers": headers,
        "cookies": cookies,
        "data": body,
        "json": json_data,
    }


def send_param_probe(endpoint: Endpoint, param: Param, value: str) -> Dict[str, Any]:
    """Send one parameter probe and return a normalized response record."""
    request = build_request(endpoint, param, value)
    with httpx.Client(**_request_kwargs()) as client:
        response = rate_limited_call(
            request["url"],
            lambda: client.request(
                request["method"],
                request["url"],
                headers=request["headers"],
                cookies=request["cookies"],
                data=request["data"],
                json=request["json"],
            ),
        )

    return {
        "request": request,
        "status_code": response.status_code,
        "headers": {key.lower(): value for key, value in response.headers.items()},
        "text": response.text[:200000],
        "url": str(response.url),
    }


def curl_command(request: Dict[str, Any]) -> str:
    """Render a replayable curl command for a probe request."""
    parts = ["curl", "-i", "-X", request["method"]]
    for key, value in (request.get("headers") or {}).items():
        parts.extend(["-H", f'"{key}: {value}"'])
    if request.get("json") is not None:
        import json

        parts.extend(["-H", '"Content-Type: application/json"'])
        parts.extend(["--data", f"'{json.dumps(request['json'])}'"])
    elif request.get("data") is not None:
        parts.extend(["--data", f"'{urlencode(request['data'], doseq=True)}'"])
    parts.append(f'"{request["url"]}"')
    return " ".join(parts)


class HttpParamPollutionAuditor:
    """Audits endpoints for HTTP Parameter Pollution (HPP) vulnerabilities."""

    @staticmethod
    def audit_endpoints(db: Session, endpoints: Iterable[Endpoint], limit: int = 25) -> List[Finding]:
        findings: List[Finding] = []
        checked = 0

        for endpoint in endpoints:
            if checked >= limit:
                break
            if not endpoint or not endpoint.url_pattern or not endpoint.url_pattern.startswith(("http://", "https://")):
                continue
            if not endpoint.params:
                continue

            checked += 1
            for param in endpoint.params:
                if param.location not in ("query", "body"):
                    continue
                try:
                    hit = HttpParamPollutionAuditor._test_hpp(endpoint, param)
                    if hit:
                        finding = HttpParamPollutionAuditor._upsert_finding(
                            db=db,
                            endpoint=endpoint,
                            param=param,
                            details=hit,
                        )
                        if finding:
                            findings.append(finding)
                            break
                except Exception as err:
                    logger.debug(f"HPP probe failed on {endpoint.url_pattern}: {err}")
                    continue
        return findings

    @staticmethod
    def _test_hpp(endpoint: Endpoint, param: Param) -> Optional[Dict[str, Any]]:
        first_val = f"first_{param.name}"
        second_val = f"second_{param.name}"

        method = (endpoint.method or "GET").upper()
        headers, cookies = _split_headers_and_cookies(endpoint)
        url = endpoint.url_pattern
        all_params = list(endpoint.params or [])

        for item in all_params:
            if item.location == "path":
                url = url.replace(f"{{{item.name}}}", benign_value(item))

        parsed = list(urlparse(url))
        query_pairs = parse_qsl(parsed[4], keep_blank_values=True)

        if param.location == "query":
            query_pairs = [p for p in query_pairs if p[0] != param.name]
            query_pairs.append((param.name, first_val))
            query_pairs.append((param.name, second_val))
            parsed[4] = urlencode(query_pairs, doseq=True)
            probe_url = urlunparse(parsed)
            req_data = None
        else:
            probe_url = urlunparse(parsed)
            req_data = [(param.name, first_val), (param.name, second_val)]

        with httpx.Client(**_request_kwargs()) as client:
            resp = rate_limited_call(
                probe_url,
                lambda: client.request(
                    method,
                    probe_url,
                    headers=headers,
                    cookies=cookies,
                    data=req_data,
                ),
            )

        body = resp.text
        if f"{first_val},{second_val}" in body or f"{first_val} {second_val}" in body or (first_val in body and second_val in body):
            return {
                "vuln_type": "http_parameter_pollution",
                "severity": Severity.LOW,
                "url": probe_url,
                "param_name": param.name,
                "status_code": resp.status_code,
                "evidence": f"Both polluted parameter values reflected in response body: {first_val} and {second_val}",
            }
        return None

    @staticmethod
    def _upsert_finding(
        db: Session,
        endpoint: Endpoint,
        param: Param,
        details: Dict[str, Any],
    ) -> Optional[Finding]:
        try:
            vuln_type = details.get("vuln_type", "http_parameter_pollution")
            severity = details.get("severity", Severity.LOW)
            evidence_summary = f"HTTP Parameter Pollution detected on '{param.name}'. {details.get('evidence', '')}"
            finding = Finding(
                endpoint_id=endpoint.id,
                param_id=param.id,
                context_id=None,
                sink_id=None,
                vuln_type=vuln_type,
                scanner_module="http_param_auditor",
                confidence="firm",
                severity=severity,
                status=FindingStatus.CONFIRMED,
                best_payload=f"{param.name}=val1&{param.name}=val2",
                evidence_summary=evidence_summary,
                report_text=evidence_summary,
            )
            db.add(finding)
            return finding
        except Exception as e:
            logger.debug(f"Failed to upsert HPP finding: {e}")
            return None
