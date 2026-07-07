"""Small HTTP probing helpers for recon-driven vulnerability auditors."""
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from backend_api.config import settings
from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param


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


def _request_kwargs() -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {
        "timeout": HTTP_AUDIT_TIMEOUT,
        "follow_redirects": False,
        "verify": False,
        "trust_env": False,
    }
    if settings.PROXY_URL:
        kwargs["proxies"] = settings.PROXY_URL
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
        response = client.request(
            request["method"],
            request["url"],
            headers=request["headers"],
            cookies=request["cookies"],
            data=request["data"],
            json=request["json"],
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
