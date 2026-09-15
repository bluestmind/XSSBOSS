"""Offline importers. Imported requests are inventoried and never replayed."""

from __future__ import annotations

import base64
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl

from .models import RequestRecord


def _headers(items: Iterable[dict[str, Any]]) -> dict[str, str]:
    return {str(item.get("name", "")): str(item.get("value", "")) for item in items if item.get("name")}


def import_har(path: Path) -> list[RequestRecord]:
    data = json.loads(path.read_text(encoding="utf-8"))
    records: list[RequestRecord] = []
    for entry in data.get("log", {}).get("entries", []):
        request = entry.get("request", {})
        response = entry.get("response", {})
        url = request.get("url")
        if not url:
            continue
        post = request.get("postData", {})
        body: Any = post.get("text")
        if "json" in str(post.get("mimeType", "")).lower() and isinstance(body, str):
            try:
                body = json.loads(body)
            except json.JSONDecodeError:
                pass
        content = response.get("content", {})
        response_body: bytes | None = None
        if isinstance(content.get("text"), str):
            raw = content["text"]
            try:
                response_body = base64.b64decode(raw) if content.get("encoding") == "base64" else raw.encode()
            except (ValueError, TypeError):
                response_body = None
        records.append(RequestRecord(
            method=str(request.get("method", "GET")), url=str(url), source="har",
            headers=_headers(request.get("headers", [])), body=body,
            response_status=response.get("status"), response_headers=_headers(response.get("headers", [])),
            response_body=response_body, elapsed_ms=entry.get("time"),
        ))
    return records


def _decode_element(element: ET.Element | None) -> str:
    if element is None or element.text is None:
        return ""
    if element.get("base64", "false").lower() == "true":
        try:
            return base64.b64decode(element.text).decode("utf-8", errors="replace")
        except (ValueError, TypeError):
            return ""
    return element.text


def _parse_raw_request(raw: str) -> tuple[dict[str, str], str | None]:
    normalized = raw.replace("\r\n", "\n")
    head, _, body = normalized.partition("\n\n")
    headers: dict[str, str] = {}
    for line in head.splitlines()[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
    return headers, body or None


def import_burp(path: Path) -> list[RequestRecord]:
    root = ET.parse(path).getroot()
    records: list[RequestRecord] = []
    for item in root.findall(".//item"):
        url = item.findtext("url")
        if not url:
            continue
        request_text = _decode_element(item.find("request"))
        headers, body = _parse_raw_request(request_text)
        records.append(RequestRecord(
            method=item.findtext("method") or "GET", url=url, source="burp",
            headers=headers, body=body, response_status=_integer(item.findtext("status")),
            response_headers=_parse_raw_request(_decode_element(item.find("response")))[0],
            response_body=_decode_element(item.find("response")).encode() or None,
        ))
    return records


def _integer(value: str | None) -> int | None:
    try:
        return int(value) if value else None
    except ValueError:
        return None


def import_urls(path: Path) -> list[RequestRecord]:
    records = []
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            records.append(RequestRecord(method="GET", url=line, source="url-file"))
    return records


def import_openapi(path: Path, base_url: str | None = None) -> list[RequestRecord]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data.get("paths"), dict):
        raise ValueError("OpenAPI document has no paths object")
    if not base_url:
        servers = data.get("servers", [])
        base_url = servers[0].get("url") if servers and isinstance(servers[0], dict) else None
    if not base_url:
        raise ValueError("OpenAPI import requires --base-url when the document has no servers URL")
    records = []
    for route, path_item in data["paths"].items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                continue
            operation = operation if isinstance(operation, dict) else {}
            declared = []
            for parameter in list(path_item.get("parameters", [])) + list(operation.get("parameters", [])):
                if not isinstance(parameter, dict) or not parameter.get("name"):
                    continue
                schema = parameter.get("schema", {}) if isinstance(parameter.get("schema"), dict) else {}
                declared.append({"name": str(parameter["name"]), "location": str(parameter.get("in", "unknown")),
                                 "data_type": str(schema.get("type", "unknown"))})
            request_body = operation.get("requestBody", {}) if isinstance(operation.get("requestBody"), dict) else {}
            for media in request_body.get("content", {}).values() if isinstance(request_body.get("content"), dict) else []:
                if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                    declared.extend(_schema_parameters(media["schema"]))
            records.append(RequestRecord(method=method.upper(), url=base_url.rstrip("/") + "/" + route.lstrip("/"), source="openapi",
                                         metadata={"operation_id": operation.get("operationId"), "tags": operation.get("tags", []),
                                                   "declared_parameters": declared}))
    return records


def _schema_parameters(schema: dict[str, Any], prefix: str = "") -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        return found
    for name, child in properties.items():
        full_name = f"{prefix}.{name}" if prefix else str(name)
        child = child if isinstance(child, dict) else {}
        if isinstance(child.get("properties"), dict):
            found.extend(_schema_parameters(child, full_name))
        else:
            found.append({"name": full_name, "location": "json", "data_type": str(child.get("type", "unknown"))})
    return found


IMPORTERS = {"har": import_har, "burp": import_burp, "urls": import_urls}
