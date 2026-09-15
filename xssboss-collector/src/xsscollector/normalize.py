"""Stable endpoint identity and rich parameter extraction."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
HASH_RE = re.compile(r"^[0-9a-f]{20,128}$", re.I)
DATE_RE = re.compile(r"^\d{4}[-/]\d{2}[-/]\d{2}$")
JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


def infer_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, (dict, list)):
        return "object" if isinstance(value, dict) else "array"
    text = str(value).strip()
    if UUID_RE.match(text):
        return "uuid"
    if JWT_RE.match(text):
        return "jwt"
    if re.fullmatch(r"-?\d+", text):
        return "integer"
    if re.fullmatch(r"-?\d+\.\d+", text):
        return "number"
    if text.lower() in {"true", "false"}:
        return "boolean"
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", text):
        return "email"
    return "string"


def normalize_path(path: str) -> tuple[str, list[tuple[str, str, str]]]:
    params: list[tuple[str, str, str]] = []
    result: list[str] = []
    for index, segment in enumerate(path.split("/")):
        kind = None
        if UUID_RE.match(segment):
            kind = "uuid"
        elif DATE_RE.match(segment):
            kind = "date"
        elif segment.isdigit():
            kind = "id"
        elif HASH_RE.match(segment):
            kind = "hash"
        elif JWT_RE.match(segment):
            kind = "jwt"
        if kind:
            name = f"path_{kind}_{index}"
            result.append(f"{{{name}}}")
            params.append((name, "path", kind))
        else:
            result.append(segment)
    return "/".join(result) or "/", params


def canonical_url(url: str, keep_values: bool = False) -> str:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    port = parsed.port
    netloc = host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if keep_values:
        query = urlencode(sorted(query_pairs))
    else:
        query = urlencode([(key, "") for key in sorted({key for key, _ in query_pairs})])
    normalized_path, _ = normalize_path(parsed.path or "/")
    return urlunsplit((scheme, netloc, normalized_path, query, ""))


def endpoint_fingerprint(method: str, url: str, content_type: str | None = None, extra_params: Iterable[str] = ()) -> str:
    parsed = urlsplit(url)
    query_names = {key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    query_names.update(extra_params)
    normalized = canonical_url(url, keep_values=False)
    base = "|".join([
        method.upper(), normalized, ",".join(sorted(query_names)), (content_type or "").split(";", 1)[0].lower()
    ])
    return hashlib.sha256(base.encode()).hexdigest()


def flatten_json(value: Any, prefix: str = "") -> list[tuple[str, str, Any]]:
    found: list[tuple[str, str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(child, (dict, list)):
                found.extend(flatten_json(child, name))
            else:
                found.append((name, "json", child))
    elif isinstance(value, list):
        for child in value[:25]:
            name = f"{prefix}[]" if prefix else "[]"
            if isinstance(child, (dict, list)):
                found.extend(flatten_json(child, name))
            else:
                found.append((name, "json", child))
    return found


def extract_parameters(method: str, url: str, headers: dict[str, str], body: Any) -> list[tuple[str, str, Any, str]]:
    parsed = urlsplit(url)
    found: list[tuple[str, str, Any]] = [(k, "query", v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
    _, path_params = normalize_path(parsed.path)
    found.extend((name, location, None) for name, location, _ in path_params)
    content_type = next((v for k, v in headers.items() if k.lower() == "content-type"), "").lower()
    if isinstance(body, (dict, list)):
        found.extend(flatten_json(body))
    elif isinstance(body, str) and body:
        if "json" in content_type:
            try:
                found.extend(flatten_json(json.loads(body)))
            except json.JSONDecodeError:
                pass
        elif "x-www-form-urlencoded" in content_type:
            found.extend((k, "body", v) for k, v in parse_qsl(body, keep_blank_values=True))
    cookie = next((v for k, v in headers.items() if k.lower() == "cookie"), "")
    for pair in cookie.split(";"):
        if "=" in pair:
            found.append((pair.split("=", 1)[0].strip(), "cookie", None))
    unique: dict[tuple[str, str], tuple[str, str, Any, str]] = {}
    for name, location, sample in found:
        if name:
            unique[(name, location)] = (name, location, sample, infer_type(sample))
    return list(unique.values())
