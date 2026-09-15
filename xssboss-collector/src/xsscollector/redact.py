"""Secret-aware redaction before persistence or export."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

TOKEN_PATTERNS = [
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    re.compile(r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{12,}\b", re.I),
    re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
]


class Redactor:
    def __init__(self, headers: list[str], parameters: list[str], retain_query_values: bool = False):
        self.headers = {item.lower() for item in headers}
        self.parameters = {item.lower() for item in parameters}
        self.retain_query_values = retain_query_values
        names = "|".join(sorted((re.escape(item) for item in self.parameters), key=len, reverse=True))
        self._named_value = re.compile(
            rf"((?:^|[?&;\s])(?:{names})=)[^&;\s<>\"']+", re.I
        ) if names else None
        self._json_value = re.compile(
            rf"((?:\"|')(?:{names})(?:\"|')\s*:\s*(?:\"|'))(.*?)(\"|')", re.I
        ) if names else None

    def is_sensitive_name(self, name: str) -> bool:
        normalized = name.lower().replace("-", "_")
        return any(token == normalized or token in normalized for token in self.parameters)

    def text(self, value: str) -> str:
        result = value
        for pattern in TOKEN_PATTERNS:
            result = pattern.sub("[REDACTED_TOKEN]", result)
        if self._named_value:
            result = self._named_value.sub(r"\1[REDACTED]", result)
        if self._json_value:
            result = self._json_value.sub(r"\1[REDACTED]\3", result)
        result = re.sub(r"<input\b[^>]*>", self._redact_input, result, flags=re.I)
        return result

    def _redact_input(self, match: re.Match[str]) -> str:
        tag = match.group(0)
        name = re.search(r"\bname\s*=\s*(['\"])(.*?)\1", tag, re.I)
        if not name or not self.is_sensitive_name(name.group(2)):
            return tag
        return re.sub(r"(\bvalue\s*=\s*(['\"]))(.*?)(\2)", r"\1[REDACTED]\4", tag, flags=re.I)

    def headers_map(self, headers: dict[str, str]) -> dict[str, str]:
        return {
            key: "[REDACTED]" if key.lower() in self.headers else self.text(str(value))
            for key, value in headers.items()
        }

    def value(self, name: str, value: Any) -> Any:
        if self.is_sensitive_name(name):
            return "[REDACTED]"
        if isinstance(value, str):
            return self.text(value)
        return value

    def structured(self, value: Any, key: str = "") -> Any:
        if self.is_sensitive_name(key):
            return "[REDACTED]"
        if isinstance(value, dict):
            return {str(k): self.structured(v, str(k)) for k, v in value.items()}
        if isinstance(value, list):
            return [self.structured(item, key) for item in value]
        return self.text(value) if isinstance(value, str) else value

    def url(self, url: str) -> str:
        parsed = urlsplit(url)
        pairs = []
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            kept = self.value(key, value) if self.retain_query_values else "[VALUE]"
            pairs.append((key, kept))
        host = parsed.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        try:
            port = parsed.port
        except ValueError:
            port = None
        netloc = f"{host}:{port}" if port else host
        return urlunsplit((parsed.scheme, netloc, parsed.path, urlencode(pairs), ""))
