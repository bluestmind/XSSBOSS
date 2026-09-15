"""Small, dependency-free domain models used across the collector."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class RequestRecord:
    method: str
    url: str
    source: str
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = None
    response_status: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: bytes | None = None
    elapsed_ms: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class FetchResult:
    request: RequestRecord
    final_url: str
    status: int
    headers: dict[str, str]
    body: bytes
    elapsed_ms: float
    truncated: bool = False
    error: str | None = None


@dataclass(slots=True)
class ParsedDocument:
    title: str | None = None
    urls: set[str] = field(default_factory=set)
    asset_urls: set[str] = field(default_factory=set)
    endpoint_hints: list[tuple[str, str, str]] = field(default_factory=list)
    parameters: list[tuple[str, str, str | None]] = field(default_factory=list)
    endpoint_parameters: dict[str, list[tuple[str, str, str | None]]] = field(default_factory=dict)
    observations: list[tuple[str, str, Any, float]] = field(default_factory=list)
    technologies: set[str] = field(default_factory=set)
    inline_scripts: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CollectionStats:
    fetched: int = 0
    imported: int = 0
    endpoints: int = 0
    parameters: int = 0
    observations: int = 0
    errors: int = 0
    skipped_scope: int = 0
    skipped_robots: int = 0
    bytes_received: int = 0
    js_files: int = 0
    js_functions: int = 0
    js_inputs: int = 0
    js_outputs: int = 0
    js_sources: int = 0
    js_sinks: int = 0
    js_calls: int = 0
    js_flows: int = 0

    def as_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}
