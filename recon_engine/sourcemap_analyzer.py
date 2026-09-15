"""
Source Map (.map) Reconstruction & Deep Code Surface Analyzer for XSS Boss.

Unpacks remote and local JavaScript source maps to reconstruct original TypeScript, JSX,
and Vue components, harvesting hidden API routes, parameters, developer comments, and DOM sinks.
"""
from __future__ import annotations

import base64
import binascii
import json
import posixpath
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Set, Tuple

try:
    import httpx
except ImportError:
    httpx = None

from backend_api.utils.logger import logger
from backend_api.config import settings


_SOURCE_MAP_LINE_DIRECTIVE = re.compile(
    r"//[#@]\s*sourceMappingURL\s*=\s*([^\s]+)", re.IGNORECASE
)
_SOURCE_MAP_BLOCK_DIRECTIVE = re.compile(
    r"/\*[#@]\s*sourceMappingURL\s*=\s*([^*]+?)\s*\*/", re.IGNORECASE
)
_DATA_URL_PREFIX = "data:"


def resolve_sourcemap_reference(script_url: str, value: Any) -> Optional[str]:
    """Resolve one source-map reference without performing network I/O."""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if not isinstance(value, str):
        return None

    reference = value.strip()
    if len(reference) >= 2 and reference[0] == reference[-1] and reference[0] in {"'", '"'}:
        reference = reference[1:-1].strip()
    if reference.startswith("<") and reference.endswith(">"):
        reference = reference[1:-1].strip()
    if not reference or any(char in reference for char in "\r\n\x00"):
        return None
    if reference.lower().startswith(_DATA_URL_PREFIX):
        return reference
    return urllib.parse.urljoin(script_url, reference)


def _is_same_http_origin(left: str, right: str) -> bool:
    """Keep automatic map retrieval on the already-authorized script origin."""
    try:
        first = urllib.parse.urlsplit(left)
        second = urllib.parse.urlsplit(right)
        if first.scheme.lower() not in {"http", "https"}:
            return False
        if second.scheme.lower() != first.scheme.lower():
            return False
        def effective_port(parts: urllib.parse.SplitResult) -> Optional[int]:
            return parts.port or (443 if parts.scheme.lower() == "https" else 80)

        return (
            first.hostname == second.hostname
            and effective_port(first) == effective_port(second)
        )
    except (TypeError, ValueError):
        return False


def sourcemap_url_from_headers(
    script_url: str,
    headers: Optional[Mapping[str, Any] | Iterable[Tuple[Any, Any]]],
) -> Optional[str]:
    """Return a resolved ``SourceMap``/``X-SourceMap`` response-header value.

    ``SourceMap`` takes precedence over the legacy alias. This pure helper accepts ordinary
    dictionaries, httpx-style mappings, and iterables of header pairs.
    """
    if not headers:
        return None
    try:
        items = headers.items() if hasattr(headers, "items") else headers
        collected: Dict[str, List[Any]] = {"sourcemap": [], "x-sourcemap": []}
        for raw_name, raw_value in items:
            name = str(raw_name).strip().lower()
            if name not in collected:
                continue
            values = raw_value if isinstance(raw_value, (list, tuple)) else [raw_value]
            collected[name].extend(values)
    except (TypeError, ValueError, AttributeError):
        return None

    for name in ("sourcemap", "x-sourcemap"):
        for value in collected[name]:
            resolved = resolve_sourcemap_reference(script_url, value)
            if resolved:
                return resolved
    return None


parse_sourcemap_headers = sourcemap_url_from_headers


@dataclass
class SourceMapFinding:
    """Findings extracted from reconstructed source maps."""

    original_file_path: str
    discovered_endpoints: List[str] = field(default_factory=list)
    discovered_parameters: List[str] = field(default_factory=list)
    dom_sinks: List[Dict[str, Any]] = field(default_factory=list)
    developer_comments: List[str] = field(default_factory=list)
    secrets_or_flags: List[str] = field(default_factory=list)


class SourceMapAnalyzer:
    """Unpacks source maps and performs deep static analysis on unminified source code."""

    # Source maps are untrusted input. Bound decoding, indexed-map recursion, and source scanning.
    MAX_MAP_BYTES = 5 * 1024 * 1024
    MAX_SOURCES = 2_000
    MAX_SOURCE_BYTES = 512 * 1024
    MAX_TOTAL_SOURCE_BYTES = 12 * 1024 * 1024
    MAX_SECTIONS = 256
    MAX_SECTION_DEPTH = 8
    MAX_PATH_CHARS = 4_096
    MAX_ENDPOINTS_PER_SOURCE = 500
    MAX_PARAMETERS_PER_SOURCE = 1_000
    MAX_SINKS_PER_SOURCE = 500
    MAX_FLAGS_PER_SOURCE = 200

    def __init__(
        self,
        timeout: float = 8.0,
        request_headers: Optional[Mapping[str, str]] = None,
        response_guard: Optional[Callable[[int, str, str], None]] = None,
    ):
        self.timeout = timeout
        self.request_headers = dict(request_headers or {})
        self.response_guard = response_guard

    @staticmethod
    def sourcemap_url_from_headers(
        script_url: str,
        headers: Optional[Mapping[str, Any] | Iterable[Tuple[Any, Any]]],
    ) -> Optional[str]:
        """Expose the pure response-header parser through the analyzer API."""
        return sourcemap_url_from_headers(script_url, headers)

    def analyze_script_for_sourcemap(
        self,
        script_url: str,
        script_content: Optional[str] = None,
        response_headers: Optional[Mapping[str, Any] | Iterable[Tuple[Any, Any]]] = None,
    ) -> List[SourceMapFinding]:
        """Locate and analyze one map, decoding inline maps without network access."""
        map_url = sourcemap_url_from_headers(script_url, response_headers)

        if not map_url and script_content:
            raw_map = self._source_mapping_reference(script_content)
            if raw_map:
                map_url = resolve_sourcemap_reference(script_url, raw_map)

        if not map_url:
            map_url = self._fallback_map_url(script_url)

        if not map_url.lower().startswith(_DATA_URL_PREFIX) and not _is_same_http_origin(
            script_url, map_url
        ):
            logger.info("Skipping cross-origin source map reference for %s", script_url)
            return []

        map_json_str = self._load_map_text(map_url)
        if not map_json_str:
            return []

        map_data = self._parse_map_json(map_json_str)
        if map_data is None:
            return []

        logger.info(f"Successfully reconstructed source map: {map_url}")
        return self.parse_sourcemap_data(map_data, map_url=map_url)

    @staticmethod
    def _source_mapping_reference(script_content: str) -> Optional[str]:
        """Return the last valid line or block sourceMappingURL directive."""
        matches: List[Tuple[int, str]] = []
        for pattern in (_SOURCE_MAP_LINE_DIRECTIVE, _SOURCE_MAP_BLOCK_DIRECTIVE):
            matches.extend((match.start(), match.group(1).strip()) for match in pattern.finditer(script_content))
        return max(matches, key=lambda item: item[0])[1] if matches else None

    @staticmethod
    def _fallback_map_url(script_url: str) -> str:
        """Append ``.map`` to the path while preserving URL query and fragment."""
        parts = urllib.parse.urlsplit(script_url)
        return urllib.parse.urlunsplit(
            (parts.scheme, parts.netloc, f"{parts.path}.map", parts.query, parts.fragment)
        )

    def _load_map_text(self, map_url: str) -> Optional[str]:
        if map_url.lower().startswith(_DATA_URL_PREFIX):
            return self._decode_data_url(map_url)
        return self._fetch_text(map_url)

    def _decode_data_url(self, data_url: str) -> Optional[str]:
        """Decode a bounded base64 or percent-encoded JSON data URL."""
        if not isinstance(data_url, str) or not data_url.lower().startswith(_DATA_URL_PREFIX):
            return None
        try:
            metadata, payload = data_url[5:].split(",", 1)
        except ValueError:
            return None

        metadata_parts = [part.strip() for part in metadata.split(";") if part.strip()]
        media_type = metadata_parts[0].lower() if metadata_parts and "/" in metadata_parts[0] else "text/plain"
        if media_type not in {"application/json", "text/json", "application/octet-stream", "text/plain"}:
            return None
        is_base64 = any(part.lower() == "base64" for part in metadata_parts)

        encoded_limit = self.MAX_MAP_BYTES * (4 if is_base64 else 3) + 16
        if len(payload) > encoded_limit:
            return None
        try:
            encoded_bytes = urllib.parse.unquote_to_bytes(payload)
            if is_base64:
                compact = b"".join(encoded_bytes.split())
                decoded = base64.b64decode(compact, validate=True)
            else:
                decoded = encoded_bytes
        except (ValueError, UnicodeError, binascii.Error):
            return None
        if len(decoded) > self.MAX_MAP_BYTES:
            return None
        try:
            return decoded.decode("utf-8-sig")
        except UnicodeDecodeError:
            return None

    def _parse_map_json(self, raw: str) -> Optional[Dict[str, Any]]:
        if not isinstance(raw, str) or len(raw.encode("utf-8", errors="ignore")) > self.MAX_MAP_BYTES:
            return None
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError, ValueError, MemoryError):
            return None
        return parsed if isinstance(parsed, dict) else None

    def parse_sourcemap_data(
        self,
        map_data: Dict[str, Any],
        map_url: Optional[str] = None,
    ) -> List[SourceMapFinding]:
        """Parse regular or indexed source maps under shared count and byte budgets.

        Indexed section URLs are decoded only when they are inline data URLs. Parsing an already
        acquired map never triggers additional network requests.
        """
        if not isinstance(map_data, dict):
            return []

        budget = {"sources": 0, "source_bytes": 0, "sections": 0}
        entries: List[Tuple[str, str]] = []
        self._collect_sources(
            map_data,
            map_url=map_url,
            depth=0,
            budget=budget,
            entries=entries,
            active_maps=set(),
        )

        findings: List[SourceMapFinding] = []
        seen_entries: Set[Tuple[str, str]] = set()
        for src_path, content in entries:
            entry_key = (src_path, content)
            if entry_key in seen_entries:
                continue
            seen_entries.add(entry_key)
            finding = self._analyze_source(src_path, content)
            if finding is not None:
                findings.append(finding)
        return findings

    def _collect_sources(
        self,
        map_data: Dict[str, Any],
        *,
        map_url: Optional[str],
        depth: int,
        budget: Dict[str, int],
        entries: List[Tuple[str, str]],
        active_maps: Set[int],
    ) -> None:
        if depth > self.MAX_SECTION_DEPTH or budget["sources"] >= self.MAX_SOURCES:
            return
        map_identity = id(map_data)
        if map_identity in active_maps:
            return
        active_maps.add(map_identity)
        try:
            sources = map_data.get("sources")
            contents = map_data.get("sourcesContent")
            if isinstance(sources, list):
                if not isinstance(contents, list):
                    contents = []
                source_root = map_data.get("sourceRoot") if isinstance(map_data.get("sourceRoot"), str) else None
                for index, raw_path in enumerate(sources):
                    if budget["sources"] >= self.MAX_SOURCES:
                        break
                    if not isinstance(raw_path, str) or not raw_path:
                        continue
                    content = contents[index] if index < len(contents) else None
                    if not isinstance(content, str) or not content:
                        continue
                    remaining = self.MAX_TOTAL_SOURCE_BYTES - budget["source_bytes"]
                    if remaining <= 0:
                        break
                    bounded_content, byte_count = self._bounded_source(content, remaining)
                    if not bounded_content:
                        continue
                    resolved_path = self._resolve_source_path(raw_path, source_root, map_url)
                    entries.append((resolved_path[: self.MAX_PATH_CHARS], bounded_content))
                    budget["sources"] += 1
                    budget["source_bytes"] += byte_count

            sections = map_data.get("sections")
            if not isinstance(sections, list) or depth >= self.MAX_SECTION_DEPTH:
                return
            for section in sections:
                if budget["sections"] >= self.MAX_SECTIONS or budget["sources"] >= self.MAX_SOURCES:
                    break
                if not isinstance(section, dict):
                    continue
                budget["sections"] += 1
                nested_map = section.get("map")
                nested_url = map_url
                if not isinstance(nested_map, dict):
                    resolved_section_url = resolve_sourcemap_reference(map_url or "", section.get("url"))
                    if not resolved_section_url or not resolved_section_url.lower().startswith(_DATA_URL_PREFIX):
                        continue
                    section_text = self._decode_data_url(resolved_section_url)
                    nested_map = self._parse_map_json(section_text) if section_text is not None else None
                    nested_url = resolved_section_url
                if isinstance(nested_map, dict):
                    self._collect_sources(
                        nested_map,
                        map_url=nested_url,
                        depth=depth + 1,
                        budget=budget,
                        entries=entries,
                        active_maps=active_maps,
                    )
        finally:
            active_maps.remove(map_identity)

    def _bounded_source(self, content: str, total_remaining: int) -> Tuple[str, int]:
        allowed = min(self.MAX_SOURCE_BYTES, total_remaining)
        encoded = content.encode("utf-8", errors="ignore")
        if len(encoded) > allowed:
            encoded = encoded[:allowed]
            content = encoded.decode("utf-8", errors="ignore")
            encoded = content.encode("utf-8")
        return content, len(encoded)

    @staticmethod
    def _resolve_source_path(source: str, source_root: Optional[str], map_url: Optional[str]) -> str:
        """Resolve sourceRoot and source paths without touching the filesystem."""
        source = source.strip()
        parsed_source = urllib.parse.urlsplit(source)
        if parsed_source.scheme:
            return source
        if source.startswith("//"):
            return urllib.parse.urljoin(map_url or "https://invalid/", source)
        if not source_root:
            return urllib.parse.urljoin(map_url, source) if map_url else source

        root = source_root.strip()
        parsed_root = urllib.parse.urlsplit(root)
        if parsed_root.scheme and parsed_root.scheme not in {"http", "https", "file"}:
            return f"{root.rstrip('/')}/{source.lstrip('/')}"
        if parsed_root.scheme:
            root_base = root if root.endswith("/") else f"{root}/"
            return urllib.parse.urljoin(root_base, source)

        if map_url:
            root_base = urllib.parse.urljoin(map_url, root if root.endswith("/") else f"{root}/")
            return urllib.parse.urljoin(root_base, source)

        joined = posixpath.normpath(posixpath.join(root, source))
        if root.startswith("/") and not joined.startswith("/"):
            joined = f"/{joined}"
        return joined

    def _analyze_source(self, src_path: str, content: str) -> Optional[SourceMapFinding]:
        finding = SourceMapFinding(original_file_path=src_path)

        endpoint_matches = re.finditer(
            r"['\"`](/(?:api|n-api|admin|v\d+|auth|user|checkout|cart|gateway)/[a-zA-Z0-9_/.-]+)['\"`]",
            content,
        )
        finding.discovered_endpoints = list(
            dict.fromkeys(match.group(1) for match in endpoint_matches)
        )[: self.MAX_ENDPOINTS_PER_SOURCE]

        param_matches = re.finditer(
            r"(?:searchParams\.get|params\.get|\.get|req\.query\[|router\.query\.)\(?['\"`]?([a-zA-Z0-9_]+)['\"`]?",
            content,
        )
        finding.discovered_parameters = list(
            dict.fromkeys(match.group(1) for match in param_matches)
        )[: self.MAX_PARAMETERS_PER_SOURCE]

        sink_matches = re.finditer(
            r"(dangerouslySetInnerHTML|innerHTML|outerHTML|eval|document\.write|location\.href)\s*[:=]\s*([^;\n]+)",
            content,
        )
        for sink_match in sink_matches:
            finding.dom_sinks.append(
                {
                    "sink": sink_match.group(1),
                    "code_snippet": sink_match.group(0)[:120].strip(),
                }
            )
            if len(finding.dom_sinks) >= self.MAX_SINKS_PER_SOURCE:
                break

        comment_matches = re.finditer(
            r"//\s*(?:TODO|FIXME|NOTE|HACK|DEV|DEBUG|SECURITY)[^\n]+",
            content,
            re.IGNORECASE,
        )
        finding.developer_comments = [match.group(0).strip() for match in comment_matches][:10]

        flags_matches = re.finditer(
            r"(?:DEBUG|ENABLE_TESTING|DEV_MODE|IS_ADMIN|STAGING)\s*[:=]\s*(?:true|1)",
            content,
        )
        finding.secrets_or_flags = [
            match.group(0).strip() for match in flags_matches
        ][: self.MAX_FLAGS_PER_SOURCE]

        if (
            finding.discovered_endpoints
            or finding.discovered_parameters
            or finding.dom_sinks
            or finding.developer_comments
        ):
            return finding
        return None

    def _fetch_text(self, url: str) -> Optional[str]:
        """Safely fetch bounded HTTP text."""
        if not httpx or not url:
            return None
        try:
            response_stream = httpx.stream(
                "GET",
                url,
                timeout=self.timeout,
                verify=not settings.ALLOW_INSECURE_TLS,
                # Redirects are not followed automatically: a same-origin map endpoint
                # must not redirect the scanner outside the authorized script origin.
                follow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0", **self.request_headers},
            )
            with response_stream as resp:
                if resp.status_code != 200:
                    return None
                content_length = resp.headers.get("content-length")
                if content_length:
                    try:
                        if int(content_length) > self.MAX_MAP_BYTES:
                            return None
                    except (TypeError, ValueError):
                        pass

                raw = bytearray()
                for chunk in resp.iter_bytes():
                    if len(raw) + len(chunk) > self.MAX_MAP_BYTES:
                        return None
                    raw.extend(chunk)
                try:
                    text = bytes(raw).decode(resp.encoding or "utf-8-sig")
                except (UnicodeDecodeError, LookupError):
                    text = bytes(raw).decode("utf-8-sig", errors="replace")
                if self.response_guard:
                    self.response_guard(resp.status_code, str(resp.url), text)
                return text
        except Exception:
            return None
