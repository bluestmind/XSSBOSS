"""Bounded V8 code-coverage correlation for browser security research.

Precise coverage answers one narrow question that static bundle analysis cannot:
did the browser execute the exact source region containing a security-relevant
site?  It does *not* prove that attacker-controlled data reached the site.  The
module therefore emits ``runtime_reached`` evidence only and never upgrades a
candidate to a confirmed vulnerability.

The browser-facing collector keeps source in memory just long enough to run the
static correlator.  Reports contain hashes, safe URLs, offsets, and counts; raw
JavaScript is deliberately omitted.
"""
from __future__ import annotations

import hashlib
import heapq
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Optional
from urllib.parse import urlsplit, urlunsplit


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def _origin(value: str) -> tuple[str, str, int] | None:
    """Return a normalized HTTP(S) origin, including default ports."""
    try:
        parsed = urlsplit(str(value or ""))
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        if scheme not in {"http", "https"} or not host:
            return None
        port = parsed.port or (443 if scheme == "https" else 80)
        return scheme, host, port
    except (TypeError, ValueError):
        return None


def _origin_label(origin: tuple[str, str, int]) -> str:
    scheme, host, port = origin
    host_label = f"[{host}]" if ":" in host and not host.startswith("[") else host
    default = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    return f"{scheme}://{host_label}" if default else f"{scheme}://{host_label}:{port}"


def safe_runtime_script_url(
    script_url: str,
    document_url: str,
    *,
    execution_context_origin: str = "",
) -> tuple[bool, str, str]:
    """Classify a script URL and return a redacted, same-origin label.

    Empty URLs are accepted only when CDP tied their execution context to the
    target origin.  This permits eval-created scripts without trusting arbitrary
    anonymous debugger sources.  Blob URLs are reduced to an origin label so
    their opaque identifiers never enter persisted evidence.
    """
    target_origin = _origin(document_url)
    if target_origin is None:
        return False, "<invalid-target>", "invalid"

    raw = str(script_url or "").strip()
    if not raw:
        if _origin(execution_context_origin) == target_origin:
            return True, f"<eval@{_origin_label(target_origin)}>", "eval"
        return False, "<anonymous>", "anonymous"

    if raw.lower().startswith("blob:"):
        inner_origin = _origin(raw[5:])
        if inner_origin != target_origin:
            return False, "<cross-origin-blob>", "blob"
        return True, f"blob:{_origin_label(target_origin)}/<runtime-script>", "blob"

    parsed_origin = _origin(raw)
    if parsed_origin != target_origin:
        return False, "<cross-origin-script>", "network"
    try:
        parsed = urlsplit(raw)
        host = parsed.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        default = (
            (parsed.scheme.lower() == "https" and (parsed.port in {None, 443}))
            or (parsed.scheme.lower() == "http" and (parsed.port in {None, 80}))
        )
        netloc = host if default else f"{host}:{parsed.port}"
        safe = urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", "", ""))
    except (TypeError, ValueError):
        return False, "<invalid-script>", "network"
    return True, safe, "network"


def python_index_to_utf16(value: str, index: int) -> int:
    """Translate a Python code-point offset to V8's UTF-16 source offset."""
    bounded = max(0, min(int(index or 0), len(value)))
    return len(value[:bounded].encode("utf-16-le", errors="surrogatepass")) // 2


@dataclass(frozen=True)
class ExecutedInterval:
    start: int
    end: int
    count: int


def effective_executed_intervals(
    functions: Any,
    *,
    max_ranges: int = 10_000,
) -> tuple[list[ExecutedInterval], int, bool]:
    """Flatten nested V8 ranges using the innermost range's execution count.

    V8 commonly emits a positive top-level range around an uncalled function's
    zero-count child range.  A naive overlap test marks that dead function as
    executed.  The sweep below resolves each segment to its narrowest active
    range, preferring a zero-count range on exact-span conflicts.
    """
    candidates: list[tuple[int, int, int]] = []
    exhausted = False
    for function in functions if isinstance(functions, list) else []:
        if not isinstance(function, Mapping):
            continue
        ranges = function.get("ranges")
        for item in ranges if isinstance(ranges, list) else []:
            if len(candidates) >= max(0, int(max_ranges)):
                exhausted = True
                break
            if not isinstance(item, Mapping):
                continue
            try:
                start = int(item.get("startOffset"))
                end = int(item.get("endOffset"))
                count = int(item.get("count"))
            except (TypeError, ValueError, OverflowError):
                continue
            if start < 0 or end <= start:
                continue
            candidates.append((start, end, max(0, count)))
        if exhausted:
            break

    if not candidates:
        return [], 0, exhausted

    starts: dict[int, list[int]] = {}
    ends: dict[int, list[int]] = {}
    records: list[tuple[int, int, int]] = []
    for index, record in enumerate(candidates):
        records.append(record)
        starts.setdefault(record[0], []).append(index)
        ends.setdefault(record[1], []).append(index)

    boundaries = sorted(set(starts) | set(ends))
    active: set[int] = set()
    heap: list[tuple[int, int, int]] = []
    segments: list[ExecutedInterval] = []
    for boundary_index, position in enumerate(boundaries[:-1]):
        for record_id in ends.get(position, []):
            active.discard(record_id)
        for record_id in starts.get(position, []):
            active.add(record_id)
            start, end, count = records[record_id]
            # Narrowest range wins. On identical spans, zero is conservative.
            heapq.heappush(
                heap,
                (end - start, 0 if count == 0 else 1, record_id),
            )
        while heap and heap[0][2] not in active:
            heapq.heappop(heap)
        next_position = boundaries[boundary_index + 1]
        if not heap or next_position <= position:
            continue
        _, _, selected_id = heap[0]
        count = records[selected_id][2]
        if count <= 0:
            continue
        if segments and segments[-1].end == position and segments[-1].count == count:
            previous = segments[-1]
            segments[-1] = ExecutedInterval(previous.start, next_position, count)
        else:
            segments.append(ExecutedInterval(position, next_position, count))
    return segments, len(candidates), exhausted


def _count_at(intervals: list[ExecutedInterval], offset: int) -> int:
    low, high = 0, len(intervals)
    while low < high:
        middle = (low + high) // 2
        interval = intervals[middle]
        if offset < interval.start:
            high = middle
        elif offset >= interval.end:
            low = middle + 1
        else:
            return interval.count
    return 0


class RuntimeCoverageAnalyzer:
    """Correlate executed UTF-16 ranges with bounded static finding offsets."""

    MAX_SOURCE_CHARS = 2_000_000
    MAX_FINDINGS = 250

    _GENERIC_SITES: tuple[tuple[str, str, str], ...] = (
        ("dom_sink", "innerHTML", r"\.\s*(?:innerHTML|outerHTML|srcdoc)\s*=(?!=)"),
        ("dom_sink", "insertAdjacentHTML", r"\.\s*insertAdjacentHTML\s*\("),
        ("dom_sink", "document_write", r"\bdocument\s*\.\s*write(?:ln)?\s*\("),
        ("code_execution_sink", "eval", r"\beval\s*\("),
        ("code_execution_sink", "function_ctor", r"(?:\bnew\s+Function\b|\bFunction\s*\()"),
        ("navigation_sink", "location", r"(?:\blocation(?:\s*\.\s*href)?\s*=|\blocation\s*\.\s*(?:assign|replace)\s*\()"),
    )

    @classmethod
    def correlate_script(
        cls,
        *,
        script_url: str,
        source: str,
        functions: Any,
        phase: str,
        max_ranges: int = 10_000,
        max_findings: int | None = None,
    ) -> dict[str, Any]:
        """Return source-free activation evidence for one script."""
        import re

        from analysis_engine.client_trust_analyzer import (
            ClientTrustAnalyzer,
            _mask_strings_preserving_offsets,
            _strip_comments_preserving_offsets,
        )

        raw_source = str(source or "")
        truncated = len(raw_source) > cls.MAX_SOURCE_CHARS
        code = raw_source[: cls.MAX_SOURCE_CHARS]
        intervals, observed_ranges, range_truncated = effective_executed_intervals(
            functions,
            max_ranges=max_ranges,
        )
        source_fingerprint = _sha256(code)
        requested_findings = cls.MAX_FINDINGS if max_findings is None else int(max_findings)
        finding_limit = max(0, min(cls.MAX_FINDINGS, requested_findings))
        sites: list[dict[str, Any]] = []

        for finding in ClientTrustAnalyzer.analyze(code, max_findings=finding_limit):
            utf16_offset = python_index_to_utf16(code, finding.offset)
            execution_count = _count_at(intervals, utf16_offset)
            if execution_count <= 0:
                continue
            sites.append({
                "category": finding.category,
                "site_kind": str(finding.details.get("sink") or "trust_boundary")[:80],
                "code_fingerprint": finding.code_fingerprint,
                "offset_utf16": utf16_offset,
                "execution_count": execution_count,
                "runtime_reached": True,
                "phase": str(phase or "unknown")[:40],
            })
            if len(sites) >= finding_limit:
                break

        # Add exact generic sink activation even when no higher-level trust finding
        # exists. Comment and string masks preserve offsets and suppress decoys.
        masked = _mask_strings_preserving_offsets(
            _strip_comments_preserving_offsets(code)
        )
        if len(sites) < finding_limit:
            for category, site_kind, pattern in cls._GENERIC_SITES:
                for match in re.finditer(pattern, masked, re.IGNORECASE):
                    utf16_offset = python_index_to_utf16(code, match.start())
                    execution_count = _count_at(intervals, utf16_offset)
                    if execution_count <= 0:
                        continue
                    fingerprint_window = code[
                        max(0, match.start() - 80):min(len(code), match.end() + 80)
                    ]
                    record = {
                        "category": category,
                        "site_kind": site_kind,
                        "code_fingerprint": _sha256(fingerprint_window),
                        "offset_utf16": utf16_offset,
                        "execution_count": execution_count,
                        "runtime_reached": True,
                        "phase": str(phase or "unknown")[:40],
                    }
                    dedupe_key = (
                        record["category"], record["site_kind"], record["offset_utf16"]
                    )
                    if not any(
                        (item["category"], item["site_kind"], item["offset_utf16"])
                        == dedupe_key for item in sites
                    ):
                        sites.append(record)
                    if len(sites) >= finding_limit:
                        break
                if len(sites) >= finding_limit:
                    break

        executed_units = sum(item.end - item.start for item in intervals)
        return {
            "script": {
                "url": str(script_url)[:2048],
                "source_fingerprint": source_fingerprint,
                "source_chars": len(code),
                "source_truncated": truncated,
                "observed_ranges": observed_ranges,
                "range_budget_exhausted": range_truncated,
                "executed_utf16_units": executed_units,
                "phase": str(phase or "unknown")[:40],
            },
            "findings": sites,
        }


class RuntimeCoverageCollector:
    """Collect and normalize precise coverage through a CDP send callable."""

    SCHEMA_VERSION = "runtime-code-coverage/v1"
    MAX_SCRIPTS = 64
    MAX_SOURCE_BYTES = 8_000_000
    MAX_SOURCE_BYTES_PER_SCRIPT = 2_000_000
    MAX_RANGES = 10_000
    MAX_FINDINGS = 250

    def __init__(self, send: Callable[..., Any], document_url: str):
        self._send = send
        self.document_url = str(document_url or "")
        self._active = False
        self._contexts: dict[int, str] = {}
        self._scripts: dict[str, dict[str, Any]] = {}
        self._source_cache: dict[str, str] = {}
        self._source_bytes = 0
        self._snapshots: list[dict[str, Any]] = []
        self._errors: list[str] = []
        self._budget_exhausted: set[str] = set()

    def _command(self, method: str, params: Optional[dict[str, Any]] = None) -> Any:
        return self._send(method, params or {})

    def on_execution_context_created(self, params: Any) -> None:
        if not isinstance(params, Mapping):
            return
        context = params.get("context")
        if not isinstance(context, Mapping):
            return
        try:
            context_id = int(context.get("id"))
        except (TypeError, ValueError, OverflowError):
            return
        origin = str(context.get("origin") or "")[:2048]
        if origin:
            self._contexts[context_id] = origin

    def on_script_parsed(self, params: Any) -> None:
        if not isinstance(params, Mapping):
            return
        script_id = str(params.get("scriptId") or "")[:120]
        if not script_id:
            return
        try:
            context_id = int(params.get("executionContextId"))
        except (TypeError, ValueError, OverflowError):
            context_id = -1
        self._scripts[script_id] = {
            "url": str(params.get("url") or "")[:4096],
            "context_origin": self._contexts.get(context_id, ""),
        }

    def start(self) -> bool:
        try:
            self._command("Runtime.enable")
            self._command("Debugger.enable")
            self._command("Profiler.enable")
            self._command("Profiler.startPreciseCoverage", {
                "callCount": True,
                "detailed": True,
                "allowTriggeredUpdates": False,
            })
            self._active = True
            return True
        except Exception as error:
            self._errors.append(f"start:{error.__class__.__name__}")
            self._active = False
            self._disable_domains()
            return False

    @staticmethod
    def _has_execution(functions: Any) -> bool:
        intervals, _, _ = effective_executed_intervals(functions, max_ranges=10_000)
        return bool(intervals)

    @staticmethod
    def _is_instrumentation_source(source: str) -> bool:
        markers = (
            "XSS Oracle: Injected successfully",
            "window.__XSS_TOKEN__",
            "__registerOracleHook__",
        )
        return sum(marker in source for marker in markers) >= 2

    def _source_for(self, script_id: str) -> str | None:
        if script_id in self._source_cache:
            return self._source_cache[script_id]
        try:
            response = self._command("Debugger.getScriptSource", {"scriptId": script_id})
        except Exception as error:
            self._errors.append(f"source:{error.__class__.__name__}")
            return None
        if not isinstance(response, Mapping) or not isinstance(response.get("scriptSource"), str):
            return None
        source = response["scriptSource"]
        source_bytes = len(source.encode("utf-8", errors="ignore"))
        if source_bytes > self.MAX_SOURCE_BYTES_PER_SCRIPT:
            self._budget_exhausted.add("per_script_source_bytes")
            return None
        if self._source_bytes + source_bytes > self.MAX_SOURCE_BYTES:
            self._budget_exhausted.add("total_source_bytes")
            return None
        self._source_bytes += source_bytes
        self._source_cache[script_id] = source
        return source

    def snapshot(self, phase: str) -> bool:
        if not self._active:
            return False
        try:
            response = self._command("Profiler.takePreciseCoverage")
        except Exception as error:
            self._errors.append(f"snapshot:{error.__class__.__name__}")
            return False
        entries = response.get("result") if isinstance(response, Mapping) else None
        if not isinstance(entries, list):
            self._errors.append("snapshot:invalid_response")
            return False

        scripts: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        considered = 0
        for entry in entries:
            if considered >= self.MAX_SCRIPTS:
                self._budget_exhausted.add("scripts")
                break
            if not isinstance(entry, Mapping):
                continue
            functions = entry.get("functions")
            if not self._has_execution(functions):
                continue
            script_id = str(entry.get("scriptId") or "")[:120]
            if not script_id:
                continue
            metadata = self._scripts.get(script_id, {})
            raw_url = str(entry.get("url") or metadata.get("url") or "")
            accepted, safe_url, _kind = safe_runtime_script_url(
                raw_url,
                self.document_url,
                execution_context_origin=str(metadata.get("context_origin") or ""),
            )
            if not accepted:
                continue
            considered += 1
            source = self._source_for(script_id)
            if source is None or self._is_instrumentation_source(source):
                continue
            correlated = RuntimeCoverageAnalyzer.correlate_script(
                script_url=safe_url,
                source=source,
                functions=functions,
                phase=phase,
                max_ranges=self.MAX_RANGES,
                max_findings=max(0, self.MAX_FINDINGS - len(findings)),
            )
            scripts.append(correlated["script"])
            findings.extend(correlated["findings"])
            if len(findings) >= self.MAX_FINDINGS:
                self._budget_exhausted.add("findings")
                break
        self._snapshots.append({
            "phase": str(phase or "unknown")[:40],
            "scripts": scripts,
            "findings": findings[: self.MAX_FINDINGS],
        })
        return True

    def report(self) -> dict[str, Any]:
        scripts: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        seen_scripts: set[tuple[str, str, str]] = set()
        seen_findings: set[tuple[str, str, int, str]] = set()
        for snapshot in self._snapshots:
            for item in snapshot["scripts"]:
                key = (item["url"], item["source_fingerprint"], item["phase"])
                if key not in seen_scripts and len(scripts) < self.MAX_SCRIPTS * 3:
                    seen_scripts.add(key)
                    scripts.append(item)
            for item in snapshot["findings"]:
                key = (
                    item["category"], item["code_fingerprint"],
                    item["offset_utf16"], item["phase"],
                )
                if key not in seen_findings and len(findings) < self.MAX_FINDINGS:
                    seen_findings.add(key)
                    findings.append(item)
        categories: dict[str, int] = {}
        for item in findings:
            category = str(item.get("category") or "unknown")
            categories[category] = categories.get(category, 0) + 1
        return {
            "schema_version": self.SCHEMA_VERSION,
            "available": bool(self._snapshots),
            "interpretation": "Executed source region only; attacker-data influence is not established.",
            "phases": [item["phase"] for item in self._snapshots],
            "limits": {
                "scripts": self.MAX_SCRIPTS,
                "source_bytes": self.MAX_SOURCE_BYTES,
                "source_bytes_per_script": self.MAX_SOURCE_BYTES_PER_SCRIPT,
                "ranges": self.MAX_RANGES,
                "findings": self.MAX_FINDINGS,
            },
            "budget_exhausted": sorted(self._budget_exhausted),
            "summary": {
                "scripts_analyzed": len(scripts),
                "runtime_reached_sites": len(findings),
                "categories": categories,
                "source_bytes_analyzed": self._source_bytes,
            },
            "scripts": scripts,
            "findings": findings,
            "errors": self._errors[:20],
        }

    def _disable_domains(self) -> None:
        for method in (
            "Profiler.stopPreciseCoverage",
            "Profiler.disable",
            "Debugger.disable",
            "Runtime.disable",
        ):
            try:
                self._command(method)
            except Exception:
                pass

    def finish(self, final_phase: str | None = None) -> dict[str, Any]:
        if final_phase and self._active:
            self.snapshot(final_phase)
        self._disable_domains()
        self._active = False
        report = self.report()
        self._source_cache.clear()
        return report


__all__ = [
    "ExecutedInterval",
    "RuntimeCoverageAnalyzer",
    "RuntimeCoverageCollector",
    "effective_executed_intervals",
    "python_index_to_utf16",
    "safe_runtime_script_url",
]
