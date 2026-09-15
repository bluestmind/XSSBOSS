"""Source-free marker correlation for Chrome ``DOMSnapshot`` captures.

Chrome's snapshot domain flattens DOM state that ordinary ``page.content()``
cannot represent reliably, including shadow trees, template content, and child
documents.  This analyzer looks only for the current inert marker and exports
structural metadata.  It never retains node text, attribute values, document
URLs, or the marker itself.
"""
from __future__ import annotations

import hashlib
from typing import Any, Callable, Mapping, Optional
from urllib.parse import urlsplit


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def _bounded_int(value: Any, default: int = -1) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return result


def _origin_fingerprint(url: str) -> str:
    try:
        parsed = urlsplit(str(url or ""))
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        if scheme not in {"http", "https"} or not host:
            return _hash("unknown-origin")
        port = parsed.port or (443 if scheme == "https" else 80)
        return _hash(f"{scheme}://{host}:{port}")
    except (TypeError, ValueError):
        return _hash("unknown-origin")


class DOMSnapshotAnalyzer:
    """Extract bounded marker-placement metadata from one CDP snapshot."""

    SCHEMA_VERSION = "dom-marker-snapshot/v1"
    MAX_DOCUMENTS = 8
    MAX_NODES = 50_000
    MAX_MATCHES = 250
    MAX_VALUE_CHARS = 100_000
    MAX_ANCESTOR_DEPTH = 64

    URL_ATTRIBUTES = {
        "action", "background", "cite", "data", "formaction", "href",
        "longdesc", "poster", "src", "srcset", "xlink:href",
    }

    @staticmethod
    def _string(strings: list[Any], index: Any) -> str:
        resolved = _bounded_int(index)
        if 0 <= resolved < len(strings) and isinstance(strings[resolved], str):
            return strings[resolved]
        return ""

    @classmethod
    def _rare_values(cls, value: Any, strings: list[Any]) -> dict[int, str]:
        if not isinstance(value, Mapping):
            return {}
        indexes = value.get("index")
        values = value.get("value")
        if not isinstance(indexes, list) or not isinstance(values, list):
            return {}
        output: dict[int, str] = {}
        for node_index, string_index in zip(indexes[: cls.MAX_NODES], values[: cls.MAX_NODES]):
            resolved_node = _bounded_int(node_index)
            if resolved_node >= 0:
                output[resolved_node] = cls._string(strings, string_index)
        return output

    @staticmethod
    def _context(tag: str, attribute_name: str = "", value_kind: str = "") -> str:
        attr = attribute_name.lower()
        if attr.startswith("on"):
            return "event_attribute"
        if attr == "style":
            return "style_attribute"
        if attr == "srcdoc":
            return "html_attribute"
        if attr in DOMSnapshotAnalyzer.URL_ATTRIBUTES:
            return "url_attribute"
        if attribute_name:
            return "attribute"
        if value_kind == "input_value":
            return "form_value"
        if value_kind in {"current_source_url", "origin_url"}:
            return "resolved_url"
        lowered_tag = tag.lower()
        if lowered_tag == "script":
            return "script_text"
        if lowered_tag == "style":
            return "style_text"
        if lowered_tag == "template":
            return "template_text"
        return "text"

    @classmethod
    def _path_fingerprint(
        cls,
        node_index: int,
        parents: list[Any],
        names: list[str],
        sibling_ordinals: list[int] | None = None,
    ) -> tuple[str, bool]:
        parts: list[str] = []
        visited: set[int] = set()
        current = node_index
        truncated = False
        for _ in range(cls.MAX_ANCESTOR_DEPTH):
            if current < 0 or current >= len(names) or current in visited:
                break
            visited.add(current)
            parent = _bounded_int(parents[current]) if current < len(parents) else -1
            sibling_ordinal = (
                sibling_ordinals[current]
                if sibling_ordinals is not None and current < len(sibling_ordinals)
                else 0
            )
            if parent >= 0 and sibling_ordinals is None:
                for candidate in range(min(current, len(parents))):
                    if _bounded_int(parents[candidate]) == parent and names[candidate] == names[current]:
                        sibling_ordinal += 1
            parts.append(f"{names[current].lower()}:{sibling_ordinal}")
            current = parent
        else:
            truncated = current >= 0
        return _hash("/".join(reversed(parts))), truncated

    @classmethod
    def analyze(cls, snapshot: Any, marker: str, *, phase: str) -> dict[str, Any]:
        marker = str(marker or "")
        strings = snapshot.get("strings") if isinstance(snapshot, Mapping) else None
        documents = snapshot.get("documents") if isinstance(snapshot, Mapping) else None
        if not marker or not isinstance(strings, list) or not isinstance(documents, list):
            return {
                "schema_version": cls.SCHEMA_VERSION,
                "phase": str(phase or "unknown")[:40],
                "available": False,
                "sites": [],
                "summary": {"documents": 0, "nodes": 0, "marker_sites": 0},
                "budget_exhausted": [],
            }

        sites: list[dict[str, Any]] = []
        seen: set[tuple[Any, ...]] = set()
        node_count = 0
        budget_exhausted: set[str] = set()
        if len(documents) > cls.MAX_DOCUMENTS:
            budget_exhausted.add("documents")
        truncated_values = 0

        def contains_marker(value: str) -> bool:
            nonlocal truncated_values
            if len(value) > cls.MAX_VALUE_CHARS:
                truncated_values += 1
                value = value[: cls.MAX_VALUE_CHARS]
            return marker in value

        for document_index, document in enumerate(documents):
            if document_index >= cls.MAX_DOCUMENTS:
                budget_exhausted.add("documents")
                break
            if not isinstance(document, Mapping):
                continue
            nodes = document.get("nodes")
            if not isinstance(nodes, Mapping):
                continue
            node_types = nodes.get("nodeType") if isinstance(nodes.get("nodeType"), list) else []
            node_names_raw = nodes.get("nodeName") if isinstance(nodes.get("nodeName"), list) else []
            parents = nodes.get("parentIndex") if isinstance(nodes.get("parentIndex"), list) else []
            attributes = nodes.get("attributes") if isinstance(nodes.get("attributes"), list) else []
            node_values = nodes.get("nodeValue") if isinstance(nodes.get("nodeValue"), list) else []
            local_limit = min(
                max(len(node_types), len(node_names_raw), len(parents), len(attributes), len(node_values)),
                max(0, cls.MAX_NODES - node_count),
            )
            if local_limit <= 0:
                budget_exhausted.add("nodes")
                break
            names = [
                cls._string(strings, node_names_raw[index]) if index < len(node_names_raw) else ""
                for index in range(local_limit)
            ]
            sibling_ordinals: list[int] = []
            sibling_counts: dict[tuple[int, str], int] = {}
            for index, name in enumerate(names):
                parent = _bounded_int(parents[index]) if index < len(parents) else -1
                if parent < 0:
                    sibling_ordinals.append(0)
                    continue
                key = (parent, name)
                ordinal = sibling_counts.get(key, 0)
                sibling_ordinals.append(ordinal)
                sibling_counts[key] = ordinal + 1
            shadow_types = cls._rare_values(nodes.get("shadowRootType"), strings)
            rare_fields = {
                "text_value": cls._rare_values(nodes.get("textValue"), strings),
                "input_value": cls._rare_values(nodes.get("inputValue"), strings),
                "current_source_url": cls._rare_values(nodes.get("currentSourceURL"), strings),
                "origin_url": cls._rare_values(nodes.get("originURL"), strings),
            }
            document_url = cls._string(strings, document.get("documentURL"))
            frame_fingerprint = _origin_fingerprint(document_url)

            def nearest_shadow(index: int) -> str | None:
                visited: set[int] = set()
                current = index
                for _ in range(cls.MAX_ANCESTOR_DEPTH):
                    if current < 0 or current >= local_limit or current in visited:
                        return None
                    visited.add(current)
                    if current in shadow_types:
                        value = shadow_types[current].lower()
                        return value if value in {"open", "closed", "user-agent"} else "other"
                    current = _bounded_int(parents[current]) if current < len(parents) else -1
                return "depth-limited"

            def parent_tag(index: int) -> str:
                parent = _bounded_int(parents[index]) if index < len(parents) else -1
                return names[parent] if 0 <= parent < len(names) else names[index]

            def append_site(
                index: int,
                *,
                tag: str,
                attribute_name: str = "",
                value_kind: str = "",
            ) -> None:
                if len(sites) >= cls.MAX_MATCHES:
                    budget_exhausted.add("matches")
                    return
                path_fingerprint, path_truncated = cls._path_fingerprint(
                    index, parents, names, sibling_ordinals
                )
                context = cls._context(tag, attribute_name, value_kind)
                safe_attr = attribute_name.lower()[:80] if attribute_name else None
                signature = (
                    frame_fingerprint, path_fingerprint, context, safe_attr,
                    tag.lower()[:80], nearest_shadow(index),
                )
                if signature in seen:
                    return
                seen.add(signature)
                sites.append({
                    "document_index": document_index,
                    "node_type": _bounded_int(node_types[index]) if index < len(node_types) else -1,
                    "tag": tag.lower()[:80] or "#unknown",
                    "context": context,
                    "attribute_name": safe_attr,
                    "frame_origin_fingerprint": frame_fingerprint,
                    "shadow_root_type": signature[-1],
                    "structural_path_fingerprint": path_fingerprint,
                    "path_depth_limited": path_truncated,
                    "phase": str(phase or "unknown")[:40],
                })

            for index in range(local_limit):
                if len(sites) >= cls.MAX_MATCHES:
                    break
                node_type = _bounded_int(node_types[index]) if index < len(node_types) else -1
                tag = names[index] or (parent_tag(index) if node_type == 3 else "#unknown")

                if index < len(attributes) and isinstance(attributes[index], list):
                    raw_attrs = attributes[index]
                    for offset in range(0, min(len(raw_attrs), 400), 2):
                        if offset + 1 >= len(raw_attrs):
                            break
                        attr_name = cls._string(strings, raw_attrs[offset])
                        attr_value = cls._string(strings, raw_attrs[offset + 1])
                        if attr_value and contains_marker(attr_value):
                            append_site(index, tag=tag, attribute_name=attr_name)

                if index < len(node_values):
                    node_value = cls._string(strings, node_values[index])
                    if node_value and contains_marker(node_value):
                        append_site(index, tag=parent_tag(index), value_kind="node_value")

                for field_name, field_values in rare_fields.items():
                    value = field_values.get(index, "")
                    if value and contains_marker(value):
                        append_site(index, tag=tag, value_kind=field_name)

            node_count += local_limit
            maximum_len = max(len(node_types), len(node_names_raw), len(parents), len(attributes), len(node_values))
            if local_limit < maximum_len:
                budget_exhausted.add("nodes")
                break

        if len(sites) >= cls.MAX_MATCHES:
            budget_exhausted.add("matches")

        return {
            "schema_version": cls.SCHEMA_VERSION,
            "phase": str(phase or "unknown")[:40],
            "available": True,
            "sites": sites,
            "summary": {
                "documents": min(len(documents), cls.MAX_DOCUMENTS),
                "nodes": node_count,
                "marker_sites": len(sites),
                "values_truncated": truncated_values,
            },
            "budget_exhausted": sorted(budget_exhausted),
        }


class DOMSnapshotDifferentialCollector:
    """Capture two normalized snapshots and report newly materialized marker sites."""

    SCHEMA_VERSION = "dom-marker-differential/v1"
    MAX_CAPTURES = 2

    def __init__(self, send: Callable[..., Any], marker: str):
        self._send = send
        self.marker = str(marker or "")
        self._captures: list[dict[str, Any]] = []
        self._errors: list[str] = []

    def capture(self, phase: str) -> bool:
        if not self.marker or len(self._captures) >= self.MAX_CAPTURES:
            return False
        try:
            snapshot = self._send("DOMSnapshot.captureSnapshot", {
                "computedStyles": [],
                "includePaintOrder": False,
                "includeDOMRects": False,
                "includeBlendedBackgroundColors": False,
                "includeTextColorOpacities": False,
            })
            normalized = DOMSnapshotAnalyzer.analyze(snapshot, self.marker, phase=phase)
            if not normalized.get("available"):
                self._errors.append("capture:invalid_response")
                return False
            self._captures.append(normalized)
            return True
        except Exception as error:
            self._errors.append(f"capture:{error.__class__.__name__}")
            return False

    @staticmethod
    def _signature(site: Mapping[str, Any]) -> tuple[Any, ...]:
        return (
            site.get("frame_origin_fingerprint"),
            site.get("structural_path_fingerprint"),
            site.get("context"),
            site.get("attribute_name"),
            site.get("tag"),
            site.get("shadow_root_type"),
        )

    def report(self) -> dict[str, Any]:
        baseline = self._captures[0] if self._captures else None
        after = self._captures[1] if len(self._captures) > 1 else None
        baseline_sites = baseline.get("sites", []) if baseline else []
        after_sites = after.get("sites", []) if after else []
        baseline_signatures = {
            self._signature(item) for item in baseline_sites if isinstance(item, Mapping)
        }
        new_sites = [
            item for item in after_sites
            if isinstance(item, Mapping) and self._signature(item) not in baseline_signatures
        ]
        # If only one capture was possible, its sites still establish materialization,
        # but the report makes the lack of a differential explicit.
        materialized_sites = new_sites if after is not None else list(baseline_sites)
        budget_exhausted = sorted({
            str(reason)
            for capture in self._captures
            for reason in capture.get("budget_exhausted", [])
        })
        contexts: dict[str, int] = {}
        for item in materialized_sites:
            context = str(item.get("context") or "unknown")
            contexts[context] = contexts.get(context, 0) + 1
        return {
            "schema_version": self.SCHEMA_VERSION,
            "available": bool(self._captures),
            "differential_available": after is not None,
            "interpretation": "Marker materialization only; script execution and attacker control are not established.",
            "phases": [item.get("phase") for item in self._captures],
            "summary": {
                "baseline_marker_sites": len(baseline_sites),
                "after_marker_sites": len(after_sites),
                "new_marker_sites": len(new_sites),
                "materialized_sites": len(materialized_sites),
                "contexts": contexts,
            },
            "sites": materialized_sites[: DOMSnapshotAnalyzer.MAX_MATCHES],
            "budget_exhausted": budget_exhausted,
            "errors": self._errors[:20],
            "limits": {
                "captures": self.MAX_CAPTURES,
                "documents": DOMSnapshotAnalyzer.MAX_DOCUMENTS,
                "nodes": DOMSnapshotAnalyzer.MAX_NODES,
                "matches": DOMSnapshotAnalyzer.MAX_MATCHES,
            },
        }


__all__ = ["DOMSnapshotAnalyzer", "DOMSnapshotDifferentialCollector"]
