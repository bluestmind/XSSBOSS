"""Passive correlation for client-side property-integrity risks.

The analyzer deliberately produces *observations*, not vulnerability verdicts.  A DOM
clobbering chain requires an HTML named property, an implicit Window/Document read of
that exact name, and a security-sensitive sink reached by the read.  A prototype or
property-injection chain similarly requires an externally influenced object/property,
a merge or dynamic property write, and a sensitive gadget read that reaches a sink.

The module performs no I/O and returns bounded metadata and SHA-256 fingerprints.  It
never returns source snippets, HTML fragments, string literals, or response content.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from typing import Any, Iterable, Mapping, Sequence


MAX_HTML_CHARS = 1_000_000
MAX_JAVASCRIPT_CHARS = 2_000_000
MAX_NAMED_PROPERTIES = 2_000
MAX_STRUCTURED_RECORDS = 2_000
MAX_OBSERVATIONS = 5_000
MAX_CHAINS = 500

_FORM_TAG = "form"
_FORM_CONTROL_TAGS = {
    "button", "fieldset", "input", "object", "output", "select", "textarea",
}
_WINDOW_NAME_TAGS = {"embed", "form", "iframe", "img", "object"}
_DOCUMENT_NAME_TAGS = {"embed", "form", "iframe", "img", "object"}
_EXPLICIT_LOOKUPS = {
    "getelementbyid", "getelementsbyname", "queryselector", "queryselectorall",
    "nameditem", "closest",
}
_DOM_SINKS = {
    "innerhtml", "outerhtml", "insertadjacenthtml", "document.write",
    "document_write", "dangerouslysetinnerhtml", "srcdoc", "sethtmlunsafe",
    "parsehtmlunsafe", "eval", "function", "function_ctor", "timer-string",
    "timer_string", "location", "location-write", "location_write", "navigation",
    "window.open", "location.href", "location.assign", "location.replace",
    "setattribute", "script-text",
}
_SENSITIVE_GADGET_PROPERTIES = {
    "html", "innerhtml", "outerhtml", "template", "markup", "srcdoc", "url",
    "href", "src", "action", "formaction", "code", "script", "sequence",
}
_FORBIDDEN_KEYS = {"__proto__", "prototype", "constructor"}
_SAFE_METADATA = re.compile(r"^[A-Za-z0-9_$][A-Za-z0-9_$:.-]{0,127}$")
_SAFE_SYMBOL = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*){0,7}$")
_IDENTIFIER = re.compile(r"^[A-Za-z_$][\w$]*$")


def _fingerprint(kind: str, metadata: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        {"kind": kind, "metadata": metadata},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()


def _bounded_int(value: Any, default: int = 0) -> int:
    try:
        return max(0, min(10_000_000, int(value)))
    except (TypeError, ValueError):
        return default


def _metadata_name(value: Any) -> str | None:
    """Return a bounded HTML/property name suitable for metadata and correlation."""
    if not isinstance(value, str):
        return None
    value = value.strip()[:128]
    if not value or any(ord(char) < 0x20 for char in value):
        return None
    return value if _SAFE_METADATA.fullmatch(value) else None


def _symbol(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = re.sub(r"\s+", "", value)[:256]
    return value if _SAFE_SYMBOL.fullmatch(value) else None


def _normalized_kind(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")[:80]


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "reachable", "reaches_sink"}


def _sink_kind(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower().replace(" ", "_")[:80]
    return normalized or None


def _sensitive_sink(value: Any) -> bool:
    sink = _sink_kind(value)
    if not sink:
        return False
    compact = sink.replace("_", "").replace("-", "")
    return sink in _DOM_SINKS or compact in {
        item.replace("_", "").replace("-", "") for item in _DOM_SINKS
    }


@dataclass(frozen=True, slots=True)
class NamedPropertyDefinition:
    """A bounded HTML named-property definition."""

    name: str
    tag: str
    attribute: str
    line: int
    exposures: tuple[str, ...]
    parent_form: str | None
    fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class IntegrityObservation:
    """Metadata-only passive observation."""

    kind: str
    fingerprint: str
    confidence: float
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class PropertyIntegrityAnalysis:
    """Complete bounded result from :class:`PropertyIntegrityAnalyzer`."""

    named_properties: list[NamedPropertyDefinition] = field(default_factory=list)
    observations: list[IntegrityObservation] = field(default_factory=list)
    chains: list[IntegrityObservation] = field(default_factory=list)
    limits: dict[str, Any] = field(default_factory=dict)

    @property
    def dom_clobbering_chains(self) -> list[IntegrityObservation]:
        return [item for item in self.chains if item.kind == "dom_clobbering_chain"]

    @property
    def prototype_property_injection_chains(self) -> list[IntegrityObservation]:
        return [
            item for item in self.chains
            if item.kind == "prototype_property_injection_chain"
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "named_properties": [item.to_dict() for item in self.named_properties],
            "observations": [item.to_dict() for item in self.observations],
            "chains": [item.to_dict() for item in self.chains],
            "limits": dict(self.limits),
        }


class _NamedPropertyParser(HTMLParser):
    def __init__(self, maximum: int):
        super().__init__(convert_charrefs=True)
        self.maximum = maximum
        self.definitions: list[NamedPropertyDefinition] = []
        self._forms: list[str | None] = []
        self.truncated = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle(tag, attrs, push_form=True)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle(tag, attrs, push_form=False)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == _FORM_TAG and self._forms:
            self._forms.pop()

    def _handle(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
        *,
        push_form: bool,
    ) -> None:
        tag = tag.lower()[:40]
        attr_map = {str(key).lower(): value for key, value in attrs[:100]}
        element_id = _metadata_name(attr_map.get("id"))
        element_name = _metadata_name(attr_map.get("name"))
        explicit_form = _metadata_name(attr_map.get("form"))
        current_form = next((item for item in reversed(self._forms) if item), None)

        form_identity = element_id or element_name if tag == _FORM_TAG else None
        parent_form = explicit_form or current_form if tag in _FORM_CONTROL_TAGS else None

        for attribute, name in (("id", element_id), ("name", element_name)):
            if not name:
                continue
            exposures: set[str] = set()
            if attribute == "id":
                # Window named access includes elements with an id.  Document named
                # access varies by element type, so only claim it for exposed tags.
                exposures.add("window")
                if tag in _DOCUMENT_NAME_TAGS:
                    exposures.add("document")
            elif tag in _WINDOW_NAME_TAGS:
                exposures.add("window")
                if tag in _DOCUMENT_NAME_TAGS:
                    exposures.add("document")
            if tag in _FORM_CONTROL_TAGS and parent_form:
                exposures.add("form")
            if not exposures:
                # Retain every bounded id/name as an inventory observation.  The
                # generic exposure never satisfies Window/Document correlation.
                exposures.add("element")
            metadata = {
                "name": name,
                "tag": tag,
                "attribute": attribute,
                "line": self.getpos()[0],
                "exposures": sorted(exposures),
                "parent_form": parent_form,
            }
            definition = NamedPropertyDefinition(
                name=name,
                tag=tag,
                attribute=attribute,
                line=self.getpos()[0],
                exposures=tuple(sorted(exposures)),
                parent_form=parent_form,
                fingerprint=_fingerprint("html_named_property", metadata),
            )
            if definition.fingerprint not in {item.fingerprint for item in self.definitions}:
                if len(self.definitions) >= self.maximum:
                    self.truncated = True
                    break
                self.definitions.append(definition)

        if tag == _FORM_TAG and push_form:
            self._forms.append(form_identity)


@dataclass(frozen=True, slots=True)
class _PropertyRead:
    name: str
    base: str
    path: tuple[str, ...]
    line: int
    sink_kind: str
    implicit: bool
    reaches_sink: bool
    mitigated: bool
    trust: str | None
    source: str


@dataclass(frozen=True, slots=True)
class _ExternalSource:
    symbol: str
    source_kind: str
    line: int
    order: int
    scope: str


@dataclass(frozen=True, slots=True)
class _Mutation:
    target_symbol: str
    source_symbol: str | None
    key_symbol: str | None
    operation: str
    line: int
    order: int
    scope: str
    externally_influenced: bool
    guarded: bool
    injection_mode: str


@dataclass(frozen=True, slots=True)
class _Gadget:
    object_symbol: str
    property_name: str
    sink_kind: str
    line: int
    order: int
    scope: str
    reaches_sink: bool


class PropertyIntegrityAnalyzer:
    """Bounded passive analyzer for named-property and property-mutation chains."""

    @classmethod
    def analyze(
        cls,
        html_content: str = "",
        javascript_content: str = "",
        *,
        property_reads: Iterable[Mapping[str, Any]] | None = None,
        js_property_reads: Iterable[Mapping[str, Any]] | None = None,
        client_trust_findings: Iterable[Mapping[str, Any]] | None = None,
        property_events: Iterable[Mapping[str, Any]] | None = None,
        max_named_properties: int = MAX_NAMED_PROPERTIES,
        max_structured_records: int = MAX_STRUCTURED_RECORDS,
    ) -> PropertyIntegrityAnalysis:
        """Analyze already-acquired HTML/JavaScript and structured passive findings.

        ``client_trust_findings`` may contain nested ``property_reads`` and
        ``property_events`` arrays.  This lets a postMessage trust analyzer pass its
        handler-scoped facts without coupling either analyzer to the other's types.
        """
        html = (html_content or "")[:MAX_HTML_CHARS]
        javascript = (javascript_content or "")[:MAX_JAVASCRIPT_CHARS]
        parser = _NamedPropertyParser(max(0, min(max_named_properties, MAX_NAMED_PROPERTIES)))
        try:
            parser.feed(html)
            parser.close()
        except Exception:
            # Malformed HTML may yield a partial, still useful inventory.
            pass

        result = PropertyIntegrityAnalysis(named_properties=parser.definitions)
        result.limits = {
            "html_truncated": len(html_content or "") > MAX_HTML_CHARS,
            "javascript_truncated": len(javascript_content or "") > MAX_JAVASCRIPT_CHARS,
            "named_properties_truncated": parser.truncated,
            "max_named_properties": parser.maximum,
            "max_structured_records": max(0, min(max_structured_records, MAX_STRUCTURED_RECORDS)),
        }

        effective_record_limit = max(0, min(max_structured_records, MAX_STRUCTURED_RECORDS))
        trust_items = cls._bounded_mappings(client_trust_findings, effective_record_limit)
        read_items = cls._bounded_mappings(property_reads, effective_record_limit)
        read_items.extend(cls._bounded_mappings(js_property_reads, effective_record_limit))
        event_items = cls._bounded_mappings(property_events, effective_record_limit)
        for trust_item in trust_items:
            if any(key in trust_item for key in ("named_property", "property_path", "expression_path", "path")):
                read_items.append(trust_item)
            for key in ("property_reads", "js_property_reads", "reads"):
                for nested in cls._bounded_mappings(trust_item.get(key), effective_record_limit):
                    inherited = dict(nested)
                    if "trust" not in inherited and "trust_classification" not in inherited:
                        inherited["trust_classification"] = trust_item.get("trust_classification")
                    if "handler_fingerprint" not in inherited:
                        inherited["handler_fingerprint"] = trust_item.get("handler_fingerprint")
                    read_items.append(inherited)
            for key in ("property_events", "prototype_events", "mutation_events"):
                event_items.extend(cls._bounded_mappings(trust_item.get(key), effective_record_limit))
        read_items = read_items[:effective_record_limit]
        event_items = event_items[:effective_record_limit]

        reads = [item for raw in read_items if (item := cls._normalize_read(raw))]
        cls._append_html_observations(result)
        cls._append_read_observations(result, reads)
        cls._correlate_dom_clobbering(result, reads)

        structured_sources, structured_mutations, structured_gadgets = cls._structured_events(event_items)
        raw_sources, raw_mutations, raw_gadgets = cls._javascript_events(javascript)
        sources = [*structured_sources, *raw_sources]
        mutations = [*structured_mutations, *raw_mutations]
        gadgets = [*structured_gadgets, *raw_gadgets]
        cls._append_property_event_observations(result, sources, mutations, gadgets)
        cls._correlate_property_injection(result, sources, mutations, gadgets)

        result.observations = cls._dedupe_records(result.observations)[:MAX_OBSERVATIONS]
        result.chains = cls._dedupe_records(result.chains)[:MAX_CHAINS]
        result.limits["observations_truncated"] = len(result.observations) >= MAX_OBSERVATIONS
        result.limits["chains_truncated"] = len(result.chains) >= MAX_CHAINS
        return result

    @staticmethod
    def extract_named_properties(
        html_content: str,
        maximum: int = MAX_NAMED_PROPERTIES,
    ) -> list[NamedPropertyDefinition]:
        parser = _NamedPropertyParser(max(0, min(maximum, MAX_NAMED_PROPERTIES)))
        try:
            parser.feed((html_content or "")[:MAX_HTML_CHARS])
            parser.close()
        except Exception:
            pass
        return parser.definitions

    # Explicit alias for callers that name the acquired artifact in the method.
    extract_html_named_properties = extract_named_properties

    @staticmethod
    def _bounded_mappings(value: Any, maximum: int) -> list[Mapping[str, Any]]:
        if value is None or isinstance(value, (str, bytes, Mapping)):
            values: Iterable[Any] = [value] if isinstance(value, Mapping) else []
        else:
            try:
                values = value
            except TypeError:
                values = []
        result: list[Mapping[str, Any]] = []
        limit = max(0, min(maximum, MAX_STRUCTURED_RECORDS))
        for item in values:
            if isinstance(item, Mapping):
                result.append(item)
                if len(result) >= limit:
                    break
        return result

    @staticmethod
    def _normalize_path(value: Any) -> tuple[str, ...]:
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            return tuple(
                name for item in value
                if (name := _metadata_name(item)) is not None
            )[:12]
        if not isinstance(value, str):
            return ()
        normalized = re.sub(r"\[\s*['\"]([A-Za-z_$][\w$:-]*)['\"]\s*\]", r".\1", value)
        return tuple(
            part for raw in normalized.split(".")
            if (part := _metadata_name(raw)) is not None
        )[:12]

    @classmethod
    def _normalize_read(cls, raw: Mapping[str, Any]) -> _PropertyRead | None:
        lookup = _normalized_kind(raw.get("lookup_method") or raw.get("access_method"))
        if lookup in _EXPLICIT_LOOKUPS:
            implicit = False
        else:
            implicit = _truthy(raw.get("implicit")) or _truthy(raw.get("implicit_named_property"))

        path = cls._normalize_path(
            raw.get("path") or raw.get("property_path") or raw.get("expression_path")
        )
        base = _normalized_kind(raw.get("base") or raw.get("scope") or raw.get("receiver"))
        name = _metadata_name(raw.get("named_property") or raw.get("name") or raw.get("property"))

        if path:
            if path[0].lower() in {"window", "document"}:
                base = path[0].lower()
                implicit = lookup not in _EXPLICIT_LOOKUPS
                if base == "document" and len(path) >= 3 and path[1].lower() == "forms":
                    name = path[2]
                elif len(path) >= 2:
                    name = path[1]
            elif base in {"implicit", "global", "unqualified"} and not name:
                name = path[0]
        if base in {
            "window", "document", "document.forms", "document_forms",
            "global", "implicit", "unqualified",
        }:
            implicit = implicit or lookup not in _EXPLICIT_LOOKUPS
        if not name or not base:
            return None

        sink = _sink_kind(raw.get("sink_kind") or raw.get("sink"))
        reaches = _truthy(raw.get("reaches_sink")) or _normalized_kind(raw.get("flow_status")) in {
            "reachable", "reaches_sink",
        }
        # A structured flow with a named terminal sink may omit the redundant boolean.
        if sink and raw.get("flow") in {"source_to_sink", "property_to_sink"}:
            reaches = True
        mitigated = any(
            _truthy(raw.get(key))
            for key in ("validated", "ownership_guard", "type_guard", "lexically_shadowed", "mitigated")
        )
        trust = _normalized_kind(raw.get("trust") or raw.get("trust_classification")) or None
        return _PropertyRead(
            name=name,
            base=base,
            path=path,
            line=_bounded_int(raw.get("line")),
            sink_kind=sink or "unknown",
            implicit=implicit,
            reaches_sink=reaches,
            mitigated=mitigated,
            trust=trust,
            source="client_trust" if raw.get("handler_fingerprint") or trust else "structured_read",
        )

    @classmethod
    def _append_html_observations(cls, result: PropertyIntegrityAnalysis) -> None:
        for item in result.named_properties:
            metadata = {
                "definition_fingerprint": item.fingerprint,
                "name": item.name,
                "tag": item.tag,
                "attribute": item.attribute,
                "line": item.line,
                "exposures": list(item.exposures),
                "parent_form": item.parent_form,
            }
            cls._observation(result, "html_named_property", 0.95, metadata)

    @classmethod
    def _append_read_observations(
        cls,
        result: PropertyIntegrityAnalysis,
        reads: Iterable[_PropertyRead],
    ) -> None:
        for item in reads:
            metadata = {
                "name": item.name,
                "base": item.base,
                "path": list(item.path),
                "line": item.line,
                "sink_kind": item.sink_kind,
                "implicit": item.implicit,
                "reaches_sink": item.reaches_sink,
                "mitigated": item.mitigated,
                "trust": item.trust,
                "source": item.source,
            }
            cls._observation(result, "js_named_property_read", 0.85, metadata)

    @classmethod
    def _correlate_dom_clobbering(
        cls,
        result: PropertyIntegrityAnalysis,
        reads: Iterable[_PropertyRead],
    ) -> None:
        definitions = result.named_properties
        for read in reads:
            if not read.implicit or not read.reaches_sink or read.mitigated:
                continue
            if not _sensitive_sink(read.sink_kind):
                continue

            matched: list[NamedPropertyDefinition] = []
            relationship = "direct_named_property"
            lower_path = [part.lower() for part in read.path]
            if (
                read.base in {"document", "document_forms"}
                and len(lower_path) >= 4
                and lower_path[0] == "document"
                and lower_path[1] == "forms"
            ):
                form_name, control_name = read.path[2], read.path[3]
                forms = [
                    item for item in definitions
                    if item.tag == _FORM_TAG and item.name == form_name
                    and "document" in item.exposures
                ]
                controls = [
                    item for item in definitions
                    if item.name == control_name and item.parent_form == form_name
                    and "form" in item.exposures
                ]
                if forms and controls:
                    matched = [forms[0], controls[0]]
                    relationship = "document_forms_control"
            else:
                exposure = "document" if read.base.startswith("document") else "window"
                matched = [
                    item for item in definitions
                    if item.name == read.name and exposure in item.exposures
                ][:5]

            if not matched:
                continue
            metadata = {
                "named_property": read.name,
                "base": read.base,
                "relationship": relationship,
                "definition_fingerprints": [item.fingerprint for item in matched],
                "definition_lines": [item.line for item in matched],
                "read_line": read.line,
                "sink_kind": read.sink_kind,
                "trust": read.trust,
            }
            cls._chain(result, "dom_clobbering_chain", 0.93 if len(matched) > 1 else 0.9, metadata)

    @classmethod
    def _structured_events(
        cls,
        events: Iterable[Mapping[str, Any]],
    ) -> tuple[list[_ExternalSource], list[_Mutation], list[_Gadget]]:
        sources: list[_ExternalSource] = []
        mutations: list[_Mutation] = []
        gadgets: list[_Gadget] = []
        external_kinds = {
            "external_object", "external_source", "untrusted_object", "client_input",
            "message_data", "url_object", "storage_object",
        }
        mutation_kinds = {
            "merge", "object_merge", "deep_merge", "property_write",
            "dynamic_property_write", "recursive_merge",
        }
        gadget_kinds = {"gadget", "gadget_read", "sensitive_property_read"}

        for order, raw in enumerate(events):
            kind = _normalized_kind(raw.get("kind") or raw.get("event_type"))
            scope = _normalized_kind(raw.get("scope") or raw.get("function")) or "module"
            line = _bounded_int(raw.get("line"))
            if kind in external_kinds:
                symbol = _symbol(raw.get("symbol") or raw.get("variable") or raw.get("target_symbol"))
                if symbol and (_truthy(raw.get("externally_influenced")) or kind in external_kinds):
                    sources.append(_ExternalSource(
                        symbol=symbol,
                        source_kind=_normalized_kind(raw.get("source_kind") or kind),
                        line=line,
                        order=order,
                        scope=scope,
                    ))
            elif kind in mutation_kinds:
                target = _symbol(raw.get("target_symbol") or raw.get("target") or raw.get("object_symbol"))
                source = _symbol(raw.get("source_symbol") or raw.get("source") or raw.get("value_symbol"))
                key_symbol = _symbol(raw.get("key_symbol") or raw.get("key"))
                operation = _normalized_kind(raw.get("operation") or kind)
                if not target:
                    continue
                blocked_keys = {
                    str(item).lower() for item in raw.get("blocked_keys", [])
                } if isinstance(raw.get("blocked_keys"), Sequence) and not isinstance(raw.get("blocked_keys"), str) else set()
                guarded = (
                    _truthy(raw.get("forbidden_key_guard"))
                    or _truthy(raw.get("allowlist_guard"))
                    or _truthy(raw.get("mitigated"))
                    or _FORBIDDEN_KEYS.issubset(blocked_keys)
                )
                directly_external = _truthy(raw.get("externally_influenced"))
                dynamic = kind in {"property_write", "dynamic_property_write"}
                if dynamic and not (_truthy(raw.get("dynamic_key")) or key_symbol):
                    # A fixed assignment is normal data flow, not property injection.
                    continue
                mode = "prototype" if target.lower() in {"object.prototype", "__proto__"} else "property"
                mutations.append(_Mutation(
                    target_symbol=target,
                    source_symbol=source,
                    key_symbol=key_symbol,
                    operation=operation,
                    line=line,
                    order=order,
                    scope=scope,
                    externally_influenced=directly_external,
                    guarded=guarded,
                    injection_mode=mode,
                ))
            elif kind in gadget_kinds:
                obj = _symbol(raw.get("object_symbol") or raw.get("object") or raw.get("receiver"))
                prop = _metadata_name(raw.get("property") or raw.get("property_name"))
                sink = _sink_kind(raw.get("sink_kind") or raw.get("sink"))
                reaches = _truthy(raw.get("reaches_sink")) or _normalized_kind(raw.get("flow_status")) in {
                    "reachable", "reaches_sink",
                }
                if obj and prop and sink:
                    gadgets.append(_Gadget(obj, prop, sink, line, order, scope, reaches))
        return sources, mutations, gadgets

    @classmethod
    def _javascript_events(
        cls,
        code: str,
    ) -> tuple[list[_ExternalSource], list[_Mutation], list[_Gadget]]:
        if not code:
            return [], [], []
        masked = _mask_javascript(code)
        scopes = _javascript_scopes(masked)
        sources: list[_ExternalSource] = []
        mutations: list[_Mutation] = []
        gadgets: list[_Gadget] = []
        tainted_by_scope: dict[str, set[str]] = {}

        assignments: list[tuple[int, str, str, str]] = []
        assignment_re = re.compile(
            r"(?:\b(?:const|let|var)\s+)?(?<![.\w$])([A-Za-z_$][\w$]*)\s*=(?!=|>)\s*([^;\n]+)"
        )
        for match in assignment_re.finditer(masked):
            scope = _scope_for(scopes, match.start())
            assignments.append((match.start(), scope, match.group(1), match.group(2)))

        external_re = re.compile(
            r"(?:\b(?:event|evt|ev|e|message|msg)\s*\.\s*data\b|"
            r"\b(?:window\s*\.\s*)?location\s*\.\s*(?:hash|search|href)\b|"
            r"\bdocument\s*\.\s*(?:URL|documentURI|referrer)\b|"
            r"\bwindow\s*\.\s*name\b|"
            r"\b(?:localStorage|sessionStorage)\s*\.\s*getItem\s*\(|"
            r"\bURLSearchParams\s*\()",
            re.I,
        )
        # Assignments arrive in source order. A single forward pass preserves temporal
        # reachability and prevents a later source declaration from tainting an earlier alias.
        for position, scope, target, rhs in assignments:
            tainted = tainted_by_scope.setdefault(scope, set())
            rhs_identifiers = set(re.findall(r"\b[A-Za-z_$][\w$]*\b", rhs))
            direct = bool(external_re.search(rhs))
            inherited = bool(rhs_identifiers & tainted)
            if (direct or inherited) and target not in tainted:
                tainted.add(target)
                sources.append(_ExternalSource(
                    target,
                    "browser_input" if direct else "external_alias",
                    _line(code, position),
                    position,
                    scope,
                ))

        merge_patterns = [
            ("object_assign", re.compile(r"\bObject\s*\.\s*assign\s*\(\s*([A-Za-z_$][\w$]*)\s*,\s*([A-Za-z_$][\w$]*)", re.I)),
            ("deep_merge", re.compile(r"\b(?:_|lodash)\s*\.\s*merge\s*\(\s*([A-Za-z_$][\w$]*)\s*,\s*([A-Za-z_$][\w$]*)", re.I)),
            ("deep_merge", re.compile(r"\b(?:deepMerge|deepExtend)\s*\(\s*([A-Za-z_$][\w$]*)\s*,\s*([A-Za-z_$][\w$]*)", re.I)),
            ("deep_extend", re.compile(r"(?:\$|jQuery)\s*\.\s*extend\s*\(\s*true\s*,\s*([A-Za-z_$][\w$]*)\s*,\s*([A-Za-z_$][\w$]*)", re.I)),
        ]
        for operation, pattern in merge_patterns:
            for match in pattern.finditer(masked):
                scope = _scope_for(scopes, match.start())
                source = match.group(2)
                external = any(
                    item.scope == scope and item.symbol == source and item.order <= match.start()
                    for item in sources
                )
                mutations.append(_Mutation(
                    target_symbol=match.group(1),
                    source_symbol=source,
                    key_symbol=None,
                    operation=operation,
                    line=_line(code, match.start()),
                    order=match.start(),
                    scope=scope,
                    externally_influenced=external,
                    guarded=False,
                    injection_mode="property",
                ))

        loop_sources: dict[tuple[str, str], str] = {}
        for match in re.finditer(
            r"\bfor\s*\(\s*(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s+in\s+([A-Za-z_$][\w$]*)\s*\)",
            masked,
        ):
            scope = _scope_for(scopes, match.start())
            loop_sources[(scope, match.group(1))] = match.group(2)

        dynamic_write = re.compile(
            r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*\[\s*([A-Za-z_$][\w$]*)\s*\]\s*=(?!=)\s*([^;\n]+)"
        )
        for match in dynamic_write.finditer(masked):
            scope = _scope_for(scopes, match.start())
            key = match.group(2)
            loop_source = loop_sources.get((scope, key))
            external = any(
                item.scope == scope
                and item.symbol in {key, loop_source}
                and item.order <= match.start()
                for item in sources
            )
            guarded = _has_forbidden_key_guard(code, scopes, scope, match.start(), key)
            mutations.append(_Mutation(
                target_symbol=match.group(1),
                source_symbol=loop_source,
                key_symbol=key,
                operation="dynamic_property_write",
                line=_line(code, match.start()),
                order=match.start(),
                scope=scope,
                externally_influenced=external,
                guarded=guarded,
                injection_mode="prototype" if match.group(1).lower() == "object.prototype" else "property",
            ))

        assignment_gadget = re.compile(
            r"(?:\.\s*(innerHTML|outerHTML|srcdoc)\s*=|"
            r"\b(?:window\s*\.\s*)?location(?:\s*\.\s*href)?\s*=)\s*"
            r"([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)",
            re.I,
        )
        for match in assignment_gadget.finditer(masked):
            sink = match.group(1) or "location-write"
            gadgets.append(_Gadget(
                object_symbol=match.group(2),
                property_name=match.group(3),
                sink_kind=sink,
                line=_line(code, match.start()),
                order=match.start(),
                scope=_scope_for(scopes, match.start()),
                reaches_sink=True,
            ))

        call_gadget = re.compile(
            r"\b(document\s*\.\s*write|eval|Function|setTimeout|setInterval|window\s*\.\s*open)\s*"
            r"\(\s*([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)",
            re.I,
        )
        for match in call_gadget.finditer(masked):
            sink = re.sub(r"\s+", "", match.group(1)).lower()
            gadgets.append(_Gadget(
                object_symbol=match.group(2),
                property_name=match.group(3),
                sink_kind=sink,
                line=_line(code, match.start()),
                order=match.start(),
                scope=_scope_for(scopes, match.start()),
                reaches_sink=True,
            ))
        return sources, mutations, gadgets

    @classmethod
    def _append_property_event_observations(
        cls,
        result: PropertyIntegrityAnalysis,
        sources: Iterable[_ExternalSource],
        mutations: Iterable[_Mutation],
        gadgets: Iterable[_Gadget],
    ) -> None:
        for item in sources:
            cls._observation(result, "external_property_source", 0.85, {
                "symbol": item.symbol,
                "source_kind": item.source_kind,
                "line": item.line,
                "scope": item.scope,
            })
        for item in mutations:
            cls._observation(result, "property_mutation_candidate", 0.82, {
                "target_symbol": item.target_symbol,
                "source_symbol": item.source_symbol,
                "key_symbol": item.key_symbol,
                "operation": item.operation,
                "line": item.line,
                "scope": item.scope,
                "externally_influenced": item.externally_influenced,
                "guarded": item.guarded,
                "injection_mode": item.injection_mode,
            })
        for item in gadgets:
            cls._observation(result, "sensitive_property_gadget", 0.85, {
                "object_symbol": item.object_symbol,
                "property": item.property_name,
                "sink_kind": item.sink_kind,
                "line": item.line,
                "scope": item.scope,
                "reaches_sink": item.reaches_sink,
            })

    @classmethod
    def _correlate_property_injection(
        cls,
        result: PropertyIntegrityAnalysis,
        sources: Iterable[_ExternalSource],
        mutations: Iterable[_Mutation],
        gadgets: Iterable[_Gadget],
    ) -> None:
        source_list = list(sources)
        gadget_list = list(gadgets)
        for mutation in mutations:
            if mutation.guarded:
                continue
            source = next((
                item for item in source_list
                if item.scope == mutation.scope
                and item.symbol == mutation.source_symbol
                and item.order <= mutation.order
            ), None)
            external = mutation.externally_influenced or source is not None
            if not external:
                continue
            for gadget in gadget_list:
                if (
                    gadget.scope != mutation.scope
                    or gadget.object_symbol != mutation.target_symbol
                    or gadget.order < mutation.order
                    or not gadget.reaches_sink
                    or gadget.property_name.lower() not in _SENSITIVE_GADGET_PROPERTIES
                    or not _sensitive_sink(gadget.sink_kind)
                ):
                    continue
                metadata = {
                    "source_kind": source.source_kind if source else "structured_external_influence",
                    "source_line": source.line if source else mutation.line,
                    "mutation_operation": mutation.operation,
                    "mutation_line": mutation.line,
                    "target_symbol": mutation.target_symbol,
                    "gadget_property": gadget.property_name,
                    "gadget_line": gadget.line,
                    "sink_kind": gadget.sink_kind,
                    "scope": mutation.scope,
                    "injection_mode": mutation.injection_mode,
                }
                confidence = 0.9 if mutation.operation in {
                    "deep_merge", "deep_extend", "recursive_merge", "dynamic_property_write",
                } else 0.82
                cls._chain(result, "prototype_property_injection_chain", confidence, metadata)

    @classmethod
    def _observation(
        cls,
        result: PropertyIntegrityAnalysis,
        kind: str,
        confidence: float,
        metadata: dict[str, Any],
    ) -> None:
        if len(result.observations) >= MAX_OBSERVATIONS:
            return
        result.observations.append(IntegrityObservation(
            kind=kind,
            fingerprint=_fingerprint(kind, metadata),
            confidence=round(max(0.0, min(1.0, confidence)), 2),
            metadata=metadata,
        ))

    @classmethod
    def _chain(
        cls,
        result: PropertyIntegrityAnalysis,
        kind: str,
        confidence: float,
        metadata: dict[str, Any],
    ) -> None:
        if len(result.chains) >= MAX_CHAINS:
            return
        record = IntegrityObservation(
            kind=kind,
            fingerprint=_fingerprint(kind, metadata),
            confidence=round(max(0.0, min(1.0, confidence)), 2),
            metadata=metadata,
        )
        result.chains.append(record)
        if len(result.observations) < MAX_OBSERVATIONS:
            result.observations.append(record)

    @staticmethod
    def _dedupe_records(records: Iterable[IntegrityObservation]) -> list[IntegrityObservation]:
        result: list[IntegrityObservation] = []
        seen: set[str] = set()
        for item in records:
            if item.fingerprint not in seen:
                seen.add(item.fingerprint)
                result.append(item)
        return result


def _mask_javascript(code: str) -> str:
    """Mask comments and string contents while preserving offsets and newlines."""
    chars = list(code)
    state = "code"
    quote = ""
    index = 0
    while index < len(chars):
        current = chars[index]
        following = chars[index + 1] if index + 1 < len(chars) else ""
        if state == "code":
            if current == "/" and following == "/":
                chars[index] = chars[index + 1] = " "
                state = "line_comment"
                index += 2
                continue
            if current == "/" and following == "*":
                chars[index] = chars[index + 1] = " "
                state = "block_comment"
                index += 2
                continue
            if current in "'\"`":
                quote = current
                chars[index] = " "
                state = "string"
        elif state == "line_comment":
            if current == "\n":
                state = "code"
            else:
                chars[index] = " "
        elif state == "block_comment":
            if current == "*" and following == "/":
                chars[index] = chars[index + 1] = " "
                state = "code"
                index += 2
                continue
            if current != "\n":
                chars[index] = " "
        elif state == "string":
            if current == "\\":
                if current != "\n":
                    chars[index] = " "
                if index + 1 < len(chars) and chars[index + 1] != "\n":
                    chars[index + 1] = " "
                index += 2
                continue
            if current == quote:
                chars[index] = " "
                state = "code"
            elif current != "\n":
                chars[index] = " "
        index += 1
    return "".join(chars)


def _matching_brace(masked: str, opening: int) -> int:
    if opening < 0 or opening >= len(masked) or masked[opening] != "{":
        return -1
    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _javascript_scopes(masked: str) -> list[tuple[int, int, str]]:
    scopes = [(0, len(masked), "module")]
    patterns = [
        re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{"),
        re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{"),
    ]
    for pattern in patterns:
        for match in pattern.finditer(masked):
            opening = masked.find("{", match.start(), match.end())
            closing = _matching_brace(masked, opening)
            if closing >= 0:
                scopes.append((opening + 1, closing, f"{match.group(1)}@{_line(masked, match.start())}"))
    return scopes


def _scope_for(scopes: Iterable[tuple[int, int, str]], position: int) -> str:
    candidates = [item for item in scopes if item[0] <= position <= item[1]]
    return min(candidates, key=lambda item: item[1] - item[0])[2] if candidates else "module"


def _scope_bounds(
    scopes: Iterable[tuple[int, int, str]],
    scope_name: str,
) -> tuple[int, int]:
    for start, end, name in scopes:
        if name == scope_name:
            return start, end
    return 0, 0


def _has_forbidden_key_guard(
    code: str,
    scopes: Iterable[tuple[int, int, str]],
    scope_name: str,
    mutation_position: int,
    key_symbol: str,
) -> bool:
    start, _ = _scope_bounds(scopes, scope_name)
    prefix = code[max(start, mutation_position - 1_500):mutation_position]
    if not re.search(rf"\b{re.escape(key_symbol)}\b", prefix):
        return False
    lower = prefix.lower()
    blocks_all = all(item in lower for item in _FORBIDDEN_KEYS)
    exits = bool(re.search(r"\b(?:continue|return|throw)\b", prefix[-700:], re.I))
    allowlist = bool(re.search(
        rf"!\s*[A-Za-z_$][\w$]*\s*\.\s*has\s*\(\s*{re.escape(key_symbol)}\s*\)[\s\S]{{0,180}}\b(?:continue|return|throw)\b",
        prefix[-1_000:],
        re.I,
    ))
    return (blocks_all and exits) or allowlist


def _line(code: str, position: int) -> int:
    return code.count("\n", 0, max(0, position)) + 1


__all__ = [
    "IntegrityObservation",
    "NamedPropertyDefinition",
    "PropertyIntegrityAnalysis",
    "PropertyIntegrityAnalyzer",
]
