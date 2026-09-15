"""Bounded static analysis for browser-side trust boundaries.

The scanner already knows how to identify generic DOM sources and sinks.  This
module adds the missing *trust* layer around those primitives: message origin
validation, named DOM properties, prototype mutation, wildcard message targets,
and Trusted Types policies.  Findings are research signals, never vulnerability
proof.  They intentionally contain fingerprints and structural metadata instead
of raw bundle excerpts so bundle secrets are not copied into reports.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Iterable


_IDENT = r"[A-Za-z_$][\w$]*"


@dataclass(frozen=True)
class ClientTrustFinding:
    category: str
    title: str
    confidence: float
    severity_hint: str
    offset: int
    code_fingerprint: str
    required_confirmation: str
    remediation: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "title": self.title,
            "confidence": round(max(0.0, min(1.0, self.confidence)), 2),
            "severity_hint": self.severity_hint,
            "offset": max(0, self.offset),
            "code_fingerprint": self.code_fingerprint,
            "required_confirmation": self.required_confirmation,
            "remediation": self.remediation,
            "details": self.details,
        }


def _strip_comments_preserving_offsets(code: str) -> str:
    """Replace JavaScript comments with spaces while retaining strings and offsets."""

    output = list(code)
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(code):
        char = code[index]
        following = code[index + 1] if index + 1 < len(code) else ""
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in "'\"`":
            quote = char
            index += 1
            continue
        if char == "/" and following == "/":
            while index < len(code) and code[index] not in "\r\n":
                output[index] = " "
                index += 1
            continue
        if char == "/" and following == "*":
            output[index] = output[index + 1] = " "
            index += 2
            while index < len(code):
                if code[index] == "*" and index + 1 < len(code) and code[index + 1] == "/":
                    output[index] = output[index + 1] = " "
                    index += 2
                    break
                if code[index] not in "\r\n":
                    output[index] = " "
                index += 1
            continue
        index += 1
    return "".join(output)


def _mask_strings_preserving_offsets(code: str) -> str:
    """Mask string contents so syntax-looking text cannot become evidence."""

    output = list(code)
    quote: str | None = None
    escaped = False
    for index, char in enumerate(code):
        if quote:
            output[index] = "\n" if char == "\n" else " "
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "'\"`":
            quote = char
            output[index] = " "
    return "".join(output)


def _match_starts_in_code(code: str, match: re.Match[str]) -> bool:
    mask = _mask_strings_preserving_offsets(code)
    return match.start() < len(mask) and not mask[match.start()].isspace()


def _has_executable_match(pattern: str, code: str, flags: int = 0) -> bool:
    mask = _mask_strings_preserving_offsets(code)
    return any(
        match.start() < len(mask) and not mask[match.start()].isspace()
        for match in re.finditer(pattern, code, flags)
    )


def _balanced_block(code: str, opening_brace: int, max_chars: int = 80_000) -> str:
    """Read one JavaScript brace block without attempting a full JS parse."""
    depth = 0
    quote: str | None = None
    escaped = False
    end = min(len(code), opening_brace + max_chars)
    for index in range(opening_brace, end):
        char = code[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "'\"`":
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return code[opening_brace + 1:index]
    return code[opening_brace + 1:end]


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def _brace_depth_at(masked_code: str, position: int) -> int:
    depth = 0
    for char in masked_code[:max(0, min(position, len(masked_code)))]:
        if char == "{":
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
    return depth


def _lexical_scope_end(masked_code: str, position: int, maximum: int) -> int:
    """Return the nearest containing brace boundary, capped to a local window."""
    position = max(0, min(position, len(masked_code)))
    stack: list[int] = []
    for index, char in enumerate(masked_code[:position]):
        if char == "{":
            stack.append(index)
        elif char == "}" and stack:
            stack.pop()
    upper = min(len(masked_code), position + maximum)
    if not stack:
        return upper
    depth = 1
    for index in range(position, upper):
        if masked_code[index] == "{":
            depth += 1
        elif masked_code[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return upper


class ClientTrustAnalyzer:
    """Find high-value client trust signals without generating attack payloads."""

    MAX_SCRIPT_CHARS = 2_000_000
    MAX_CANDIDATES_PER_ANALYZER = 250

    _MESSAGE_HANDLERS = (
        re.compile(
            rf"addEventListener\s*\(\s*['\"]message['\"]\s*,\s*"
            rf"function(?:\s+{_IDENT})?\s*\(\s*(?P<param>{_IDENT})\s*\)\s*\{{",
            re.IGNORECASE,
        ),
        re.compile(
            rf"addEventListener\s*\(\s*['\"]message['\"]\s*,\s*"
            rf"\(?\s*(?P<param>{_IDENT})\s*\)?\s*=>\s*\{{",
            re.IGNORECASE,
        ),
        re.compile(
            rf"\.onmessage\s*=\s*function(?:\s+{_IDENT})?\s*"
            rf"\(\s*(?P<param>{_IDENT})\s*\)\s*\{{",
            re.IGNORECASE,
        ),
        re.compile(
            rf"\.onmessage\s*=\s*\(?\s*(?P<param>{_IDENT})\s*\)?\s*=>\s*\{{",
            re.IGNORECASE,
        ),
    )

    _BUILTIN_NAMED_PROPERTIES = {
        "alert", "atob", "btoa", "caches", "closed", "crypto", "customElements",
        "document", "frames", "history", "indexedDB", "innerHeight", "innerWidth",
        "length", "localStorage", "location", "name", "navigator", "opener", "origin",
        "parent", "performance", "screen", "self", "sessionStorage", "top", "trustedTypes",
    }

    @classmethod
    def analyze(cls, script: str, max_findings: int = 100) -> list[ClientTrustFinding]:
        code = _strip_comments_preserving_offsets(
            (script or "")[: cls.MAX_SCRIPT_CHARS]
        )
        if not code or max_findings <= 0:
            return []

        findings: list[ClientTrustFinding] = []
        findings.extend(cls._message_boundary_findings(code))
        findings.extend(cls._wildcard_message_findings(code))
        findings.extend(cls._prototype_mutation_findings(code))
        findings.extend(cls._dom_named_property_findings(code))
        findings.extend(cls._trusted_types_findings(code))

        unique: list[ClientTrustFinding] = []
        seen: set[tuple[str, int, str]] = set()
        for finding in sorted(findings, key=lambda item: (-item.confidence, item.offset, item.category)):
            key = (finding.category, finding.offset, finding.details.get("sink", ""))
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
            if len(unique) >= max_findings:
                break
        return unique

    @classmethod
    def _iter_message_handlers(cls, code: str) -> Iterable[tuple[int, str, str]]:
        matches: list[tuple[int, str, str]] = []
        code_mask = _mask_strings_preserving_offsets(code)
        for pattern in cls._MESSAGE_HANDLERS:
            if len(matches) >= cls.MAX_CANDIDATES_PER_ANALYZER:
                break
            for match in pattern.finditer(code):
                if match.start() >= len(code_mask) or code_mask[match.start()].isspace():
                    continue
                opening_brace = match.end() - 1
                matches.append((match.start(), match.group("param"), _balanced_block(code, opening_brace)))
                if len(matches) >= cls.MAX_CANDIDATES_PER_ANALYZER:
                    break

        callback_reference = re.compile(
            rf"(?:addEventListener\s*\(\s*['\"]message['\"]\s*,\s*|\.onmessage\s*=\s*)"
            rf"(?P<callback>{_IDENT})\b(?!\s*=>)",
            re.IGNORECASE,
        )
        for reference in callback_reference.finditer(code):
            if len(matches) >= cls.MAX_CANDIDATES_PER_ANALYZER:
                break
            if reference.start() >= len(code_mask) or code_mask[reference.start()].isspace():
                continue
            callback = reference.group("callback")
            if callback.lower() in {"function", "async"}:
                continue
            escaped = re.escape(callback)
            definitions = (
                re.compile(
                    rf"\bfunction\s+{escaped}\s*\(\s*(?P<param>{_IDENT})\s*\)\s*\{{",
                    re.IGNORECASE,
                ),
                re.compile(
                    rf"\b(?:const|let|var)\s+{escaped}\s*=\s*function(?:\s+{_IDENT})?\s*"
                    rf"\(\s*(?P<param>{_IDENT})\s*\)\s*\{{",
                    re.IGNORECASE,
                ),
                re.compile(
                    rf"\b(?:const|let|var)\s+{escaped}\s*=\s*\(?\s*(?P<param>{_IDENT})\s*\)?"
                    rf"\s*=>\s*\{{",
                    re.IGNORECASE,
                ),
            )
            candidates: list[re.Match[str]] = []
            for definition in definitions:
                candidates.extend(
                    item for item in definition.finditer(code)
                    if item.start() < len(code_mask) and not code_mask[item.start()].isspace()
                )
            if not candidates:
                continue
            resolved = min(candidates, key=lambda item: abs(item.start() - reference.start()))
            opening_brace = resolved.end() - 1
            matches.append((
                reference.start(),
                resolved.group("param"),
                _balanced_block(code, opening_brace),
            ))
        yield from sorted(matches, key=lambda item: item[0])

    @staticmethod
    def _origin_guard(body: str, event_param: str) -> str:
        event = re.escape(event_param)
        literal = r"['\"]https?://[^'\"]+['\"]"
        early_reject = re.compile(
            rf"\bif\s*\(\s*(?:{event}\s*\.\s*origin\s*!==\s*{literal}"
            rf"|{literal}\s*!==\s*{event}\s*\.\s*origin)\s*\)"
            rf"\s*(?:\{{\s*)?(?:return\b|throw\b)",
            re.IGNORECASE,
        )
        body_mask = _mask_strings_preserving_offsets(body)
        sink_depth = _brace_depth_at(body_mask, len(body_mask))
        for match in early_reject.finditer(body):
            if (
                not body_mask[match.start()].isspace()
                and _brace_depth_at(body_mask, match.start()) == sink_depth
            ):
                return "strict_origin_literal"

        # Positive exact checks count only while the sink is still lexically inside
        # the guarded block. ``body`` is intentionally truncated at the sink.
        positive = re.compile(
            rf"\bif\s*\(\s*(?:{event}\s*\.\s*origin\s*===\s*{literal}"
            rf"|{literal}\s*===\s*{event}\s*\.\s*origin)\s*\)\s*\{{",
            re.IGNORECASE,
        )
        for match in positive.finditer(body):
            if body_mask[match.start()].isspace():
                continue
            guarded_tail = body_mask[match.end() - 1:]
            if guarded_tail.count("{") > guarded_tail.count("}"):
                return "strict_origin_literal"

        immutable_names: set[str] = set()
        immutable = re.compile(
            rf"\bconst\s+(?P<name>{_IDENT})\s*=\s*(?:Object\s*\.\s*freeze\s*\(\s*)?"
            rf"(?:new\s+Set\s*\()?\s*\[[^\]]{{1,2000}}\]",
            re.IGNORECASE,
        )
        for match in immutable.finditer(body):
            if not body_mask[match.start()].isspace():
                immutable_names.add(match.group("name"))
        for name in immutable_names:
            escaped_name = re.escape(name)
            reject = re.compile(
                rf"\bif\s*\(\s*!\s*{escaped_name}\s*\.\s*(?:includes|has)\s*"
                rf"\(\s*{event}\s*\.\s*origin\s*\)\s*\)\s*"
                rf"(?:\{{\s*)?(?:return\b|throw\b)",
                re.IGNORECASE,
            )
            for match in reject.finditer(body):
                if (
                    not body_mask[match.start()].isspace()
                    and _brace_depth_at(body_mask, match.start()) == sink_depth
                ):
                    return "origin_allowlist"
            positive_allowlist = re.compile(
                rf"\bif\s*\(\s*{escaped_name}\s*\.\s*(?:includes|has)\s*"
                rf"\(\s*{event}\s*\.\s*origin\s*\)\s*\)\s*\{{",
                re.IGNORECASE,
            )
            for match in positive_allowlist.finditer(body):
                if body_mask[match.start()].isspace():
                    continue
                guarded_tail = body_mask[match.end() - 1:]
                if guarded_tail.count("{") > guarded_tail.count("}"):
                    return "origin_allowlist"
        weak = (
            rf"{event}\s*\.\s*origin\s*\.\s*(?:includes|indexOf|startsWith|endsWith)\s*\("
            rf"|(?:includes|indexOf|startsWith|endsWith)\s*\(\s*{event}\s*\.\s*origin"
            rf"|{_IDENT}\s*\.\s*(?:includes|has)\s*\(\s*{event}\s*\.\s*origin"
        )
        if _has_executable_match(weak, body, re.IGNORECASE):
            return "weak_substring_origin_check"
        if _has_executable_match(rf"\b{event}\s*\.\s*source\s*(?:===|==)", body):
            return "source_only"
        return "none"

    @classmethod
    def _message_boundary_findings(cls, code: str) -> list[ClientTrustFinding]:
        from analysis_engine.smart_taint_analyzer import Reachability, SmartTaintAnalyzer

        findings: list[ClientTrustFinding] = []
        for offset, event_param, body in cls._iter_message_handlers(code):
            # SmartTaintAnalyzer recognizes common event/e.data variables. Normalize
            # uncommon callback parameter names locally so it can reuse its real flow model.
            normalized_body = re.sub(
                rf"\b{re.escape(event_param)}\s*\.\s*data\b", "event.data", body
            )
            normalized_body = _mask_strings_preserving_offsets(normalized_body)
            flows = [
                item for item in SmartTaintAnalyzer.analyze(normalized_body)
                if item.source_kind == "postmessage" and item.reachability is Reachability.REACHABLE
            ]
            if flows:
                for flow in flows:
                    if len(findings) >= cls.MAX_CANDIDATES_PER_ANALYZER:
                        return findings
                    sink_offset = cls._sink_offset(body, flow.sink_kind)
                    guard_scope = body[:sink_offset] if sink_offset >= 0 else body
                    guard = cls._origin_guard(guard_scope, event_param)
                    if guard in {"strict_origin_literal", "origin_allowlist"}:
                        continue
                    confidence = 0.92 if guard == "none" else 0.76
                    findings.append(ClientTrustFinding(
                        category="postmessage_unvalidated_sink",
                        title="Message-controlled data reaches a browser sink without a strong origin guard",
                        confidence=confidence,
                        severity_hint=flow.severity,
                        offset=offset,
                        code_fingerprint=_fingerprint(body),
                        required_confirmation=(
                            "Confirm the handler's accepted sender and trace a harmless marker from "
                            "message data to the reported sink."
                        ),
                        remediation=(
                            "Compare event.origin with exact trusted origins, validate event.source and "
                            "message shape, and use a context-appropriate safe sink."
                        ),
                        details={
                            "event_parameter": event_param,
                            "guard": guard,
                            "sink": flow.sink_kind,
                            "context": flow.context,
                            "hops": flow.hops,
                        },
                    ))
                    if guard == "weak_substring_origin_check":
                        findings.append(ClientTrustFinding(
                            category="postmessage_weak_origin_validation",
                            title="Message handler uses substring-based origin validation",
                            confidence=0.88,
                            severity_hint="medium",
                            offset=offset,
                            code_fingerprint=_fingerprint(body),
                            required_confirmation=(
                                "Confirm which serialized origins pass the comparison using passive reasoning "
                                "or a harmless sender marker."
                            ),
                            remediation=(
                                "Parse the origin and compare the full serialized origin against an immutable "
                                "allowlist."
                            ),
                            details={
                                "event_parameter": event_param,
                                "guard": guard,
                                "sink": flow.sink_kind,
                            },
                        ))
            elif cls._origin_guard(body, event_param) == "weak_substring_origin_check":
                if len(findings) >= cls.MAX_CANDIDATES_PER_ANALYZER:
                    return findings
                findings.append(ClientTrustFinding(
                    category="postmessage_weak_origin_validation",
                    title="Message handler uses substring-based origin validation",
                    confidence=0.84,
                    severity_hint="medium",
                    offset=offset,
                    code_fingerprint=_fingerprint(body),
                    required_confirmation="Confirm which origins pass the comparison without sending active content.",
                    remediation="Parse the origin and compare the full serialized origin against an immutable allowlist.",
                    details={"event_parameter": event_param, "guard": "weak_substring_origin_check", "sink": ""},
                ))
        return findings

    @staticmethod
    def _sink_offset(body: str, sink_kind: str) -> int:
        patterns = {
            "innerHTML": r"\.\s*(?:innerHTML|outerHTML)\s*=",
            "insertAdjacentHTML": r"\.\s*insertAdjacentHTML\s*\(",
            "document_write": r"document\s*\.\s*write(?:ln)?\s*\(",
            "eval": r"\beval\s*\(",
            "function_ctor": r"\b(?:new\s+Function|Function)\s*\(",
            "timer_string": r"\bset(?:Timeout|Interval)\s*\(",
            "navigation": r"(?:location\s*\.\s*(?:href|assign|replace)|location\s*=)",
            "jquery_html": r"\.\s*(?:html|append|prepend|before|after|replaceWith|wrap)\s*\(",
            "srcdoc": r"\.\s*srcdoc\s*=",
            "iframe_src": r"\.\s*src\s*=",
            "range_fragment": r"\.\s*createContextualFragment\s*\(",
            "set_href_attr": r"\.\s*setAttribute\s*\(",
        }
        match = re.search(patterns.get(sink_kind, re.escape(sink_kind)), body, re.IGNORECASE)
        return match.start() if match else -1

    @classmethod
    def _wildcard_message_findings(cls, code: str) -> list[ClientTrustFinding]:
        patterns = (
            re.compile(
                r"\bpostMessage\s*\((?:(?![;\r\n]).){1,600}?,\s*['\"]\*['\"]\s*\)",
                re.IGNORECASE,
            ),
            re.compile(
                r"\bpostMessage\s*\((?:(?![;\r\n]).){1,600}?,\s*\{[^}\r\n]{0,600}"
                r"\btargetOrigin\s*:\s*['\"]\*['\"][^}\r\n]{0,600}\}\s*\)",
                re.IGNORECASE,
            ),
        )
        findings: list[ClientTrustFinding] = []
        for pattern in patterns:
            for match in pattern.finditer(code):
                if not _match_starts_in_code(code, match):
                    continue
                findings.append(ClientTrustFinding(
                    category="postmessage_wildcard_target",
                    title="postMessage sends data to a wildcard target origin",
                    confidence=0.9,
                    severity_hint="low",
                    offset=match.start(),
                    code_fingerprint=_fingerprint(match.group(0)),
                    required_confirmation="Classify the transmitted data and the possible receiving windows.",
                    remediation="Send only to the exact intended target origin and keep message contents non-sensitive.",
                    details={"target_origin": "*"},
                ))
                if len(findings) >= cls.MAX_CANDIDATES_PER_ANALYZER:
                    return findings
        return findings

    @staticmethod
    def _external_source(expr: str) -> str | None:
        expr = _mask_strings_preserving_offsets(expr)
        sources = (
            ("postmessage", r"\b(?:event|e|ev|evt|message|msg)\s*\.\s*data\b"),
            ("url", r"\b(?:location\.(?:hash|search|href)|URLSearchParams\s*\()"),
            ("storage", r"\b(?:localStorage|sessionStorage)\s*\.\s*getItem\s*\("),
        )
        for name, pattern in sources:
            if re.search(pattern, expr, re.IGNORECASE):
                return name
        return None

    @classmethod
    def _prototype_mutation_findings(cls, code: str) -> list[ClientTrustFinding]:
        patterns = (
            ("setPrototypeOf", re.compile(
                r"\b(?:Object|Reflect)\s*\.\s*setPrototypeOf\s*\(\s*[^,]{1,300},\s*(?P<src>[^)]{1,600})\)",
                re.IGNORECASE,
            )),
            ("Object.assign(Object.prototype)", re.compile(
                r"\bObject\s*\.\s*assign\s*\(\s*(?:Object\s*\.\s*prototype|[A-Za-z_$][\w$]*\s*\.\s*prototype)\s*,\s*(?P<src>[^)]{1,600})\)",
                re.IGNORECASE,
            )),
            ("prototype assignment", re.compile(
                r"(?:\.__proto__|\.constructor\s*\.\s*prototype)\s*=\s*(?P<src>[^;\r\n]{1,600})",
                re.IGNORECASE,
            )),
        )
        findings: list[ClientTrustFinding] = []
        code_mask = _mask_strings_preserving_offsets(code)
        for primitive, pattern in patterns:
            for match in pattern.finditer(code):
                if match.start() >= len(code_mask) or code_mask[match.start()].isspace():
                    continue
                source = cls._external_source(match.group("src"))
                if source is None:
                    continue
                findings.append(ClientTrustFinding(
                    category="external_prototype_mutation",
                    title="Externally influenced data reaches a prototype mutation primitive",
                    confidence=0.91,
                    severity_hint="high",
                    offset=match.start(),
                    code_fingerprint=_fingerprint(match.group(0)),
                    required_confirmation=(
                        "Use an inert marker property to confirm whether the mutation crosses an object "
                        "boundary; do not alter application behavior."
                    ),
                    remediation=(
                        "Reject prototype-related keys, copy into null-prototype objects, and avoid mutating "
                        "shared prototypes from external data."
                    ),
                    details={"source": source, "sink": primitive},
                ))
                if len(findings) >= cls.MAX_CANDIDATES_PER_ANALYZER:
                    return findings
        return findings

    @classmethod
    def _dom_named_property_findings(cls, code: str) -> list[ClientTrustFinding]:
        source = re.compile(
            rf"(?:const|let|var)\s+(?P<var>{_IDENT})\s*=\s*"
            rf"(?P<base>window|document)\s*\.\s*(?P<name>{_IDENT})"
        )
        sink_templates = (
            ("navigation", r"(?:location(?:\.href)?|\.src|\.href|\.action)\s*=\s*{var}\b"),
            ("innerHTML", r"(?:innerHTML|outerHTML|srcdoc)\s*=\s*{var}\b"),
            ("eval", r"(?:eval|Function|setTimeout|setInterval)\s*\(\s*{var}\b"),
        )
        findings: list[ClientTrustFinding] = []
        code_mask = _mask_strings_preserving_offsets(code)
        for match in source.finditer(code):
            if match.start() >= len(code_mask) or code_mask[match.start()].isspace():
                continue
            property_name = match.group("name")
            if property_name in cls._BUILTIN_NAMED_PROPERTIES:
                continue
            variable = match.group("var")
            base = match.group("base").lower()
            scope_end = _lexical_scope_end(code_mask, match.end(), 1200)
            window = code[match.end():scope_end]
            window_mask = _mask_strings_preserving_offsets(window)
            for sink_name, template in sink_templates:
                if not re.search(template.format(var=re.escape(variable)), window_mask, re.IGNORECASE):
                    continue
                findings.append(ClientTrustFinding(
                    category="dom_named_property_to_sink",
                    title="Named window/document property is consumed by a sensitive browser sink",
                    confidence=0.79,
                    severity_hint="medium",
                    offset=match.start(),
                    code_fingerprint=_fingerprint(code[match.start():match.end() + len(window)]),
                    required_confirmation=(
                        "Confirm whether markup-generated named properties can shadow this value and whether "
                        "the reported sink consumes the marker."
                    ),
                    remediation=(
                        "Resolve configuration through explicit module state or getElementById, verify its "
                        "type, and avoid implicit named access on window or document."
                    ),
                    details={
                        "property": property_name,
                        "variable": variable,
                        "sink": sink_name,
                        "base": base,
                        "path": [base, property_name],
                        "implicit": True,
                        "reaches_sink": True,
                        "flow": "property_to_sink",
                        "line": code.count("\n", 0, match.start()) + 1,
                    },
                ))
                if len(findings) >= cls.MAX_CANDIDATES_PER_ANALYZER:
                    return findings
                break
        return findings

    @classmethod
    def _trusted_types_findings(cls, code: str) -> list[ClientTrustFinding]:
        start_pattern = re.compile(r"\btrustedTypes\s*\.\s*createPolicy\s*\(", re.IGNORECASE)
        identity_patterns = (
            re.compile(
                rf"(?P<kind>createHTML|createScript|createScriptURL)\s*:\s*"
                rf"\(?\s*(?P<arg>{_IDENT})\s*\)?\s*=>\s*(?P=arg)\b",
                re.IGNORECASE,
            ),
            re.compile(
                rf"(?P<kind>createHTML|createScript|createScriptURL)\s*:\s*function\s*"
                rf"\(\s*(?P<arg>{_IDENT})\s*\)\s*\{{\s*return\s+(?P=arg)\s*;?\s*\}}",
                re.IGNORECASE,
            ),
            re.compile(
                rf"(?P<kind>createHTML|createScript|createScriptURL)\s*"
                rf"\(\s*(?P<arg>{_IDENT})\s*\)\s*\{{\s*return\s+(?P=arg)\s*;?\s*\}}",
                re.IGNORECASE,
            ),
        )
        findings: list[ClientTrustFinding] = []
        code_mask = _mask_strings_preserving_offsets(code)
        for start in start_pattern.finditer(code):
            if start.start() >= len(code_mask) or code_mask[start.start()].isspace():
                continue
            opening = code.find("{", start.end(), min(len(code), start.end() + 1200))
            if opening < 0:
                continue
            policy_body = _balanced_block(code, opening, max_chars=20_000)
            policy_mask = _mask_strings_preserving_offsets(policy_body)
            for identity in identity_patterns:
                for match in identity.finditer(policy_body):
                    if match.start() >= len(policy_mask) or policy_mask[match.start()].isspace():
                        continue
                    kind = match.group("kind")
                    findings.append(ClientTrustFinding(
                        category="trusted_types_identity_policy",
                        title="Trusted Types policy returns unvalidated input",
                        confidence=0.95,
                        severity_hint="high" if kind.lower() != "createhtml" else "medium",
                        offset=opening + 1 + match.start(),
                        code_fingerprint=_fingerprint(policy_body),
                        required_confirmation="Confirm which call sites can invoke this policy with external data.",
                        remediation=(
                            "Make the policy perform strict, context-specific validation or sanitization and "
                            "keep policy creation in a small reviewed module."
                        ),
                        details={"policy_method": kind, "sink": kind},
                    ))
                    if len(findings) >= cls.MAX_CANDIDATES_PER_ANALYZER:
                        return findings
        return findings
