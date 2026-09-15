"""Ordered, context-aware sanitizer and Trusted Types boundary analysis.

The legacy taint pass clears an entire expression when it sees a sanitizer-like
token.  That creates dangerous false negatives for mixed expressions and for a
transform used in the wrong output context.  This module follows individual
source atoms through assignments in source order, records only structural
fingerprints, and treats unknown custom helpers as unknown rather than trusted.
"""
from __future__ import annotations

import hashlib
import re
from collections import deque
from dataclasses import dataclass, field, replace
from typing import Any, Iterable, Mapping

from analysis_engine.client_trust_analyzer import (
    _balanced_block,
    _mask_strings_preserving_offsets,
    _strip_comments_preserving_offsets,
)
from analysis_engine.smart_taint_analyzer import (
    _ASSIGN_RE,
    _IDENT_RE,
    _SINKS,
    _SOURCES,
    _default_param,
    _read_call_arg,
    _read_rhs,
)


_IDENT = r"[A-Za-z_$][\w$]*"


def _fingerprint(*values: Any) -> str:
    normalized = "|".join(str(value) for value in values)
    return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()


def _split_top_level(value: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    quote: str | None = None
    escaped = False
    for char in value:
        if quote:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "'\"`":
            quote = char
            current.append(char)
        elif char in "([{":
            depth += 1
            current.append(char)
        elif char in ")]}":
            depth = max(0, depth - 1)
            current.append(char)
        elif char == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if current:
        parts.append("".join(current).strip())
    return parts


def _split_top_level_concatenation(value: str) -> list[tuple[str, int]]:
    """Split JavaScript string concatenation while preserving operand offsets."""
    parts: list[tuple[str, int]] = []
    start = 0
    depth = 0
    quote: str | None = None
    escaped = False
    for index, char in enumerate(value):
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
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif char == "+" and depth == 0:
            # Do not split increment operators or unary positive values.
            previous = value[index - 1] if index else ""
            following = value[index + 1] if index + 1 < len(value) else ""
            if previous == "+" or following in {"+", "="}:
                continue
            raw = value[start:index]
            leading = len(raw) - len(raw.lstrip())
            operand = raw.strip()
            if operand:
                parts.append((operand, start + leading))
            start = index + 1
    raw = value[start:]
    leading = len(raw) - len(raw.lstrip())
    operand = raw.strip()
    if operand:
        parts.append((operand, start + leading))
    return parts if len(parts) > 1 else []


def _full_call(expression: str) -> tuple[str, list[str]] | None:
    """Return a full-expression call target and arguments."""
    stripped = expression.strip()
    match = re.match(rf"(?P<callee>{_IDENT}(?:\s*\.\s*{_IDENT})*)\s*\(", stripped)
    if not match:
        return None
    opening = stripped.find("(", match.start())
    depth = 0
    quote: str | None = None
    escaped = False
    closing = -1
    for index in range(opening, len(stripped)):
        char = stripped[index]
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
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                closing = index
                break
    if closing < 0 or stripped[closing + 1:].strip():
        return None
    callee = re.sub(r"\s+", "", match.group("callee"))
    return callee, _split_top_level(stripped[opening + 1:closing])


def _read_rhs_bounded(code: str, eq_pos: int, max_chars: int) -> str:
    if eq_pos < 0 or eq_pos >= len(code):
        return ""
    fragment = code[eq_pos:min(len(code), eq_pos + max_chars + 1)]
    return _read_rhs(fragment, 0)


def _read_call_arg_bounded(code: str, opening: int, max_chars: int) -> str:
    if opening < 0 or opening >= len(code):
        return ""
    fragment = code[opening:min(len(code), opening + max_chars + 1)]
    return _read_call_arg(fragment, 0)


@dataclass(frozen=True)
class FlowAtom:
    source_kind: str
    source_param: str
    source_offset: int
    protection_state: str = "unprotected"
    transform_kind: str = "none"
    protected_context: str = ""
    transform_offset: int = -1
    reason_codes: tuple[str, ...] = ()
    hops: int = 0
    policy_method: str = ""


@dataclass(frozen=True)
class SanitizerBoundaryFinding:
    category: str
    source_kind: str
    source_param: str
    sink_kind: str
    required_context: str
    transform_kind: str
    protection_state: str
    reason_codes: tuple[str, ...]
    source_offset: int
    transform_offset: int
    sink_offset: int
    confidence: float
    fingerprint: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "source_kind": self.source_kind,
            "source_param": self.source_param,
            "sink_kind": self.sink_kind,
            "required_context": self.required_context,
            "transform_kind": self.transform_kind,
            "protection_state": self.protection_state,
            "reason_codes": list(self.reason_codes),
            "source_offset": max(0, self.source_offset),
            "transform_offset": max(-1, self.transform_offset),
            "sink_offset": max(0, self.sink_offset),
            "confidence": round(max(0.0, min(1.0, self.confidence)), 2),
            "fingerprint": self.fingerprint,
            "details": self.details,
        }


@dataclass(frozen=True)
class PolicyMethod:
    policy_variable: str
    method: str
    classification: str
    offset: int


@dataclass(frozen=True)
class _Event:
    offset: int
    kind: str
    name: str
    expression: str
    sink_kind: str = ""
    sink_context: str = ""
    operator: str = "="
    declared: bool = False
    priority: int = 0
    conditional: bool = False


class SanitizerBoundaryAnalyzer:
    """Find complete external-source → transform → sink boundary paths."""

    MAX_SCRIPT_CHARS = 2_000_000
    MAX_POLICIES = 250
    MAX_ASSIGNMENTS = 500
    MAX_SINKS = 500
    MAX_EVENTS = 1_000
    MAX_ATOMS_PER_VALUE = 8
    MAX_HOPS = 8
    MAX_FINDINGS = 100
    MAX_SCOPE_DEPTH = 64
    MAX_IDENTIFIERS_PER_EXPRESSION = 2_048
    MAX_EXPRESSION_DEPTH = 8
    MAX_SINKS_PER_KIND = 64
    MAX_EXPRESSION_CHARS = 20_000

    _SINK_CONTEXTS = {
        "innerHTML": "HTML",
        "insertAdjacentHTML": "HTML",
        "document_write": "HTML",
        "jquery_html": "HTML",
        "jquery_selector": "HTML",
        "srcdoc": "HTML",
        "range_fragment": "HTML",
        "eval": "SCRIPT",
        "function_ctor": "SCRIPT",
        "timer_string": "SCRIPT",
        "navigation": "URL",
        "iframe_src": "URL",
        "set_href_attr": "URL",
    }

    _KNOWN_TRANSFORMS = {
        "DOMPurify.sanitize": ("dompurify", "HTML"),
        # Encoding is not URL validation. These contexts intentionally do not
        # match a navigation sink; a complete component/scheme construction
        # must be proven elsewhere before it can be considered protective.
        "encodeURIComponent": ("url_component_encoding", "URL_COMPONENT"),
        "encodeURI": ("url_encoding", "URL_SYNTAX"),
        "CSS.escape": ("css_escape", "CSS"),
        "Number": ("numeric_coercion", "NUMERIC"),
        "parseInt": ("numeric_coercion", "NUMERIC"),
        "parseFloat": ("numeric_coercion", "NUMERIC"),
    }

    _RELAXED_DOMPURIFY = re.compile(
        r"\b(?:ALLOW_UNKNOWN_PROTOCOLS\s*:\s*true|SANITIZE_DOM\s*:\s*false|"
        r"ADD_TAGS\s*:|ADD_ATTR\s*:|ALLOWED_URI_REGEXP\s*:|CUSTOM_ELEMENT_HANDLING\s*:|"
        r"ALLOWED_TAGS\s*:[^,}\n]*(?:script|style)|ALLOWED_ATTR\s*:[^,}\n]*on\w+)",
        re.IGNORECASE,
    )

    @classmethod
    def analyze(cls, script: str, max_findings: int | None = None) -> list[SanitizerBoundaryFinding]:
        code = _strip_comments_preserving_offsets(
            str(script or "")[: cls.MAX_SCRIPT_CHARS]
        )
        if not code:
            return []
        masked = _mask_strings_preserving_offsets(code)
        dompurify_uncertain = bool(re.search(
            r"\bDOMPurify\s*\.\s*(?:addHook|removeHook|removeAllHooks|setConfig|clearConfig)\s*\(",
            masked,
            re.IGNORECASE,
        ))
        policies = cls._policies(
            code, masked, dompurify_uncertain=dompurify_uncertain
        )
        events = cls._events(code, masked)
        event_scopes = cls._event_scopes(masked, events)
        scope_kinds = cls._scope_kinds(
            masked,
            {brace for scope in event_scopes for brace in scope},
        )
        has_transform_syntax = bool(re.search(
            r"\b(?:DOMPurify\s*\.\s*sanitize|trustedTypes\s*\.\s*createPolicy|"
            r"[A-Za-z_$][\w$]*(?:sanitize|escape|clean|encode)[\w$]*)\b",
            masked,
            re.IGNORECASE,
        ))
        states: dict[tuple[tuple[int, ...], str], list[FlowAtom]] = {}
        findings: list[SanitizerBoundaryFinding] = []
        finding_limit = cls.MAX_FINDINGS if max_findings is None else max(
            0, min(cls.MAX_FINDINGS, int(max_findings))
        )

        for event_index, event in enumerate(events):
            scope = event_scopes[event_index]
            if event.kind == "assignment":
                prior_state = cls._resolve_state(states, scope, event.name)
                atoms = cls._atoms_for_expression(
                    event.expression,
                    expression_offset=event.offset,
                    scope=scope,
                    states=states,
                    policies=policies,
                    dompurify_uncertain=dompurify_uncertain,
                )
                if event.operator != "=":
                    atoms = cls._merge_atoms(prior_state, atoms)
                elif event.conditional:
                    atoms = cls._merge_atoms(prior_state, atoms)
                states[(scope, event.name)] = atoms[: cls.MAX_ATOMS_PER_VALUE]

                # A reassignment inside a conditional/loop may not execute.
                # Retain both predecessor and branch states at the ancestor
                # join. Function bodies remain isolated until runtime evidence
                # proves a call path.
                if not event.declared and scope:
                    resolved_scope = cls._resolved_scope(states, scope[:-1], event.name)
                    nested_scopes = (
                        scope[len(resolved_scope):] if resolved_scope is not None else ()
                    )
                    nested_kinds = [scope_kinds.get(item, "block") for item in nested_scopes]
                    if (
                        resolved_scope is not None
                        and "function" not in nested_kinds
                        and resolved_scope != scope
                    ):
                        prior = states.get((resolved_scope, event.name), [])
                        if any(kind == "conditional" for kind in nested_kinds):
                            states[(resolved_scope, event.name)] = cls._merge_atoms(
                                prior, atoms
                            )
                        elif prior:
                            states[(resolved_scope, event.name)] = atoms[: cls.MAX_ATOMS_PER_VALUE]
                continue

            atoms = cls._atoms_for_expression(
                event.expression,
                expression_offset=event.offset,
                scope=scope,
                states=states,
                policies=policies,
                dompurify_uncertain=dompurify_uncertain,
            )
            required_context = cls._SINK_CONTEXTS.get(event.sink_kind, event.sink_context)
            for atom in atoms:
                if atom.transform_kind == "none" and has_transform_syntax:
                    atom = replace(
                        atom,
                        protection_state="ineffective",
                        transform_kind="non_dominating_transform",
                        protected_context=required_context,
                        reason_codes=("unprotected_sink_path",),
                    )
                finding = cls._classify_boundary(atom, event, required_context)
                if finding is None:
                    continue
                findings.append(finding)

        unique: list[SanitizerBoundaryFinding] = []
        seen: set[tuple[str, str, str, int]] = set()
        for item in findings:
            key = (item.category, item.source_param, item.sink_kind, item.sink_offset)
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)
        unique.sort(key=lambda item: (
            item.category == "effective_sanitizer_boundary",
            -item.confidence,
            item.sink_offset,
            item.fingerprint,
        ))
        return unique[:finding_limit]

    @staticmethod
    def _event_scopes(masked: str, events: list[_Event]) -> list[tuple[int, ...]]:
        """Resolve lexical brace paths for sorted events in one linear scan."""
        scopes: list[tuple[int, ...]] = []
        stack: list[int] = []
        overflow_depth = 0
        cursor = 0
        for event in events:
            upper = max(cursor, min(event.offset, len(masked)))
            for index in range(cursor, upper):
                char = masked[index]
                if char == "{":
                    if len(stack) < SanitizerBoundaryAnalyzer.MAX_SCOPE_DEPTH:
                        stack.append(index)
                    else:
                        overflow_depth += 1
                elif char == "}":
                    if overflow_depth:
                        overflow_depth -= 1
                    elif stack:
                        stack.pop()
            scopes.append(tuple(stack))
            cursor = upper
        return scopes

    @classmethod
    def _scope_kinds(
        cls, masked: str, brace_offsets: Iterable[int]
    ) -> dict[int, str]:
        """Classify bounded brace scopes for conservative state joins."""
        kinds: dict[int, str] = {}
        for index in sorted(set(brace_offsets)):
            if index < 0 or index >= len(masked) or masked[index] != "{":
                continue
            prefix = masked[max(0, index - 500):index].rstrip()
            tail = prefix[-500:]
            if re.search(
                r"(?:\b(?:if|for|while|switch|catch|with)\s*\([^{};]*\)|"
                r"\b(?:else|try|finally|do))\s*$",
                tail,
                re.IGNORECASE,
            ):
                kinds[index] = "conditional"
            elif re.search(
                rf"(?:\bfunction(?:\s+{_IDENT})?\s*\([^{{}};]*\)|"
                rf"(?:\([^{{}};]*\)|{_IDENT})\s*=>|"
                rf"\b(?:async\s+)?(?:get\s+|set\s+)?{_IDENT}\s*\([^{{}};]*\))\s*$",
                tail,
                re.IGNORECASE,
            ):
                kinds[index] = "function"
            else:
                kinds[index] = "block"
        return kinds

    @staticmethod
    def _is_unbraced_conditional(masked: str, offset: int) -> bool:
        prefix = masked[max(0, offset - 500):offset]
        statement_start = max(
            prefix.rfind(";"), prefix.rfind("{"), prefix.rfind("}"), prefix.rfind("\n")
        )
        tail = prefix[statement_start + 1:].strip()
        return bool(re.search(
            r"\b(?:if|for|while|with)\s*\([^{};]*\)\s*$|\belse\s*$",
            tail,
            re.IGNORECASE,
        ))

    @classmethod
    def _events(cls, code: str, masked: str) -> list[_Event]:
        assignment_candidates: dict[tuple[int, str, str], _Event] = {}
        sinks: list[_Event] = []

        def bounded_matches(pattern: re.Pattern[str]) -> list[re.Match[str]]:
            head_limit = max(1, cls.MAX_ASSIGNMENTS // 2)
            tail_limit = max(1, cls.MAX_ASSIGNMENTS - head_limit)
            head: list[re.Match[str]] = []
            tail: deque[re.Match[str]] = deque(maxlen=tail_limit)
            for candidate in pattern.finditer(masked):
                if len(head) < head_limit:
                    head.append(candidate)
                else:
                    tail.append(candidate)
            return head + list(tail)

        for match in bounded_matches(_ASSIGN_RE):
            name = match.group(1)
            eq = match.end() - 1
            offset = match.start(1)
            declared = bool(re.search(
                rf"\b(?:const|let|var)\s+{re.escape(name)}\s*=$",
                masked[match.start():match.end()],
            ))
            assignment_candidates[(offset, name, "=")] = _Event(
                offset,
                "assignment",
                name,
                _read_rhs_bounded(code, eq, cls.MAX_EXPRESSION_CHARS),
                declared=declared,
                conditional=cls._is_unbraced_conditional(masked, offset),
            )

        # Ordinary reassignments are needed to preserve source order. Avoid
        # properties, comparisons, arrow syntax, and declaration matches.
        reassign = re.compile(rf"(?<![.\w$])(?P<name>{_IDENT})\s*=(?!=|>)")
        for match in bounded_matches(reassign):
            offset = match.start("name")
            name = match.group("name")
            if (offset, name, "=") in assignment_candidates:
                continue
            prefix = masked[max(0, match.start() - 12):match.start()]
            if re.search(r"\b(?:const|let|var)\s*$", prefix):
                continue
            eq = masked.find("=", match.start(), match.end())
            assignment_candidates[(offset, name, "=")] = _Event(
                offset,
                "assignment",
                name,
                _read_rhs_bounded(code, eq, cls.MAX_EXPRESSION_CHARS),
                conditional=cls._is_unbraced_conditional(masked, offset),
            )

        compound = re.compile(
            rf"(?<![.\w$])(?P<name>{_IDENT})\s*(?P<operator>\+=|&&=|\|\|=|\?\?=)"
        )
        for match in bounded_matches(compound):
            offset = match.start("name")
            eq = match.end("operator") - 1
            operator = match.group("operator")
            assignment_candidates[(offset, match.group("name"), operator)] = _Event(
                offset,
                "assignment",
                match.group("name"),
                _read_rhs_bounded(code, eq, cls.MAX_EXPRESSION_CHARS),
                operator=operator,
                conditional=True,
            )

        ordered_assignments = sorted(
            assignment_candidates.values(), key=lambda item: item.offset
        )
        if len(ordered_assignments) <= cls.MAX_ASSIGNMENTS:
            assignments = ordered_assignments
        else:
            # Preserve both ends plus source/transform-bearing statements from
            # the middle. This avoids the old first-N behavior hiding late flows.
            interesting = [
                item for item in ordered_assignments
                if re.search(
                    r"(?:DOMPurify|trustedTypes|sanitize|escape|clean|encode|"
                    r"location|document|searchParams|urlParams|localStorage|"
                    r"sessionStorage|\.data\b)",
                    item.expression,
                    re.IGNORECASE,
                )
            ]
            chosen: dict[tuple[int, str, str], _Event] = {}

            def retain(items: Iterable[_Event]) -> None:
                for item in items:
                    if len(chosen) >= cls.MAX_ASSIGNMENTS:
                        return
                    chosen[(item.offset, item.name, item.operator)] = item

            edge_budget = max(1, cls.MAX_ASSIGNMENTS * 3 // 10)
            signal_budget = max(1, cls.MAX_ASSIGNMENTS // 5)
            retain(ordered_assignments[:edge_budget])
            retain(ordered_assignments[-edge_budget:])
            retain(interesting[:signal_budget // 2])
            retain(interesting[-(signal_budget - signal_budget // 2):])
            if len(chosen) < cls.MAX_ASSIGNMENTS:
                remaining = cls.MAX_ASSIGNMENTS - len(chosen)
                stride = max(1, len(ordered_assignments) // remaining)
                retain(ordered_assignments[::stride])
            assignments = sorted(chosen.values(), key=lambda item: item.offset)

        severity_priority = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        for sink_kind, pattern, sink_context, severity, extractor in _SINKS:
            kind_count = 0
            sink_search_text = code if sink_kind == "set_href_attr" else masked
            for match in re.finditer(pattern, sink_search_text, re.IGNORECASE):
                if kind_count >= cls.MAX_SINKS_PER_KIND:
                    break
                if (
                    sink_kind == "set_href_attr"
                    and (
                        match.start() >= len(masked)
                        or masked[match.start()].isspace()
                    )
                ):
                    continue
                actual_sink_kind = sink_kind
                actual_context = cls._SINK_CONTEXTS.get(sink_kind, sink_context)
                if sink_kind == "set_href_attr" and re.search(
                    r"setAttribute\s*\(\s*['\"]on\w+['\"]",
                    code[match.start():match.end()],
                    re.IGNORECASE,
                ):
                    actual_sink_kind = "set_event_attr"
                    actual_context = "SCRIPT"
                expression = ""
                if extractor == "rhs":
                    eq = masked.find("=", match.start(), min(len(masked), match.end() + 2))
                    if eq >= 0:
                        expression = _read_rhs_bounded(
                            code, eq, cls.MAX_EXPRESSION_CHARS
                        )
                    else:
                        opening = masked.find("(", match.start(), match.end())
                        expression = _read_call_arg_bounded(
                            code, opening, cls.MAX_EXPRESSION_CHARS
                        )
                else:
                    opening = masked.find("(", match.start(), match.end())
                    args = _read_call_arg_bounded(
                        code, opening, cls.MAX_EXPRESSION_CHARS
                    )
                    if extractor == "arg2":
                        parts = _split_top_level(args)
                        expression = parts[1] if len(parts) > 1 else (parts[0] if parts else "")
                    else:
                        expression = args
                if expression:
                    sinks.append(_Event(
                        match.start(), "sink", "", expression,
                        sink_kind=actual_sink_kind,
                        sink_context=actual_context,
                        priority=severity_priority.get(str(severity).lower(), 0),
                    ))
                    kind_count += 1
                if kind_count >= cls.MAX_SINKS_PER_KIND:
                    break
        sinks = sorted(sinks, key=lambda item: (-item.priority, item.offset))[: cls.MAX_SINKS]
        return sorted(
            (assignments + sinks)[: cls.MAX_EVENTS],
            key=lambda item: (item.offset, item.kind != "assignment"),
        )

    @classmethod
    def _source_atoms(cls, expression: str, expression_offset: int) -> list[FlowAtom]:
        atoms: list[FlowAtom] = []
        executable_mask = _mask_strings_preserving_offsets(expression)
        for source_kind, pattern in _SOURCES.items():
            for match in re.finditer(pattern, expression):
                if (
                    match.start() >= len(executable_mask)
                    or executable_mask[match.start()].isspace()
                ):
                    continue
                try:
                    param = match.group(1) if match.lastindex and match.group(1) else _default_param(source_kind)
                except IndexError:
                    param = _default_param(source_kind)
                atoms.append(FlowAtom(
                    source_kind=source_kind,
                    source_param=str(param)[:120],
                    source_offset=max(0, expression_offset + match.start()),
                ))
                if len(atoms) >= cls.MAX_ATOMS_PER_VALUE:
                    return atoms
        return atoms

    @classmethod
    def _resolve_state(
        cls,
        states: Mapping[tuple[tuple[int, ...], str], list[FlowAtom]],
        scope: tuple[int, ...],
        name: str,
    ) -> list[FlowAtom]:
        for depth in range(len(scope), -1, -1):
            value = states.get((scope[:depth], name))
            if value is not None:
                return value
        return []

    @classmethod
    def _resolved_scope(
        cls,
        states: Mapping[tuple[tuple[int, ...], str], list[FlowAtom]],
        scope: tuple[int, ...],
        name: str,
    ) -> tuple[int, ...] | None:
        for depth in range(len(scope), -1, -1):
            candidate = scope[:depth]
            if (candidate, name) in states:
                return candidate
        return None

    @classmethod
    def _merge_atoms(
        cls, left: Iterable[FlowAtom], right: Iterable[FlowAtom]
    ) -> list[FlowAtom]:
        """Join bounded flow states while retaining the least-safe alternatives."""
        ranked = sorted(
            list(left) + list(right),
            key=lambda atom: (
                atom.protection_state == "effective",
                atom.protection_state not in {"unprotected", "invalidated", "ineffective"},
                atom.source_offset,
            ),
        )
        merged: list[FlowAtom] = []
        seen: set[tuple[Any, ...]] = set()
        for atom in ranked:
            key = (
                atom.source_kind,
                atom.source_param,
                atom.source_offset,
                atom.protection_state,
                atom.transform_kind,
                atom.protected_context,
                atom.reason_codes,
                atom.policy_method,
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(atom)
            if len(merged) >= cls.MAX_ATOMS_PER_VALUE:
                break
        return merged

    @classmethod
    def _atoms_for_expression(
        cls,
        expression: str,
        *,
        expression_offset: int,
        scope: tuple[int, ...],
        states: Mapping[tuple[tuple[int, ...], str], list[FlowAtom]],
        policies: Mapping[tuple[str, str], PolicyMethod],
        dompurify_uncertain: bool = False,
        _depth: int = 0,
    ) -> list[FlowAtom]:
        if _depth < cls.MAX_EXPRESSION_DEPTH:
            operands = _split_top_level_concatenation(expression)
            if operands:
                atoms: list[FlowAtom] = []
                for operand, relative_offset in operands:
                    atoms = cls._merge_atoms(atoms, cls._atoms_for_expression(
                        operand,
                        expression_offset=expression_offset + relative_offset,
                        scope=scope,
                        states=states,
                        policies=policies,
                        dompurify_uncertain=dompurify_uncertain,
                        _depth=_depth + 1,
                    ))
                has_raw = any(atom.protection_state == "unprotected" for atom in atoms)
                has_effective = any(atom.protection_state == "effective" for atom in atoms)
                contains_dompurify = bool(re.search(
                    r"\bDOMPurify\s*\.\s*sanitize\s*\(", expression
                ))
                if contains_dompurify and has_raw:
                    atoms = [
                        replace(
                            atom,
                            protection_state="ineffective",
                            transform_kind=(
                                "dompurify" if atom.transform_kind == "none"
                                else atom.transform_kind
                            ),
                            protected_context=(
                                "HTML" if atom.transform_kind == "none"
                                else atom.protected_context
                            ),
                            transform_offset=(
                                expression_offset if atom.transform_offset < 0
                                else atom.transform_offset
                            ),
                            reason_codes=tuple(dict.fromkeys(
                                atom.reason_codes + ("source_outside_transform",)
                            )),
                        ) if atom.protection_state == "unprotected" else atom
                        for atom in atoms
                    ]
                if has_effective and has_raw:
                    atoms = [
                        replace(
                            atom,
                            protection_state="invalidated",
                            reason_codes=tuple(dict.fromkeys(
                                atom.reason_codes + ("mixed_with_external_value",)
                            )),
                        ) if atom.protection_state == "effective" else atom
                        for atom in atoms
                    ]
                return cls._merge_atoms([], atoms)

        direct_expression_atoms = cls._source_atoms(expression, expression_offset)
        if any(
            atom.source_offset == expression_offset for atom in direct_expression_atoms
        ):
            return direct_expression_atoms

        full_call = _full_call(expression)
        if full_call and _depth < cls.MAX_EXPRESSION_DEPTH:
            callee, args = full_call
            callee = re.sub(r"\s+", "", callee)
            argument_atoms: list[FlowAtom] = []
            for argument in args[: cls.MAX_ATOMS_PER_VALUE]:
                relative_offset = max(0, expression.find(argument))
                argument_atoms = cls._merge_atoms(
                    argument_atoms,
                    cls._atoms_for_expression(
                        argument,
                        expression_offset=expression_offset + relative_offset,
                        scope=scope,
                        states=states,
                        policies=policies,
                        dompurify_uncertain=dompurify_uncertain,
                        _depth=_depth + 1,
                    ),
                )

            if callee in cls._KNOWN_TRANSFORMS:
                transform_kind, context = cls._KNOWN_TRANSFORMS[callee]
                input_atoms = cls._atoms_for_expression(
                    args[0] if args else "",
                    expression_offset=expression_offset + (
                        max(0, expression.find(args[0])) if args else 0
                    ),
                    scope=scope,
                    states=states,
                    policies=policies,
                    dompurify_uncertain=dompurify_uncertain,
                    _depth=_depth + 1,
                )
                if callee == "DOMPurify.sanitize":
                    config = args[1] if len(args) > 1 else ""
                    if dompurify_uncertain or (
                        config and (
                            cls._RELAXED_DOMPURIFY.search(config)
                            or not config.lstrip().startswith("{")
                            or "..." in config
                            or "[" in _mask_strings_preserving_offsets(config)
                        )
                    ):
                        return [replace(
                            atom,
                            protection_state="unknown",
                            transform_kind=transform_kind,
                            protected_context=context,
                            transform_offset=expression_offset,
                            reason_codes=("dynamic_or_relaxed_configuration",),
                        ) for atom in input_atoms]
                return [replace(
                    atom,
                    protection_state="effective",
                    transform_kind=transform_kind,
                    protected_context=context,
                    transform_offset=expression_offset,
                    reason_codes=("known_transform",),
                ) for atom in input_atoms]

            if "." in callee:
                policy_variable, method = callee.rsplit(".", 1)
                policy = policies.get((policy_variable, method))
                if policy:
                    typed_context = {
                        "createHTML": "HTML",
                        "createScript": "SCRIPT",
                        "createScriptURL": "SCRIPT_URL",
                    }.get(method, "")
                    state = (
                        "effective" if policy.classification == "known_context_sanitizer"
                        else "unknown" if policy.classification == "opaque"
                        else "ineffective"
                    )
                    reason = {
                        "known_context_sanitizer": "policy_uses_known_sanitizer",
                        "opaque": "opaque_policy_method",
                        "identity": "identity_policy_method",
                        "dependency_preserving_passthrough": "content_preserving_policy_method",
                    }.get(policy.classification, "unknown_policy_method")
                    return [replace(
                        atom,
                        protection_state=state,
                        transform_kind="trusted_types_policy",
                        protected_context=typed_context,
                        transform_offset=expression_offset,
                        reason_codes=(reason,),
                        policy_method=method,
                    ) for atom in argument_atoms]

            if callee == "String":
                return [replace(
                    atom,
                    reason_codes=tuple(dict.fromkeys(
                        atom.reason_codes + ("content_preserving_wrapper",)
                    )),
                ) for atom in argument_atoms]

            if re.search(r"(?:sanitize|escape|clean|encode)", callee, re.IGNORECASE):
                return [replace(
                    atom,
                    protection_state="unknown",
                    transform_kind="custom_transform",
                    transform_offset=expression_offset,
                    reason_codes=("unverified_custom_transform",),
                ) for atom in argument_atoms]

            # Opaque wrappers can change the semantics of protected output.
            return [
                replace(
                    atom,
                    protection_state="unknown",
                    reason_codes=tuple(dict.fromkeys(
                        atom.reason_codes + ("opaque_post_transform",)
                    )),
                ) if atom.protection_state == "effective" else atom
                for atom in argument_atoms
            ]

        direct = direct_expression_atoms
        referenced: list[FlowAtom] = []
        seen_names: set[str] = set()
        masked_expression = _mask_strings_preserving_offsets(expression)
        for match in _IDENT_RE.finditer(masked_expression):
            name = match.group(0)
            if name in seen_names:
                continue
            seen_names.add(name)
            for atom in cls._resolve_state(states, scope, name):
                if atom.hops < cls.MAX_HOPS:
                    referenced.append(replace(atom, hops=atom.hops + 1))
                    if len(referenced) >= cls.MAX_ATOMS_PER_VALUE:
                        break
            if len(referenced) >= cls.MAX_ATOMS_PER_VALUE:
                break
            if len(seen_names) >= cls.MAX_IDENTIFIERS_PER_EXPRESSION:
                break
        atoms = cls._merge_atoms([], direct + referenced)
        if (
            any(atom.protection_state == "effective" for atom in atoms)
            and any(atom.protection_state != "effective" for atom in atoms)
        ):
            atoms = [
                replace(
                    atom,
                    protection_state="invalidated",
                    reason_codes=tuple(dict.fromkeys(
                        atom.reason_codes + ("alternative_unprotected_path",)
                    )),
                ) if atom.protection_state == "effective" else atom
                for atom in atoms
            ]
        return cls._merge_atoms([], atoms)

    @classmethod
    def _classify_boundary(
        cls,
        atom: FlowAtom,
        event: _Event,
        required_context: str,
    ) -> SanitizerBoundaryFinding | None:
        if atom.transform_kind == "none":
            return None
        compatible = (
            atom.protected_context == required_context
            or atom.protected_context == "NUMERIC"
            or (atom.protected_context == "SCRIPT_URL" and required_context == "URL")
        )
        if atom.transform_kind == "trusted_types_policy" and atom.protection_state in {
            "ineffective", "unknown",
        }:
            category = "trusted_types_unvalidated_flow"
            confidence = 0.91 if atom.protection_state == "ineffective" else 0.68
        elif atom.protection_state == "invalidated":
            category = "sanitizer_output_invalidated"
            confidence = 0.9
        elif atom.protection_state == "unknown":
            category = "opaque_sanitizer_flow"
            confidence = 0.64
        elif atom.protection_state == "ineffective":
            category = "sanitizer_partial_coverage"
            confidence = 0.92
        elif atom.protection_state == "effective" and not compatible:
            category = "sanitizer_context_mismatch"
            confidence = 0.9
        elif atom.protection_state == "effective" and compatible:
            category = "effective_sanitizer_boundary"
            confidence = 0.88
        else:
            return None
        reasons = atom.reason_codes
        if not compatible:
            reasons = tuple(dict.fromkeys(reasons + ("output_context_mismatch",)))
        return SanitizerBoundaryFinding(
            category=category,
            source_kind=atom.source_kind,
            source_param=atom.source_param,
            sink_kind=event.sink_kind,
            required_context=required_context,
            transform_kind=atom.transform_kind,
            protection_state=(
                "ineffective" if atom.protection_state == "effective" and not compatible
                else atom.protection_state
            ),
            reason_codes=reasons,
            source_offset=atom.source_offset,
            transform_offset=atom.transform_offset,
            sink_offset=event.offset,
            confidence=confidence,
            fingerprint=_fingerprint(
                category, atom.source_kind, atom.source_param, event.sink_kind,
                atom.transform_kind, atom.transform_offset, event.offset,
            ),
            details={
                "hops": atom.hops,
                "policy_method": atom.policy_method or None,
                "compatible_context": compatible,
                "requires_dynamic_confirmation": category != "effective_sanitizer_boundary",
            },
        )

    @classmethod
    def _policies(
        cls,
        code: str,
        masked: str,
        *,
        dompurify_uncertain: bool = False,
    ) -> dict[tuple[str, str], PolicyMethod]:
        object_bodies: dict[str, tuple[str, int]] = {}
        object_decl = re.compile(
            rf"\b(?:const|let|var)\s+(?P<name>{_IDENT})\s*=\s*\{{"
        )
        for match in object_decl.finditer(masked):
            body = _balanced_block(code, match.end() - 1, max_chars=80_000)
            object_bodies[match.group("name")] = (body, match.start())
            if len(object_bodies) >= cls.MAX_POLICIES:
                break

        policies: dict[tuple[str, str], PolicyMethod] = {}
        policy_decl = re.compile(
            rf"\b(?:const|let|var)\s+(?P<policy>{_IDENT})\s*=\s*"
            rf"(?:window\s*\.\s*)?trustedTypes\s*\.\s*createPolicy\s*\("
        )
        for match in policy_decl.finditer(masked):
            opening = masked.find("(", match.start(), match.end())
            arguments = _read_call_arg_bounded(
                code, opening, cls.MAX_EXPRESSION_CHARS
            )
            parts = _split_top_level(arguments)
            if len(parts) < 2:
                continue
            rules_expr = parts[1].strip()
            if rules_expr.startswith("{"):
                rules = rules_expr[1:-1] if rules_expr.endswith("}") else rules_expr[1:]
                rules_offset = match.start()
            elif re.fullmatch(_IDENT, rules_expr) and rules_expr in object_bodies:
                rules, rules_offset = object_bodies[rules_expr]
            else:
                rules, rules_offset = "", match.start()
            for method in ("createHTML", "createScript", "createScriptURL"):
                classification = cls._policy_method_classification(rules, method)
                if classification == "known_context_sanitizer" and dompurify_uncertain:
                    classification = "opaque"
                if classification:
                    policies[(match.group("policy"), method)] = PolicyMethod(
                        policy_variable=match.group("policy"),
                        method=method,
                        classification=classification,
                        offset=rules_offset,
                    )
            if len(policies) >= cls.MAX_POLICIES:
                break
        return policies

    @classmethod
    def _policy_method_classification(cls, rules: str, method: str) -> str:
        escaped = re.escape(method)
        arrow = re.search(
            rf"\b{escaped}\s*:\s*(?:\(\s*)?(?P<param>{_IDENT})(?:\s*\))?\s*=>\s*"
            rf"(?P<body>[^,}}]{{1,1000}})",
            rules,
            re.IGNORECASE,
        )
        shorthand = re.search(
            rf"\b{escaped}\s*\(\s*(?P<param>{_IDENT})\s*\)\s*\{{"
            rf"(?P<body>[^}}]{{1,2000}})\}}",
            rules,
            re.IGNORECASE,
        )
        match = arrow or shorthand
        if not match:
            return "opaque" if re.search(rf"\b{escaped}\b", rules) else ""
        param = match.group("param")
        body = match.group("body").strip()
        return_match = re.search(r"\breturn\s+(.+?)(?:;|$)", body, re.DOTALL)
        expression = return_match.group(1).strip() if return_match else body
        normalized = re.sub(r"\s+", "", expression).rstrip(";")
        escaped_param = re.escape(param)
        if normalized == param:
            return "identity"
        sanitizer_call = _full_call(expression)
        if sanitizer_call and sanitizer_call[0] == "DOMPurify.sanitize":
            arguments = sanitizer_call[1]
            input_is_parameter = bool(arguments) and re.fullmatch(
                rf"\s*{re.escape(param)}\s*", arguments[0]
            )
            config = arguments[1] if len(arguments) > 1 else ""
            config_is_strict = not config or (
                config.lstrip().startswith("{")
                and "..." not in config
                and "[" not in _mask_strings_preserving_offsets(config)
                and not cls._RELAXED_DOMPURIFY.search(config)
            )
            if method == "createHTML" and input_is_parameter and config_is_strict:
                return "known_context_sanitizer"
            return "opaque"
        if re.search(r"DOMPurify\s*\.\s*sanitize\s*\(", expression):
            return "opaque"
        passthrough_patterns = (
            rf"String\({escaped_param}\)",
            rf"{escaped_param}\.(?:trim|toString)\(\)",
            rf"`[^`]*\$\{{{escaped_param}\}}[^`]*`",
            rf"(?:['\"][^'\"]*['\"]\+)?{escaped_param}(?:\+['\"][^'\"]*['\"])?",
        )
        if any(re.fullmatch(pattern, normalized, re.DOTALL) for pattern in passthrough_patterns):
            return "dependency_preserving_passthrough"
        return "opaque"


__all__ = ["SanitizerBoundaryAnalyzer", "SanitizerBoundaryFinding"]
