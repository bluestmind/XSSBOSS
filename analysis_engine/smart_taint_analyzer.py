"""Smart taint analyzer — prove source→sink reachability, don't spray.

The old sink detection matched sink *names* and source *names* by regex proximity and then fuzzed
everything. This does real **data-flow taint propagation**: it tracks how a user-controlled value
moves through variable assignments, string building, and calls, applies sanitizer awareness, and
reports only the flows that actually reach a dangerous sink **unsanitized** — with the exact source
parameter to inject and the context to inject in. That turns the fuzzer from a bot that tests every
parameter into a hunter that tests the ones that can actually pop.

Model: a taint lattice over variables (UNTAINTED / TAINTED / SANITIZED), propagated to a fixpoint
over assignments, then matched against sink expressions. It is a sound-ish over-approximation for the
common DOM-XSS patterns — heavy enough to be useful, light enough to run on every discovered bundle
without a full JS engine.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class Reachability(str, Enum):
    REACHABLE = "reachable"        # tainted value hits the sink unsanitized -> worth testing
    SANITIZED = "sanitized"        # a sanitizer stands between source and sink -> low priority
    UNREACHABLE = "unreachable"    # sink exists but no user data reaches it -> do NOT test


# --- sources (user-controllable). Capture group 1 = parameter name when knowable. ---
_SOURCES: Dict[str, str] = {
    "url_param": r"(?:URLSearchParams\([^)]*\)|searchParams|params|query|qs|urlParams)\s*\.\s*get\s*\(\s*['\"]([\w\-\.\[\]]+)['\"]\s*\)",
    "url_param_index": r"(?:params|query|args|q)\s*\[\s*['\"]([\w\-]+)['\"]\s*\]",
    "location_hash": r"location\s*\.\s*hash",
    "location_search": r"location\s*\.\s*search",
    "location_href": r"(?:document\s*\.\s*URL|document\s*\.\s*documentURI|location\s*\.\s*href|window\s*\.\s*location\s*\.\s*href)",
    "referrer": r"document\s*\.\s*referrer",
    "window_name": r"\bwindow\s*\.\s*name\b",
    "postmessage": r"\b(?:e|ev|evt|event|msg|message)\s*\.\s*data\b",
    "cookie": r"document\s*\.\s*cookie",
    "storage": r"(?:localStorage|sessionStorage)\s*\.\s*getItem\s*\(\s*['\"]([\w\-]+)['\"]",
}

# --- sanitizers: their presence in an expression clears/downgrades taint. ---
_SANITIZER = re.compile(
    r"\b(?:encodeURIComponent|encodeURI|escape|CSS\s*\.\s*escape|DOMPurify\s*\.\s*sanitize|"
    r"sanitize(?:HTML|Html)?|escapeHtml|escapeHTML|htmlEscape|he\s*\.\s*encode|Number|parseInt|parseFloat)\b"
)

# --- sinks: (kind, context, severity, how to reach the argument expression) ---
# kind: label ; context: injection context for the fuzzer ; extractor: 'rhs' | 'call' | 'arg2'
_SINKS: List[Tuple[str, str, str, str, str]] = [
    # (name, regex, context, severity, extractor)
    ("innerHTML", r"\.\s*(?:innerHTML|outerHTML)\s*=(?!=)", "HTML_TEXT", "high", "rhs"),
    ("insertAdjacentHTML", r"\.\s*insertAdjacentHTML\s*\(", "HTML_TEXT", "high", "arg2"),
    ("document_write", r"document\s*\.\s*write(?:ln)?\s*\(", "HTML_TEXT", "high", "call"),
    ("eval", r"\beval\s*\(", "JS_BLOCK", "critical", "call"),
    ("function_ctor", r"(?:new\s+Function|\bFunction)\s*\(", "JS_BLOCK", "critical", "call"),
    ("timer_string", r"\bset(?:Timeout|Interval)\s*\(", "JS_BLOCK", "high", "call"),
    ("navigation", r"(?:location\s*\.\s*(?:href|assign|replace)\s*[=(]|location\s*=)", "URL_HREF", "medium", "rhs"),
    ("jquery_html", r"\.\s*(?:html|append|prepend|before|after|replaceWith|wrap)\s*\(", "HTML_TEXT", "high", "call"),
    ("jquery_selector", r"\$\s*\(", "HTML_TEXT", "medium", "call"),
    ("srcdoc", r"\.\s*srcdoc\s*=(?!=)", "HTML_TEXT", "high", "rhs"),
    ("iframe_src", r"\.\s*src\s*=(?!=)", "URL_SRC", "medium", "rhs"),
    ("range_fragment", r"\.\s*createContextualFragment\s*\(", "HTML_TEXT", "high", "call"),
    ("set_href_attr", r"\.\s*setAttribute\s*\(\s*['\"](?:href|src|formaction|xlink:href|on\w+)['\"]", "URL_HREF", "medium", "arg2"),
]

_ASSIGN_RE = re.compile(r"(?:^|[;\{\}\n]|\bvar\b|\blet\b|\bconst\b)\s*([A-Za-z_$][\w$]*)\s*=(?!=)")
_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")
# identifiers that are language/globals, never a tainted local var to chase
_STOPWORDS = {
    "var", "let", "const", "function", "return", "if", "else", "for", "while", "new", "true",
    "false", "null", "undefined", "this", "document", "window", "location", "typeof", "void",
}


@dataclass
class VarTaint:
    tainted: bool = False
    sanitized: bool = False
    source_kind: str = ""
    source_param: str = ""
    hops: int = 0


@dataclass
class TaintFinding:
    source_kind: str
    source_param: str
    sink_kind: str
    context: str
    severity: str
    reachability: Reachability
    confidence: float
    hops: int
    evidence: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "source_kind": self.source_kind, "source_param": self.source_param,
            "sink_kind": self.sink_kind, "context": self.context, "severity": self.severity,
            "reachability": self.reachability.value, "confidence": round(self.confidence, 2),
            "hops": self.hops, "evidence": self.evidence[:200],
        }


def _strip_comments(code: str) -> str:
    code = re.sub(r"/\*.*?\*/", " ", code, flags=re.DOTALL)
    code = re.sub(r"(?<!:)//[^\n]*", " ", code)
    return code


def _read_call_arg(code: str, open_paren: int) -> str:
    """Return the argument text inside the balanced (...) starting at ``open_paren``."""
    depth = 0
    i = open_paren
    quote = None
    out = []
    while i < len(code):
        c = code[i]
        if quote:
            out.append(c)
            if c == quote and code[i - 1] != "\\":
                quote = None
        elif c in "\"'`":
            quote = c
            out.append(c)
        elif c == "(":
            depth += 1
            if depth > 1:
                out.append(c)
        elif c == ")":
            depth -= 1
            if depth == 0:
                return "".join(out)
            out.append(c)
        else:
            out.append(c)
        i += 1
    return "".join(out)


def _read_rhs(code: str, eq_pos: int) -> str:
    """Return the right-hand side after ``=`` up to a top-level ; or newline."""
    i = eq_pos + 1
    depth = 0
    quote = None
    out = []
    while i < len(code):
        c = code[i]
        if quote:
            out.append(c)
            if c == quote and code[i - 1] != "\\":
                quote = None
        elif c in "\"'`":
            quote = c
            out.append(c)
        elif c in "([{":
            depth += 1
            out.append(c)
        elif c in ")]}":
            if depth == 0:
                break
            depth -= 1
            out.append(c)
        elif (c == ";" or c == "\n") and depth == 0:
            break
        else:
            out.append(c)
        i += 1
    return "".join(out).strip()


def _sources_in(expr: str) -> List[Tuple[str, str]]:
    """Return (kind, param) for every source found in an expression."""
    found = []
    for kind, pat in _SOURCES.items():
        for m in re.finditer(pat, expr):
            param = m.group(1) if (m.lastindex and m.group(1)) else _default_param(kind)
            found.append((kind, param))
    return found


def _default_param(kind: str) -> str:
    return {
        "location_hash": "hash", "location_search": "query", "location_href": "url",
        "referrer": "referrer", "window_name": "window.name", "postmessage": "postMessage",
        "cookie": "cookie",
    }.get(kind, kind)


class SmartTaintAnalyzer:
    """Data-flow taint analysis: prove source→sink reachability for DOM XSS."""

    @classmethod
    def analyze(cls, js_code: str) -> List[TaintFinding]:
        code = _strip_comments(js_code or "")
        var_taint = cls._propagate(code)
        return cls._match_sinks(code, var_taint)

    # ---- taint propagation to a fixpoint over variable assignments -------------

    @classmethod
    def _propagate(cls, code: str) -> Dict[str, VarTaint]:
        # Gather assignments: name -> rhs expression (last write wins for this light model).
        assigns: Dict[str, str] = {}
        for m in _ASSIGN_RE.finditer(code):
            name = m.group(1)
            if name in _STOPWORDS:
                continue
            assigns[name] = _read_rhs(code, m.end() - 1)

        taint: Dict[str, VarTaint] = {}
        # Seed: variables whose RHS contains a source directly.
        for name, rhs in assigns.items():
            srcs = _sources_in(rhs)
            if srcs and not _SANITIZER.search(rhs):
                kind, param = srcs[0]
                taint[name] = VarTaint(True, False, kind, param, 1)
            elif srcs:  # source present but sanitized on assignment
                kind, param = srcs[0]
                taint[name] = VarTaint(True, True, kind, param, 1)

        # Fixpoint: a var referencing a tainted var inherits taint (sanitizer clears it).
        changed = True
        guard = 0
        while changed and guard < 50:
            changed = False
            guard += 1
            for name, rhs in assigns.items():
                if name in taint and taint[name].tainted and not taint[name].sanitized:
                    continue
                refs = {t for t in _IDENT_RE.findall(rhs) if t not in _STOPWORDS and t != name}
                for ref in refs:
                    rt = taint.get(ref)
                    if rt and rt.tainted:
                        sanitized = bool(_SANITIZER.search(rhs)) or rt.sanitized
                        new = VarTaint(True, sanitized, rt.source_kind, rt.source_param, rt.hops + 1)
                        old = taint.get(name)
                        if old is None or (old.sanitized and not sanitized):
                            taint[name] = new
                            changed = True
                        break
        return taint

    # ---- match tainted data against sinks -------------------------------------

    @classmethod
    def _match_sinks(cls, code: str, taint: Dict[str, VarTaint]) -> List[TaintFinding]:
        findings: List[TaintFinding] = []
        seen = set()
        for name, sink_re, context, severity, extractor in _SINKS:
            for m in re.finditer(sink_re, code):
                expr = cls._sink_expr(code, m, extractor)
                if expr is None:
                    continue
                finding = cls._classify(expr, name, context, severity, taint)
                if finding is None:
                    continue
                key = (finding.source_param, finding.sink_kind, finding.reachability)
                if key in seen:
                    continue
                seen.add(key)
                finding.evidence = expr.strip()[:200]
                findings.append(finding)
        # Reachable first, then by confidence.
        findings.sort(key=lambda f: (f.reachability != Reachability.REACHABLE, -f.confidence))
        return findings

    @staticmethod
    def _sink_expr(code: str, m: re.Match, extractor: str) -> Optional[str]:
        if extractor == "rhs":
            eq = code.find("=", m.start(), m.end() + 2)
            if eq != -1:
                return _read_rhs(code, eq)
            # fall through to call form (e.g. location.assign(x))
        # call / arg2: read the balanced call argument list.
        paren = code.find("(", m.end() - 1)
        if paren == -1:
            return None
        args = _read_call_arg(code, paren)
        if extractor == "arg2":
            parts = SmartTaintAnalyzer._split_top_level(args)
            return parts[1] if len(parts) > 1 else (parts[0] if parts else "")
        return args

    @staticmethod
    def _split_top_level(args: str) -> List[str]:
        parts, depth, quote, cur = [], 0, None, []
        for i, c in enumerate(args):
            if quote:
                cur.append(c)
                if c == quote and (i == 0 or args[i - 1] != "\\"):
                    quote = None
            elif c in "\"'`":
                quote = c
                cur.append(c)
            elif c in "([{":
                depth += 1
                cur.append(c)
            elif c in ")]}":
                depth -= 1
                cur.append(c)
            elif c == "," and depth == 0:
                parts.append("".join(cur))
                cur = []
            else:
                cur.append(c)
        if cur:
            parts.append("".join(cur))
        return [p.strip() for p in parts]

    @staticmethod
    def _classify(expr: str, sink_kind: str, context: str, severity: str,
                  taint: Dict[str, VarTaint]) -> Optional[TaintFinding]:
        # A literal-only argument (no identifiers, no source) is a dead sink — skip it.
        direct = _sources_in(expr)
        sanitized_here = bool(_SANITIZER.search(expr))

        source_kind = source_param = ""
        hops = 1
        tainted = False
        sanitized = sanitized_here

        if direct:
            source_kind, source_param = direct[0]
            tainted = True
        else:
            for ref in {t for t in _IDENT_RE.findall(expr) if t not in _STOPWORDS}:
                rt = taint.get(ref)
                if rt and rt.tainted:
                    tainted = True
                    source_kind, source_param = rt.source_kind, rt.source_param
                    hops = rt.hops + 1
                    sanitized = sanitized or rt.sanitized
                    break

        if not tainted:
            return None  # sink exists but no user data flows in -> do NOT test

        if sanitized:
            reach = Reachability.SANITIZED
            confidence = 0.25
        else:
            reach = Reachability.REACHABLE
            confidence = max(0.4, 0.95 - 0.12 * (hops - 1))

        return TaintFinding(source_kind, source_param, sink_kind, context, severity,
                            reach, confidence, hops)


def prioritized_injection_targets(js_code: str) -> List[Dict[str, object]]:
    """Convenience: the parameters worth fuzzing, best-first (reachable + high confidence).

    Each item names the exact source parameter, the sink it reaches, and the context to inject in —
    so the fuzzer tests what can actually execute instead of every parameter.
    """
    findings = SmartTaintAnalyzer.analyze(js_code)
    out = []
    for f in findings:
        if f.reachability == Reachability.REACHABLE:
            out.append(f.to_dict())
    return out
