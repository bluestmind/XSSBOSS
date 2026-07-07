"""
OWASP / PortSwigger-style XSS challenge definitions.

Each challenge simulates a real-world sanitization scenario with a specific
context type, blocked characters/keywords, and a template. The evaluate()
method uses regex heuristics to decide whether a payload would execute in a
real browser — identical to the existing benchmark_fuzzer_efficacy harness
but covering far more contexts.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set


@dataclass
class ChallengeTarget:
    """A simulated web endpoint with specific sanitization rules and context."""

    name: str
    context_type: str
    template: str  # Template with {INPUT}
    blocked_chars: Set[str] = field(default_factory=set)
    blocked_keywords: List[str] = field(default_factory=list)
    case_sensitive: bool = False
    max_length: int | None = None
    description: str = ""
    difficulty: str = "medium"  # easy | medium | hard | boss

    def evaluate(self, payload: str, token: str) -> Dict[str, Any]:
        """Simulate browser evaluation of the payload in this target."""
        # 0. Length check
        if self.max_length and len(payload) > self.max_length:
            return {
                "executed": False,
                "blocked_by_filter": True,
                "reason": f"Length exceeded: {len(payload)} > {self.max_length}",
                "errors": [],
                "logs": {"errors": [f"Length limit exceeded"]},
            }

        # 1. Character filter
        for char in self.blocked_chars:
            if char in payload:
                return {
                    "executed": False,
                    "blocked_by_filter": True,
                    "reason": f"Blocked character: {char}",
                    "errors": [],
                    "logs": {"errors": [f"WAF blocked character: {char}"]},
                }

        # 2. Keyword filter
        check_payload = payload.lower() if not self.case_sensitive else payload
        for kw in self.blocked_keywords:
            kw_check = kw.lower() if not self.case_sensitive else kw
            if kw_check in check_payload:
                return {
                    "executed": False,
                    "blocked_by_filter": True,
                    "reason": f"Blocked keyword: {kw}",
                    "errors": [],
                    "logs": {"errors": [f"WAF blocked keyword: {kw}"]},
                }

        # 3. Render in template
        rendered = self.template.replace("{INPUT}", payload)

        # 4. Simulate browser execution
        executed = self._simulate_browser_execution(rendered, payload, token)

        errors = []
        if not executed and token in rendered:
            if self.context_type in ["JS_STRING_LITERAL", "JS_SCRIPT_BLOCK", "JS_TEMPLATE_LITERAL"]:
                if "'" in payload or '"' in payload or ";" in payload:
                    errors.append(f"Uncaught SyntaxError: Unexpected token '{token}'")

        return {
            "executed": executed,
            "blocked_by_filter": False,
            "rendered": rendered,
            "errors": errors,
            "logs": {
                "errors": errors,
                "sink": "execution" if executed else None,
                "sample": payload if executed else None,
            },
        }

    def _simulate_browser_execution(self, rendered: str, payload: str, token: str) -> bool:
        """Heuristic AST/DOM execution simulator."""
        ctx = self.context_type

        # --- Attribute contexts ---
        if ctx in ("ATTR_QUOTED", "ATTR_UNQUOTED", "EVENT_HANDLER_ATTR"):
            if re.search(r"""[\"']\s+on[a-z]+\s*=\s*[^>]+""", rendered, re.IGNORECASE):
                return True
            if re.search(r"""[\"']\s*>\s*<(?:script|svg|img|iframe|body|details|video|audio|marquee|object|embed|math)[^>]*>""", rendered, re.IGNORECASE):
                return True
            if ctx == "ATTR_UNQUOTED":
                if re.search(r"""\s+on[a-z]+\s*=\s*[^\s>]+""", rendered, re.IGNORECASE):
                    return True
            if ctx == "EVENT_HANDLER_ATTR":
                # Direct JS injection in event handler value
                if re.search(r"""on[a-z]+=["']?[^"'>]*(?:alert|confirm|prompt|eval|fetch|constructor|Function)\b""", rendered, re.IGNORECASE):
                    return True

        # --- HTML text ---
        elif ctx == "HTML_TEXT":
            if re.search(r"<(?:script|svg|img|iframe|body|details|video|audio|marquee|object|embed|math|xss)[^>]*>", rendered, re.IGNORECASE):
                return True

        # --- HTML comment ---
        elif ctx == "HTML_COMMENT":
            if "-->" in payload and re.search(r"<(?:script|svg|img|iframe|math)[^>]*>", rendered, re.IGNORECASE):
                return True

        # --- JS string literal ---
        elif ctx == "JS_STRING_LITERAL":
            if re.search(r"</script\s*>\s*<(?:script|svg|img)[^>]*>", rendered, re.IGNORECASE):
                return True
            if re.search(r"""[\"'];?\s*(?:alert|confirm|prompt|throw|eval|fetch|window|document)\b""", rendered, re.IGNORECASE):
                return True
            if re.search(r"""[\"']\s*[-+*/]\s*(?:alert|confirm|prompt|eval)\b""", rendered, re.IGNORECASE):
                return True

        # --- JS template literal ---
        elif ctx == "JS_TEMPLATE_LITERAL":
            if re.search(r"\$\{[^}]*(?:alert|confirm|prompt|eval|constructor|Function)\b", rendered, re.IGNORECASE):
                return True
            if re.search(r"</script\s*>\s*<(?:script|svg|img)[^>]*>", rendered, re.IGNORECASE):
                return True

        # --- CSS style block ---
        elif ctx in ("CSS_STYLE_BLOCK", "CSS_INLINE_STYLE"):
            if re.search(r"</style\s*>\s*<(?:script|svg|img)[^>]*>", rendered, re.IGNORECASE):
                return True

        # --- JSON in script ---
        elif ctx == "JSON_IN_SCRIPT":
            if re.search(r"</script\s*>\s*<(?:script|svg|img)[^>]*>", rendered, re.IGNORECASE):
                return True

        # --- SVG namespace ---
        elif ctx in ("SVG_TEXT", "SVG_SCRIPT"):
            if re.search(r"<(?:script|animate|set|svg|foreignObject|use)[^>]*(?:on\w+|href)\s*=", rendered, re.IGNORECASE):
                return True
            if re.search(r"<svg[^>]*on\w+\s*=", rendered, re.IGNORECASE):
                return True

        # --- MathML namespace ---
        elif ctx in ("MATHML_TEXT", "ANNOTATION_XML"):
            if re.search(r"<annotation-xml[^>]*encoding\s*=\s*[\"']text/html[\"']", rendered, re.IGNORECASE):
                if re.search(r"<(?:script|img|svg|iframe)[^>]*>", rendered, re.IGNORECASE):
                    return True

        # --- RCDATA (title, textarea) ---
        elif ctx == "HTML_RCDATA":
            if re.search(r"</(?:title|textarea)\s*>\s*<(?:script|svg|img|iframe)[^>]*>", rendered, re.IGNORECASE):
                return True

        # --- URL context ---
        elif ctx in ("URL_QUERY", "URL_FRAGMENT"):
            if re.search(r"""(?:javascript|data)\s*:""", rendered, re.IGNORECASE):
                return True

        # --- CSTI ---
        elif ctx in ("CSTI_ANGULAR", "CSTI_VUE", "CSTI_GENERIC"):
            if re.search(r"\{\{.*(?:constructor|alert|eval|Function)\b", rendered, re.IGNORECASE):
                return True

        return False


# ─────────────────────────────────────────────────────────────────────────────
# 25+ challenge definitions modeled after OWASP XSS Filter Evasion Cheat Sheet
# and PortSwigger XSS lab scenarios
# ─────────────────────────────────────────────────────────────────────────────

OWASP_CHALLENGES: List[ChallengeTarget] = [
    # --- Easy: Basic contexts, minimal filtering ---
    ChallengeTarget(
        name="O-01: Raw HTML Reflection (no filter)",
        context_type="HTML_TEXT",
        template='<div>Search: {INPUT}</div>',
        description="Trivial raw HTML reflection with no sanitization.",
        difficulty="easy",
    ),
    ChallengeTarget(
        name="O-02: Quoted Attribute (no filter)",
        context_type="ATTR_QUOTED",
        template='<input value="{INPUT}">',
        description="Trivial quoted attribute reflection.",
        difficulty="easy",
    ),
    ChallengeTarget(
        name="O-03: Unquoted Attribute Reflection",
        context_type="ATTR_UNQUOTED",
        template='<img src=x data-val={INPUT} alt=probe>',
        description="Unquoted attribute — space or > breaks out.",
        difficulty="easy",
    ),

    # --- Medium: Single-dimension filtering ---
    ChallengeTarget(
        name="O-04: Attribute Breakout (angle brackets blocked)",
        context_type="ATTR_QUOTED",
        template='<input type="text" value="{INPUT}">',
        blocked_chars={"<", ">"},
        description="Must use event handler injection (e.g. \" onfocus=alert(1) autofocus=\").",
        difficulty="medium",
    ),
    ChallengeTarget(
        name="O-05: JS String Literal (quotes + backslash blocked)",
        context_type="JS_STRING_LITERAL",
        template='<script>let user = "{INPUT}";</script>',
        blocked_chars={"\\", '"', "'"},
        description="Must break out via </script> tag closure.",
        difficulty="medium",
    ),
    ChallengeTarget(
        name="O-06: HTML Comment Breakout (script keyword blocked)",
        context_type="HTML_COMMENT",
        template='<!-- User: {INPUT} -->',
        blocked_keywords=["script"],
        description="Close comment with --> then use <svg> or <img>.",
        difficulty="medium",
    ),
    ChallengeTarget(
        name="O-07: Keyword Evasion (alert/onerror/script blocked)",
        context_type="HTML_TEXT",
        template='<div>Results: {INPUT}</div>',
        blocked_keywords=["alert", "onerror", "script", "javascript"],
        description="Must use alternate events/functions: confirm, prompt, onload, etc.",
        difficulty="medium",
    ),
    ChallengeTarget(
        name="O-08: CSS Style Block Breakout (quotes blocked)",
        context_type="CSS_STYLE_BLOCK",
        template='<style>body {{ font: "{INPUT}"; }}</style>',
        blocked_chars={"\\", '"', "'"},
        blocked_keywords=["alert"],
        description="Close </style> then inject SVG/IMG tag.",
        difficulty="medium",
    ),
    ChallengeTarget(
        name="O-09: URL Href Injection (script keyword blocked)",
        context_type="URL_QUERY",
        template='<a href="{INPUT}">Click</a>',
        blocked_keywords=["script"],
        description="Use data: URI or javascript with encoding tricks.",
        difficulty="medium",
    ),
    ChallengeTarget(
        name="O-10: Event Handler Attr (parentheses blocked)",
        context_type="EVENT_HANDLER_ATTR",
        template='<div onmouseover="{INPUT}">hover</div>',
        blocked_chars={"(", ")"},
        description="Use backtick template or onerror throw or import().",
        difficulty="medium",
    ),

    # --- Hard: Multi-dimension filtering ---
    ChallengeTarget(
        name="O-11: RCDATA Title Breakout (img/script blocked)",
        context_type="HTML_RCDATA",
        template='<title>{INPUT}</title>',
        blocked_keywords=["script", "img"],
        description="Close </title> then use <svg>, <details>, <body>, etc.",
        difficulty="hard",
    ),
    ChallengeTarget(
        name="O-12: JSON-in-Script Breakout (quotes blocked)",
        context_type="JSON_IN_SCRIPT",
        template='<script type="application/json">{{"user":"{INPUT}"}}</script>',
        blocked_chars={"\\", '"'},
        description="Close </script> with payload, open new script context.",
        difficulty="hard",
    ),
    ChallengeTarget(
        name="O-13: JS Template Literal Injection",
        context_type="JS_TEMPLATE_LITERAL",
        template='<script>let msg = `Hello {INPUT}`;</script>',
        blocked_keywords=["alert", "eval"],
        description="Use ${constructor.constructor('...')()}  or ${confirm(1)}.",
        difficulty="hard",
    ),
    ChallengeTarget(
        name="O-14: SVG Namespace Injection (script blocked)",
        context_type="SVG_TEXT",
        template='<svg><text>{INPUT}</text></svg>',
        blocked_keywords=["script", "onerror"],
        description="Use <animate> onbegin, <set> attributeName, <use> href.",
        difficulty="hard",
    ),
    ChallengeTarget(
        name="O-15: Double Keyword Filter (recursive strip)",
        context_type="HTML_TEXT",
        template='<div>{INPUT}</div>',
        blocked_keywords=["script", "onerror", "onload", "svg", "img", "iframe"],
        description="Use <body>, <details ontoggle>, <video>, <marquee>, math namespace.",
        difficulty="hard",
    ),
    ChallengeTarget(
        name="O-16: Angle Brackets + Quotes + Parens Blocked",
        context_type="ATTR_QUOTED",
        template='<input value="{INPUT}">',
        blocked_chars={"<", ">", "(", ")", "'"},
        description="Event handler injection with backtick/template call.",
        difficulty="hard",
    ),
    ChallengeTarget(
        name="O-17: Extreme Char Restriction (only alphanums + = + space)",
        context_type="ATTR_QUOTED",
        template='<input value="{INPUT}">',
        blocked_chars={"<", ">", "(", ")", "'", "`", "/", "\\", ";", ":", "{", "}", "[", "]", "!", "@", "#", "$", "%", "^", "&", "*", "~"},
        description="Very constrained charset — event handler with entity-encoded values.",
        difficulty="hard",
    ),

    # --- Hard: Length-restricted ---
    ChallengeTarget(
        name="O-18: Length-Restricted (max 50 chars)",
        context_type="HTML_TEXT",
        template='<div>{INPUT}</div>',
        max_length=50,
        description="Must craft a short but executable payload under 50 characters.",
        difficulty="hard",
    ),
    ChallengeTarget(
        name="O-19: Length-Restricted (max 30 chars)",
        context_type="HTML_TEXT",
        template='<div>{INPUT}</div>',
        max_length=30,
        description="Ultra-short payload constraint.",
        difficulty="hard",
    ),

    # --- Boss: Multi-layer defenses ---
    ChallengeTarget(
        name="O-20: WAF + Keyword + Char Filter",
        context_type="HTML_TEXT",
        template='<div>{INPUT}</div>',
        blocked_chars={"'", '"', "`"},
        blocked_keywords=["script", "alert", "onerror", "onload", "javascript", "eval", "svg", "iframe"],
        description="Heavy multi-layer filtering — must use exotic tags/events.",
        difficulty="boss",
    ),
    ChallengeTarget(
        name="O-21: MathML Namespace mXSS Breakout",
        context_type="MATHML_TEXT",
        template='<math><mtext>{INPUT}</mtext></math>',
        blocked_keywords=["script", "onerror"],
        description="mXSS via annotation-xml encoding=\"text/html\" namespace switch.",
        difficulty="boss",
    ),
    ChallengeTarget(
        name="O-22: Stored XSS with Input Length + Keyword Filter",
        context_type="HTML_TEXT",
        template='<div class="comment">{INPUT}</div>',
        blocked_keywords=["script", "onerror", "alert", "eval", "iframe"],
        max_length=80,
        description="Simulated stored XSS with combined length and keyword constraints.",
        difficulty="boss",
    ),
    ChallengeTarget(
        name="O-23: CSTI Angular Expression Injection",
        context_type="CSTI_ANGULAR",
        template='<div ng-app>{{{{INPUT}}}}</div>',
        blocked_keywords=["alert", "eval", "window"],
        description="Angular template injection — use constructor.constructor chains.",
        difficulty="boss",
    ),
    ChallengeTarget(
        name="O-24: CSS url() Injection (quotes + parens partially blocked)",
        context_type="CSS_STYLE_BLOCK",
        template='<style>.user {{ background: url({INPUT}); }}</style>',
        blocked_chars={"'", '"'},
        blocked_keywords=["javascript", "expression"],
        description="Break out of CSS url() then close </style> for tag injection.",
        difficulty="boss",
    ),
    ChallengeTarget(
        name="O-25: Triple-Layer: Case-Sensitive Keyword + Char + Length",
        context_type="HTML_TEXT",
        template='<div>{INPUT}</div>',
        blocked_chars={"'", '"', "`", "(", ")"},
        blocked_keywords=["script", "alert", "svg", "iframe", "onerror", "onload", "eval"],
        case_sensitive=True,
        max_length=100,
        description="Case-sensitive filters open uppercase bypass (e.g. <SCRIPT>, <SVG>).",
        difficulty="boss",
    ),
]
