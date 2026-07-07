"""
Simulated WAF rule-set profiles for benchmarking XSSBOSS bypass capabilities.

Each WAF profile is a callable filter that returns (blocked: bool, rule_id: str)
for a given payload. Profiles model real-world WAF signatures at varying strictness.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple


@dataclass
class WAFRule:
    """A single WAF detection rule."""
    rule_id: str
    description: str
    pattern: re.Pattern
    severity: str = "critical"  # critical | high | medium | low


@dataclass
class WAFProfile:
    """A complete WAF rule-set profile."""
    name: str
    description: str
    rules: List[WAFRule] = field(default_factory=list)
    blocked_chars: Set[str] = field(default_factory=set)
    max_payload_length: int | None = None

    def check(self, payload: str) -> Tuple[bool, Optional[str]]:
        """Check if payload is blocked. Returns (blocked, rule_id)."""
        if self.max_payload_length and len(payload) > self.max_payload_length:
            return True, "LENGTH_LIMIT"

        for char in self.blocked_chars:
            if char in payload:
                return True, f"BLOCKED_CHAR_{ord(char)}"

        for rule in self.rules:
            if rule.pattern.search(payload):
                return True, rule.rule_id

        return False, None


# ─────────────────────────────────────────────────────────────────────────────
# ModSecurity CRS v3.x — Rules 941100-941180 (XSS Attack Detection)
# ─────────────────────────────────────────────────────────────────────────────

MODSECURITY_CRS = WAFProfile(
    name="ModSecurity CRS v3.x",
    description="OWASP ModSecurity Core Rule Set — XSS detection rules 941100-941180",
    rules=[
        WAFRule("941100", "XSS via libinjection", re.compile(
            r"<\s*script\b[^>]*>", re.IGNORECASE)),
        WAFRule("941110", "XSS filter category 1: script tag vector", re.compile(
            r"<\s*/?script\b", re.IGNORECASE)),
        WAFRule("941120", "XSS filter category 2: event handler", re.compile(
            r"\bon(?:error|load|click|mouse\w+|focus|blur|submit|change|key\w+|touch\w+|pointer\w+|toggle)\s*=", re.IGNORECASE)),
        WAFRule("941130", "XSS filter category 3: attribute injection", re.compile(
            r"(?:style|xmlns|formaction|data-\w+)\s*=\s*['\"]?\s*(?:javascript|expression|vbscript)\s*:", re.IGNORECASE)),
        WAFRule("941140", "XSS filter category 4: javascript URI", re.compile(
            r"(?:href|src|action|formaction|data|poster|codebase|background)\s*=\s*['\"]?\s*javascript\s*:", re.IGNORECASE)),
        WAFRule("941150", "XSS filter category 5: dangerous tags", re.compile(
            r"<\s*(?:iframe|object|embed|applet|form|base|meta|link|import|svg\s+on)\b", re.IGNORECASE)),
        WAFRule("941160", "XSS via HTML injection", re.compile(
            r"<\s*(?:img|video|audio|source|marquee|body|details|math)\s+[^>]*on\w+\s*=", re.IGNORECASE)),
        WAFRule("941170", "XSS filter: eval/setTimeout/Function", re.compile(
            r"\b(?:eval|setTimeout|setInterval|Function|constructor)\s*[(`]", re.IGNORECASE)),
        WAFRule("941180", "XSS filter: document/window sinks", re.compile(
            r"\b(?:document\.(?:write|writeln|cookie|domain|location)|window\.(?:location|name|open)|\.innerHTML)\s*=", re.IGNORECASE)),
    ],
)


# ─────────────────────────────────────────────────────────────────────────────
# Cloudflare-like WAF
# ─────────────────────────────────────────────────────────────────────────────

CLOUDFLARE_LIKE = WAFProfile(
    name="Cloudflare-like WAF",
    description="Simulated Cloudflare managed WAF rules for XSS",
    rules=[
        WAFRule("CF-001", "Script tag detection", re.compile(
            r"<\s*/?script\b", re.IGNORECASE)),
        WAFRule("CF-002", "Event handler on HTML tags", re.compile(
            r"<[^>]+\s+on\w+\s*=", re.IGNORECASE)),
        WAFRule("CF-003", "javascript: URI scheme", re.compile(
            r"javascript\s*:", re.IGNORECASE)),
        WAFRule("CF-004", "data: URI with text/html", re.compile(
            r"data\s*:\s*text/html", re.IGNORECASE)),
        WAFRule("CF-005", "SVG onload/animate abuse", re.compile(
            r"<\s*(?:svg|animate|set)\s+[^>]*(?:on\w+|attributeName)\s*=", re.IGNORECASE)),
        WAFRule("CF-006", "Expression/eval in CSS", re.compile(
            r"(?:expression|behavior|import|@import|url\s*\()\s*['\"]?\s*(?:javascript|data|vbscript)\s*:", re.IGNORECASE)),
        WAFRule("CF-007", "Dangerous function calls", re.compile(
            r"\b(?:alert|confirm|prompt|eval|Function)\s*\(", re.IGNORECASE)),
        WAFRule("CF-008", "Template injection markers", re.compile(
            r"\{\{\s*constructor", re.IGNORECASE)),
    ],
)


# ─────────────────────────────────────────────────────────────────────────────
# AWS WAF — Managed XSS Rule Group
# ─────────────────────────────────────────────────────────────────────────────

AWS_WAF = WAFProfile(
    name="AWS WAF Managed XSS Rules",
    description="Simulated AWS WAF managed rule group for cross-site scripting",
    max_payload_length=8192,
    rules=[
        WAFRule("AWS-XSS-001", "Script tag injection", re.compile(
            r"<\s*script\b", re.IGNORECASE)),
        WAFRule("AWS-XSS-002", "Event handler attributes", re.compile(
            r"\bon(?:error|load|click|focus|blur|mouseover|mouseout|submit|toggle|begin|end|animationend)\s*=", re.IGNORECASE)),
        WAFRule("AWS-XSS-003", "Iframe/object injection", re.compile(
            r"<\s*(?:iframe|object|embed|applet)\b", re.IGNORECASE)),
        WAFRule("AWS-XSS-004", "javascript: and vbscript: URIs", re.compile(
            r"(?:javascript|vbscript|data)\s*:", re.IGNORECASE)),
        WAFRule("AWS-XSS-005", "Alert/eval/document.cookie", re.compile(
            r"\b(?:alert|eval|document\.cookie)\b", re.IGNORECASE)),
    ],
)


# ─────────────────────────────────────────────────────────────────────────────
# Custom Enterprise WAF — Strict allowlist + blocklist
# ─────────────────────────────────────────────────────────────────────────────

ENTERPRISE_STRICT = WAFProfile(
    name="Enterprise Strict WAF",
    description="Strict enterprise WAF with charset allowlist and extensive blocklist",
    max_payload_length=500,
    rules=[
        WAFRule("ENT-001", "HTML tag injection", re.compile(
            r"<\s*[a-zA-Z]", re.IGNORECASE)),
        WAFRule("ENT-002", "Event handler pattern", re.compile(
            r"on\w+\s*=", re.IGNORECASE)),
        WAFRule("ENT-003", "JavaScript URI", re.compile(
            r"javascript\s*:", re.IGNORECASE)),
        WAFRule("ENT-004", "Dangerous JS functions", re.compile(
            r"\b(?:alert|confirm|prompt|eval|Function|setTimeout|setInterval|constructor)\b", re.IGNORECASE)),
        WAFRule("ENT-005", "Script closing tag", re.compile(
            r"</\s*script", re.IGNORECASE)),
        WAFRule("ENT-006", "Backtick template literal", re.compile(
            r"`")),
        WAFRule("ENT-007", "Curly brace injection", re.compile(
            r"\{\{|\$\{")),
        WAFRule("ENT-008", "Entity encoding bypass attempt", re.compile(
            r"&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);", re.IGNORECASE)),
    ],
)


ALL_WAF_PROFILES: List[WAFProfile] = [
    MODSECURITY_CRS,
    CLOUDFLARE_LIKE,
    AWS_WAF,
    ENTERPRISE_STRICT,
]
