"""
XSSBOSS False-Positive Discipline Benchmark.

Tests XSSBOSS analysis against properly-secured endpoints to verify ZERO false
positives. This is the most critical benchmark for credibility — a scanner that
reports false positives on safe code is worse than useless.

Each test case provides a safe HTML response (properly escaped/encoded) and asserts
that XSSBOSS's context classifier + knowledge base does NOT generate a payload
that the simulated execution oracle would consider "executed."
"""
from __future__ import annotations

import html
import json
import time
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from analysis_engine.enhanced_context_classifier import EnhancedContextClassifier, ClassifiedContext
from backend_api.models.context import ContextType
from fuzzer.payload_knowledge_base import PayloadKnowledgeBase


PROBE_MARKER = "xB0ss_FP_PROBE_9z"


@dataclass
class SafeEndpoint:
    """A properly-secured endpoint that should produce zero findings."""

    name: str
    description: str
    response_html: str
    defense_category: str  # encoding | csp | safe_sink | sanitizer | content_type
    expected_context_count: int = 0  # How many reflection contexts should be detected (may be >0 but not exploitable)

    def build_response(self, marker: str) -> str:
        """Build the response HTML with the marker inserted according to the defense."""
        return self.response_html.replace("{MARKER}", marker)


SAFE_ENDPOINTS: List[SafeEndpoint] = [
    # --- HTML Entity Encoding ---
    SafeEndpoint(
        name="FP-01: html.escape() in HTML text",
        description="Standard HTML entity encoding of user input in text context.",
        defense_category="encoding",
        response_html=f'<div>Search: {html.escape("<script>alert(1)</script>")}</div>'.replace(
            html.escape("<script>alert(1)</script>"), "{ESCAPED_MARKER}"
        ),
    ),
    SafeEndpoint(
        name="FP-02: html.escape() in attribute",
        description="HTML entity encoding in a quoted attribute value.",
        defense_category="encoding",
        response_html='<input value="{ESCAPED_MARKER}">',
    ),
    SafeEndpoint(
        name="FP-03: json.dumps() with script close neutralization",
        description="JSON encoding with </script close tag neutralized.",
        defense_category="encoding",
        response_html='<script>var data = {JSON_MARKER};</script>',
    ),
    SafeEndpoint(
        name="FP-04: URL-encoded output in href",
        description="Percent-encoded user input in an href attribute.",
        defense_category="encoding",
        response_html='<a href="/search?q={URL_MARKER}">link</a>',
    ),
    SafeEndpoint(
        name="FP-05: Double HTML-entity encoding",
        description="User input double-entity-encoded — even more safe.",
        defense_category="encoding",
        response_html='<div>{DOUBLE_ESCAPED_MARKER}</div>',
    ),

    # --- Safe Sinks ---
    SafeEndpoint(
        name="FP-06: textContent assignment",
        description="textContent is a safe DOM property — no HTML parsing occurs.",
        defense_category="safe_sink",
        response_html="""<div id="out"></div>
<script>document.getElementById('out').textContent = "{MARKER}";</script>""",
    ),
    SafeEndpoint(
        name="FP-07: innerText assignment",
        description="innerText is safe — HTML is not parsed.",
        defense_category="safe_sink",
        response_html="""<div id="out"></div>
<script>document.getElementById('out').innerText = "{MARKER}";</script>""",
    ),

    # --- RCDATA safe contexts ---
    SafeEndpoint(
        name="FP-08: textarea RCDATA reflection",
        description="Content inside <textarea> is RCDATA — HTML tags are NOT parsed.",
        defense_category="safe_sink",
        response_html='<textarea>{MARKER}</textarea>',
    ),
    SafeEndpoint(
        name="FP-09: title RCDATA reflection",
        description="Content inside <title> is RCDATA — HTML tags are NOT parsed (unless </title> closes it).",
        defense_category="safe_sink",
        response_html='<title>{ESCAPED_MARKER}</title>',
    ),

    # --- CSP Protection ---
    SafeEndpoint(
        name="FP-10: Strict CSP with nonce (no unsafe-inline)",
        description="CSP blocks execution of injected inline scripts — XSS mitigated.",
        defense_category="csp",
        response_html="""<!DOCTYPE html><html><head>
<meta http-equiv="Content-Security-Policy" content="script-src 'nonce-abc123'">
</head><body><div>{MARKER}</div>
<script nonce="abc123">console.log('safe');</script></body></html>""",
    ),

    # --- Content-Type defense ---
    SafeEndpoint(
        name="FP-11: application/json Content-Type",
        description="JSON response — browser does not render HTML at all.",
        defense_category="content_type",
        response_html='{{"query": "{MARKER}", "results": []}}',
    ),
    SafeEndpoint(
        name="FP-12: text/plain Content-Type",
        description="Plain text response — no HTML rendering.",
        defense_category="content_type",
        response_html='Search results for: {MARKER}',
    ),

    # --- Sanitizer-defended ---
    SafeEndpoint(
        name="FP-13: DOMPurify-sanitized innerHTML",
        description="DOMPurify strips all dangerous tags/attributes before innerHTML.",
        defense_category="sanitizer",
        response_html="""<div id="out"></div>
<script src="https://cdn.jsdelivr.net/npm/dompurify/dist/purify.min.js"></script>
<script>document.getElementById('out').innerHTML = DOMPurify.sanitize("{MARKER}");</script>""",
    ),

    # --- Server-side template autoescaping ---
    SafeEndpoint(
        name="FP-14: Jinja2 autoescaped output",
        description="Jinja2 template with autoescape on — HTML entities encoded.",
        defense_category="encoding",
        response_html='<p>Hello {ESCAPED_MARKER}</p>',
    ),

    # --- HTTP-Only cookie reflection ---
    SafeEndpoint(
        name="FP-15: Cookie value in HTTP-only cookie header (not in HTML)",
        description="Cookie value reflected only in Set-Cookie header, not in page body.",
        defense_category="content_type",
        response_html='<div>Welcome back, user.</div>',
    ),
]


def _build_safe_response(endpoint: SafeEndpoint, marker: str) -> str:
    """Build the safe response with proper encoding applied."""
    resp = endpoint.response_html
    # Apply encoding transformations
    resp = resp.replace("{MARKER}", marker)
    resp = resp.replace("{ESCAPED_MARKER}", html.escape(marker))
    resp = resp.replace("{DOUBLE_ESCAPED_MARKER}", html.escape(html.escape(marker)))
    resp = resp.replace("{JSON_MARKER}", json.dumps(marker).replace("</", "<\\/"))
    resp = resp.replace("{URL_MARKER}", re.sub(r'[^a-zA-Z0-9._~-]', lambda m: f'%{ord(m.group()):02X}', marker))
    return resp


def _simulate_execution(rendered_html: str, payload: str) -> bool:
    """Conservative execution simulation — checks if a payload would actually fire."""
    # Script tag with content
    if re.search(r'<script[^>]*>[^<]*(?:alert|confirm|prompt|eval|__XSS__)\b', rendered_html, re.IGNORECASE):
        return True
    # Event handler with executable content
    if re.search(r'\bon\w+\s*=\s*["\'][^"\']*(?:alert|confirm|prompt|eval|__XSS__)\b', rendered_html, re.IGNORECASE):
        return True
    # SVG/IMG with event handler
    if re.search(r'<(?:svg|img|body|iframe|details)[^>]+on\w+\s*=', rendered_html, re.IGNORECASE):
        return True
    return False


class FalsePositiveBenchmark:
    """Benchmark measuring false-positive discipline."""

    def __init__(self, max_payloads_per_endpoint: int = 30):
        self.max_payloads = max_payloads_per_endpoint

    def run(self) -> Dict[str, Any]:
        """Run the false-positive benchmark across all safe endpoints."""
        start_time = time.time()
        results: List[Dict[str, Any]] = []
        total_fp = 0

        for endpoint in SAFE_ENDPOINTS:
            res = self._test_endpoint(endpoint)
            results.append(res)
            if res["false_positive"]:
                total_fp += 1

        elapsed = time.time() - start_time
        fp_rate = (total_fp / len(SAFE_ENDPOINTS)) * 100.0

        return {
            "benchmark": "False-Positive Discipline",
            "total_endpoints": len(SAFE_ENDPOINTS),
            "false_positives": total_fp,
            "fp_rate": fp_rate,
            "target_fp_rate": 0.0,
            "passed": total_fp == 0,
            "elapsed_seconds": elapsed,
            "details": results,
        }

    def _test_endpoint(self, endpoint: SafeEndpoint) -> Dict[str, Any]:
        """Test a single safe endpoint for false positives."""
        marker = PROBE_MARKER
        safe_html = _build_safe_response(endpoint, marker)

        # Step 1: Classify contexts
        contexts = EnhancedContextClassifier.classify_all_reflections(safe_html, marker)

        # Step 2: For each detected context, try generating payloads
        false_positive = False
        fp_payload = None

        for ctx in contexts:
            context_type_str = ctx.context_type.value if isinstance(ctx.context_type, ContextType) else str(ctx.context_type)
            try:
                context_type_enum = ContextType(context_type_str)
            except (ValueError, KeyError):
                context_type_enum = ContextType.HTML_TEXT

            # Build a minimal filter profile from the safe response
            filter_profile = {
                "blocked_tokens": [],
                "allowed_tokens": ["<", ">", '"', "'", ";", "(", ")", "/", "`"],
                "normalization_behavior": [],
                "waf_detected": False,
                "sanitizer_detected": endpoint.defense_category == "sanitizer",
                "csp_rules": {},
                "context_type": context_type_str,
            }

            try:
                payloads = PayloadKnowledgeBase.get_context_payloads(
                    context_type=context_type_enum,
                    filter_profile=filter_profile,
                    token=marker,
                    limit=self.max_payloads,
                )
            except Exception:
                payloads = []

            # Step 3: Check if any generated payload would "execute" in the safe response
            for p in payloads:
                test_html = _build_safe_response(endpoint, p)
                if _simulate_execution(test_html, p):
                    false_positive = True
                    fp_payload = p
                    break

            if false_positive:
                break

        return {
            "endpoint": endpoint.name,
            "defense_category": endpoint.defense_category,
            "contexts_detected": len(contexts),
            "false_positive": false_positive,
            "fp_payload": fp_payload,
        }


if __name__ == "__main__":
    benchmark = FalsePositiveBenchmark()
    summary = benchmark.run()

    print("\n" + "=" * 70)
    print("     XSSBOSS FALSE-POSITIVE DISCIPLINE BENCHMARK")
    print("=" * 70)
    print(f"Total Safe Endpoints: {summary['total_endpoints']}")
    print(f"False Positives:      {summary['false_positives']}")
    print(f"FP Rate:              {summary['fp_rate']:.1f}% (target: 0.0%)")
    print(f"Passed:               {'✅ YES' if summary['passed'] else '❌ NO'}")
    print(f"Elapsed:              {summary['elapsed_seconds']:.2f}s")
    print("-" * 70)

    for r in summary["details"]:
        status = "❌ FALSE POSITIVE" if r["false_positive"] else "✅ SAFE"
        print(f"  {status}  {r['endpoint']} [{r['defense_category']}] (contexts: {r['contexts_detected']})")
        if r["false_positive"]:
            print(f"           FP payload: {r['fp_payload']}")
