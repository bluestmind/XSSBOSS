"""
DOM-based XSS challenge definitions for benchmarking.

These simulate client-side sinks (innerHTML, document.write, eval, location),
sources (URL params, postMessage, hash fragments), and defense scenarios
(Trusted Types, DOMPurify, CSP). Used for context classifier and fuzzer benchmarks.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class DOMChallenge:
    """A DOM-based XSS challenge with a source-to-sink data flow."""

    name: str
    source: str           # url_param | hash | postmessage | cookie | referrer | storage
    sink: str             # innerHTML | document_write | eval | location | outerHTML | insertAdjacentHTML
    template_html: str    # Full HTML page with {INPUT} marker
    defenses: List[str] = field(default_factory=list)  # dompurify | trusted_types | csp_nonce | sanitize_api
    expected_vulnerable: bool = True
    description: str = ""
    difficulty: str = "medium"

    def get_labeled_context(self) -> str:
        """Return the expected ContextType for this challenge."""
        sink_context_map = {
            "innerHTML": "HTML_TEXT",
            "outerHTML": "HTML_TEXT",
            "insertAdjacentHTML": "HTML_TEXT",
            "document_write": "HTML_TEXT",
            "eval": "JS_STRING_LITERAL",
            "location": "URL_QUERY",
            "location_hash": "URL_FRAGMENT",
        }
        return sink_context_map.get(self.sink, "HTML_TEXT")


DOM_CHALLENGES: List[DOMChallenge] = [
    # --- Vulnerable sinks (no defense) ---
    DOMChallenge(
        name="DOM-01: innerHTML via URL param",
        source="url_param",
        sink="innerHTML",
        template_html="""<!DOCTYPE html><html><body>
<div id="sink">Loading...</div>
<script>
var q = new URLSearchParams(location.search).get('q') || '';
document.getElementById('sink').innerHTML = q;
</script></body></html>""",
        description="Classic DOM XSS: URL param flows to innerHTML with no sanitization.",
        difficulty="easy",
    ),
    DOMChallenge(
        name="DOM-02: document.write via URL param",
        source="url_param",
        sink="document_write",
        template_html="""<!DOCTYPE html><html><body>
<script>
var q = new URLSearchParams(location.search).get('q') || '';
document.write('<div>' + q + '</div>');
</script></body></html>""",
        description="document.write with unsanitized URL parameter.",
        difficulty="easy",
    ),
    DOMChallenge(
        name="DOM-03: eval via hash fragment",
        source="hash",
        sink="eval",
        template_html="""<!DOCTYPE html><html><body>
<div id="result"></div>
<script>
var data = decodeURIComponent(location.hash.slice(1));
try { eval(data); } catch(e) {}
</script></body></html>""",
        description="Hash fragment directly passed to eval().",
        difficulty="easy",
    ),
    DOMChallenge(
        name="DOM-04: location.href via URL param",
        source="url_param",
        sink="location",
        template_html="""<!DOCTYPE html><html><body>
<script>
var next = new URLSearchParams(location.search).get('next') || '/';
if (next) location.href = next;
</script></body></html>""",
        description="Open redirect / javascript: URI via location.href.",
        difficulty="medium",
    ),
    DOMChallenge(
        name="DOM-05: innerHTML via postMessage (no origin check)",
        source="postmessage",
        sink="innerHTML",
        template_html="""<!DOCTYPE html><html><body>
<div id="sink">Waiting...</div>
<script>
window.addEventListener('message', function(e) {
    document.getElementById('sink').innerHTML = e.data;
});
</script></body></html>""",
        description="postMessage to innerHTML with no origin validation.",
        difficulty="medium",
    ),
    DOMChallenge(
        name="DOM-06: Delayed innerHTML via setTimeout",
        source="url_param",
        sink="innerHTML",
        template_html="""<!DOCTYPE html><html><body>
<div id="sink">Loading...</div>
<script>
setTimeout(function() {
    var q = new URLSearchParams(location.search).get('q') || '';
    document.getElementById('sink').innerHTML = q;
}, 100);
</script></body></html>""",
        description="Delayed DOM sink requiring headless browser wait.",
        difficulty="medium",
    ),
    DOMChallenge(
        name="DOM-07: insertAdjacentHTML via URL param",
        source="url_param",
        sink="insertAdjacentHTML",
        template_html="""<!DOCTYPE html><html><body>
<div id="sink">Content</div>
<script>
var q = new URLSearchParams(location.search).get('q') || '';
document.getElementById('sink').insertAdjacentHTML('beforeend', q);
</script></body></html>""",
        description="insertAdjacentHTML sink.",
        difficulty="medium",
    ),
    DOMChallenge(
        name="DOM-08: outerHTML replacement",
        source="url_param",
        sink="outerHTML",
        template_html="""<!DOCTYPE html><html><body>
<div id="sink">Replace me</div>
<script>
var q = new URLSearchParams(location.search).get('q') || '';
if (q) document.getElementById('sink').outerHTML = q;
</script></body></html>""",
        description="outerHTML replacement with URL param.",
        difficulty="medium",
    ),

    # --- Defended (should NOT be vulnerable — used for FP testing) ---
    DOMChallenge(
        name="DOM-09: innerHTML with DOMPurify",
        source="url_param",
        sink="innerHTML",
        template_html="""<!DOCTYPE html><html><head>
<script src="https://cdn.jsdelivr.net/npm/dompurify/dist/purify.min.js"></script>
</head><body>
<div id="sink">Loading...</div>
<script>
var q = new URLSearchParams(location.search).get('q') || '';
document.getElementById('sink').innerHTML = DOMPurify.sanitize(q);
</script></body></html>""",
        defenses=["dompurify"],
        expected_vulnerable=False,
        description="DOMPurify-sanitized innerHTML — should be safe.",
        difficulty="medium",
    ),
    DOMChallenge(
        name="DOM-10: textContent assignment (safe sink)",
        source="url_param",
        sink="innerHTML",  # labeled as innerHTML but actually textContent
        template_html="""<!DOCTYPE html><html><body>
<div id="sink">Loading...</div>
<script>
var q = new URLSearchParams(location.search).get('q') || '';
document.getElementById('sink').textContent = q;
</script></body></html>""",
        defenses=["safe_sink"],
        expected_vulnerable=False,
        description="textContent is a safe sink — no XSS possible.",
        difficulty="easy",
    ),
    DOMChallenge(
        name="DOM-11: CSP nonce-based script restriction",
        source="url_param",
        sink="innerHTML",
        template_html="""<!DOCTYPE html><html><head>
<meta http-equiv="Content-Security-Policy" content="script-src 'nonce-abc123'">
</head><body>
<div id="sink">Loading...</div>
<script nonce="abc123">
var q = new URLSearchParams(location.search).get('q') || '';
document.getElementById('sink').innerHTML = q;
</script></body></html>""",
        defenses=["csp_nonce"],
        expected_vulnerable=False,
        description="CSP with script-src nonce blocks inline script execution.",
        difficulty="hard",
    ),
    DOMChallenge(
        name="DOM-12: Trusted Types enforcement",
        source="url_param",
        sink="innerHTML",
        template_html="""<!DOCTYPE html><html><head>
<meta http-equiv="Content-Security-Policy" content="require-trusted-types-for 'script'; trusted-types default">
</head><body>
<div id="sink">Loading...</div>
<script>
var policy = trustedTypes.createPolicy('default', {createHTML: s => s.replace(/</g, '&lt;')});
var q = new URLSearchParams(location.search).get('q') || '';
document.getElementById('sink').innerHTML = policy.createHTML(q);
</script></body></html>""",
        defenses=["trusted_types"],
        expected_vulnerable=False,
        description="Trusted Types with escaping policy — should be safe.",
        difficulty="hard",
    ),
]
