"""Tests for modern client bundle and SPA analyzer."""
import pytest
from recon_engine.bundle_analyzer import BundleAnalyzer

def test_extract_script_urls():
    html = """
    <html>
        <head>
            <script src="/_next/static/chunks/main-app.js"></script>
            <script src="https://cdn.example.com/vendor.js"></script>
            <script src="/_next/static/chunks/app/page.js?v=123"></script>
        </head>
    </html>
    """
    urls = BundleAnalyzer.extract_script_urls(html, "https://target.com/home")
    assert len(urls) == 3
    assert "https://target.com/_next/static/chunks/main-app.js" in urls
    assert "https://cdn.example.com/vendor.js" in urls
    assert "https://target.com/_next/static/chunks/app/page.js?v=123" in urls

def test_analyze_script_content_dom_sinks():
    sample_js = """
    function render(data) {
        const route = location.hash;
        document.getElementById("output").innerHTML = data.content;
        window.location.href = data.redirectUrl;
        eval(data.rawJs);
        window.addEventListener("message", function(e) { process(e.data); });
    }
    const endpoint = "/api/v1/user/profile";
    const internalGw = "/n-api/search";
    """
    res = BundleAnalyzer.analyze_script_content("https://cdn.com/chunk.js", sample_js)
    assert res["file_name"] == "chunk.js"
    assert len(res["dom_sources"]) >= 1
    assert len(res["dom_sinks"]) >= 1
    assert len(res["navigation_sinks"]) >= 1
    assert len(res["eval_sinks"]) >= 1
    assert len(res["postmessage_listeners"]) >= 1
    assert "/api/v1/user/profile" in res["internal_api_endpoints"]
    assert "/n-api/search" in res["internal_api_endpoints"]


def test_sensitive_bundle_values_are_fingerprinted_not_returned():
    secret = "super-secret-client-token-12345"
    res = BundleAnalyzer.analyze_script_content(
        "https://target.test/app.js", f'const api_key = "{secret}";'
    )
    finding = res["sensitive_tokens"][0]
    assert finding["length"] == len(secret)
    assert len(finding["fingerprint"]) == 64
    assert secret not in str(finding)
