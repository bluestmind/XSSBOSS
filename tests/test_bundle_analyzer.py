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


def test_bundle_uses_script_url_as_passive_library_evidence():
    secret = "private-query-value"
    res = BundleAnalyzer.analyze_script_content(
        f"https://cdn.example.test/jquery-3.4.1.min.js?token={secret}",
        "",
        analyze_sourcemaps=False,
    )

    assert {item["ref"] for item in res["vulnerable_libraries"]} == {"CVE-2020-11022"}
    assert {item["source"] for item in res["vulnerable_libraries"]} == {"script_url"}
    assert res["url"] == "https://cdn.example.test/jquery-3.4.1.min.js"
    assert secret not in str(res)


def test_bundle_forwards_response_headers_to_sourcemap_analysis(monkeypatch):
    observed = {}

    def fake_analyze(_self, script_url, script_content=None, response_headers=None):
        observed.update(
            script_url=script_url,
            script_content=script_content,
            response_headers=response_headers,
        )
        return []

    monkeypatch.setattr(
        "recon_engine.bundle_analyzer.SourceMapAnalyzer.analyze_script_for_sourcemap",
        fake_analyze,
    )
    headers = {"SourceMap": "maps/app.js.map"}
    BundleAnalyzer.analyze_script_content(
        "https://target.test/assets/app.js",
        "console.log('ok')",
        response_headers=headers,
    )

    assert observed == {
        "script_url": "https://target.test/assets/app.js",
        "script_content": "console.log('ok')",
        "response_headers": headers,
    }


def test_bundle_analysis_has_a_hard_input_boundary(monkeypatch):
    monkeypatch.setattr(BundleAnalyzer, "MAX_SCRIPT_CHARS", 80)
    outside = 'target.postMessage("ready", "*");'
    content = ("const safe = 1;" + (" " * 100) + outside)

    result = BundleAnalyzer.analyze_script_content(
        "https://target.test/app.js",
        content,
        analyze_sourcemaps=False,
    )

    assert result["size_bytes"] == len(content)
    assert result["analyzed_chars"] == 80
    assert result["analysis_truncated"] is True
    assert result["client_trust_findings"] == []
