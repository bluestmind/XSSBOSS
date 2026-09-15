"""Focused integration tests for crawler-to-research client bundle signals."""
from __future__ import annotations

import json
import urllib.parse

from recon_engine.crawler import Crawler


_BOUNDARY_CATEGORIES = (
    "sanitizer_context_mismatch",
    "sanitizer_output_invalidated",
    "sanitizer_partial_coverage",
    "opaque_sanitizer_flow",
    "trusted_types_unvalidated_flow",
    "effective_sanitizer_boundary",
)


class _BundleDriver:
    current_url = "https://target.test/dashboard"
    page_source = '<html><div id="applicationConfig"></div></html>'

    def __init__(self, script: str, source_map_header: str):
        self.script = script
        self.source_map_header = source_map_header
        self.calls = []

    def execute_async_script(self, code, *args):
        self.calls.append((code, args))
        return {
            "success": True,
            "status": 200,
            "content": self.script,
            "oversized": False,
            "response_headers": {"SourceMap": self.source_map_header},
        }


def _inline_map_header() -> str:
    source_map = {
        "version": 3,
        "sources": ["src/routes.ts"],
        "sourcesContent": ["fetch('/api/v1/from-source-map')"],
        "mappings": "",
    }
    return "data:application/json," + urllib.parse.quote(
        json.dumps(source_map), safe=""
    )


def test_crawler_exports_advanced_bounded_bundle_evidence_without_url_secrets():
    script = """
    const config = window.applicationConfig;
    output.innerHTML = config;
    addEventListener("message", event => {
        const html = event.data.html;
        result.innerHTML = html;
    });
    target.postMessage("ready", "*");
    """
    secret = "browser-fetch-secret"
    script_url = f"https://target.test/assets/app.js?token={secret}"
    driver = _BundleDriver(script, _inline_map_header())
    crawler = Crawler("https://target.test")
    crawler.driver = driver
    saved_requests = []
    crawler._is_safe_url = lambda _url: True
    crawler._save_request = saved_requests.append

    crawler._analyze_script_bundle(script_url)

    assert len(driver.calls) == 1
    fetch_code, args = driver.calls[0]
    assert script_url not in fetch_code
    assert args == (script_url, 2_000_000)

    signal = crawler.research_signals[0]
    assert signal["script_url"] == "https://target.test/assets/app.js"
    assert secret not in str(signal)
    assert signal["counts"]["postmessage_unvalidated_sink"] == 1
    assert signal["counts"]["postmessage_wildcard_target"] == 1
    assert signal["counts"]["dom_clobbering_chain"] == 1
    assert signal["client_trust_findings"]
    assert signal["property_integrity_chains"]
    assert "/api/v1/from-source-map" in signal["discovered_endpoints"]
    assert any(item["url"].endswith("/api/v1/from-source-map") for item in saved_requests)


def test_crawler_skips_oversized_browser_bundle_before_analysis():
    class OversizedDriver(_BundleDriver):
        def execute_async_script(self, code, *args):
            self.calls.append((code, args))
            return {"success": False, "oversized": True, "status": 200}

    driver = OversizedDriver("", "")
    events = []
    crawler = Crawler("https://target.test", decision_callback=events.append)
    crawler.driver = driver

    crawler._analyze_script_bundle("https://target.test/huge.js")

    assert crawler.research_signals == []
    assert events[-1]["event_type"] == "crawler_bundle_skipped"
    assert events[-1]["reason"] == "bundle_size_limit_exceeded"


def test_crawler_exports_bounded_sanitizer_boundary_schema(monkeypatch):
    findings = [
        {
            "category": _BOUNDARY_CATEGORIES[index % len(_BOUNDARY_CATEGORIES)],
            "source_param": f"param-{index}",
        }
        for index in range(130)
    ]
    findings[0]["raw_snippet"] = "private-source-text"
    analysis = {
        "size_bytes": 12,
        "internal_api_endpoints": [],
        "discovered_parameters": [],
        "reachable_params": [],
        "sanitizer_boundary_findings": findings,
        "sanitizer_boundary_summary": {
            "sanitizer_context_mismatch": 130,
            "sanitizer_output_invalidated": -4,
            "sanitizer_partial_coverage": "17",
            "opaque_sanitizer_flow": "invalid",
            "trusted_types_unvalidated_flow": 2,
            "effective_sanitizer_boundary": 9,
        },
    }
    monkeypatch.setattr(
        "recon_engine.bundle_analyzer.BundleAnalyzer.analyze_script_content",
        lambda *_args, **_kwargs: analysis,
    )
    crawler = Crawler("https://target.test")
    crawler.driver = _BundleDriver("const x = 1", "")

    crawler._analyze_script_bundle("https://target.test/assets/boundaries.js")

    signal = crawler.research_signals[0]
    assert signal["kind"] == "client_bundle"
    assert len(signal["sanitizer_boundary_findings"]) == 100
    assert signal["counts"]["sanitizer_boundary_findings"] == 100
    assert signal["counts"]["sanitizer_context_mismatch"] == 100
    assert signal["counts"]["sanitizer_output_invalidated"] == 0
    assert signal["counts"]["sanitizer_partial_coverage"] == 17
    assert signal["counts"]["opaque_sanitizer_flow"] == 0
    assert signal["counts"]["trusted_types_unvalidated_flow"] == 2
    assert signal["counts"]["effective_sanitizer_boundary"] == 9
    assert signal["sanitizer_boundary_findings"][0] == {
        "category": findings[0]["category"],
        "source_param": findings[0]["source_param"],
    }
    assert "private-source-text" not in str(signal)
