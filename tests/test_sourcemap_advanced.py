"""Focused tests for bounded, passive source-map recovery."""
from __future__ import annotations

import base64
import json
import urllib.parse
from unittest.mock import patch

from recon_engine.sourcemap_analyzer import (
    SourceMapAnalyzer,
    parse_sourcemap_headers,
    resolve_sourcemap_reference,
    sourcemap_url_from_headers,
)


def _map_with_source(path: str = "src/app.ts", content: str = "fetch('/api/v1/users/list')") -> dict:
    return {
        "version": 3,
        "sources": [path],
        "sourcesContent": [content],
        "mappings": "",
    }


def _base64_data_url(map_data: dict) -> str:
    encoded = base64.b64encode(json.dumps(map_data).encode()).decode()
    return f"data:application/json;charset=utf-8;base64,{encoded}"


def test_inline_base64_map_is_analyzed_without_network():
    analyzer = SourceMapAnalyzer()
    directive = _base64_data_url(_map_with_source())

    with patch.object(analyzer, "_fetch_text", side_effect=AssertionError("network not expected")):
        findings = analyzer.analyze_script_for_sourcemap(
            "https://target.test/assets/app.js",
            f"console.log('app');\n//# sourceMappingURL={directive}",
        )

    assert len(findings) == 1
    assert findings[0].discovered_endpoints == ["/api/v1/users/list"]


def test_inline_percent_encoded_map_and_block_directive():
    analyzer = SourceMapAnalyzer()
    raw = json.dumps(_map_with_source(content="params.get('returnTo'); // SECURITY validate redirect"))
    directive = "data:application/json;charset=utf-8," + urllib.parse.quote(raw, safe="")

    findings = analyzer.analyze_script_for_sourcemap(
        "https://target.test/static/main.js",
        f"/*# sourceMappingURL={directive} */",
    )

    assert len(findings) == 1
    assert findings[0].discovered_parameters == ["returnTo"]
    assert findings[0].developer_comments == ["// SECURITY validate redirect"]


def test_source_root_resolves_against_map_url():
    analyzer = SourceMapAnalyzer()
    source_map = _map_with_source("components/search.ts", "searchParams.get('query')")
    source_map["sourceRoot"] = "../src"

    findings = analyzer.parse_sourcemap_data(
        source_map,
        map_url="https://target.test/static/maps/app.js.map",
    )

    assert findings[0].original_file_path == "https://target.test/static/src/components/search.ts"
    assert findings[0].discovered_parameters == ["query"]


def test_absolute_source_root_resolves_without_map_url():
    analyzer = SourceMapAnalyzer()
    source_map = _map_with_source("components/search.ts", "searchParams.get('query')")
    source_map["sourceRoot"] = "https://sources.target.test/src"

    findings = analyzer.parse_sourcemap_data(source_map)

    assert findings[0].original_file_path == "https://sources.target.test/src/components/search.ts"


def test_indexed_sections_feed_existing_discovery_and_inline_section_urls():
    analyzer = SourceMapAnalyzer()
    indexed_map = {
        "version": 3,
        "sections": [
            {"offset": {"line": 0, "column": 0}, "map": _map_with_source("a.ts", "fetch('/api/v1/a/run')")},
            {
                "offset": {"line": 100, "column": 0},
                "url": _base64_data_url(_map_with_source("b.ts", "router.query.next; innerHTML = value")),
            },
        ],
    }

    findings = analyzer.parse_sourcemap_data(
        indexed_map,
        map_url="https://target.test/assets/app.js.map",
    )

    assert [finding.original_file_path for finding in findings] == [
        "https://target.test/assets/a.ts",
        "b.ts",
    ]
    assert findings[0].discovered_endpoints == ["/api/v1/a/run"]
    assert findings[1].discovered_parameters == ["next"]
    assert findings[1].dom_sinks[0]["sink"] == "innerHTML"


def test_response_header_parser_is_case_insensitive_pure_and_standard_header_wins():
    headers = {
        "x-sourcemap": "legacy.js.map",
        "SoUrCeMaP": '"maps/app.js.map"',
    }

    expected = "https://target.test/assets/maps/app.js.map"
    assert sourcemap_url_from_headers("https://target.test/assets/app.js", headers) == expected
    assert parse_sourcemap_headers("https://target.test/assets/app.js", headers) == expected
    assert SourceMapAnalyzer.sourcemap_url_from_headers("https://target.test/assets/app.js", headers) == expected
    assert resolve_sourcemap_reference("https://target.test/app.js", "bad\r\nvalue") is None


def test_analyzer_uses_source_map_response_header():
    analyzer = SourceMapAnalyzer()
    map_text = json.dumps(_map_with_source(content="document.write = input"))

    with patch.object(analyzer, "_fetch_text", return_value=map_text) as fetch:
        findings = analyzer.analyze_script_for_sourcemap(
            "https://target.test/assets/app.js",
            "console.log('no directive')",
            {"X-SourceMap": "../maps/app.js.map"},
        )

    fetch.assert_called_once_with("https://target.test/maps/app.js.map")
    assert findings[0].dom_sinks[0]["sink"] == "document.write"


def test_cross_origin_map_reference_is_not_fetched():
    analyzer = SourceMapAnalyzer()

    with patch.object(analyzer, "_fetch_text") as fetch:
        findings = analyzer.analyze_script_for_sourcemap(
            "https://target.test/assets/app.js",
            "console.log('no directive')",
            {"SourceMap": "https://outside.test/app.js.map"},
        )

    fetch.assert_not_called()
    assert findings == []


def test_same_origin_default_port_reference_remains_supported():
    analyzer = SourceMapAnalyzer()
    map_text = json.dumps(_map_with_source(content="params.get('next')"))

    with patch.object(analyzer, "_fetch_text", return_value=map_text) as fetch:
        findings = analyzer.analyze_script_for_sourcemap(
            "https://target.test/assets/app.js",
            response_headers={"SourceMap": "https://target.test:443/maps/app.js.map"},
        )

    fetch.assert_called_once_with("https://target.test:443/maps/app.js.map")
    assert findings[0].discovered_parameters == ["next"]


def test_source_count_and_byte_budgets_bound_reconstruction(monkeypatch):
    analyzer = SourceMapAnalyzer()
    monkeypatch.setattr(analyzer, "MAX_SOURCES", 1)
    monkeypatch.setattr(analyzer, "MAX_SOURCE_BYTES", 45)
    source_map = {
        "version": 3,
        "sources": ["one.ts", "two.ts"],
        "sourcesContent": [
            "fetch('/api/v1/first/path');" + ("x" * 200),
            "fetch('/api/v1/second/path')",
        ],
    }

    findings = analyzer.parse_sourcemap_data(source_map)

    assert len(findings) == 1
    assert findings[0].original_file_path == "one.ts"
    assert findings[0].discovered_endpoints == ["/api/v1/first/path"]


def test_oversized_inline_map_is_rejected_before_json_parsing(monkeypatch):
    analyzer = SourceMapAnalyzer()
    monkeypatch.setattr(analyzer, "MAX_MAP_BYTES", 32)
    source_map_url = _base64_data_url(_map_with_source(content="x" * 100))

    with patch.object(analyzer, "_fetch_text", side_effect=AssertionError("network not expected")):
        findings = analyzer.analyze_script_for_sourcemap(
            "https://target.test/app.js",
            f"//# sourceMappingURL={source_map_url}",
        )

    assert findings == []


def test_external_map_fetch_streams_and_stops_at_byte_budget(monkeypatch):
    analyzer = SourceMapAnalyzer()
    monkeypatch.setattr(analyzer, "MAX_MAP_BYTES", 5)

    class Response:
        status_code = 200
        headers = {}
        encoding = "utf-8"

        def iter_bytes(self):
            yield b"1234"
            yield b"56"

    class Stream:
        def __enter__(self):
            return Response()

        def __exit__(self, *_args):
            return False

    with patch("recon_engine.sourcemap_analyzer.httpx.stream", return_value=Stream()) as request:
        result = analyzer._fetch_text("https://target.test/app.js.map")

    assert result is None
    assert request.call_args.kwargs["follow_redirects"] is False
