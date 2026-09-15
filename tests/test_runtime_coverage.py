"""V8 precise-coverage correlation stays bounded, source-free, and conservative."""
from __future__ import annotations

from analysis_engine.runtime_coverage import (
    RuntimeCoverageAnalyzer,
    RuntimeCoverageCollector,
    effective_executed_intervals,
    python_index_to_utf16,
    safe_runtime_script_url,
)


def _coverage_entry(script_id: str, url: str, source: str, count: int = 1) -> dict:
    return {
        "scriptId": script_id,
        "url": url,
        "functions": [{
            "functionName": "",
            "ranges": [{
                "startOffset": 0,
                "endOffset": python_index_to_utf16(source, len(source)),
                "count": count,
            }],
            "isBlockCoverage": True,
        }],
    }


def test_nested_zero_count_range_overrides_executed_parent():
    functions = [
        {"ranges": [{"startOffset": 0, "endOffset": 100, "count": 1}]},
        {"ranges": [{"startOffset": 20, "endOffset": 40, "count": 0}]},
    ]

    intervals, observed, exhausted = effective_executed_intervals(functions)

    assert observed == 2
    assert exhausted is False
    assert [(item.start, item.end, item.count) for item in intervals] == [
        (0, 20, 1),
        (40, 100, 1),
    ]


def test_range_budget_is_explicit_and_malformed_ranges_are_ignored():
    functions = [{"ranges": [
        {"startOffset": "bad", "endOffset": 10, "count": 1},
        {"startOffset": 0, "endOffset": 10, "count": 1},
        {"startOffset": 10, "endOffset": 20, "count": 1},
    ]}]

    intervals, observed, exhausted = effective_executed_intervals(functions, max_ranges=1)

    # Invalid input does not consume the one valid-range budget.
    assert observed == 1
    assert exhausted is True
    assert [(item.start, item.end) for item in intervals] == [(0, 10)]


def test_utf16_conversion_matches_v8_offsets_after_non_bmp_text():
    source = 'const icon = "😀"; child.postMessage("ready", "*");'
    python_offset = source.index("postMessage")

    assert python_index_to_utf16(source, python_offset) == python_offset + 1


def test_same_origin_script_labels_drop_credentials_query_and_blob_ids():
    accepted, label, kind = safe_runtime_script_url(
        "https://user:password@target.test/app.js?token=secret#fragment",
        "https://target.test/page",
    )
    blob_accepted, blob_label, blob_kind = safe_runtime_script_url(
        "blob:https://target.test/4d36e96e-e325-11ce-bfc1-08002be10318",
        "https://target.test/page",
    )

    assert (accepted, label, kind) == (
        True, "https://target.test/app.js", "network"
    )
    assert blob_accepted is True
    assert blob_label == "blob:https://target.test/<runtime-script>"
    assert blob_kind == "blob"
    assert safe_runtime_script_url(
        "https://cdn.test/app.js", "https://target.test/page"
    )[0] is False


def test_anonymous_eval_requires_a_same_origin_execution_context():
    assert safe_runtime_script_url(
        "", "https://target.test/page", execution_context_origin="https://target.test"
    )[:2] == (True, "<eval@https://target.test>")
    assert safe_runtime_script_url(
        "", "https://target.test/page", execution_context_origin="https://other.test"
    )[0] is False


def test_only_the_executed_static_finding_is_correlated():
    source = (
        'function dead(){ child.postMessage("dead", "*"); }\n'
        'function live(){ child.postMessage("live", "*"); }\n'
        'live();'
    )
    dead_start = python_index_to_utf16(source, source.index("function dead"))
    dead_end = python_index_to_utf16(source, source.index("function live"))
    source_end = python_index_to_utf16(source, len(source))
    functions = [
        {"ranges": [{"startOffset": 0, "endOffset": source_end, "count": 1}]},
        {"ranges": [{"startOffset": dead_start, "endOffset": dead_end, "count": 0}]},
    ]

    result = RuntimeCoverageAnalyzer.correlate_script(
        script_url="https://target.test/app.js",
        source=source,
        functions=functions,
        phase="interaction",
    )

    wildcard_sites = [
        item for item in result["findings"]
        if item["category"] == "postmessage_wildcard_target"
    ]
    assert len(wildcard_sites) == 1
    assert wildcard_sites[0]["runtime_reached"] is True
    assert wildcard_sites[0]["offset_utf16"] >= dead_end
    assert source not in str(result)


def test_generic_sink_decoys_are_masked_before_correlation():
    source = (
        'const decoy = "panel.innerHTML = input";\n'
        '// output.innerHTML = commentOnly;\n'
        'output.innerHTML = safeValue;'
    )
    result = RuntimeCoverageAnalyzer.correlate_script(
        script_url="https://target.test/app.js",
        source=source,
        functions=_coverage_entry("1", "", source)["functions"],
        phase="bootstrap",
    )

    sites = [item for item in result["findings"] if item["category"] == "dom_sink"]
    assert len(sites) == 1


def test_zero_finding_budget_exports_no_activation_sites():
    source = "output.innerHTML = location.hash;"

    result = RuntimeCoverageAnalyzer.correlate_script(
        script_url="https://target.test/app.js",
        source=source,
        functions=_coverage_entry("1", "", source)["functions"],
        phase="bootstrap",
        max_findings=0,
    )

    assert result["findings"] == []


def test_collector_fetches_only_executed_same_origin_source_and_never_exports_it():
    same_source = 'child.postMessage("runtime-secret", "*");'
    cross_source = 'eval("cross-origin-secret")'
    commands: list[tuple[str, dict]] = []

    def send(method: str, params: dict):
        commands.append((method, params))
        if method == "Profiler.takePreciseCoverage":
            return {"result": [
                _coverage_entry(
                    "same",
                    "https://user:password@target.test/app.js?token=secret",
                    same_source,
                ),
                _coverage_entry("cross", "https://cdn.test/vendor.js", cross_source),
                _coverage_entry("dead", "https://target.test/dead.js", "eval('dead')", 0),
            ]}
        if method == "Debugger.getScriptSource":
            return {"scriptSource": {
                "same": same_source,
                "cross": cross_source,
            }.get(params["scriptId"], "")}
        return {}

    collector = RuntimeCoverageCollector(send, "https://target.test/page")
    assert collector.start() is True
    assert collector.snapshot("bootstrap") is True
    report = collector.finish()

    fetched_ids = [
        params["scriptId"] for method, params in commands
        if method == "Debugger.getScriptSource"
    ]
    assert fetched_ids == ["same"]
    assert report["available"] is True
    assert report["summary"]["scripts_analyzed"] == 1
    assert report["summary"]["runtime_reached_sites"] == 1
    assert report["scripts"][0]["url"] == "https://target.test/app.js"
    assert "runtime-secret" not in str(report)
    assert "password" not in str(report)
    assert "token=secret" not in str(report)
    assert [method for method, _ in commands[-4:]] == [
        "Profiler.stopPreciseCoverage",
        "Profiler.disable",
        "Debugger.disable",
        "Runtime.disable",
    ]


def test_collector_accepts_eval_only_after_context_and_script_metadata_events():
    eval_source = 'eval(location.hash)'

    def send(method: str, params: dict):
        if method == "Profiler.takePreciseCoverage":
            entry = _coverage_entry("eval-1", "", eval_source)
            return {"result": [entry]}
        if method == "Debugger.getScriptSource":
            return {"scriptSource": eval_source}
        return {}

    collector = RuntimeCoverageCollector(send, "https://target.test/page")
    collector.on_execution_context_created({
        "context": {"id": 7, "origin": "https://target.test"}
    })
    collector.on_script_parsed({
        "scriptId": "eval-1", "url": "", "executionContextId": 7
    })
    collector.start()
    collector.snapshot("interaction")
    report = collector.finish()

    assert report["scripts"][0]["url"] == "<eval@https://target.test>"
    assert report["summary"]["runtime_reached_sites"] == 1


def test_script_and_finding_budgets_are_reported(monkeypatch):
    source = 'eval(location.hash); child.postMessage("x", "*");'

    def send(method: str, params: dict):
        if method == "Profiler.takePreciseCoverage":
            return {"result": [
                _coverage_entry("one", "https://target.test/one.js", source),
                _coverage_entry("two", "https://target.test/two.js", source),
            ]}
        if method == "Debugger.getScriptSource":
            return {"scriptSource": source}
        return {}

    monkeypatch.setattr(RuntimeCoverageCollector, "MAX_SCRIPTS", 1)
    monkeypatch.setattr(RuntimeCoverageCollector, "MAX_FINDINGS", 1)
    collector = RuntimeCoverageCollector(send, "https://target.test/page")
    collector.start()
    collector.snapshot("bootstrap")
    report = collector.finish()

    assert set(report["budget_exhausted"]) == {"findings"}
    assert report["summary"]["scripts_analyzed"] == 1
    assert report["summary"]["runtime_reached_sites"] == 1
