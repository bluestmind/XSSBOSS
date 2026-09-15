"""MCP server + SARIF + pipe-scan — the dalfox-parity output/integration layer."""
from analysis_engine.agent_tools import AgentToolkit
from analysis_engine.mcp_server import McpServer
from backend_api.services.sarif_report_service import SarifReportService
from backend_api.services.pipe_scan_service import PipeScanService


# --------------------------------------------------------------------- MCP server

def _mcp():
    return McpServer(AgentToolkit(allow_network=False))


def test_mcp_initialize():
    r = _mcp().handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert r["result"]["serverInfo"]["name"] == "xssboss"
    assert "protocolVersion" in r["result"]


def test_mcp_tools_list_exposes_toolkit():
    r = _mcp().handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = {t["name"] for t in r["result"]["tools"]}
    assert {"taint_analyze", "decide_bypass", "scan_libraries"} <= names
    assert all("inputSchema" in t for t in r["result"]["tools"])


def test_mcp_tools_call_dispatches():
    js = "var q = new URLSearchParams(location.search).get('q'); el.innerHTML = q;"
    r = _mcp().handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                       "params": {"name": "taint_analyze", "arguments": {"js_code": js}}})
    assert r["result"]["isError"] is False
    assert "q" in r["result"]["content"][0]["text"]


def test_mcp_unknown_method_errors_and_notifications_silent():
    assert _mcp().handle({"jsonrpc": "2.0", "id": 9, "method": "bogus"})["error"]["code"] == -32601
    assert _mcp().handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_mcp_serve_over_stream():
    import io, json
    stdin = io.StringIO(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n")
    stdout = io.StringIO()
    _mcp().serve(stdin=stdin, stdout=stdout)
    resp = json.loads(stdout.getvalue().strip())
    assert resp["id"] == 1 and "tools" in resp["result"]


# --------------------------------------------------------------------- SARIF

def test_sarif_structure_and_level_mapping():
    findings = [
        {"rule_id": "xss", "severity": "high", "url": "https://a.test/s?q=1", "param": "q",
         "payload": "<img onerror=x>", "message": "reflected XSS"},
        {"rule_id": "vulnerable_library", "severity": "low", "url": "https://a.test/",
         "message": "jQuery 1.6.4"},
    ]
    log = SarifReportService.build(findings)
    assert log["version"] == "2.1.0"
    run = log["runs"][0]
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {"xss", "vulnerable_library"}
    levels = [res["level"] for res in run["results"]]
    assert "error" in levels and "note" in levels        # high->error, low->note
    xss = next(r for r in run["results"] if r["ruleId"] == "xss")
    assert xss["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith("q=1")


def test_sarif_empty_is_valid():
    log = SarifReportService.build([])
    assert log["runs"][0]["results"] == [] and log["version"] == "2.1.0"


# --------------------------------------------------------------------- pipe scan

def test_pipe_flags_candidate_with_lib_and_dom():
    html = ('<script src="/jquery-1.6.4.min.js"></script>'
            '<script>el.innerHTML = new URLSearchParams(location.search).get("q");</script>')
    r = PipeScanService.scan_url("https://x.test/", fetch_fn=lambda u: html)
    assert r["candidate"] is True
    assert r["vulnerable_libraries"] and r["dom_sinks"]


def test_pipe_clean_page_not_candidate():
    r = PipeScanService.scan_url("https://x.test/", fetch_fn=lambda u: "<html>nothing</html>")
    assert r["candidate"] is False and r["reason"] == "clean-http"


def test_pipe_rejects_non_absolute():
    assert "error" in PipeScanService.scan_url("ftp://x")


def test_pipe_candidates_only_filter():
    def fetch(u):
        return '<script src="/angular-1.5.8.js"></script>' if "vuln" in u else "<html>clean</html>"
    res = PipeScanService.scan_urls(["https://a.test/vuln", "https://a.test/clean"],
                                    fetch_fn=fetch, candidates_only=True)
    assert len(res) == 1 and "vuln" in res[0]["url"]
