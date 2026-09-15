"""LLM login analyzer — parses the model's answer into selectors/steps, gracefully degrades."""
import json

from analysis_engine.llm_login_analyzer import LlmLoginAnalyzer


def _q(payload):
    """A fake LLM query_fn returning the given payload (dict or JSON string)."""
    return lambda prompt: payload


def test_parses_selectors_from_json_string():
    raw = json.dumps({
        "username_selector": "#email", "password_selector": "#pw", "submit_selector": "#go",
        "steps": [{"action": "fill", "selector": "#email", "value": "{{USERNAME}}"}],
        "mfa_detected": False,
    })
    r = LlmLoginAnalyzer.analyze("<html>login</html>", query_fn=_q(raw))
    assert r["username_selector"] == "#email" and r["password_selector"] == "#pw"
    assert r["mfa_detected"] is False
    sel = LlmLoginAnalyzer.selectors(r)
    assert sel == {"username_selector": "#email", "password_selector": "#pw", "submit_selector": "#go"}


def test_handles_prose_wrapped_json():
    raw = "Sure! Here is the login flow:\n{\"username_selector\":\"#u\",\"password_selector\":\"#p\",\"submit_selector\":\"#s\"}\nHope that helps."
    r = LlmLoginAnalyzer.analyze("<html>x</html>", query_fn=_q(raw))
    assert r and r["password_selector"] == "#p"


def test_flags_mfa():
    raw = {"username_selector": "#u", "password_selector": "#p", "submit_selector": "#s", "mfa_detected": True}
    r = LlmLoginAnalyzer.analyze("<html>otp</html>", query_fn=_q(raw))
    assert r["mfa_detected"] is True


def test_no_password_field_returns_none():
    raw = {"username_selector": "#u", "submit_selector": "#s"}   # no password -> useless
    assert LlmLoginAnalyzer.analyze("<html>x</html>", query_fn=_q(raw)) is None


def test_malformed_output_returns_none():
    assert LlmLoginAnalyzer.analyze("<html>x</html>", query_fn=_q("not json at all")) is None
    assert LlmLoginAnalyzer.analyze("", query_fn=_q("{}")) is None       # empty html


def test_query_exception_degrades_to_none():
    def boom(prompt):
        raise RuntimeError("ollama down")
    assert LlmLoginAnalyzer.analyze("<html>x</html>", query_fn=boom) is None


def test_selectors_needs_username_and_password():
    assert LlmLoginAnalyzer.selectors(None) is None
    assert LlmLoginAnalyzer.selectors({"username_selector": "#u"}) is None   # missing password


def test_multistep_flow_without_explicit_password_selector():
    # A multi-step flow that fills password via steps still counts as usable.
    raw = {"username_selector": "#email", "password_selector": "",
           "submit_selector": "#next",
           "steps": [{"action": "fill", "selector": "#email", "value": "{{USERNAME}}"},
                     {"action": "click", "selector": "#next"},
                     {"action": "fill", "selector": "#pass", "value": "{{PASSWORD}}"}]}
    r = LlmLoginAnalyzer.analyze("<html>multistep</html>", query_fn=_q(raw))
    assert r is not None and len(r["steps"]) == 3


def test_agent_tool_analyze_login_degrades_offline():
    # Via the toolkit: with no live LLM it returns an error dict, never crashes.
    from analysis_engine.agent_tools import AgentToolkit
    tk = AgentToolkit(allow_network=False)
    r = tk.call("analyze_login", {"html": "<form><input type=password></form>"})
    assert r["ok"] is True   # dispatched cleanly (result may be an 'error' dict, that's fine)
