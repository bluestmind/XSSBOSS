"""Agent loop — tool-calling orchestration over the toolkit (model injected/mocked)."""
from analysis_engine.agent_loop import AgentLoop
from analysis_engine.agent_tools import AgentToolkit


def scripted(*responses):
    """A fake chat_fn that returns the given responses in order, then answers 'done'."""
    it = iter(responses)

    def fn(messages, tools):
        try:
            return next(it)
        except StopIteration:
            return {"content": "done", "tool_calls": []}
    return fn


def test_agent_calls_a_tool_then_answers():
    loop = AgentLoop(AgentToolkit(allow_network=False))
    js = "var q = new URLSearchParams(location.search).get('q'); el.innerHTML = q;"
    chat = scripted(
        {"content": None, "tool_calls": [{"name": "taint_analyze", "arguments": {"js_code": js}}]},
        {"content": "Confirmed: param q reaches innerHTML.", "tool_calls": []},
    )
    run = loop.run("analyze this bundle", chat)
    assert run.answer.startswith("Confirmed")
    assert run.tool_trace[0]["tool"] == "taint_analyze" and run.tool_trace[0]["ok"] is True
    assert run.stopped_reason == "answered"


def test_agent_answers_without_tools():
    loop = AgentLoop(AgentToolkit(allow_network=False))
    run = loop.run("hi", scripted({"content": "hello", "tool_calls": []}))
    assert run.answer == "hello" and run.steps == 1 and run.tool_trace == []


def test_string_arguments_are_parsed():
    loop = AgentLoop(AgentToolkit(allow_network=False))
    chat = scripted(
        {"content": None, "tool_calls": [{"name": "decide_bypass",
         "arguments": '{"context": "HTML_TEXT", "blocked_chars": ["<"]}'}]},
        {"content": "skip", "tool_calls": []},
    )
    run = loop.run("decide", chat)
    assert run.tool_trace[0]["ok"] is True   # JSON-string args were parsed and dispatched


def test_step_budget_is_bounded():
    loop = AgentLoop(AgentToolkit(allow_network=False), max_steps=3)
    # Always asks for a tool -> never answers -> budget stops it.
    always_tool = lambda messages, tools: {"content": None,
        "tool_calls": [{"name": "recall", "arguments": {"query": "x"}}]}
    run = loop.run("loop forever", always_tool)
    assert run.stopped_reason == "step_budget_exhausted" and run.steps == 3


def test_unknown_tool_does_not_crash_the_loop():
    loop = AgentLoop(AgentToolkit(allow_network=False))
    chat = scripted(
        {"content": None, "tool_calls": [{"name": "rm_rf", "arguments": {}}]},
        {"content": "recovered", "tool_calls": []},
    )
    run = loop.run("try bad tool", chat)
    assert run.tool_trace[0]["ok"] is False   # reported, not raised
    assert run.answer == "recovered"
