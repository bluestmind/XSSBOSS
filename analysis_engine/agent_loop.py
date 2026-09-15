"""Agent loop — drive WhiteRabbitNeo over the XSSBOSS toolkit (function calling).

This is the connective tissue that turns :class:`AgentToolkit` from a shelf module into a working
agent: given a goal, the local model plans, calls tools (taint_analyze, decide_bypass, analyze_login,
web_search, remember/recall), reads the ground-truth results, and iterates until it answers — bounded
by a step budget, with anti-thrashing steering injected on repeated failures.

The model itself is injected as ``chat_fn`` so the loop is fully testable without Ollama; on the
user's machine :func:`make_ollama_chat_fn` binds it to the live model via ``/api/chat`` tool calling.
The agent orchestrates the deterministic engines — it never overrides their verdicts.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from analysis_engine.agent_tools import AgentToolkit

# chat_fn(messages, tools) -> {"content": str|None, "tool_calls": [{"name": str, "arguments": dict}]}
ChatFn = Callable[[List[Dict[str, Any]], List[Dict[str, Any]]], Dict[str, Any]]

_SYSTEM = (
    "You are an XSS hunting agent. Use the tools to gather GROUND TRUTH — never assert a "
    "vulnerability the tools did not confirm. taint_analyze proves reachability; decide_bypass "
    "proves whether a bypass exists; analyze_login reads login pages; remember/recall persist what "
    "worked. Plan, call tools, read results, and give a final answer only when the tools support it. "
    "For MFA/CAPTCHA or anything destructive, stop and say a human is needed."
)


@dataclass
class AgentRun:
    answer: Optional[str] = None
    stopped_reason: str = "answered"
    steps: int = 0
    tool_trace: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"answer": self.answer, "stopped_reason": self.stopped_reason,
                "steps": self.steps, "tool_trace": self.tool_trace}


class AgentLoop:
    """Bounded tool-calling loop over the toolkit."""

    def __init__(self, toolkit: Optional[AgentToolkit] = None, *, system: str = _SYSTEM,
                 max_steps: int = 8):
        self.toolkit = toolkit or AgentToolkit()
        self.system = system
        self.max_steps = max_steps

    def run(self, goal: str, chat_fn: ChatFn) -> AgentRun:
        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": self.system},
            {"role": "user", "content": goal},
        ]
        tools = self.toolkit.schemas()
        run = AgentRun()

        for step in range(self.max_steps):
            run.steps = step + 1
            resp = chat_fn(messages, tools) or {}
            tool_calls = resp.get("tool_calls") or []

            if not tool_calls:
                run.answer = resp.get("content")
                run.stopped_reason = "answered"
                return run

            messages.append({"role": "assistant", "content": resp.get("content") or "",
                             "tool_calls": tool_calls})
            for tc in tool_calls:
                name = tc.get("name", "")
                args = tc.get("arguments") or {}
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except Exception:
                        args = {}
                result = self.toolkit.call(name, args)
                run.tool_trace.append({"tool": name, "args": args, "ok": result.get("ok")})
                messages.append({"role": "tool", "name": name,
                                 "content": json.dumps(result, default=str)[:4000]})
                if result.get("blocked") and result.get("steer"):
                    messages.append({"role": "system", "content": result["steer"]})

        run.stopped_reason = "step_budget_exhausted"
        return run


def make_ollama_chat_fn(model: Optional[str] = None, url: Optional[str] = None) -> ChatFn:
    """Bind the loop to the live local model via Ollama's /api/chat tool-calling (runs on the host)."""
    import httpx
    from backend_api.config import settings

    model = model or settings.LLM_MODEL
    base = (url or settings.LLM_API_URL).replace("/api/generate", "/api/chat")

    def chat_fn(messages: List[Dict[str, Any]], tools: List[Dict[str, Any]]) -> Dict[str, Any]:
        r = httpx.post(base, json={"model": model, "messages": messages, "tools": tools,
                       "stream": False}, timeout=120)
        msg = r.json().get("message", {})
        calls = []
        for c in msg.get("tool_calls", []) or []:
            fn = c.get("function", {})
            calls.append({"name": fn.get("name"), "arguments": fn.get("arguments")})
        return {"content": msg.get("content"), "tool_calls": calls}

    return chat_fn
