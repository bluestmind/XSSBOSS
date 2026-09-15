"""MCP stdio server — expose XSSBOSS tools to AI agents (dalfox-parity, and fits the local agent).

Wraps :class:`AgentToolkit` as a Model Context Protocol server over stdio (newline-delimited
JSON-RPC 2.0), so Claude Code, your WhiteRabbitNeo agent, or any MCP client can call
``taint_analyze`` / ``decide_bypass`` / ``scan_libraries`` / ``analyze_login`` / memory tools. The
deterministic engines stay the source of truth; MCP is just the wire.

Run:  python -m analysis_engine.mcp_server
"""
from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional

from analysis_engine.agent_tools import AgentToolkit

PROTOCOL_VERSION = "2024-11-05"


class McpServer:
    def __init__(self, toolkit: Optional[AgentToolkit] = None) -> None:
        self.toolkit = toolkit or AgentToolkit()

    # ---- JSON-RPC helpers ----
    @staticmethod
    def _ok(rid: Any, result: Dict[str, Any]) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    @staticmethod
    def _err(rid: Any, code: int, message: str) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}

    def _tools(self) -> list:
        return [
            {"name": t["function"]["name"], "description": t["function"]["description"],
             "inputSchema": t["function"]["parameters"]}
            for t in self.toolkit.schemas()
        ]

    def handle(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Dispatch one JSON-RPC request; returns a response dict, or None for notifications."""
        method = request.get("method", "")
        rid = request.get("id")

        if method == "initialize":
            return self._ok(rid, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "xssboss", "version": "1.0"},
            })
        if method == "tools/list":
            return self._ok(rid, {"tools": self._tools()})
        if method == "tools/call":
            params = request.get("params") or {}
            name = params.get("name", "")
            args = params.get("arguments") or {}
            result = self.toolkit.call(name, args)
            return self._ok(rid, {
                "content": [{"type": "text", "text": json.dumps(result, default=str)}],
                "isError": not bool(result.get("ok", True)),
            })
        if method.startswith("notifications/"):
            return None  # notifications carry no id and get no response
        if method == "ping":
            return self._ok(rid, {})
        return self._err(rid, -32601, f"Method not found: {method}")

    def serve(self, stdin=None, stdout=None) -> None:
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
            except Exception:
                continue
            response = self.handle(request)
            if response is not None:
                stdout.write(json.dumps(response) + "\n")
                stdout.flush()


if __name__ == "__main__":
    McpServer().serve()
