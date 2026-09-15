from __future__ import annotations

import base64
import json
import threading
import urllib.request

from xsscollector.webui import create_server


def _request(base: str, path: str, data: dict | None = None) -> tuple[bytes, dict[str, str]]:
    body = json.dumps(data).encode() if data is not None else None
    request = urllib.request.Request(
        base + path,
        data=body,
        headers={"Content-Type": "application/json", "Origin": base.rstrip("/")} if body else {},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.read(), dict(response.headers)


def test_guided_dashboard_end_to_end(tmp_path):
    server = create_server(tmp_path / "collector.toml", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        page, headers = _request(base, "/")
        assert b"Senior data collection workspace" in page
        assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]

        state = json.loads(_request(base, "/api/state")[0])
        assert state["configured"] is False
        assert state["runs"] == []

        setup = {
            "allow": "https://example.com/",
            "deny": "https://example.com/private/",
            "authorized_use": True,
            "allow_private_networks": False,
            "profile": "passive",
            "max_pages": 20,
            "max_depth": 1,
            "requests_per_second": 1,
        }
        assert json.loads(_request(base, "/api/setup", setup)[0])["ok"] is True

        source = "export function render(input) { const q = location.search; document.body.innerHTML = input + q; return input; }"
        payload = {
            "base_url": "https://example.com/static-analysis/",
            "files": [{"name": "src/app.js", "content": base64.b64encode(source.encode()).decode()}],
        }
        first = json.loads(_request(base, "/api/analyze-js", payload)[0])
        assert first["run"]["js_functions"] == 1
        assert first["run"]["js_sinks"] >= 1

        mirror_payload = {
            "format": "mirror",
            "base_url": "https://example.com/",
            "files": [
                {"name": "example.com/index.html", "content": base64.b64encode(b"<script src='/assets/mirror.js'></script>").decode()},
                {"name": "example.com/assets/mirror.js", "content": base64.b64encode(b"document.body.innerHTML = location.hash").decode()},
            ],
        }
        mirror = json.loads(_request(base, "/api/import", mirror_payload)[0])
        assert mirror["run"]["endpoints"] >= 2
        assert mirror["run"]["js_sinks"] >= 1

        payload["files"][0]["content"] = base64.b64encode((source + "\nfetch('/api/items');").encode()).decode()
        second = json.loads(_request(base, "/api/analyze-js", payload)[0])
        inventory = json.loads(_request(base, f"/api/inventory?run={second['run']['run_id']}")[0])
        assert inventory["endpoints"]
        assert inventory["javascript"]["functions"]

        diff = json.loads(_request(base, f"/api/diff?from={first['run']['run_id']}&to={second['run']['run_id']}")[0])
        assert diff["summary"]["categories"] == 20
        report, report_headers = _request(base, f"/download/diff?from={first['run']['run_id']}&to={second['run']['run_id']}&format=html")
        assert report.count(b"<table>") == 20
        assert "attachment" in report_headers["Content-Disposition"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
