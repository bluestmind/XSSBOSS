from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from xsscollector.config import CollectorConfig, CrawlConfig, ScopeConfig, StorageConfig
from xsscollector.pipeline import CollectorPipeline
from xsscollector.storage import CollectorStore


class _Handler(BaseHTTPRequestHandler):
    requested: list[tuple[str, str]] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).requested.append(("GET", self.path))
        if self.path == "/":
            body = b"<html><title>Local App</title><a href='/api/users/42?view=full'>API</a><form method='post' action='/submit'><input name='email'></form></html>"
            content_type = "text/html"
        elif self.path.startswith("/api/users/"):
            body = b'{"user":{"id":42,"name":"Ada"}}'
            content_type = "application/json"
        else:
            body = b"not found"
            content_type = "text/plain"
        self.send_response(200 if self.path == "/" or self.path.startswith("/api/users/") else 404)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass


def test_get_only_live_collection_end_to_end(tmp_path: Path) -> None:
    _Handler.requested = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}/"
        cfg = CollectorConfig(
            scope=ScopeConfig(allow=[base], allow_private_networks=True, authorized_use=True),
            crawl=CrawlConfig(profile="passive", max_depth=1, max_pages=10, concurrency=2,
                              per_host_concurrency=1, requests_per_second=100, respect_robots=False),
            storage=StorageConfig(database=str(tmp_path / "collector.db"), evidence_dir=str(tmp_path / "evidence")),
        )
        with CollectorStore(Path(cfg.storage.database)) as store:
            run_id = store.begin_run("live", cfg.digest())
            stats = asyncio.run(CollectorPipeline(cfg, store).collect(run_id, [base]))
            store.finish_run(run_id, "completed", stats.as_dict())
            rows = store.endpoint_rows(run_id)
            assert any(row["url_pattern"].endswith("/api/users/{path_id_3}?view=") for row in rows)
            assert any(row["method"] == "POST" and row["url_pattern"].endswith("/submit") for row in rows)
            assert store.stats(run_id)["samples"] == 2
        assert all(method == "GET" for method, _ in _Handler.requested)
        assert not any(path == "/submit" for _, path in _Handler.requested)
    finally:
        server.shutdown()
        server.server_close()

