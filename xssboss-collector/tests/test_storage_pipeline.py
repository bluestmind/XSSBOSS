from __future__ import annotations

import json
from pathlib import Path

from xsscollector.config import CollectorConfig, CrawlConfig, PrivacyConfig, ScopeConfig, StorageConfig
from xsscollector.models import RequestRecord
from xsscollector.pipeline import CollectorPipeline
from xsscollector.storage import CollectorStore


def config(tmp_path: Path) -> CollectorConfig:
    return CollectorConfig(
        scope=ScopeConfig(allow=["https://example.com/"], authorized_use=False),
        crawl=CrawlConfig(profile="passive"),
        storage=StorageConfig(database=str(tmp_path / "db.sqlite"), evidence_dir=str(tmp_path / "evidence")),
        privacy=PrivacyConfig(),
    )


def test_offline_pipeline_deduplicates_redacts_and_diffs(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    with CollectorStore(Path(cfg.storage.database)) as store:
        first = store.begin_run("import:har", cfg.digest())
        pipeline = CollectorPipeline(cfg, store)
        stats = pipeline.import_records(first, [RequestRecord(
            method="GET", url="https://example.com/users/123?token=secret&view=full", source="har",
            headers={"Authorization": "Bearer topsecret"}, response_status=200,
            response_headers={"Content-Type": "text/html", "Content-Security-Policy": "default-src 'self'"},
            response_body=b"<html><title>One</title><a href='/api/items/99?limit=10'>API</a></html>",
        )])
        store.finish_run(first, "completed", stats.as_dict())
        assert store.stats(first)["endpoints"] >= 2
        sample = store.connection.execute("SELECT * FROM samples WHERE run_id=?", (first,)).fetchone()
        assert "secret" not in sample["sample_url"]
        assert "topsecret" not in sample["request_headers_json"]
        parameter = store.connection.execute("SELECT sample_redacted FROM parameters WHERE name='token'").fetchone()
        assert parameter[0] == "[REDACTED]"

        second = store.begin_run("import:urls", cfg.digest())
        stats2 = CollectorPipeline(cfg, store).import_records(second, [RequestRecord("GET", "https://example.com/new", "url-file")])
        store.finish_run(second, "completed", stats2.as_dict())
        diff = store.diff(first, second)
        assert any(row["url_pattern"].endswith("/new") for row in diff["added"])
        assert diff["removed"]


def test_live_collection_does_not_block_without_prior_authorization(tmp_path: Path) -> None:
    import asyncio
    cfg = config(tmp_path)
    with CollectorStore(Path(cfg.storage.database)) as store:
        run_id = store.begin_run("live", cfg.digest())
        try:
            asyncio.run(CollectorPipeline(cfg, store).collect(run_id, []))
        except ValueError as exc:
            assert "seed URL is required" in str(exc)


def test_robots_root_rule_blocks_all_non_robots(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    pipeline = CollectorPipeline(cfg, CollectorStore(Path(cfg.storage.database)))
    try:
        pipeline._robots_deny["https://example.com/"] = {"/"}
        assert pipeline._blocked_by_robots("https://example.com/anything")
        assert not pipeline._blocked_by_robots("https://example.com/robots.txt")
    finally:
        pipeline.store.close()
