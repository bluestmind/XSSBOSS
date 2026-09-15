from __future__ import annotations

import json
from pathlib import Path

from xsscollector.config import CollectorConfig, CrawlConfig, ScopeConfig, StorageConfig
from xsscollector.exporters import export_diff, export_run
from xsscollector.models import RequestRecord
from xsscollector.pipeline import CollectorPipeline
from xsscollector.storage import CollectorStore


def _config(tmp_path: Path) -> CollectorConfig:
    return CollectorConfig(
        scope=ScopeConfig(allow=["https://example.com/"]),
        crawl=CrawlConfig(profile="passive"),
        storage=StorageConfig(database=str(tmp_path / "collector.db"), evidence_dir=str(tmp_path / "evidence")),
    )


def _js_record(body: str, status: int, build: str) -> RequestRecord:
    return RequestRecord(
        "GET", "https://example.com/assets/app.js", "test",
        response_status=status,
        response_headers={"Content-Type": "application/javascript", "X-Build": build},
        response_body=body.encode(),
    )


def test_javascript_is_persisted_and_every_domain_is_diffed(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    old_code = '''
const __NEXT_DATA__ = {};
export function render(node, value) {
  const name = new URLSearchParams(location.search).get("name");
  node.innerHTML = name;
  return value;
}
'''
    new_code = '''
const __VUE__ = true;
export function render(node, value = "") {
  const name = new URLSearchParams(location.search).get("name");
  node.textContent = name;
  fetch("/audit", {method: "POST", body: value});
  return {name, value};
}
export const extra = (input) => input.trim();
'''
    with CollectorStore(Path(cfg.storage.database)) as store:
        old_run = store.begin_run("test-old", cfg.digest())
        old_stats = CollectorPipeline(cfg, store).import_records(old_run, [_js_record(old_code, 200, "one")])
        store.finish_run(old_run, "completed", old_stats.as_dict())
        assert store.stats(old_run)["js_functions"] == 1
        assert store.stats(old_run)["js_sinks"] >= 1

        new_run = store.begin_run("test-new", cfg.digest())
        new_stats = CollectorPipeline(cfg, store).import_records(new_run, [_js_record(new_code, 201, "two")])
        store.finish_run(new_run, "completed", new_stats.as_dict())

        diff = store.diff(old_run, new_run)
        assert len(diff["categories"]) >= 19
        assert diff["category_summary"]["http_status"]["changed"] == 1
        assert diff["category_summary"]["response_headers"]["changed"] == 1
        assert diff["category_summary"]["evidence"]["changed"] == 1
        assert diff["category_summary"]["js_files"]["changed"] == 1
        assert diff["category_summary"]["js_functions"]["added"] >= 1
        assert diff["category_summary"]["js_sinks"]["added"] >= 1
        assert diff["category_summary"]["js_sinks"]["removed"] >= 1
        assert diff["category_summary"]["technologies"]["added"] == 1
        assert diff["category_summary"]["technologies"]["removed"] == 1

        json_report = tmp_path / "inventory.json"
        html_report = tmp_path / "inventory.html"
        diff_report = tmp_path / "diff.html"
        export_run(store, new_run, json_report, "json")
        export_run(store, new_run, html_report, "html")
        export_diff(diff, diff_report, "html")
        exported = json.loads(json_report.read_text(encoding="utf-8"))
        assert exported["javascript"]["functions"]
        assert "JavaScript Sinks" in html_report.read_text(encoding="utf-8")
        assert "Comprehensive difference report" in diff_report.read_text(encoding="utf-8")


def test_inline_scripts_and_source_map_sources_are_analyzed(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    html_record = RequestRecord(
        "GET", "https://example.com/", "test", response_status=200,
        response_headers={"Content-Type": "text/html"},
        response_body=b"<html><script>function inline(x){el.innerHTML=x;return x}</script></html>",
    )
    source_map = {
        "version": 3,
        "sources": ["src/original.ts"],
        "sourcesContent": ["export function original(input: string){ document.write(input); return input; }"],
        "names": [], "mappings": "",
    }
    map_record = RequestRecord(
        "GET", "https://example.com/assets/app.js.map", "test", response_status=200,
        response_headers={"Content-Type": "application/json+source-map"},
        response_body=json.dumps(source_map).encode(),
    )
    with CollectorStore(Path(cfg.storage.database)) as store:
        run_id = store.begin_run("source-map", cfg.digest())
        stats = CollectorPipeline(cfg, store).import_records(run_id, [html_record, map_record])
        store.finish_run(run_id, "completed", stats.as_dict())
        analysis = store.js_analysis(run_id)
        urls = {item["file_url"] for item in analysis["files"]}
        assert "https://example.com/#inline-script-1" in urls
        assert "https://example.com/assets/src/original.ts" in urls
        assert any(item["function_key"] == "inline" for item in analysis["functions"])
        assert any(item["function_key"] == "original" for item in analysis["functions"])

