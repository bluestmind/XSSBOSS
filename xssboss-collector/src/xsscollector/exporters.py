"""Stable machine- and human-readable exports."""

from __future__ import annotations

import csv
import html
import json
from pathlib import Path
from typing import Any

from .storage import CollectorStore


def _human_title(value: str) -> str:
    """Format internal field/category names without mangling common acronyms."""
    acronyms = {"api": "API", "http": "HTTP", "id": "ID", "js": "JS", "sha256": "SHA-256", "url": "URL"}
    return " ".join(acronyms.get(part, part.title()) for part in value.split("_"))


def export_run(store: CollectorStore, run_id: int | None, output: Path, format_name: str) -> int:
    rows = store.endpoint_rows(run_id)
    javascript = store.js_analysis(run_id)
    output.parent.mkdir(parents=True, exist_ok=True)
    if format_name == "json":
        output.write_text(json.dumps({"schema_version": 2, "endpoints": rows, "javascript": javascript}, indent=2, sort_keys=True), encoding="utf-8")
    elif format_name == "jsonl":
        output.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    elif format_name == "csv":
        with output.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=["id", "method", "url_pattern", "host", "source", "title", "technologies", "parameter_count"])
            writer.writeheader()
            for row in rows:
                writer.writerow({key: row.get(key) for key in ("id", "method", "url_pattern", "host", "source", "title")} |
                                {"technologies": ";".join(row["technologies"]), "parameter_count": len(row["parameters"])})
    elif format_name == "html":
        output.write_text(_html_report(store.stats(run_id), rows, javascript), encoding="utf-8")
    else:
        raise ValueError(f"unsupported export format: {format_name}")
    return len(rows)


def _html_report(stats: dict[str, Any], rows: list[dict[str, Any]], javascript: dict[str, list[dict[str, Any]]]) -> str:
    cards = "".join(f"<div class=card><b>{html.escape(str(value))}</b><span>{html.escape(key)}</span></div>"
                    for key, value in stats.items() if key in {"endpoints", "parameters", "observations", "samples", "js_files", "js_functions", "js_sources", "js_sinks", "js_flows"})
    table_rows = []
    for row in rows:
        params = ", ".join(f"{p['location']}:{p['name']}" for p in row["parameters"])
        table_rows.append("<tr>" + "".join(f"<td>{html.escape(str(value or ''))}</td>" for value in (
            row["method"], row["url_pattern"], row["source"], ", ".join(row["technologies"]), params
        )) + "</tr>")
    sections = ["<h2>Endpoints</h2><div class=table-wrap><table><thead><tr><th>Method</th><th>Endpoint pattern</th><th>Source</th><th>Technology</th><th>Parameters</th></tr></thead><tbody>" + "".join(table_rows) + "</tbody></table></div>"]
    columns = {
        "files": ["file_url", "sha256", "size_bytes", "module_kind", "source_map_url"],
        "functions": ["file_url", "function_key", "kind", "parameters", "start_line", "end_line", "complexity", "body_hash"],
        "inputs": ["file_url", "function_key", "name", "kind", "default_value", "type_hint", "line"],
        "outputs": ["file_url", "function_key", "kind", "expression", "line"],
        "sources": ["file_url", "function_key", "kind", "variable", "input_name", "expression", "line", "confidence"],
        "sinks": ["file_url", "function_key", "kind", "category", "severity", "value_expression", "line", "confidence"],
        "flows": ["file_url", "function_key", "source_kind", "source_name", "sink_kind", "path", "sanitized", "confidence", "line"],
        "calls": ["file_url", "caller", "callee", "arguments", "awaited", "optional", "line"],
        "modules": ["file_url", "kind", "module", "names", "line"],
        "symbols": ["file_url", "symbol_kind", "name"],
    }
    for category, wanted in columns.items():
        sections.append(f"<h2>JavaScript {html.escape(_human_title(category))} <small>{len(javascript.get(category, []))}</small></h2>" + _html_table(javascript.get(category, []), wanted))
    return """<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width'>
<title>XSSBOSS Collector inventory</title><style>
body{font:14px system-ui;margin:2rem;color:#172033;background:#f7f9fc}.cards{display:flex;gap:1rem;flex-wrap:wrap}.card{background:white;padding:1rem 2rem;border-radius:10px;box-shadow:0 2px 12px #0001;display:grid}.card b{font-size:1.8rem}.card span,small{color:#687386}.table-wrap{overflow:auto;max-height:38rem;border:1px solid #e7eaf0;margin:1rem 0 2.5rem}table{width:100%;border-collapse:collapse;background:white}th,td{padding:.7rem;border-bottom:1px solid #e7eaf0;text-align:left;vertical-align:top;white-space:pre-wrap;word-break:break-word;max-width:34rem}th{position:sticky;top:0;background:#172033;color:white;z-index:1}code{font:12px ui-monospace}h2{margin-top:2.5rem}
</style></head><body><h1>XSSBOSS Collector inventory</h1><div class=cards>""" + cards + "</div>" + "".join(sections) + "</body></html>"


def export_diff(data: dict[str, Any], output: Path | None, format_name: str = "json") -> str:
    if format_name == "json":
        rendered = json.dumps(data, indent=2, sort_keys=True)
    elif format_name == "markdown":
        rendered = _markdown_diff(data)
    elif format_name == "html":
        rendered = _html_diff(data)
    else:
        raise ValueError(f"unsupported diff format: {format_name}")
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    return rendered


def _html_table(rows: list[dict[str, Any]], columns: list[str] | None = None) -> str:
    columns = columns or sorted({key for row in rows for key in row}) or ["records"]
    head = "".join(f"<th>{html.escape(_human_title(column))}</th>" for column in columns)
    body = []
    for row in rows:
        body.append("<tr>" + "".join(f"<td>{html.escape(_display(row.get(column)))}</td>" for column in columns) + "</tr>")
    if not body:
        body.append(f"<tr><td colspan='{len(columns)}' class=empty>No changed records.</td></tr>")
    return f"<div class=table-wrap><table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table></div>"


def _display(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    if value is None:
        return ""
    return str(value)


def _html_diff(data: dict[str, Any]) -> str:
    summary = data["summary"]
    cards = "".join(f"<div class='card {key}'><b>{value}</b><span>{html.escape(key.title())}</span></div>"
                    for key, value in summary.items() if key != "categories")
    navigation = "".join(f"<a href='#{html.escape(name)}'>{html.escape(_human_title(name))}</a>"
                         for name in data["categories"])
    sections = []
    for name, changes in data["categories"].items():
        rows = []
        for change in changes["added"]:
            rows.append({"change": "added", "identity": change.get("identity"), "before": "", "after": {k: v for k, v in change.items() if k != "identity"}})
        for change in changes["removed"]:
            rows.append({"change": "removed", "identity": change.get("identity"), "before": {k: v for k, v in change.items() if k != "identity"}, "after": ""})
        for change in changes["changed"]:
            rows.append({"change": "changed", "identity": change["identity"], "changed_fields": change["changed_fields"], "before": change["before"], "after": change["after"]})
        count = len(rows)
        sections.append(f"<section id='{html.escape(name)}'><h2>{html.escape(_human_title(name))} <small>{count} changes · {changes['unchanged_count']} unchanged</small></h2>{_html_table(rows, ['change','identity','changed_fields','before','after'])}</section>")
    return """<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width'><title>XSSBOSS Collector comprehensive diff</title><style>
body{font:14px system-ui;margin:2rem;color:#172033;background:#f7f9fc}.cards{display:flex;gap:1rem;flex-wrap:wrap}.card{background:#fff;padding:1rem 2rem;border-radius:10px;display:grid;box-shadow:0 2px 12px #0001}.card b{font-size:1.8rem}.card.added b{color:#087a42}.card.removed b{color:#b42318}.card.changed b{color:#b76e00}.card span,small{color:#687386}nav{display:flex;flex-wrap:wrap;gap:.5rem;margin:1.5rem 0;position:sticky;top:0;background:#f7f9fc;padding:.8rem 0;z-index:3}nav a{background:#172033;color:#fff;text-decoration:none;padding:.4rem .7rem;border-radius:5px}.table-wrap{overflow:auto;max-height:35rem;border:1px solid #dfe3eb;background:#fff}table{width:100%;border-collapse:collapse}th,td{padding:.65rem;border-bottom:1px solid #e7eaf0;text-align:left;vertical-align:top;white-space:pre-wrap;word-break:break-word;max-width:38rem}th{position:sticky;top:0;background:#172033;color:#fff}section{scroll-margin-top:5rem;margin-top:2.5rem}.empty{color:#687386}
</style></head><body><h1>Comprehensive difference report</h1><p>Run """ + str(data["from_run"]) + " → " + str(data["to_run"]) + "</p><div class=cards>" + cards + "</div><nav>" + navigation + "</nav>" + "".join(sections) + "</body></html>"


def _markdown_diff(data: dict[str, Any]) -> str:
    lines = [f"# Comprehensive difference report", "", f"Run {data['from_run']} → {data['to_run']}", "",
             f"Added: {data['summary']['added']} · Removed: {data['summary']['removed']} · Changed: {data['summary']['changed']} · Unchanged: {data['summary']['unchanged']}", ""]
    for name, changes in data["categories"].items():
        lines.extend([f"## {_human_title(name)}", "", "| Change | Identity | Details |", "|---|---|---|"])
        for label in ("added", "removed"):
            for item in changes[label]:
                details = _display({key: value for key, value in item.items() if key != "identity"}).replace("|", "\\|")
                lines.append(f"| {label} | `{item['identity']}` | `{details}` |")
        for item in changes["changed"]:
            details = _display({"fields": item["changed_fields"], "before": item["before"], "after": item["after"]}).replace("|", "\\|")
            lines.append(f"| changed | `{item['identity']}` | `{details}` |")
        if not any(changes[key] for key in ("added", "removed", "changed")):
            lines.append(f"| unchanged | {changes['unchanged_count']} records | |")
        lines.append("")
    return "\n".join(lines)
