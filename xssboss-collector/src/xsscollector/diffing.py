"""Comprehensive run snapshots and difference tables."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import defaultdict
from typing import Any, Callable


def _json(value: str | None, default: Any) -> Any:
    try:
        return json.loads(value) if value else default
    except json.JSONDecodeError:
        return default


def _stable(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


class ComprehensiveDiff:
    """Compare inventory, HTTP evidence, graph, and JavaScript analysis independently."""

    def __init__(self, connection: sqlite3.Connection):
        self.db = connection

    def compare(self, old_run: int, new_run: int) -> dict[str, Any]:
        self._require_run(old_run)
        self._require_run(new_run)
        old = self.snapshot(old_run)
        new = self.snapshot(new_run)
        categories = {name: self._compare_maps(old.get(name, {}), new.get(name, {})) for name in sorted(set(old) | set(new))}
        totals = {
            "added": sum(len(value["added"]) for value in categories.values()),
            "removed": sum(len(value["removed"]) for value in categories.values()),
            "changed": sum(len(value["changed"]) for value in categories.values()),
            "unchanged": sum(value["unchanged_count"] for value in categories.values()),
        }
        return {
            "schema_version": 2,
            "from_run": old_run,
            "to_run": new_run,
            "summary": {"categories": len(categories), **totals},
            "category_summary": {
                name: {"added": len(value["added"]), "removed": len(value["removed"]),
                       "changed": len(value["changed"]), "unchanged": value["unchanged_count"]}
                for name, value in categories.items()
            },
            "categories": categories,
        }

    def snapshot(self, run_id: int) -> dict[str, dict[str, dict[str, Any]]]:
        snapshot: dict[str, dict[str, dict[str, Any]]] = {}
        endpoints = self._endpoints(run_id)
        snapshot["endpoints"] = endpoints
        snapshot["parameters"] = self._parameters(run_id)
        samples = self._samples(run_id)
        snapshot.update(samples)
        snapshot["technologies"] = self._technologies(endpoints)
        snapshot["observations"] = self._observations(run_id)
        snapshot["relationships"] = self._relationships(run_id)
        snapshot["artifacts"] = self._artifacts(run_id)
        snapshot.update(self._javascript(run_id))
        return snapshot

    def _require_run(self, run_id: int) -> None:
        if not self.db.execute("SELECT 1 FROM runs WHERE id=?", (run_id,)).fetchone():
            raise ValueError(f"run {run_id} not found")

    def _endpoints(self, run_id: int) -> dict[str, dict[str, Any]]:
        rows = self.db.execute(
            "SELECT e.*,d.source run_source,d.title run_title,d.metadata_json run_metadata_json FROM endpoints e "
            "JOIN run_endpoints r ON r.endpoint_id=e.id LEFT JOIN run_endpoint_details d ON d.endpoint_id=e.id AND d.run_id=r.run_id "
            "WHERE r.run_id=?", (run_id,)
        ).fetchall()
        result = {
            row["fingerprint"]: {
                "fingerprint": row["fingerprint"], "method": row["method"], "url_pattern": row["url_pattern"],
                "host": row["host"], "source": row["run_source"] or row["source"],
                "title": row["run_title"] if row["run_title"] is not None else row["title"],
                "technologies": [],
                "metadata": _json(row["run_metadata_json"], {}) if row["run_metadata_json"] is not None else _json(row["metadata_json"], {}),
            }
            for row in rows
        }
        for row in self.db.execute(
            "SELECT e.fingerprint,t.technology FROM run_technologies t JOIN endpoints e ON e.id=t.endpoint_id WHERE t.run_id=?",
            (run_id,),
        ).fetchall():
            if row["fingerprint"] in result:
                result[row["fingerprint"]]["technologies"].append(row["technology"])
        for endpoint in result.values():
            endpoint["technologies"].sort()
        return result

    def _parameters(self, run_id: int) -> dict[str, dict[str, Any]]:
        rows = self.db.execute(
            "SELECT e.fingerprint,e.url_pattern,p.name,p.location,p.data_type,p.sample_redacted FROM parameters p "
            "JOIN run_parameters rp ON rp.parameter_id=p.id JOIN endpoints e ON e.id=p.endpoint_id WHERE rp.run_id=?",
            (run_id,),
        ).fetchall()
        return {
            f"{row['fingerprint']}|{row['location']}|{row['name']}": {
                "endpoint": row["url_pattern"], "name": row["name"], "location": row["location"],
                "data_type": row["data_type"], "sample": row["sample_redacted"],
            }
            for row in rows
        }

    def _samples(self, run_id: int) -> dict[str, dict[str, dict[str, Any]]]:
        rows = self.db.execute(
            "SELECT s.*,e.fingerprint,e.url_pattern FROM samples s JOIN endpoints e ON e.id=s.endpoint_id "
            "WHERE s.run_id=? ORDER BY s.id", (run_id,)
        ).fetchall()
        latest = {row["fingerprint"]: row for row in rows}
        status: dict[str, dict[str, Any]] = {}
        evidence: dict[str, dict[str, Any]] = {}
        request_headers: dict[str, dict[str, Any]] = {}
        response_headers: dict[str, dict[str, Any]] = {}
        for fingerprint, row in latest.items():
            status[fingerprint] = {
                "endpoint": row["url_pattern"], "status_code": row["status_code"], "content_type": row["content_type"],
                "response_bytes": row["response_bytes"], "error": row["error"],
            }
            evidence[fingerprint] = {
                "endpoint": row["url_pattern"], "sha256": row["evidence_sha256"], "path": row["evidence_path"],
            }
            for category, raw, target in (
                ("request", row["request_headers_json"], request_headers),
                ("response", row["response_headers_json"], response_headers),
            ):
                for name, value in _json(raw, {}).items():
                    target[f"{fingerprint}|{str(name).lower()}"] = {
                        "endpoint": row["url_pattern"], "header": str(name).lower(), "value": value,
                    }
        return {"http_status": status, "evidence": evidence, "request_headers": request_headers, "response_headers": response_headers}

    @staticmethod
    def _technologies(endpoints: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
        return {
            f"{fingerprint}|{technology}": {"endpoint": endpoint["url_pattern"], "technology": technology}
            for fingerprint, endpoint in endpoints.items() for technology in endpoint.get("technologies", [])
        }

    def _observations(self, run_id: int) -> dict[str, dict[str, Any]]:
        rows = self.db.execute(
            "SELECT o.*,e.fingerprint,e.url_pattern FROM observations o LEFT JOIN endpoints e ON e.id=o.endpoint_id WHERE o.run_id=? ORDER BY o.id",
            (run_id,),
        ).fetchall()
        result = {}
        counters: defaultdict[str, int] = defaultdict(int)
        for row in rows:
            base = f"{row['fingerprint'] or '<run>'}|{row['kind']}|{row['key']}"
            counters[base] += 1
            result[f"{base}|{counters[base]}"] = {
                "endpoint": row["url_pattern"], "kind": row["kind"], "key": row["key"],
                "value": _json(row["value_json"], row["value_json"]), "confidence": row["confidence"],
            }
        return result

    def _relationships(self, run_id: int) -> dict[str, dict[str, Any]]:
        rows = self.db.execute(
            "SELECT r.relation,a.fingerprint af,a.url_pattern au,b.fingerprint bf,b.url_pattern bu FROM relationships r "
            "JOIN endpoints a ON a.id=r.from_endpoint_id JOIN endpoints b ON b.id=r.to_endpoint_id WHERE r.run_id=?", (run_id,)
        ).fetchall()
        return {f"{row['af']}|{row['relation']}|{row['bf']}": {"from": row["au"], "relation": row["relation"], "to": row["bu"]} for row in rows}

    def _artifacts(self, run_id: int) -> dict[str, dict[str, Any]]:
        rows = self.db.execute(
            "SELECT a.* FROM artifacts a JOIN run_artifacts r ON r.sha256=a.sha256 WHERE r.run_id=?", (run_id,)
        ).fetchall()
        return {row["sha256"]: {key: row[key] for key in ("sha256", "kind", "relative_path", "original_bytes", "stored_bytes", "mime_type")} for row in rows}

    def _javascript(self, run_id: int) -> dict[str, dict[str, dict[str, Any]]]:
        files = self.db.execute("SELECT * FROM js_files WHERE run_id=? ORDER BY file_url,id", (run_id,)).fetchall()
        file_ids = [row["id"] for row in files]
        result: dict[str, dict[str, dict[str, Any]]] = {
            "js_files": {row["file_url"]: {"url": row["file_url"], "sha256": row["sha256"], "size_bytes": row["size_bytes"],
                                                   "module_kind": row["module_kind"], "source_map_url": row["source_map_url"],
                                                   "warnings": _json(row["parse_warnings_json"], [])} for row in files}
        }
        specs: list[tuple[str, str, list[str], Callable[[sqlite3.Row], dict[str, Any]]]] = [
            ("js_functions", "js_functions", ["function_key"], lambda r: {"function": r["function_key"], "name": r["name"], "kind": r["kind"], "parameters": _json(r["parameters_json"], []), "start_line": r["start_line"], "end_line": r["end_line"], "async": bool(r["async_flag"]), "generator": bool(r["generator"]), "exported": bool(r["exported"]), "body_hash": r["body_hash"], "complexity": r["complexity"]}),
            ("js_inputs", "js_inputs", ["function_key", "name", "kind"], lambda r: {"function": r["function_key"], "name": r["name"], "kind": r["kind"], "default": r["default_value"], "type": r["type_hint"], "line": r["line"]}),
            ("js_outputs", "js_outputs", ["function_key", "kind", "ordinal"], lambda r: {"function": r["function_key"], "kind": r["kind"], "expression": r["expression"], "line": r["line"], "ordinal": r["ordinal"]}),
            ("js_sources", "js_sources", ["function_key", "kind", "line"], lambda r: {"function": r["function_key"], "kind": r["kind"], "expression": r["expression"], "variable": r["variable"], "input_name": r["input_name"], "line": r["line"], "confidence": r["confidence"]}),
            ("js_sinks", "js_sinks", ["function_key", "kind", "line"], lambda r: {"function": r["function_key"], "kind": r["kind"], "category": r["category"], "expression": r["expression"], "value": r["value_expression"], "line": r["line"], "severity": r["severity"], "confidence": r["confidence"]}),
            ("js_calls", "js_calls", ["caller", "callee", "line"], lambda r: {"caller": r["caller"], "callee": r["callee"], "arguments": _json(r["arguments_json"], []), "line": r["line"], "awaited": bool(r["awaited"]), "optional": bool(r["optional"])}),
            ("js_flows", "js_flows", ["function_key", "source_kind", "source_name", "sink_kind", "line"], lambda r: {"function": r["function_key"], "source_kind": r["source_kind"], "source_name": r["source_name"], "sink_kind": r["sink_kind"], "sink": r["sink_expression"], "path": _json(r["path_json"], []), "line": r["line"], "confidence": r["confidence"], "sanitized": bool(r["sanitized"])}),
            ("js_modules", "js_modules", ["kind", "module", "line"], lambda r: {"kind": r["kind"], "module": r["module"], "names": _json(r["names_json"], []), "line": r["line"]}),
            ("js_symbols", "js_symbols", ["symbol_kind", "name"], lambda r: {"kind": r["symbol_kind"], "name": r["name"]}),
        ]
        if not file_ids:
            for category, *_ in specs:
                result[category] = {}
            return result
        placeholders = ",".join("?" for _ in file_ids)
        file_urls = {row["id"]: row["file_url"] for row in files}
        for category, table, identity_columns, converter in specs:
            rows = self.db.execute(f"SELECT * FROM {table} WHERE js_file_id IN ({placeholders}) ORDER BY js_file_id,id", file_ids).fetchall()
            values: dict[str, dict[str, Any]] = {}
            counters: defaultdict[str, int] = defaultdict(int)
            for row in rows:
                base = "|".join([file_urls[row["js_file_id"]], *(str(row[column]) for column in identity_columns)])
                counters[base] += 1
                identity = base if counters[base] == 1 else f"{base}|{counters[base]}"
                values[identity] = {"file": file_urls[row["js_file_id"]], **converter(row)}
            result[category] = values
        return result

    @staticmethod
    def _compare_maps(old: dict[str, dict[str, Any]], new: dict[str, dict[str, Any]]) -> dict[str, Any]:
        old_keys, new_keys = set(old), set(new)
        added = [{"identity": key, **new[key]} for key in sorted(new_keys - old_keys)]
        removed = [{"identity": key, **old[key]} for key in sorted(old_keys - new_keys)]
        changed = []
        unchanged = 0
        for key in sorted(old_keys & new_keys):
            if _stable(old[key]) == _stable(new[key]):
                unchanged += 1
            else:
                changed.append({"identity": key, "before": old[key], "after": new[key],
                                "changed_fields": sorted({*old[key], *new[key]} - {field for field in set(old[key]) & set(new[key]) if _stable(old[key][field]) == _stable(new[key][field])})})
        return {"added": added, "removed": removed, "changed": changed, "unchanged_count": unchanged}
