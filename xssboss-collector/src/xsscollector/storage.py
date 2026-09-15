"""SQLite persistence, run lineage, deduplication, and run-to-run diff support."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .normalize import canonical_url, endpoint_fingerprint

SCHEMA = """
PRAGMA foreign_keys=ON;
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS schema_meta(version INTEGER NOT NULL);
INSERT INTO schema_meta(version) SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_meta);
UPDATE schema_meta SET version=2;
CREATE TABLE IF NOT EXISTS runs(
  id INTEGER PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL,
  mode TEXT NOT NULL, config_digest TEXT NOT NULL, stats_json TEXT NOT NULL DEFAULT '{}', error TEXT
);
CREATE TABLE IF NOT EXISTS endpoints(
  id INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE, method TEXT NOT NULL, url_pattern TEXT NOT NULL,
  scheme TEXT NOT NULL, host TEXT NOT NULL, source TEXT NOT NULL, title TEXT, technologies_json TEXT NOT NULL DEFAULT '[]',
  metadata_json TEXT NOT NULL DEFAULT '{}', first_seen_run INTEGER NOT NULL, last_seen_run INTEGER NOT NULL,
  FOREIGN KEY(first_seen_run) REFERENCES runs(id), FOREIGN KEY(last_seen_run) REFERENCES runs(id)
);
CREATE TABLE IF NOT EXISTS run_endpoints(
  run_id INTEGER NOT NULL, endpoint_id INTEGER NOT NULL, PRIMARY KEY(run_id, endpoint_id),
  FOREIGN KEY(run_id) REFERENCES runs(id), FOREIGN KEY(endpoint_id) REFERENCES endpoints(id)
);
CREATE TABLE IF NOT EXISTS run_technologies(
  run_id INTEGER NOT NULL, endpoint_id INTEGER NOT NULL, technology TEXT NOT NULL,
  PRIMARY KEY(run_id,endpoint_id,technology), FOREIGN KEY(run_id) REFERENCES runs(id), FOREIGN KEY(endpoint_id) REFERENCES endpoints(id)
);
CREATE TABLE IF NOT EXISTS run_endpoint_details(
  run_id INTEGER NOT NULL, endpoint_id INTEGER NOT NULL, source TEXT NOT NULL, title TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}', PRIMARY KEY(run_id,endpoint_id),
  FOREIGN KEY(run_id) REFERENCES runs(id), FOREIGN KEY(endpoint_id) REFERENCES endpoints(id)
);
CREATE TABLE IF NOT EXISTS samples(
  id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL, endpoint_id INTEGER NOT NULL, observed_at TEXT NOT NULL,
  sample_url TEXT NOT NULL, status_code INTEGER, content_type TEXT, elapsed_ms REAL, response_bytes INTEGER,
  request_headers_json TEXT NOT NULL DEFAULT '{}', response_headers_json TEXT NOT NULL DEFAULT '{}',
  evidence_sha256 TEXT, evidence_path TEXT, error TEXT,
  FOREIGN KEY(run_id) REFERENCES runs(id), FOREIGN KEY(endpoint_id) REFERENCES endpoints(id)
);
CREATE TABLE IF NOT EXISTS parameters(
  id INTEGER PRIMARY KEY, endpoint_id INTEGER NOT NULL, name TEXT NOT NULL, location TEXT NOT NULL,
  data_type TEXT NOT NULL, sample_redacted TEXT, first_seen_run INTEGER NOT NULL, last_seen_run INTEGER NOT NULL,
  UNIQUE(endpoint_id, name, location), FOREIGN KEY(endpoint_id) REFERENCES endpoints(id)
);
CREATE TABLE IF NOT EXISTS run_parameters(
  run_id INTEGER NOT NULL, parameter_id INTEGER NOT NULL, PRIMARY KEY(run_id, parameter_id),
  FOREIGN KEY(run_id) REFERENCES runs(id), FOREIGN KEY(parameter_id) REFERENCES parameters(id)
);
CREATE TABLE IF NOT EXISTS observations(
  id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL, endpoint_id INTEGER, kind TEXT NOT NULL, key TEXT NOT NULL,
  value_json TEXT NOT NULL, confidence REAL NOT NULL, evidence_sha256 TEXT,
  UNIQUE(run_id, endpoint_id, kind, key, value_json), FOREIGN KEY(run_id) REFERENCES runs(id)
);
CREATE TABLE IF NOT EXISTS relationships(
  id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL, from_endpoint_id INTEGER NOT NULL, to_endpoint_id INTEGER NOT NULL,
  relation TEXT NOT NULL, UNIQUE(run_id, from_endpoint_id, to_endpoint_id, relation)
);
CREATE TABLE IF NOT EXISTS artifacts(
  sha256 TEXT PRIMARY KEY, first_seen_run INTEGER NOT NULL, kind TEXT NOT NULL, relative_path TEXT NOT NULL,
  original_bytes INTEGER NOT NULL, stored_bytes INTEGER NOT NULL, mime_type TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS run_artifacts(
  run_id INTEGER NOT NULL, sha256 TEXT NOT NULL, PRIMARY KEY(run_id,sha256),
  FOREIGN KEY(run_id) REFERENCES runs(id), FOREIGN KEY(sha256) REFERENCES artifacts(sha256)
);
CREATE TABLE IF NOT EXISTS js_files(
  id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL, endpoint_id INTEGER, file_url TEXT NOT NULL,
  sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL, module_kind TEXT NOT NULL, source_map_url TEXT,
  parse_warnings_json TEXT NOT NULL DEFAULT '[]',
  UNIQUE(run_id,file_url,sha256), FOREIGN KEY(run_id) REFERENCES runs(id), FOREIGN KEY(endpoint_id) REFERENCES endpoints(id)
);
CREATE TABLE IF NOT EXISTS js_functions(
  id INTEGER PRIMARY KEY, js_file_id INTEGER NOT NULL, function_key TEXT NOT NULL, name TEXT NOT NULL,
  kind TEXT NOT NULL, parameters_json TEXT NOT NULL, start_line INTEGER NOT NULL, end_line INTEGER NOT NULL,
  async_flag INTEGER NOT NULL, generator INTEGER NOT NULL, exported INTEGER NOT NULL, body_hash TEXT NOT NULL,
  complexity INTEGER NOT NULL, UNIQUE(js_file_id,function_key,start_line), FOREIGN KEY(js_file_id) REFERENCES js_files(id)
);
CREATE TABLE IF NOT EXISTS js_inputs(
  id INTEGER PRIMARY KEY, js_file_id INTEGER NOT NULL, function_key TEXT NOT NULL, name TEXT NOT NULL,
  kind TEXT NOT NULL, default_value TEXT, type_hint TEXT, line INTEGER NOT NULL,
  UNIQUE(js_file_id,function_key,name,kind), FOREIGN KEY(js_file_id) REFERENCES js_files(id)
);
CREATE TABLE IF NOT EXISTS js_outputs(
  id INTEGER PRIMARY KEY, js_file_id INTEGER NOT NULL, function_key TEXT NOT NULL, kind TEXT NOT NULL,
  expression TEXT NOT NULL, line INTEGER NOT NULL, ordinal INTEGER NOT NULL,
  UNIQUE(js_file_id,function_key,kind,ordinal), FOREIGN KEY(js_file_id) REFERENCES js_files(id)
);
CREATE TABLE IF NOT EXISTS js_sources(
  id INTEGER PRIMARY KEY, js_file_id INTEGER NOT NULL, function_key TEXT NOT NULL, kind TEXT NOT NULL,
  expression TEXT NOT NULL, variable TEXT, input_name TEXT, line INTEGER NOT NULL, confidence REAL NOT NULL,
  UNIQUE(js_file_id,function_key,kind,line,expression), FOREIGN KEY(js_file_id) REFERENCES js_files(id)
);
CREATE TABLE IF NOT EXISTS js_sinks(
  id INTEGER PRIMARY KEY, js_file_id INTEGER NOT NULL, function_key TEXT NOT NULL, kind TEXT NOT NULL,
  category TEXT NOT NULL, expression TEXT NOT NULL, value_expression TEXT NOT NULL, line INTEGER NOT NULL,
  severity TEXT NOT NULL, confidence REAL NOT NULL,
  UNIQUE(js_file_id,function_key,kind,line,expression), FOREIGN KEY(js_file_id) REFERENCES js_files(id)
);
CREATE TABLE IF NOT EXISTS js_calls(
  id INTEGER PRIMARY KEY, js_file_id INTEGER NOT NULL, caller TEXT NOT NULL, callee TEXT NOT NULL,
  arguments_json TEXT NOT NULL, line INTEGER NOT NULL, awaited INTEGER NOT NULL, optional INTEGER NOT NULL,
  UNIQUE(js_file_id,caller,callee,line,arguments_json), FOREIGN KEY(js_file_id) REFERENCES js_files(id)
);
CREATE TABLE IF NOT EXISTS js_flows(
  id INTEGER PRIMARY KEY, js_file_id INTEGER NOT NULL, function_key TEXT NOT NULL, source_kind TEXT NOT NULL,
  source_name TEXT NOT NULL, sink_kind TEXT NOT NULL, sink_expression TEXT NOT NULL, path_json TEXT NOT NULL,
  line INTEGER NOT NULL, confidence REAL NOT NULL, sanitized INTEGER NOT NULL,
  UNIQUE(js_file_id,function_key,source_kind,source_name,sink_kind,line,sanitized), FOREIGN KEY(js_file_id) REFERENCES js_files(id)
);
CREATE TABLE IF NOT EXISTS js_modules(
  id INTEGER PRIMARY KEY, js_file_id INTEGER NOT NULL, kind TEXT NOT NULL, module TEXT NOT NULL,
  names_json TEXT NOT NULL, line INTEGER NOT NULL,
  UNIQUE(js_file_id,kind,module,line), FOREIGN KEY(js_file_id) REFERENCES js_files(id)
);
CREATE TABLE IF NOT EXISTS js_symbols(
  id INTEGER PRIMARY KEY, js_file_id INTEGER NOT NULL, symbol_kind TEXT NOT NULL, name TEXT NOT NULL,
  UNIQUE(js_file_id,symbol_kind,name), FOREIGN KEY(js_file_id) REFERENCES js_files(id)
);
CREATE INDEX IF NOT EXISTS ix_endpoints_host ON endpoints(host);
CREATE INDEX IF NOT EXISTS ix_samples_run ON samples(run_id);
CREATE INDEX IF NOT EXISTS ix_parameters_endpoint ON parameters(endpoint_id);
CREATE INDEX IF NOT EXISTS ix_observations_run ON observations(run_id);
CREATE INDEX IF NOT EXISTS ix_js_files_run ON js_files(run_id);
CREATE INDEX IF NOT EXISTS ix_js_functions_file ON js_functions(js_file_id);
CREATE INDEX IF NOT EXISTS ix_js_sinks_file ON js_sinks(js_file_id);
CREATE INDEX IF NOT EXISTS ix_js_flows_file ON js_flows(js_file_id);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_object(value: str | None) -> dict[str, Any]:
    try:
        data = json.loads(value) if value else {}
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


class CollectorStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(SCHEMA)
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "CollectorStore":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def begin_run(self, mode: str, config_digest: str) -> int:
        cursor = self.connection.execute(
            "INSERT INTO runs(started_at,status,mode,config_digest) VALUES(?,?,?,?)",
            (utc_now(), "running", mode, config_digest),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def finish_run(self, run_id: int, status: str, stats: dict[str, Any], error: str | None = None) -> None:
        self.connection.execute(
            "UPDATE runs SET finished_at=?,status=?,stats_json=?,error=? WHERE id=?",
            (utc_now(), status, json.dumps(stats, sort_keys=True), error, run_id),
        )
        self.connection.commit()

    def upsert_endpoint(
        self, run_id: int, method: str, url: str, source: str, *, content_type: str = "",
        title: str | None = None, technologies: Iterable[str] = (), metadata: dict[str, Any] | None = None,
        extra_params: Iterable[str] = (),
    ) -> int:
        from urllib.parse import urlsplit
        pattern = canonical_url(url)
        parsed = urlsplit(url)
        fingerprint = endpoint_fingerprint(method, url, content_type, extra_params)
        row = self.connection.execute("SELECT id,technologies_json,metadata_json FROM endpoints WHERE fingerprint=?", (fingerprint,)).fetchone()
        current_tech = sorted(set(technologies))
        tech = list(current_tech)
        meta = metadata or {}
        if row:
            endpoint_id = int(row["id"])
            tech = sorted(set(json.loads(row["technologies_json"])) | set(tech))
            old_meta = json.loads(row["metadata_json"])
            old_meta.update(meta)
            self.connection.execute(
                "UPDATE endpoints SET last_seen_run=?,title=COALESCE(?,title),technologies_json=?,metadata_json=? WHERE id=?",
                (run_id, title, json.dumps(tech), json.dumps(old_meta, sort_keys=True), endpoint_id),
            )
        else:
            cursor = self.connection.execute(
                "INSERT INTO endpoints(fingerprint,method,url_pattern,scheme,host,source,title,technologies_json,metadata_json,first_seen_run,last_seen_run) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (fingerprint, method.upper(), pattern, parsed.scheme.lower(), (parsed.hostname or "").lower(), source,
                 title, json.dumps(tech), json.dumps(meta, sort_keys=True), run_id, run_id),
            )
            endpoint_id = int(cursor.lastrowid)
        self.connection.execute("INSERT OR IGNORE INTO run_endpoints(run_id,endpoint_id) VALUES(?,?)", (run_id, endpoint_id))
        detail = self.connection.execute(
            "SELECT source,title,metadata_json FROM run_endpoint_details WHERE run_id=? AND endpoint_id=?", (run_id, endpoint_id)
        ).fetchone()
        if detail:
            run_meta = _json_object(detail["metadata_json"])
            run_meta.update(meta)
            self.connection.execute(
                "UPDATE run_endpoint_details SET source=?,title=COALESCE(?,title),metadata_json=? WHERE run_id=? AND endpoint_id=?",
                (source, title, json.dumps(run_meta, sort_keys=True), run_id, endpoint_id),
            )
        else:
            self.connection.execute(
                "INSERT INTO run_endpoint_details(run_id,endpoint_id,source,title,metadata_json) VALUES(?,?,?,?,?)",
                (run_id, endpoint_id, source, title, json.dumps(meta, sort_keys=True)),
            )
        for technology in current_tech:
            self.connection.execute(
                "INSERT OR IGNORE INTO run_technologies(run_id,endpoint_id,technology) VALUES(?,?,?)",
                (run_id, endpoint_id, technology),
            )
        return endpoint_id

    def add_sample(self, run_id: int, endpoint_id: int, *, url: str, status: int | None, content_type: str,
                   elapsed_ms: float | None, response_bytes: int, request_headers: dict[str, str],
                   response_headers: dict[str, str], evidence_sha256: str | None = None,
                   evidence_path: str | None = None, error: str | None = None) -> None:
        self.connection.execute(
            "INSERT INTO samples(run_id,endpoint_id,observed_at,sample_url,status_code,content_type,elapsed_ms,response_bytes,request_headers_json,response_headers_json,evidence_sha256,evidence_path,error) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, endpoint_id, utc_now(), url, status, content_type, elapsed_ms, response_bytes,
             json.dumps(request_headers, sort_keys=True), json.dumps(response_headers, sort_keys=True),
             evidence_sha256, evidence_path, error),
        )

    def add_parameters(self, run_id: int, endpoint_id: int, params: Iterable[tuple[str, str, Any, str]]) -> int:
        count = 0
        for name, location, sample, data_type in params:
            existing = self.connection.execute(
                "SELECT id FROM parameters WHERE endpoint_id=? AND name=? AND location=?", (endpoint_id, name, location)
            ).fetchone()
            sample_text = None if sample is None else str(sample)[:500]
            if existing:
                parameter_id = int(existing["id"])
                self.connection.execute("UPDATE parameters SET last_seen_run=?,data_type=? WHERE id=?", (run_id, data_type, parameter_id))
            else:
                cursor = self.connection.execute(
                    "INSERT INTO parameters(endpoint_id,name,location,data_type,sample_redacted,first_seen_run,last_seen_run) VALUES(?,?,?,?,?,?,?)",
                    (endpoint_id, name, location, data_type, sample_text, run_id, run_id),
                )
                parameter_id = int(cursor.lastrowid)
                count += 1
            self.connection.execute("INSERT OR IGNORE INTO run_parameters(run_id,parameter_id) VALUES(?,?)", (run_id, parameter_id))
        return count

    def add_observation(self, run_id: int, endpoint_id: int | None, kind: str, key: str, value: Any,
                        confidence: float = 1.0, evidence_sha256: str | None = None) -> bool:
        cursor = self.connection.execute(
            "INSERT OR IGNORE INTO observations(run_id,endpoint_id,kind,key,value_json,confidence,evidence_sha256) VALUES(?,?,?,?,?,?,?)",
            (run_id, endpoint_id, kind, key, json.dumps(value, sort_keys=True), confidence, evidence_sha256),
        )
        return cursor.rowcount > 0

    def add_relationship(self, run_id: int, source_id: int, target_id: int, relation: str) -> None:
        self.connection.execute(
            "INSERT OR IGNORE INTO relationships(run_id,from_endpoint_id,to_endpoint_id,relation) VALUES(?,?,?,?)",
            (run_id, source_id, target_id, relation),
        )

    def add_artifact(self, run_id: int, ref: Any, kind: str) -> None:
        self.connection.execute(
            "INSERT OR IGNORE INTO artifacts(sha256,first_seen_run,kind,relative_path,original_bytes,stored_bytes,mime_type) VALUES(?,?,?,?,?,?,?)",
            (ref.sha256, run_id, kind, ref.relative_path, ref.size, ref.stored_size, ref.mime_type),
        )
        self.connection.execute("INSERT OR IGNORE INTO run_artifacts(run_id,sha256) VALUES(?,?)", (run_id, ref.sha256))

    def add_js_analysis(self, run_id: int, endpoint_id: int | None, analysis: Any, redact=lambda value: value) -> dict[str, int]:
        existing = self.connection.execute(
            "SELECT id FROM js_files WHERE run_id=? AND file_url=? AND sha256=?",
            (run_id, analysis.file_url, analysis.sha256),
        ).fetchone()
        if existing:
            return {name: 0 for name in ("files", "functions", "inputs", "outputs", "sources", "sinks", "calls", "flows")}
        cursor = self.connection.execute(
            "INSERT INTO js_files(run_id,endpoint_id,file_url,sha256,size_bytes,module_kind,source_map_url,parse_warnings_json) VALUES(?,?,?,?,?,?,?,?)",
            (run_id, endpoint_id, analysis.file_url, analysis.sha256, analysis.size_bytes, analysis.module_kind,
             analysis.source_map_url, json.dumps(analysis.parse_warnings)),
        )
        file_id = int(cursor.lastrowid)
        for item in analysis.functions:
            self.connection.execute(
                "INSERT OR IGNORE INTO js_functions(js_file_id,function_key,name,kind,parameters_json,start_line,end_line,async_flag,generator,exported,body_hash,complexity) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (file_id, item.qualified_name, item.name, item.kind, json.dumps([redact(value) for value in item.parameters]),
                 item.start_line, item.end_line, int(item.async_flag), int(item.generator), int(item.exported), item.body_hash, item.complexity),
            )
        for item in analysis.inputs:
            self.connection.execute(
                "INSERT OR IGNORE INTO js_inputs(js_file_id,function_key,name,kind,default_value,type_hint,line) VALUES(?,?,?,?,?,?,?)",
                (file_id, item.function, redact(item.name), item.kind, redact(item.default_value) if item.default_value else None,
                 redact(item.type_hint) if item.type_hint else None, item.line),
            )
        for item in analysis.outputs:
            self.connection.execute(
                "INSERT OR IGNORE INTO js_outputs(js_file_id,function_key,kind,expression,line,ordinal) VALUES(?,?,?,?,?,?)",
                (file_id, item.function, item.kind, redact(item.expression), item.line, item.ordinal),
            )
        for item in analysis.sources:
            self.connection.execute(
                "INSERT OR IGNORE INTO js_sources(js_file_id,function_key,kind,expression,variable,input_name,line,confidence) VALUES(?,?,?,?,?,?,?,?)",
                (file_id, item.function, item.kind, redact(item.expression), item.variable,
                 redact(item.input_name) if item.input_name else None, item.line, item.confidence),
            )
        for item in analysis.sinks:
            self.connection.execute(
                "INSERT OR IGNORE INTO js_sinks(js_file_id,function_key,kind,category,expression,value_expression,line,severity,confidence) VALUES(?,?,?,?,?,?,?,?,?)",
                (file_id, item.function, item.kind, item.category, redact(item.expression), redact(item.value_expression),
                 item.line, item.severity, item.confidence),
            )
        for item in analysis.calls:
            self.connection.execute(
                "INSERT OR IGNORE INTO js_calls(js_file_id,caller,callee,arguments_json,line,awaited,optional) VALUES(?,?,?,?,?,?,?)",
                (file_id, item.caller, item.callee, json.dumps([redact(value) for value in item.arguments]),
                 item.line, int(item.awaited), int(item.optional)),
            )
        for item in analysis.flows:
            self.connection.execute(
                "INSERT OR IGNORE INTO js_flows(js_file_id,function_key,source_kind,source_name,sink_kind,sink_expression,path_json,line,confidence,sanitized) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (file_id, item.function, item.source_kind, redact(item.source_name), item.sink_kind,
                 redact(item.sink_expression), json.dumps([redact(value) for value in item.path]), item.line,
                 item.confidence, int(item.sanitized)),
            )
        for item in analysis.modules:
            self.connection.execute(
                "INSERT OR IGNORE INTO js_modules(js_file_id,kind,module,names_json,line) VALUES(?,?,?,?,?)",
                (file_id, item.kind, redact(item.module), json.dumps([redact(value) for value in item.names]), item.line),
            )
        for symbol_kind, names in (("global", analysis.globals), ("export", analysis.exports)):
            for name in names:
                self.connection.execute(
                    "INSERT OR IGNORE INTO js_symbols(js_file_id,symbol_kind,name) VALUES(?,?,?)",
                    (file_id, symbol_kind, redact(name)),
                )
        return {
            "files": 1, "functions": len(analysis.functions), "inputs": len(analysis.inputs),
            "outputs": len(analysis.outputs), "sources": len(analysis.sources), "sinks": len(analysis.sinks),
            "calls": len(analysis.calls), "flows": len(analysis.flows),
        }

    def js_analysis(self, run_id: int | None = None) -> dict[str, list[dict[str, Any]]]:
        run_id = run_id or self.latest_run_id()
        if run_id is None:
            return {name: [] for name in ("files", "functions", "inputs", "outputs", "sources", "sinks", "calls", "flows", "modules", "symbols")}
        files = [dict(row) for row in self.connection.execute(
            "SELECT * FROM js_files WHERE run_id=? ORDER BY file_url,id", (run_id,)
        ).fetchall()]
        ids = [row["id"] for row in files]
        result: dict[str, list[dict[str, Any]]] = {"files": files}
        tables = {
            "functions": "js_functions", "inputs": "js_inputs", "outputs": "js_outputs",
            "sources": "js_sources", "sinks": "js_sinks", "calls": "js_calls", "flows": "js_flows",
            "modules": "js_modules", "symbols": "js_symbols",
        }
        for key, table in tables.items():
            if not ids:
                result[key] = []
                continue
            placeholders = ",".join("?" for _ in ids)
            rows = self.connection.execute(
                f"SELECT t.*,f.file_url,f.sha256 AS file_sha256 FROM {table} t JOIN js_files f ON f.id=t.js_file_id WHERE t.js_file_id IN ({placeholders}) ORDER BY f.file_url,t.id",
                ids,
            ).fetchall()
            result[key] = [dict(row) for row in rows]
        for item in result["files"]:
            item["parse_warnings"] = json.loads(item.pop("parse_warnings_json"))
        for item in result["functions"]:
            item["parameters"] = json.loads(item.pop("parameters_json"))
        for item in result["calls"]:
            item["arguments"] = json.loads(item.pop("arguments_json"))
        for item in result["flows"]:
            item["path"] = json.loads(item.pop("path_json"))
        for item in result["modules"]:
            item["names"] = json.loads(item.pop("names_json"))
        return result

    def commit(self) -> None:
        self.connection.commit()

    def latest_run_id(self) -> int | None:
        row = self.connection.execute("SELECT id FROM runs ORDER BY id DESC LIMIT 1").fetchone()
        return int(row["id"]) if row else None

    def runs(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return recent run summaries for interactive clients."""
        bounded_limit = max(1, min(int(limit), 1_000))
        rows = self.connection.execute(
            "SELECT id,started_at,finished_at,status,mode,stats_json,error FROM runs ORDER BY id DESC LIMIT ?",
            (bounded_limit,),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["collector_stats"] = json.loads(item.pop("stats_json") or "{}")
            result.append(item)
        return result

    def stats(self, run_id: int | None = None) -> dict[str, Any]:
        run_id = run_id or self.latest_run_id()
        if run_id is None:
            return {"run_id": None, "endpoints": 0, "parameters": 0, "observations": 0, "samples": 0}
        row = self.connection.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if not row:
            raise ValueError(f"run {run_id} not found")
        counts = {}
        for name, query in {
            "endpoints": "SELECT COUNT(*) FROM run_endpoints WHERE run_id=?",
            "parameters": "SELECT COUNT(*) FROM run_parameters WHERE run_id=?",
            "observations": "SELECT COUNT(*) FROM observations WHERE run_id=?",
            "samples": "SELECT COUNT(*) FROM samples WHERE run_id=?",
            "js_files": "SELECT COUNT(*) FROM js_files WHERE run_id=?",
            "js_functions": "SELECT COUNT(*) FROM js_functions f JOIN js_files j ON j.id=f.js_file_id WHERE j.run_id=?",
            "js_inputs": "SELECT COUNT(*) FROM js_inputs i JOIN js_files j ON j.id=i.js_file_id WHERE j.run_id=?",
            "js_outputs": "SELECT COUNT(*) FROM js_outputs o JOIN js_files j ON j.id=o.js_file_id WHERE j.run_id=?",
            "js_sources": "SELECT COUNT(*) FROM js_sources s JOIN js_files j ON j.id=s.js_file_id WHERE j.run_id=?",
            "js_sinks": "SELECT COUNT(*) FROM js_sinks s JOIN js_files j ON j.id=s.js_file_id WHERE j.run_id=?",
            "js_calls": "SELECT COUNT(*) FROM js_calls c JOIN js_files j ON j.id=c.js_file_id WHERE j.run_id=?",
            "js_flows": "SELECT COUNT(*) FROM js_flows f JOIN js_files j ON j.id=f.js_file_id WHERE j.run_id=?",
        }.items():
            counts[name] = int(self.connection.execute(query, (run_id,)).fetchone()[0])
        return {"run_id": run_id, "status": row["status"], "mode": row["mode"], **counts,
                "collector_stats": json.loads(row["stats_json"]), "started_at": row["started_at"], "finished_at": row["finished_at"]}

    def endpoint_rows(self, run_id: int | None = None) -> list[dict[str, Any]]:
        run_id = run_id or self.latest_run_id()
        if run_id is None:
            return []
        rows = self.connection.execute(
            "SELECT e.*,d.source run_source,d.title run_title,d.metadata_json run_metadata_json FROM endpoints e "
            "JOIN run_endpoints r ON r.endpoint_id=e.id LEFT JOIN run_endpoint_details d ON d.endpoint_id=e.id AND d.run_id=r.run_id "
            "WHERE r.run_id=? ORDER BY e.host,e.url_pattern,e.method", (run_id,)
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["source"] = item.pop("run_source") or item["source"]
            run_title = item.pop("run_title")
            item["title"] = run_title if run_title is not None else item["title"]
            item.pop("technologies_json")
            item["technologies"] = [tech[0] for tech in self.connection.execute(
                "SELECT technology FROM run_technologies WHERE run_id=? AND endpoint_id=? ORDER BY technology", (run_id, row["id"])
            ).fetchall()]
            run_metadata = item.pop("run_metadata_json")
            item["metadata"] = _json_object(run_metadata) if run_metadata is not None else _json_object(item["metadata_json"])
            item.pop("metadata_json", None)
            item["parameters"] = [dict(p) for p in self.connection.execute(
                "SELECT p.name,p.location,p.data_type,p.sample_redacted FROM parameters p JOIN run_parameters rp ON rp.parameter_id=p.id WHERE p.endpoint_id=? AND rp.run_id=? ORDER BY p.location,p.name", (row["id"], run_id)
            ).fetchall()]
            result.append(item)
        return result

    def diff(self, old_run: int, new_run: int) -> dict[str, Any]:
        from .diffing import ComprehensiveDiff
        data = ComprehensiveDiff(self.connection).compare(old_run, new_run)
        endpoints = data["categories"]["endpoints"]
        data["added"] = endpoints["added"]
        data["removed"] = endpoints["removed"]
        data["unchanged_count"] = endpoints["unchanged_count"]
        return data
