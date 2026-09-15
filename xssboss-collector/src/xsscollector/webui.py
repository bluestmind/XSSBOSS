"""Local, dependency-free guided web interface for XSSBOSS Collector."""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import mimetypes
import tempfile
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any, Callable
from urllib.parse import parse_qs, quote, urljoin, urlsplit

from .config import CollectorConfig, ScopeConfig
from .exporters import export_diff, export_run
from .importers import IMPORTERS, import_openapi
from .mirror_import import MIRROR_EXTENSIONS, import_uploaded_mirror
from .models import RequestRecord
from .pipeline import CollectorPipeline
from .scope import ScopePolicy, ScopeRule
from .storage import CollectorStore

MAX_REQUEST_BYTES = 100 * 1024 * 1024
WEB_ROOT = Path(__file__).with_name("web")
JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}


def ensure_config(path: Path) -> CollectorConfig:
    path = path.resolve()
    if not path.exists():
        CollectorConfig(scope=ScopeConfig(allow=["https://example.com/"], authorized_use=False, allow_private_networks=True), config_path=path).save(path)
    return CollectorConfig.load(path)


def create_server(config_path: str | Path, host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("the dashboard is local-only; use 127.0.0.1, localhost, or ::1")
    path = Path(config_path).resolve()
    ensure_config(path)
    handler = type("CollectorUIHandler", (_Handler,), {"config_path": path})
    return ThreadingHTTPServer((host, port), handler)


def run_ui(config_path: str | Path, host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    server = create_server(config_path, host, port)
    address = f"http://{'[::1]' if host == '::1' else host}:{server.server_port}/"
    if open_browser:
        threading.Timer(0.35, webbrowser.open, args=(address,)).start()
    print(json.dumps({"dashboard": address, "config": str(Path(config_path).resolve()), "status": "ready"}))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


class _Handler(BaseHTTPRequestHandler):
    config_path: Path
    server_version = "XSSBOSSCollectorUI/1.3"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        try:
            parsed = urlsplit(self.path)
            if parsed.path == "/api/state":
                self._state()
            elif parsed.path == "/api/runs":
                self._runs(parsed.query)
            elif parsed.path == "/api/inventory":
                self._inventory(parsed.query)
            elif parsed.path == "/api/diff":
                self._diff(parsed.query)
            elif parsed.path == "/download/inventory":
                self._download_inventory(parsed.query)
            elif parsed.path == "/download/diff":
                self._download_diff(parsed.query)
            else:
                self._static(parsed.path)
        except Exception as exc:
            self._error(exc)

    def do_POST(self) -> None:  # noqa: N802
        try:
            if not self._same_origin():
                self._json({"error": "request origin is not allowed"}, HTTPStatus.FORBIDDEN)
                return
            routes: dict[str, Callable[[dict[str, Any]], None]] = {
                "/api/setup": self._setup,
                "/api/analyze-js": self._analyze_js,
                "/api/collect": self._collect,
                "/api/import": self._import_capture,
            }
            handler = routes.get(urlsplit(self.path).path)
            if not handler:
                self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                return
            handler(self._read_json())
        except Exception as exc:
            self._error(exc)

    def _config(self) -> CollectorConfig:
        return ensure_config(self.config_path)

    def _store(self, config: CollectorConfig) -> CollectorStore:
        return CollectorStore(config.resolve_path(config.storage.database))

    def _state(self) -> None:
        config = self._config()
        with self._store(config) as store:
            latest = store.stats()
            runs = store.runs(20)
        self._json({
            "version": "1.3.0",
            "configured": bool(config.scope.authorized_use and config.scope.allow),
            "config": {
                "authorized_use": config.scope.authorized_use,
                "allow": config.scope.allow,
                "deny": config.scope.deny,
                "allow_private_networks": config.scope.allow_private_networks,
                "profile": config.crawl.profile,
                "max_pages": config.crawl.max_pages,
                "max_depth": config.crawl.max_depth,
                "requests_per_second": config.crawl.requests_per_second,
            },
            "latest": latest,
            "runs": runs,
        })

    def _runs(self, query: str) -> None:
        limit = self._integer(parse_qs(query).get("limit", ["100"])[0], "limit", 1, 1_000)
        config = self._config()
        with self._store(config) as store:
            self._json({"runs": store.runs(limit)})

    def _inventory(self, query: str) -> None:
        run_id = self._required_run(query, "run")
        config = self._config()
        with self._store(config) as store:
            self._json({"stats": store.stats(run_id), "endpoints": store.endpoint_rows(run_id), "javascript": store.js_analysis(run_id)})

    def _diff(self, query: str) -> None:
        values = parse_qs(query)
        old_run = self._integer(self._one(values, "from"), "from", 1)
        new_run = self._integer(self._one(values, "to"), "to", 1)
        config = self._config()
        with self._store(config) as store:
            self._json(store.diff(old_run, new_run))

    def _setup(self, data: dict[str, Any]) -> None:
        config = self._config()
        allow = self._lines(data.get("allow"))
        deny = self._lines(data.get("deny"))
        if not allow:
            raise ValueError("add at least one exact authorized scope rule")
        for rule in allow + deny:
            ScopeRule.parse(rule)
        config.scope.allow = allow
        config.scope.deny = deny
        config.scope.authorized_use = bool(data.get("authorized_use", True))
        config.scope.allow_private_networks = bool(data.get("allow_private_networks", True))
        config.crawl.profile = str(data.get("profile", config.crawl.profile))
        config.crawl.max_pages = self._integer(data.get("max_pages", config.crawl.max_pages), "max_pages", 1, 1_000_000)
        config.crawl.max_depth = self._integer(data.get("max_depth", config.crawl.max_depth), "max_depth", 0, 20)
        try:
            config.crawl.requests_per_second = float(data.get("requests_per_second", config.crawl.requests_per_second))
        except (TypeError, ValueError) as exc:
            raise ValueError("requests_per_second must be a number") from exc
        config.validate()
        config.save(self.config_path)
        self._json({"ok": True, "configured": bool(config.scope.authorized_use and config.scope.allow), "message": "Settings saved"})

    def _analyze_js(self, data: dict[str, Any]) -> None:
        config = self._config()
        base_url = str(data.get("base_url", "")).strip()
        policy = ScopePolicy(config.scope.allow, config.scope.deny, config.scope.allow_private_networks)
        if not policy.is_allowed(base_url):
            parsed = urlsplit(base_url)
            rule_str = f"{parsed.scheme}://{parsed.netloc}/" if parsed.scheme and parsed.netloc else base_url
            if rule_str not in config.scope.allow:
                config.scope.allow.append(rule_str)
                config.save(self.config_path)
        raw_files = data.get("files")
        if not isinstance(raw_files, list) or not raw_files:
            raise ValueError("choose at least one JavaScript or TypeScript file")
        if len(raw_files) > config.crawl.max_pages:
            raise ValueError(f"file count exceeds max_pages ({config.crawl.max_pages})")
        records = []
        for item in raw_files:
            if not isinstance(item, dict):
                raise ValueError("invalid uploaded file")
            name = self._safe_relative_name(item.get("name"))
            if Path(name).suffix.lower() not in JS_EXTENSIONS:
                continue
            body = self._decode_file(item, config.crawl.max_response_bytes)
            source_url = urljoin(base_url.rstrip("/") + "/", quote(name, safe="/"))
            records.append(RequestRecord("GET", source_url, "ui-upload", response_status=200,
                                         response_headers={"Content-Type": "application/javascript"}, response_body=body,
                                         metadata={"uploaded_name": name}))
        if not records:
            raise ValueError("no supported .js, .mjs, .cjs, .jsx, .ts, or .tsx files were selected")
        stats = self._import_records(config, "analyze-js", records)
        self._json({"ok": True, "message": "JavaScript analysis completed", "run": stats})

    def _collect(self, data: dict[str, Any]) -> None:
        config = self._config()
        seeds = self._lines(data.get("urls"))
        policy = ScopePolicy(config.scope.allow, config.scope.deny, config.scope.allow_private_networks)
        updated_scope = False
        for seed in seeds:
            val = seed.strip()
            if not val:
                continue
            if not policy.is_allowed(val):
                parsed = urlsplit(val)
                rule_str = f"{parsed.scheme}://{parsed.netloc}/" if parsed.scheme and parsed.netloc else val
                if rule_str not in config.scope.allow:
                    config.scope.allow.append(rule_str)
                    updated_scope = True
        if updated_scope:
            config.save(self.config_path)
        with self._store(config) as store:
            run_id = store.begin_run("live", config.digest())
            try:
                result = asyncio.run(CollectorPipeline(config, store).collect(run_id, seeds))
                store.finish_run(run_id, "completed", result.as_dict())
            except Exception as exc:
                store.finish_run(run_id, "failed", {}, str(exc))
                raise
            stats = store.stats(run_id)
        self._json({"ok": True, "message": "Collection completed", "run": stats})

    def _import_capture(self, data: dict[str, Any]) -> None:
        config = self._config()
        format_name = str(data.get("format", "")).lower()
        if format_name == "mirror":
            base_url = str(data.get("base_url", "")).strip()
            policy = ScopePolicy(config.scope.allow, config.scope.deny, config.scope.allow_private_networks)
            if not policy.is_allowed(base_url):
                parsed = urlsplit(base_url)
                rule_str = f"{parsed.scheme}://{parsed.netloc}/" if parsed.scheme and parsed.netloc else base_url
                if rule_str not in config.scope.allow:
                    config.scope.allow.append(rule_str)
                    config.save(self.config_path)
            raw_files = data.get("files")
            if not isinstance(raw_files, list) or not raw_files:
                raise ValueError("choose a website mirror folder")
            decoded: list[tuple[str, bytes]] = []
            for item in raw_files:
                if not isinstance(item, dict):
                    raise ValueError("invalid uploaded mirror file")
                name = self._safe_relative_name(item.get("name"))
                if Path(name).suffix.lower() in MIRROR_EXTENSIONS:
                    decoded.append((name, self._decode_file(item, config.crawl.max_response_bytes)))
            records = import_uploaded_mirror(decoded, base_url, max_files=config.crawl.max_pages)
            stats = self._import_records(config, "import:mirror", records)
            self._json({"ok": True, "message": "Mirror import completed", "run": stats})
            return
        if format_name not in {"har", "burp", "openapi", "urls"}:
            raise ValueError("format must be HAR, Burp XML, OpenAPI, URL list, or mirror folder")
        item = data.get("file")
        if not isinstance(item, dict):
            raise ValueError("choose a capture file")
        body = self._decode_file(item, MAX_REQUEST_BYTES)
        suffix = {"har": ".har", "burp": ".xml", "openapi": ".json", "urls": ".txt"}[format_name]
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as handle:
                handle.write(body)
                temporary_path = Path(handle.name)
            if format_name == "openapi":
                base_url = str(data.get("base_url", "")).strip() or None
                records = import_openapi(temporary_path, base_url)
            else:
                records = IMPORTERS[format_name](temporary_path)
            stats = self._import_records(config, f"import:{format_name}", records)
        finally:
            if temporary_path:
                temporary_path.unlink(missing_ok=True)
        self._json({"ok": True, "message": f"{format_name.upper()} import completed", "run": stats})

    def _import_records(self, config: CollectorConfig, mode: str, records: Any) -> dict[str, Any]:
        with self._store(config) as store:
            run_id = store.begin_run(mode, config.digest())
            try:
                result = CollectorPipeline(config, store).import_records(run_id, records)
                store.finish_run(run_id, "completed", result.as_dict())
            except Exception as exc:
                store.finish_run(run_id, "failed", {}, str(exc))
                raise
            return store.stats(run_id)

    def _download_inventory(self, query: str) -> None:
        values = parse_qs(query)
        run_id = self._integer(self._one(values, "run"), "run", 1)
        format_name = values.get("format", ["html"])[0]
        if format_name not in {"json", "jsonl", "csv", "html"}:
            raise ValueError("unsupported inventory format")
        config = self._config()
        with tempfile.TemporaryDirectory() as directory, self._store(config) as store:
            path = Path(directory) / f"inventory-run-{run_id}.{format_name}"
            export_run(store, run_id, path, format_name)
            self._file(path.read_bytes(), path.name, mimetypes.guess_type(path.name)[0] or "application/octet-stream")

    def _download_diff(self, query: str) -> None:
        values = parse_qs(query)
        old_run = self._integer(self._one(values, "from"), "from", 1)
        new_run = self._integer(self._one(values, "to"), "to", 1)
        format_name = values.get("format", ["html"])[0]
        if format_name not in {"json", "html", "markdown"}:
            raise ValueError("unsupported difference format")
        config = self._config()
        with self._store(config) as store:
            rendered = export_diff(store.diff(old_run, new_run), None, format_name)
        extension = "md" if format_name == "markdown" else format_name
        mime = {"json": "application/json", "html": "text/html; charset=utf-8", "markdown": "text/markdown; charset=utf-8"}[format_name]
        self._file(rendered.encode(), f"diff-{old_run}-to-{new_run}.{extension}", mime)

    def _static(self, url_path: str) -> None:
        relative = "index.html" if url_path in {"", "/"} else url_path.lstrip("/")
        if relative not in {"index.html", "app.css", "app.js"}:
            self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            return
        path = WEB_ROOT / relative
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        self._send(path.read_bytes(), mime, HTTPStatus.OK)

    def _read_json(self) -> dict[str, Any]:
        length = self._integer(self.headers.get("Content-Length", "0"), "content length", 1, MAX_REQUEST_BYTES)
        if self.headers.get_content_type() != "application/json":
            raise ValueError("Content-Type must be application/json")
        try:
            value = json.loads(self.rfile.read(length))
        except json.JSONDecodeError as exc:
            raise ValueError("invalid JSON request") from exc
        if not isinstance(value, dict):
            raise ValueError("request body must be an object")
        return value

    def _same_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        parsed = urlsplit(origin)
        if parsed.scheme.lower() != "http" or (parsed.hostname or "").lower() not in {"127.0.0.1", "localhost", "::1"}:
            return False
        origin_port = parsed.port or 80
        return origin_port == self.server.server_port

    def _required_run(self, query: str, name: str) -> int:
        return self._integer(self._one(parse_qs(query), name), name, 1)

    @staticmethod
    def _one(values: dict[str, list[str]], name: str) -> str:
        value = values.get(name, [""])[0]
        if not value:
            raise ValueError(f"missing {name}")
        return value

    @staticmethod
    def _integer(value: Any, name: str, minimum: int, maximum: int | None = None) -> int:
        try:
            result = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must be an integer") from exc
        if result < minimum or (maximum is not None and result > maximum):
            range_text = f"{minimum}–{maximum}" if maximum is not None else f"at least {minimum}"
            raise ValueError(f"{name} must be {range_text}")
        return result

    @staticmethod
    def _lines(value: Any) -> list[str]:
        if isinstance(value, list):
            candidates = value
        else:
            candidates = str(value or "").replace(",", "\n").splitlines()
        return list(dict.fromkeys(str(item).strip() for item in candidates if str(item).strip()))

    @staticmethod
    def _safe_relative_name(value: Any) -> str:
        raw = str(value or "").replace("\\", "/").strip("/")
        path = PurePosixPath(raw)
        if not raw or path.is_absolute() or ".." in path.parts:
            raise ValueError("uploaded file has an invalid name")
        return path.as_posix()

    @staticmethod
    def _decode_file(item: dict[str, Any], maximum: int) -> bytes:
        encoded = item.get("content")
        if not isinstance(encoded, str):
            raise ValueError("uploaded file content is missing")
        try:
            body = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("uploaded file content is invalid") from exc
        if len(body) > maximum:
            raise ValueError(f"uploaded file exceeds the {maximum:,}-byte limit")
        return body

    def _error(self, exc: Exception) -> None:
        status = HTTPStatus.FORBIDDEN if isinstance(exc, PermissionError) else HTTPStatus.BAD_REQUEST
        self._json({"error": str(exc) or exc.__class__.__name__}, status)

    def _json(self, value: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        self._send(json.dumps(value, ensure_ascii=False, sort_keys=True).encode(), "application/json; charset=utf-8", status)

    def _file(self, body: bytes, filename: str, content_type: str) -> None:
        self.send_response(HTTPStatus.OK)
        self._security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send(self, body: bytes, content_type: str, status: HTTPStatus) -> None:
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
