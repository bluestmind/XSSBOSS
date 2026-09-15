"""Operator CLI for live collection, offline imports, exports, and diffs."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import shutil
import sqlite3
import sys
from pathlib import Path
from urllib.parse import quote, urljoin

from . import __version__
from .config import CollectorConfig
from .exporters import export_diff, export_run
from .importers import IMPORTERS, import_openapi, import_urls
from .mirror_import import import_mirror
from .pipeline import CollectorPipeline
from .models import RequestRecord
from .storage import CollectorStore

CONFIG_TEMPLATE = '''# XSSBOSS Collector
[scope]
authorized_use = true
allow = ["https://example.com/"]
deny = ["https://example.com/admin/private/*"]
allow_private_networks = false

[crawl]
profile = "standard" # passive, standard, or deep
max_depth = 2
max_pages = 500
concurrency = 8
per_host_concurrency = 2
requests_per_second = 2.0
timeout_seconds = 15.0
max_response_bytes = 2000000
retries = 2
respect_robots = true
follow_redirects = true
user_agent = "XSSBOSS-Collector/1.3 (+authorized-security-inventory)"

[storage]
database = "data/collector.db"
evidence_dir = "data/evidence"
store_response_bodies = true
compress_evidence = true

[privacy]
redact_headers = ["authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"]
redact_parameters = ["password", "passwd", "secret", "token", "api_key", "apikey", "access_token", "refresh_token", "session", "jwt", "credit_card", "ssn"]
retain_query_values = false
retain_request_bodies = false

[analysis]
javascript_enabled = true
analyze_inline_scripts = true
analyze_source_maps = true
max_source_map_sources = 10000
'''


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="xsscollect", description="Authorized collection-only web inventory")
    root.add_argument("--version", action="version", version=__version__)
    sub = root.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="create a safe starter configuration")
    init.add_argument("directory", nargs="?", default=".")
    init.add_argument("--force", action="store_true")

    collect = sub.add_parser("collect", help="perform bounded GET-only collection")
    collect.add_argument("urls", nargs="*")
    collect.add_argument("--urls-file", type=Path)
    collect.add_argument("--config", default="collector.toml")

    imp = sub.add_parser("import", help="inventory captured or mirrored evidence without replaying it")
    imp.add_argument("format", choices=["har", "burp", "openapi", "urls", "mirror"])
    imp.add_argument("path", type=Path)
    imp.add_argument("--base-url")
    imp.add_argument("--manifest", type=Path, help="optional URL-to-file JSON or text manifest for a mirror")
    imp.add_argument("--config", default="collector.toml")

    analyze = sub.add_parser("analyze-js", help="deeply inventory local JavaScript/TypeScript without executing it")
    analyze.add_argument("paths", nargs="+", type=Path)
    analyze.add_argument("--base-url", required=True, help="in-scope URL used to identify the local source tree")
    analyze.add_argument("--recursive", action="store_true", help="include JS/TS files below directories")
    analyze.add_argument("--config", default="collector.toml")

    stats = sub.add_parser("stats", help="show run statistics")
    stats.add_argument("--run", type=int)
    stats.add_argument("--config", default="collector.toml")

    export = sub.add_parser("export", help="export an inventory")
    export.add_argument("--format", choices=["json", "jsonl", "csv", "html"], default="json")
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--run", type=int)
    export.add_argument("--config", default="collector.toml")

    diff = sub.add_parser("diff", help="compare all inventory data between two runs")
    diff.add_argument("--from-run", type=int, required=True)
    diff.add_argument("--to-run", type=int, required=True)
    diff.add_argument("--output", type=Path)
    diff.add_argument("--format", choices=["json", "html", "markdown"], default="json")
    diff.add_argument("--config", default="collector.toml")

    ui = sub.add_parser("ui", help="open the guided local dashboard")
    ui.add_argument("--config", default="collector.toml")
    ui.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1", "localhost", "::1"])
    ui.add_argument("--port", type=int, default=8765)
    ui.add_argument("--no-open", action="store_true", help="start without opening the browser")

    sub.add_parser("doctor", help="verify the local runtime")
    return root


def _open(config_path: str) -> tuple[CollectorConfig, CollectorStore]:
    config = CollectorConfig.load(config_path)
    return config, CollectorStore(config.resolve_path(config.storage.database))


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "init":
            directory = Path(args.directory).resolve()
            directory.mkdir(parents=True, exist_ok=True)
            destination = directory / "collector.toml"
            if destination.exists() and not args.force:
                raise FileExistsError(f"{destination} exists; use --force to replace it")
            destination.write_text(CONFIG_TEMPLATE, encoding="utf-8")
            print(json.dumps({"created": str(destination), "next": "run 'xsscollect ui' for guided setup"}))
            return 0
        if args.command == "doctor":
            print(json.dumps({"version": __version__, "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
                              "free_disk_bytes": shutil.disk_usage(Path.cwd()).free, "status": "ok"}, indent=2))
            return 0
        if args.command == "ui":
            from .webui import run_ui
            run_ui(args.config, args.host, args.port, not args.no_open)
            return 0

        config, store = _open(args.config)
        with store:
            if args.command == "collect":
                seeds = list(args.urls)
                if args.urls_file:
                    seeds.extend(record.url for record in import_urls(args.urls_file))
                run_id = store.begin_run("live", config.digest())
                try:
                    result = asyncio.run(CollectorPipeline(config, store).collect(run_id, seeds))
                    store.finish_run(run_id, "completed", result.as_dict())
                except Exception as exc:
                    store.finish_run(run_id, "failed", {}, str(exc))
                    raise
                print(json.dumps(store.stats(run_id), indent=2, sort_keys=True))
                return 0
            if args.command == "import":
                if args.format == "mirror":
                    if not args.base_url:
                        raise ValueError("mirror import requires --base-url")
                    records = import_mirror(
                        args.path, args.base_url, args.manifest,
                        max_files=config.crawl.max_pages,
                        max_file_bytes=config.crawl.max_response_bytes,
                    )
                elif args.format == "openapi":
                    records = import_openapi(args.path, args.base_url)
                else:
                    records = IMPORTERS[args.format](args.path)
                run_id = store.begin_run(f"import:{args.format}", config.digest())
                try:
                    result = CollectorPipeline(config, store).import_records(run_id, records)
                    store.finish_run(run_id, "completed", result.as_dict())
                except Exception as exc:
                    store.finish_run(run_id, "failed", {}, str(exc))
                    raise
                print(json.dumps(store.stats(run_id), indent=2, sort_keys=True))
                return 0
            if args.command == "analyze-js":
                files = _javascript_files(args.paths, args.recursive)
                if not files:
                    raise ValueError("no JavaScript or TypeScript files found")
                if len(files) > config.crawl.max_pages:
                    raise ValueError(f"file count exceeds crawl.max_pages ({config.crawl.max_pages})")
                records = []
                try:
                    common_root = Path(os.path.commonpath([str(path.parent) for path in files]))
                except ValueError:
                    common_root = files[0].parent
                for path in files:
                    body = path.read_bytes()
                    if len(body) > config.crawl.max_response_bytes:
                        raise ValueError(f"{path} exceeds max_response_bytes")
                    relative_name = path.relative_to(common_root).as_posix()
                    source_url = urljoin(args.base_url.rstrip("/") + "/", quote(relative_name, safe="/"))
                    records.append(RequestRecord("GET", source_url, "local-js", response_status=200,
                                                 response_headers={"Content-Type": "application/javascript"}, response_body=body,
                                                 metadata={"local_path": relative_name}))
                run_id = store.begin_run("analyze-js", config.digest())
                try:
                    result = CollectorPipeline(config, store).import_records(run_id, records)
                    store.finish_run(run_id, "completed", result.as_dict())
                except Exception as exc:
                    store.finish_run(run_id, "failed", {}, str(exc))
                    raise
                print(json.dumps(store.stats(run_id), indent=2, sort_keys=True))
                return 0
            if args.command == "stats":
                print(json.dumps(store.stats(args.run), indent=2, sort_keys=True))
                return 0
            if args.command == "export":
                count = export_run(store, args.run, args.output.resolve(), args.format)
                print(json.dumps({"exported": count, "output": str(args.output.resolve()), "format": args.format}))
                return 0
            if args.command == "diff":
                data = store.diff(args.from_run, args.to_run)
                rendered = export_diff(data, args.output.resolve() if args.output else None, args.format)
                if args.output:
                    print(json.dumps({"output": str(args.output.resolve()), "format": args.format, **data["summary"]}))
                else:
                    print(rendered)
                return 0
    except (FileNotFoundError, FileExistsError, PermissionError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    return 1


def _javascript_files(paths: list[Path], recursive: bool) -> list[Path]:
    extensions = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
    found: list[Path] = []
    for raw in paths:
        path = raw.resolve()
        if path.is_file() and path.suffix.lower() in extensions:
            found.append(path)
        elif path.is_dir():
            iterator = path.rglob("*") if recursive else path.glob("*")
            found.extend(item.resolve() for item in iterator if item.is_file() and item.suffix.lower() in extensions)
        elif not path.exists():
            raise FileNotFoundError(path)
    return sorted(set(found))
