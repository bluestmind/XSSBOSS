"""Collection orchestration. It inventories; it never mutates or replays endpoints."""

from __future__ import annotations

import asyncio
import json
import urllib.robotparser
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urljoin, urlsplit

from .config import CollectorConfig
from .evidence import EvidenceStore
from .http_client import HTTPCollector
from .js_analysis import JavaScriptAnalyzer
from .models import CollectionStats, FetchResult, RequestRecord
from .normalize import canonical_url, extract_parameters, infer_type
from .parsers import infer_technologies, parse_document, parse_robots
from .redact import Redactor
from .scope import ScopePolicy, ScopeRule
from .storage import CollectorStore

TEXT_TYPES = ("text/", "json", "javascript", "xml", "svg", "x-www-form-urlencoded")
STANDARD_PATHS = ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt")
DEEP_PATHS = ("/openapi.json", "/swagger.json", "/api/openapi.json", "/graphql")


class CollectorPipeline:
    def __init__(self, config: CollectorConfig, store: CollectorStore):
        self.config = config
        self.store = store
        self.scope = ScopePolicy(config.scope.allow, config.scope.deny, config.scope.allow_private_networks)
        self.redactor = Redactor(config.privacy.redact_headers, config.privacy.redact_parameters,
                                 config.privacy.retain_query_values)
        self.evidence = EvidenceStore(config.resolve_path(config.storage.evidence_dir), config.storage.compress_evidence)
        self.stats = CollectionStats()
        self._robots_deny: dict[str, set[str]] = defaultdict(set)
        self._robots: dict[str, urllib.robotparser.RobotFileParser] = {}

    async def collect(self, run_id: int, seeds: Iterable[str]) -> CollectionStats:
        normalized_seeds: list[str] = []
        for seed in seeds:
            value = seed.strip()
            if not value:
                continue
            if not self.scope.is_allowed(value):
                parsed = urlsplit(value)
                rule_str = f"{parsed.scheme}://{parsed.netloc}/" if parsed.scheme and parsed.netloc else value
                self.scope.allow.append(ScopeRule.parse(rule_str))
                if rule_str not in self.config.scope.allow:
                    self.config.scope.allow.append(rule_str)
            self.scope.require_allowed(value)
            normalized_seeds.append(value)
        if not normalized_seeds:
            raise ValueError("at least one in-scope seed URL is required")

        client = HTTPCollector(self.config.crawl, self.scope)
        queue: list[tuple[str, int, int | None]] = [(url, 0, None) for url in normalized_seeds]
        origins = {self._origin(url) for url in normalized_seeds}
        if self.config.crawl.profile in {"standard", "deep"}:
            for origin in origins:
                queue.extend((urljoin(origin, path), 0, None) for path in STANDARD_PATHS)
        if self.config.crawl.profile == "deep":
            for origin in origins:
                queue.extend((urljoin(origin, path), 0, None) for path in DEEP_PATHS)

        visited: set[str] = set()
        # Fetch robots first so its rules govern the rest of the run.
        if self.config.crawl.respect_robots:
            for origin in sorted(origins):
                robots_url = urljoin(origin, "/robots.txt")
                if self.scope.is_allowed(robots_url):
                    result = await client.fetch(robots_url)
                    endpoint_id, parsed_urls = self._persist_fetch(run_id, result)
                    visited.add(canonical_url(robots_url))
                    if result.status == 200:
                        robots_text = result.body.decode("utf-8", errors="replace")
                        parser = urllib.robotparser.RobotFileParser(robots_url)
                        parser.parse(robots_text.splitlines())
                        self._robots[origin] = parser
                        sitemaps, denied = parse_robots(robots_text)
                        self._robots_deny[origin].update(denied)
                        queue.extend((url, 0, endpoint_id) for url in sitemaps if self.scope.is_allowed(url))

        while queue and self.stats.fetched < self.config.crawl.max_pages:
            batch: list[tuple[str, int, int | None]] = []
            while queue and len(batch) < self.config.crawl.concurrency:
                url, depth, parent_id = queue.pop(0)
                identity = canonical_url(url)
                if identity in visited:
                    continue
                visited.add(identity)
                if depth > self.config.crawl.max_depth or not self.scope.is_allowed(url):
                    self.stats.skipped_scope += 1
                    continue
                if self._blocked_by_robots(url):
                    self.stats.skipped_robots += 1
                    continue
                batch.append((url, depth, parent_id))
            if not batch:
                continue
            results = await asyncio.gather(*(client.fetch(item[0]) for item in batch))
            for (requested_url, depth, parent_id), result in zip(batch, results):
                endpoint_id, discovered = self._persist_fetch(run_id, result)
                if parent_id and endpoint_id:
                    self.store.add_relationship(run_id, parent_id, endpoint_id, "discovered-from")
                if depth < self.config.crawl.max_depth:
                    for url in sorted(discovered):
                        if self.scope.is_allowed(url) and not self._is_url_template(url):
                            queue.append((url, depth + 1, endpoint_id))
                        else:
                            self.stats.skipped_scope += 1
            self.store.commit()

        self.stats.endpoints = self.store.stats(run_id)["endpoints"]
        return self.stats

    def import_records(self, run_id: int, records: Iterable[RequestRecord]) -> CollectionStats:
        for record in records:
            if not self.scope.is_allowed(record.url):
                self.stats.skipped_scope += 1
                continue
            self._persist_record(run_id, record)
            self.stats.imported += 1
        self.store.commit()
        self.stats.endpoints = self.store.stats(run_id)["endpoints"]
        return self.stats

    def _persist_fetch(self, run_id: int, result: FetchResult) -> tuple[int, set[str]]:
        record = result.request
        record.url = result.final_url
        record.response_status = result.status or None
        record.response_headers = result.headers
        record.response_body = result.body
        record.elapsed_ms = result.elapsed_ms
        record.metadata.update({"truncated": result.truncated, "error": result.error})
        endpoint_id, discovered = self._persist_record(run_id, record)
        self.stats.fetched += 1
        self.stats.bytes_received += len(result.body)
        if result.error:
            self.stats.errors += 1
        return endpoint_id, discovered

    def _persist_record(self, run_id: int, record: RequestRecord) -> tuple[int, set[str]]:
        content_type = self._header(record.response_headers, "content-type") or self._header(record.headers, "content-type")
        parsed = parse_document(record.response_body or b"", content_type, record.url) if record.response_body else None
        technologies = infer_technologies(record.response_headers, record.response_body or b"")
        if parsed:
            technologies.update(parsed.technologies)
        request_params = extract_parameters(record.method, record.url, record.headers, record.body)
        for declared in record.metadata.get("declared_parameters", []):
            if isinstance(declared, dict) and declared.get("name"):
                request_params.append((str(declared["name"]), str(declared.get("location", "unknown")), None,
                                       str(declared.get("data_type", "unknown"))))
        safe_params = [(name, location, self._safe_sample(name, location, value), data_type)
                       for name, location, value, data_type in request_params]
        endpoint_id = self.store.upsert_endpoint(
            run_id, record.method, record.url, record.source, content_type=content_type,
            title=parsed.title if parsed else None, technologies=technologies,
            metadata=self.redactor.structured(record.metadata), extra_params=(p[0] for p in safe_params),
        )
        added_params = self.store.add_parameters(run_id, endpoint_id, safe_params)
        self.stats.parameters += added_params

        evidence_ref = None
        safe_body = self._safe_evidence(record.response_body, content_type)
        if safe_body is not None and self.config.storage.store_response_bodies:
            evidence_ref = self.evidence.put(safe_body, content_type or "application/octet-stream")
            self.store.add_artifact(run_id, evidence_ref, "response-body")
        self.store.add_sample(
            run_id, endpoint_id, url=self.redactor.url(record.url), status=record.response_status,
            content_type=content_type, elapsed_ms=record.elapsed_ms, response_bytes=len(record.response_body or b""),
            request_headers=self.redactor.headers_map(record.headers),
            response_headers=self.redactor.headers_map(record.response_headers),
            evidence_sha256=evidence_ref.sha256 if evidence_ref else None,
            evidence_path=evidence_ref.relative_path if evidence_ref else None,
            error=record.metadata.get("error"),
        )

        discovered: set[str] = set()
        if parsed:
            discovered.update(parsed.urls)
            for kind, key, value, confidence in parsed.observations:
                if self.store.add_observation(run_id, endpoint_id, kind, key, self.redactor.structured(value), confidence,
                                              evidence_ref.sha256 if evidence_ref else None):
                    self.stats.observations += 1
            for method, url, source in parsed.endpoint_hints:
                if not self.scope.is_allowed(url):
                    continue
                hinted_params = extract_parameters(method, url, {}, None)
                hinted_params.extend((name, location, None, data_type or "unknown")
                                     for name, location, data_type in parsed.endpoint_parameters.get(f"{method} {url}", []))
                hint_id = self.store.upsert_endpoint(run_id, method, url, source,
                                                     extra_params=(item[0] for item in hinted_params))
                self.stats.parameters += self.store.add_parameters(run_id, hint_id, hinted_params)
                self.store.add_relationship(run_id, endpoint_id, hint_id, "references")
            hinted_urls = {url for _, url, _ in parsed.endpoint_hints}
            for url in parsed.urls - hinted_urls:
                if not self.scope.is_allowed(url):
                    continue
                is_asset = url in parsed.asset_urls
                hint_id = self.store.upsert_endpoint(run_id, "GET", url, "document-asset" if is_asset else "document-link")
                self.stats.parameters += self.store.add_parameters(run_id, hint_id, extract_parameters("GET", url, {}, None))
                self.store.add_relationship(run_id, endpoint_id, hint_id, "embeds" if is_asset else "links-to")
            if parsed.parameters:
                parsed_params = [(name, location, None, inferred or "unknown") for name, location, inferred in parsed.parameters]
                self.stats.parameters += self.store.add_parameters(run_id, endpoint_id, parsed_params)

        is_javascript = "javascript" in content_type.lower() or record.url.split("?", 1)[0].lower().endswith((".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"))
        if self.config.analysis.javascript_enabled and is_javascript and record.response_body:
            javascript = record.response_body.decode("utf-8", errors="replace")
            analysis = JavaScriptAnalyzer.analyze(javascript, record.url)
            self._persist_js_analysis(run_id, endpoint_id, analysis)
            if analysis.source_map_url:
                map_url = urljoin(record.url, analysis.source_map_url)
                if self.scope.is_allowed(map_url):
                    discovered.add(map_url)
        if self.config.analysis.javascript_enabled and self.config.analysis.analyze_inline_scripts and parsed and parsed.inline_scripts:
            for index, script in enumerate(parsed.inline_scripts, 1):
                if script.strip():
                    analysis = JavaScriptAnalyzer.analyze(script, f"{record.url}#inline-script-{index}")
                    self._persist_js_analysis(run_id, endpoint_id, analysis)
        if self.config.analysis.javascript_enabled and self.config.analysis.analyze_source_maps and record.response_body and (record.url.split("?", 1)[0].lower().endswith(".map") or "source-map" in content_type.lower()):
            self._analyze_source_map(run_id, endpoint_id, record.url, record.response_body)

        for key, value in record.response_headers.items():
            lower = key.lower()
            if lower in {"content-security-policy", "strict-transport-security", "permissions-policy", "referrer-policy",
                         "cross-origin-opener-policy", "cross-origin-resource-policy", "access-control-allow-origin"}:
                if self.store.add_observation(run_id, endpoint_id, "response-header", lower, self.redactor.text(value), 1.0,
                                              evidence_ref.sha256 if evidence_ref else None):
                    self.stats.observations += 1
        return endpoint_id, discovered

    def _persist_js_analysis(self, run_id: int, endpoint_id: int, analysis: Any) -> None:
        counts = self.store.add_js_analysis(run_id, endpoint_id, analysis, self.redactor.text)
        self.stats.js_files += counts["files"]
        self.stats.js_functions += counts["functions"]
        self.stats.js_inputs += counts["inputs"]
        self.stats.js_outputs += counts["outputs"]
        self.stats.js_sources += counts["sources"]
        self.stats.js_sinks += counts["sinks"]
        self.stats.js_calls += counts["calls"]
        self.stats.js_flows += counts["flows"]

    def _analyze_source_map(self, run_id: int, endpoint_id: int, map_url: str, body: bytes) -> None:
        try:
            data = json.loads(body.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return
        sources = data.get("sources", [])
        contents = data.get("sourcesContent", [])
        if not isinstance(sources, list) or not isinstance(contents, list):
            return
        for index, source in enumerate(sources[:self.config.analysis.max_source_map_sources]):
            if index >= len(contents) or not isinstance(contents[index], str) or not contents[index].strip():
                continue
            source_url = urljoin(map_url, str(source))
            self._persist_js_analysis(run_id, endpoint_id, JavaScriptAnalyzer.analyze(contents[index], source_url))

    def _safe_evidence(self, body: bytes | None, content_type: str) -> bytes | None:
        if not body:
            return None
        if not any(marker in content_type.lower() for marker in TEXT_TYPES):
            return None
        text = body.decode("utf-8", errors="replace")
        if "json" in content_type.lower():
            try:
                return json.dumps(self.redactor.structured(json.loads(text)), sort_keys=True).encode()
            except json.JSONDecodeError:
                pass
        return self.redactor.text(text).encode()

    def _safe_sample(self, name: str, location: str, value: Any) -> Any:
        if self.redactor.is_sensitive_name(name):
            return "[REDACTED]"
        if location == "query" and not self.config.privacy.retain_query_values:
            return "[VALUE]" if value is not None else None
        if location in {"body", "json"} and not self.config.privacy.retain_request_bodies:
            return "[VALUE]" if value is not None else None
        return self.redactor.value(name, value)

    def _blocked_by_robots(self, url: str) -> bool:
        if not self.config.crawl.respect_robots or urlsplit(url).path == "/robots.txt":
            return False
        origin = self._origin(url)
        path = urlsplit(url).path or "/"
        if origin in self._robots:
            return not self._robots[origin].can_fetch(self.config.crawl.user_agent, url)
        return any(path.startswith(prefix) for prefix in self._robots_deny.get(origin, set()))

    @staticmethod
    def _origin(url: str) -> str:
        parsed = urlsplit(url)
        return f"{parsed.scheme}://{parsed.netloc}/"

    @staticmethod
    def _is_url_template(url: str) -> bool:
        path = urlsplit(url).path
        return "{" in path or "}" in path or any(segment.startswith(":") for segment in path.split("/"))

    @staticmethod
    def _header(headers: dict[str, str], name: str) -> str:
        return next((value for key, value in headers.items() if key.lower() == name), "")
