"""
Modern Reconnaissance Hub & Unified Orchestrator for XSS Boss.

Executes and coordinates all modern reconnaissance, framework harvesting,
API discovery, source map reconstruction, and bundle analysis engines concurrently.
"""
from __future__ import annotations

import concurrent.futures
import json
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from sqlalchemy.orm import Session

from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from backend_api.models.target import Target
from backend_api.services.recon_service import ReconService
from backend_api.utils.logger import logger
from backend_api.utils.scope_guard import is_url_in_scope
from recon_engine.framework_harvester import FrameworkHarvester, DiscoveredRoute
from recon_engine.api_discovery import APIDiscovery, DiscoveredAPIEndpoint
from recon_engine.sourcemap_analyzer import SourceMapAnalyzer
from recon_engine.bundle_analyzer import BundleAnalyzer
from recon_engine.bundle_signal_schema import bounded_sanitizer_boundary_evidence


@dataclass
class ReconHubSummary:
    """Comprehensive summary of reconnaissance execution results."""
    target_id: int
    target_name: str
    base_url: str
    total_endpoints_imported: int
    total_params_discovered: int
    framework_routes_count: int
    graphql_endpoints_count: int
    openapi_endpoints_count: int
    discovered_sinks_count: int
    discovered_tokens_count: int
    details: Dict[str, Any] = field(default_factory=dict)


class ModernReconHub:
    """
    Unified, high-speed reconnaissance hub for modern Single Page Applications (SPAs),
    REST/GraphQL APIs, and micro-frontends.
    """

    def __init__(self, db: Session, target_id: int, timeout: float = 8.0, max_threads: int = 10):
        self.db = db
        self.target_id = target_id
        self.target = db.query(Target).filter(Target.id == target_id).first()
        if not self.target:
            raise ValueError(f"Target ID {target_id} not found in database.")
        self.base_url = self.target.base_url.rstrip("/")
        self.timeout = timeout
        self.max_threads = max_threads

        self.imported_endpoint_ids: Set[int] = set()
        self.discovered_params_count = 0

    def _fetch_bounded(
        self,
        url: str,
        *,
        max_bytes: int = 2_000_000,
        accept: str = "*/*",
    ) -> tuple[bytes, str, int, Dict[str, str]]:
        """Fetch a scoped resource with bounded redirects, auth, traffic, and memory."""
        import httpx

        from backend_api.config import settings
        from backend_api.services.auth_session_service import AuthSessionService
        from backend_api.utils.rate_limiter import rate_limiter
        from backend_api.utils.stealth import get_http_proxy_kwargs

        current = url
        for _ in range(4):
            if not is_url_in_scope(self.target, current):
                raise ValueError(f"resource is outside target scope: {current}")
            headers = {
                "User-Agent": "XSSBoss-Recon/1.0",
                "Accept": accept,
            }
            if self.target.auth_info:
                headers = AuthSessionService.request_context_for_url(
                    self.target.auth_info,
                    current,
                    self.base_url,
                    endpoint_context=headers,
                )
            proxy_kwargs = get_http_proxy_kwargs(rotated=True)
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=False,
                verify=not settings.ALLOW_INSECURE_TLS,
                **proxy_kwargs,
            ) as client:
                rate_limiter.wait_for_slot(current)
                response_reported = False
                try:
                    with client.stream("GET", current, headers=headers) as response:
                        rate_limiter.report_response(current, response)
                        response_reported = True
                        if response.status_code in {301, 302, 303, 307, 308}:
                            location = response.headers.get("location")
                            if not location:
                                raise ValueError("redirect response omitted Location")
                            current = urllib.parse.urljoin(current, location)
                            continue
                        if response.status_code != 200:
                            raise ValueError(f"resource returned HTTP {response.status_code}")
                        body = bytearray()
                        for chunk in response.iter_bytes():
                            if len(body) + len(chunk) > max_bytes:
                                raise ValueError(f"resource exceeds the {max_bytes} byte analysis limit")
                            body.extend(chunk)
                        return bytes(body), str(response.url), response.status_code, dict(response.headers)
                except Exception:
                    if not response_reported:
                        rate_limiter.report_error(current)
                    raise
        raise ValueError("resource exceeded the scoped redirect limit")

    def run_full_recon(self, html_content: Optional[str] = None, probe_remote: bool = True) -> ReconHubSummary:
        """
        Execute all modern recon engines concurrently against the target.
        """
        logger.info(f"[*] Starting Modern Recon Hub execution for target {self.target.name} ({self.base_url})")

        framework_routes: List[DiscoveredRoute] = []
        api_endpoints: List[DiscoveredAPIEndpoint] = []
        bundle_findings: Dict[str, Any] = {}
        bundle_signals: List[Dict[str, Any]] = []
        initial_document: Dict[str, Any] = {
            "source": "provided" if html_content is not None else "unavailable",
            "size_bytes": len(html_content.encode("utf-8")) if html_content is not None else 0,
        }

        # The CLI normally has no caller-provided HTML. Acquire the entry document once so
        # framework, API, and bundle analysis all operate on the same real application state.
        effective_html = html_content
        if effective_html is None and probe_remote:
            try:
                content, final_url, status, response_headers = self._fetch_bounded(
                    self.base_url,
                    accept="text/html,*/*;q=0.8",
                )
                header_names = sorted(response_headers)
                effective_html = content.decode("utf-8", errors="ignore")
                initial_document = {
                    "source": "fetched",
                    "url": final_url,
                    "status": status,
                    "size_bytes": len(content),
                    "response_header_names": header_names,
                }
            except Exception as exc:
                initial_document = {"source": "fetch_failed", "error": str(exc)[:300], "size_bytes": 0}
                logger.warning("Entry document acquisition failed: %s", exc)

        # 1. Concurrent execution of Framework Harvester & API Discovery
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_framework = executor.submit(self._run_framework_harvest, effective_html, probe_remote)
            future_api = executor.submit(self._run_api_discovery, effective_html, probe_remote)

            try:
                framework_routes = future_framework.result(timeout=self.timeout * 5)
            except Exception as e:
                logger.warning(f"Framework harvest encountered an error: {e}")

            try:
                api_endpoints = future_api.result(timeout=self.timeout * 5)
            except Exception as e:
                logger.warning(f"API discovery encountered an error: {e}")

        # 2. Extract and analyze script bundles from HTML
        if effective_html:
            script_urls = BundleAnalyzer.extract_script_urls(effective_html, self.base_url)
            logger.info(f"Discovered {len(script_urls)} client script bundles to analyze.")
            for s_url in script_urls[:20]:
                try:
                    if not is_url_in_scope(self.target, s_url):
                        continue
                    content, _, _, response_headers = self._fetch_bounded(s_url)
                    script_response_headers = {
                        header_name: str(response_headers[header_name.lower()])[:4096]
                        for header_name in ("SourceMap", "X-SourceMap")
                        if response_headers.get(header_name.lower())
                    }
                    decoded = content.decode("utf-8", errors="ignore")
                    analysis = BundleAnalyzer.analyze_script_content(
                        s_url,
                        decoded,
                        analyze_sourcemaps=probe_remote,
                        html_content=effective_html,
                        response_headers=script_response_headers,
                    )
                    for ep_str in analysis.get("internal_api_endpoints", []):
                        full_ep_url = urllib.parse.urljoin(self.base_url, ep_str)
                        self._persist_endpoint(full_ep_url, "GET", params=analysis.get("discovered_parameters", []))
                    counts = {
                        key: len(analysis.get(key, []) or [])
                        for key in (
                            "dom_sources", "dom_sinks", "navigation_sinks", "eval_sinks",
                            "postmessage_listeners", "postmessage_schemas", "sensitive_tokens",
                            "prototype_pollution", "sanitizers", "vulnerable_libraries",
                            "source_sink_flows", "smart_taint_targets", "websocket_urls",
                            "client_trust_findings",
                            "property_integrity_observations", "property_integrity_chains",
                        )
                    }
                    for category in (
                        "postmessage_unvalidated_sink",
                        "postmessage_weak_origin_validation",
                        "postmessage_wildcard_target",
                        "external_prototype_mutation",
                        "dom_named_property_to_sink",
                        "trusted_types_identity_policy",
                    ):
                        counts[category] = int(
                            (analysis.get("client_trust_summary") or {}).get(category, 0) or 0
                        )
                    for category in (
                        "dom_clobbering_chain",
                        "prototype_property_injection_chain",
                    ):
                        counts[category] = int(
                            (analysis.get("property_integrity_summary") or {}).get(category, 0) or 0
                        )
                    boundary_counts, boundary_findings = bounded_sanitizer_boundary_evidence(
                        analysis
                    )
                    counts.update(boundary_counts)
                    bundle_signals.append({
                        "kind": "client_bundle",
                        "script_url": analysis.get("url") or BundleAnalyzer.safe_artifact_url(s_url),
                        "size_bytes": len(content),
                        "counts": counts,
                        "discovered_endpoints": list(analysis.get("internal_api_endpoints", []) or [])[:100],
                        "discovered_parameters": list(analysis.get("discovered_parameters", []) or [])[:200],
                        "reachable_parameters": list(analysis.get("reachable_params", []) or [])[:100],
                        "websocket_urls": list(analysis.get("websocket_urls", []) or [])[:50],
                        "source_sink_flows": list(analysis.get("source_sink_flows", []) or [])[:100],
                        "smart_taint_targets": list(analysis.get("smart_taint_targets", []) or [])[:100],
                        "vulnerable_libraries": list(analysis.get("vulnerable_libraries", []) or [])[:100],
                        "client_trust_findings": list(analysis.get("client_trust_findings", []) or [])[:100],
                        "property_integrity_chains": list(
                            analysis.get("property_integrity_chains", []) or []
                        )[:100],
                        "sanitizer_boundary_findings": boundary_findings,
                        # Deliberately retain counts—not raw token matches.
                        "secret_indicator_count": counts["sensitive_tokens"],
                    })
                except Exception as exc:
                    # A missing lazy chunk must not erase analysis of every other bundle.
                    bundle_signals.append({
                        "kind": "client_bundle_error",
                        "script_url": s_url,
                        "error": str(exc)[:300],
                        "counts": {},
                    })
                    logger.warning("Bundle analysis failed for %s: %s", s_url, exc)

        bundle_findings = {
            "dom_sinks": sum((signal.get("counts", {}).get("dom_sinks", 0) for signal in bundle_signals), 0),
            "sensitive_tokens": sum((signal.get("counts", {}).get("sensitive_tokens", 0) for signal in bundle_signals), 0),
        }

        # 3. Persist framework routes into DB
        for fr in framework_routes:
            full_route_url = urllib.parse.urljoin(self.base_url, fr.path)
            self._persist_endpoint(
                url=full_route_url,
                method=fr.method,
                params=fr.params,
                headers=fr.headers,
                sample_body=fr.sample_body,
                notes=fr.notes,
            )

        # 4. Persist API endpoints into DB
        for api_ep in api_endpoints:
            all_params = api_ep.query_params + api_ep.path_params + api_ep.body_params
            self._persist_endpoint(
                url=api_ep.url,
                method=api_ep.method,
                params=all_params,
                sample_body=api_ep.sample_request_body,
                notes=f"API Discovery ({api_ep.api_type}): {api_ep.description}",
            )

        self.db.commit()

        summary = ReconHubSummary(
            target_id=self.target_id,
            target_name=self.target.name,
            base_url=self.base_url,
            total_endpoints_imported=len(self.imported_endpoint_ids),
            total_params_discovered=self.discovered_params_count,
            framework_routes_count=len(framework_routes),
            graphql_endpoints_count=len([e for e in api_endpoints if e.api_type == "graphql"]),
            openapi_endpoints_count=len([e for e in api_endpoints if e.api_type == "openapi"]),
            discovered_sinks_count=bundle_findings.get("dom_sinks", 0),
            discovered_tokens_count=bundle_findings.get("sensitive_tokens", 0),
            details={
                "initial_document": initial_document,
                "framework_routes": [
                    {
                        "path": route.path,
                        "method": route.method,
                        "framework": route.framework,
                        "source_type": route.source_type,
                        "params": list(route.params or []),
                        "header_names": sorted((route.headers or {}).keys()),
                        "notes": route.notes,
                    }
                    for route in framework_routes[:500]
                ],
                "api_endpoints": [
                    {
                        "url": endpoint.url,
                        "method": endpoint.method,
                        "api_type": endpoint.api_type,
                        "path_params": endpoint.path_params,
                        "query_params": endpoint.query_params,
                        "header_params": endpoint.header_params,
                        "body_params": endpoint.body_params,
                        "description": endpoint.description,
                        "auth_required": endpoint.auth_required,
                    }
                    for endpoint in api_endpoints[:500]
                ],
                "client_bundles": bundle_signals,
            },
        )
        logger.info(
            f"[+] Modern Recon Hub finished: {summary.total_endpoints_imported} endpoints imported, "
            f"{summary.total_params_discovered} parameters mined."
        )
        return summary

    def _run_framework_harvest(self, html_content: Optional[str], probe_remote: bool = True) -> List[DiscoveredRoute]:
        """Run FrameworkHarvester."""
        harvester = FrameworkHarvester(self.base_url, timeout=self.timeout)
        return harvester.harvest_all(html_content, probe_remote=probe_remote)

    def _run_api_discovery(self, html_content: Optional[str], probe_remote: bool = True) -> List[DiscoveredAPIEndpoint]:
        """Run APIDiscovery."""
        api_disc = APIDiscovery(self.base_url, timeout=self.timeout)
        return api_disc.discover_all(html_content, probe_remote=probe_remote)

    def _persist_endpoint(
        self,
        url: str,
        method: str = "GET",
        params: Optional[List[str]] = None,
        headers: Optional[Dict[str, str]] = None,
        sample_body: Optional[Any] = None,
        notes: str = ""
    ) -> Optional[Endpoint]:
        """Validate scope, normalize, and persist endpoint + parameters in DB."""
        if not url or not url.startswith(("http://", "https://")):
            return None

        # Enforce scope
        if not is_url_in_scope(self.target, url):
            return None

        try:
            parsed = urllib.parse.urlparse(url)
            query_dict = {
                k: v[0] if len(v) == 1 else v
                for k, v in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items()
            }

            # Merge mined parameter names if query doesn't have them
            for p in (params or []):
                if p and p not in query_dict:
                    query_dict[p] = "sample"

            request_data = {
                "method": method.upper(),
                "url": url,
                "headers": headers or {},
                "query": query_dict,
                "body": json.dumps(sample_body) if sample_body and isinstance(sample_body, dict) else (sample_body or ""),
                "json": sample_body if isinstance(sample_body, dict) else None,
            }

            endpoint = ReconService.create_endpoint_from_request(
                self.db,
                self.target_id,
                method.upper(),
                url,
                request_data,
            )

            if endpoint and endpoint.id:
                self.imported_endpoint_ids.add(endpoint.id)
                self.discovered_params_count += len(query_dict)
                return endpoint
        except Exception as e:
            logger.debug(f"Error persisting endpoint {url}: {e}")

        return None
