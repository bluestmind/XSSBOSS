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

    def run_full_recon(self, html_content: Optional[str] = None, probe_remote: bool = True) -> ReconHubSummary:
        """
        Execute all modern recon engines concurrently against the target.
        """
        logger.info(f"[*] Starting Modern Recon Hub execution for target {self.target.name} ({self.base_url})")

        framework_routes: List[DiscoveredRoute] = []
        api_endpoints: List[DiscoveredAPIEndpoint] = []
        bundle_findings: Dict[str, Any] = {}

        # 1. Concurrent execution of Framework Harvester & API Discovery
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_framework = executor.submit(self._run_framework_harvest, html_content, probe_remote)
            future_api = executor.submit(self._run_api_discovery, html_content, probe_remote)

            try:
                framework_routes = future_framework.result(timeout=self.timeout * 5)
            except Exception as e:
                logger.warning(f"Framework harvest encountered an error: {e}")

            try:
                api_endpoints = future_api.result(timeout=self.timeout * 5)
            except Exception as e:
                logger.warning(f"API discovery encountered an error: {e}")

        # 2. Extract and analyze script bundles from HTML
        if html_content:
            try:
                script_urls = BundleAnalyzer.extract_script_urls(html_content, self.base_url)
                logger.info(f"Discovered {len(script_urls)} client script bundles to analyze.")
                for s_url in script_urls[:20]:
                    analysis = BundleAnalyzer.analyze_script_content(s_url, "", analyze_sourcemaps=probe_remote)
                    for ep_str in analysis.get("internal_api_endpoints", []):
                        full_ep_url = urllib.parse.urljoin(self.base_url, ep_str)
                        self._persist_endpoint(full_ep_url, "GET", params=analysis.get("discovered_parameters", []))
            except Exception as e:
                logger.warning(f"Bundle analysis error: {e}")

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
            discovered_sinks_count=len(bundle_findings.get("dom_sinks", [])),
            discovered_tokens_count=len(bundle_findings.get("sensitive_tokens", [])),
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
