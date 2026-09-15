"""
Modern Web Framework & Meta-Framework Harvester for XSS Boss.

Extracts endpoints, dynamic routes, server action IDs, loader URLs, and serialized state
from Next.js (App & Pages router), Nuxt 3 / Nitro, Remix, SvelteKit, and Angular.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

try:
    import httpx
except ImportError:
    httpx = None

from backend_api.utils.logger import logger
from backend_api.config import settings


@dataclass
class DiscoveredRoute:
    """A discovered route or API endpoint from framework metadata."""
    path: str
    method: str = "GET"
    framework: str = "unknown"
    source_type: str = "manifest"
    params: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    sample_body: Optional[Any] = None
    notes: str = ""


class FrameworkHarvester:
    """
    State-of-the-art framework harvester for modern Single Page Applications (SPAs)
    and Server-Side Rendered (SSR) meta-frameworks.
    """

    def __init__(
        self,
        base_url: str,
        timeout: float = 2.0,
        request_headers: Optional[Dict[str, str]] = None,
        response_guard: Optional[Callable[[int, str, str], None]] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.request_headers = dict(request_headers or {})
        self.response_guard = response_guard
        self.discovered_routes: List[DiscoveredRoute] = []

    def harvest_all(self, html_content: Optional[str] = None, probe_remote: bool = True) -> List[DiscoveredRoute]:
        """Run all framework harvesters and return aggregated discovered routes."""
        routes: List[DiscoveredRoute] = []
        routes.extend(self.harvest_nextjs(html_content, probe_remote=probe_remote))
        routes.extend(self.harvest_nuxt(html_content, probe_remote=probe_remote))
        routes.extend(self.harvest_remix(html_content))
        routes.extend(self.harvest_sveltekit(html_content, probe_remote=probe_remote))
        routes.extend(self.harvest_angular(html_content))

        # Deduplicate by path + method
        seen = set()
        unique_routes = []
        for r in routes:
            key = (r.method.upper(), r.path)
            if key not in seen:
                seen.add(key)
                unique_routes.append(r)

        self.discovered_routes = unique_routes
        return self.discovered_routes

    # =========================================================================
    # 1. Next.js (App Router & Pages Router)
    # =========================================================================
    def harvest_nextjs(self, html_content: Optional[str] = None, probe_remote: bool = True) -> List[DiscoveredRoute]:
        """Harvest Next.js build manifests, SSG routes, middleware, and RSC streams."""
        routes: List[DiscoveredRoute] = []

        # 1. Extract RSC Flight Streams & Server Actions from HTML first
        if html_content:
            flight_matches = re.finditer(r'(?:self|window)\.__next_f\.push\((.*?)\)(?:\s*;|\s*<|\s*$)', html_content)
            for fm in flight_matches:
                try:
                    raw_content = fm.group(1).strip()
                    # Route references
                    route_refs = re.finditer(r'/(?:api|app|n-api|v\d+)/[a-zA-Z0-9_/.-]+', raw_content)
                    for rm in route_refs:
                        path_str = rm.group(0)
                        routes.append(
                            DiscoveredRoute(
                                path=path_str,
                                method="GET",
                                framework="nextjs_rsc",
                                source_type="rsc_flight_stream",
                                notes="Discovered from Next.js App Router RSC stream",
                            )
                        )
                    # Next-Action IDs (Server Actions)
                    action_refs = re.finditer(r'[a-f0-9]{40,64}', raw_content)
                    for ar in action_refs:
                        action_id = ar.group(0)
                        routes.append(
                            DiscoveredRoute(
                                path=self.base_url,
                                method="POST",
                                framework="nextjs_server_action",
                                source_type="rsc_server_action",
                                headers={"Next-Action": action_id},
                                notes=f"Next.js Server Action ID: {action_id}",
                            )
                        )
                except Exception:
                    pass

        # 2. Probe _buildManifest.js if probe_remote enabled
        if probe_remote:
            build_id = self._extract_next_build_id(html_content)
            manifest_urls = [
                f"{self.base_url}/_next/static/{build_id}/_buildManifest.js" if build_id else None,
                f"{self.base_url}/_next/static/development/_buildManifest.js",
                f"{self.base_url}/_next/static/{build_id}/_ssgManifest.js" if build_id else None,
                f"{self.base_url}/_next/static/{build_id}/_middlewareManifest.js" if build_id else None,
            ]

            for url in [u for u in manifest_urls if u]:
                content = self._fetch_text(url)
                if not content:
                    continue

                page_matches = re.finditer(r'["\'](/[^"\']*)["\']\s*:\s*\[', content)
                for m in page_matches:
                    p = m.group(1)
                    if not p.startswith("/_"):
                        params = self._extract_path_params(p)
                        routes.append(
                            DiscoveredRoute(
                                path=p,
                                method="GET",
                                framework="nextjs",
                                source_type="build_manifest",
                                params=params,
                                notes=f"Discovered from Next.js manifest ({url.split('/')[-1]})",
                            )
                        )

        return routes

    # =========================================================================
    # 2. Nuxt.js / Nitro (Nuxt 2 & Nuxt 3)
    # =========================================================================
    def harvest_nuxt(self, html_content: Optional[str] = None, probe_remote: bool = True) -> List[DiscoveredRoute]:
        """Harvest Nuxt 3 / Nitro static payloads, manifests, and Vue Router declarations."""
        routes: List[DiscoveredRoute] = []

        # 1. Extract window.__NUXT__ from HTML
        if html_content:
            nuxt_data_match = re.search(r'window\.__NUXT__\s*=\s*(.*?);</script>', html_content, re.DOTALL)
            if nuxt_data_match:
                raw_nuxt = nuxt_data_match.group(1)
                route_matches = re.finditer(r'["\'](/[a-zA-Z0-9_/.-]+)["\']', raw_nuxt)
                for rm in route_matches:
                    p = rm.group(1)
                    if len(p) > 1 and not p.endswith((".js", ".css", ".png", ".jpg")):
                        routes.append(
                            DiscoveredRoute(
                                path=p,
                                method="GET",
                                framework="nuxt_state",
                                source_type="nuxt_inline_state",
                                params=self._extract_path_params(p),
                                notes="Discovered from window.__NUXT__ state",
                            )
                        )

        # 2. Probe Nuxt 3 _payload.json if probe_remote enabled
        if probe_remote:
            payload_urls = [
                f"{self.base_url}/_payload.json",
                f"{self.base_url}/_payload.js",
                f"{self.base_url}/_nuxt/manifest.json",
                f"{self.base_url}/_nuxt/routes.json",
            ]

            for url in payload_urls:
                content = self._fetch_text(url)
                if not content:
                    continue

                try:
                    data = json.loads(content)
                    if isinstance(data, dict):
                        for key, val in data.items():
                            if "route" in key.lower() or "path" in key.lower():
                                if isinstance(val, list):
                                    for item in val:
                                        if isinstance(item, str) and item.startswith("/"):
                                            routes.append(
                                                DiscoveredRoute(
                                                    path=item,
                                                    method="GET",
                                                    framework="nuxt3",
                                                    source_type="nuxt_manifest",
                                                    params=self._extract_path_params(item),
                                                    notes=f"Discovered from {url.split('/')[-1]}",
                                                )
                                            )
                except Exception:
                    route_matches = re.finditer(r'["\'](/(?:api|admin|dashboard|user|auth|v\d+)/[a-zA-Z0-9_/.-]+)["\']', content)
                    for rm in route_matches:
                        routes.append(
                            DiscoveredRoute(
                                path=rm.group(1),
                                method="GET",
                                framework="nuxt",
                                source_type="nuxt_payload",
                                notes="Discovered from Nuxt static payload",
                            )
                        )

        return routes

    # =========================================================================
    # 3. Remix / React Router
    # =========================================================================
    def harvest_remix(self, html_content: Optional[str] = None) -> List[DiscoveredRoute]:
        """Harvest Remix loader endpoints, action routes, and __remixManifest."""
        routes: List[DiscoveredRoute] = []

        if html_content:
            # 1. Parse window.__remixManifest
            manifest_match = re.search(r'window\.__remixManifest\s*=\s*(\{.*?\});', html_content, re.DOTALL)
            if manifest_match:
                try:
                    manifest_data = json.loads(manifest_match.group(1))
                    routes_obj = manifest_data.get("routes", {})
                    for r_id, r_info in routes_obj.items():
                        r_path = r_info.get("path")
                        if r_path:
                            norm_path = f"/{r_path.lstrip('/')}"
                            # Remix data loader endpoint: ?_data=routes%2F...
                            loader_query = urllib.parse.urlencode({"_data": r_id})
                            routes.append(
                                DiscoveredRoute(
                                    path=f"{norm_path}?{loader_query}",
                                    method="GET",
                                    framework="remix",
                                    source_type="remix_loader",
                                    params=["_data"] + self._extract_path_params(norm_path),
                                    notes=f"Remix Route Loader ({r_id})",
                                )
                            )
                            # Standard page route
                            routes.append(
                                DiscoveredRoute(
                                    path=norm_path,
                                    method="GET",
                                    framework="remix",
                                    source_type="remix_route",
                                    params=self._extract_path_params(norm_path),
                                    notes=f"Remix Page Route ({r_id})",
                                )
                            )
                except Exception:
                    pass

            # 2. Parse window.__remixContext
            context_match = re.search(r'window\.__remixContext\s*=\s*(\{.*?\});', html_content, re.DOTALL)
            if context_match:
                try:
                    ctx_data = json.loads(context_match.group(1))
                    url_val = ctx_data.get("url")
                    if url_val:
                        routes.append(
                            DiscoveredRoute(
                                path=url_val,
                                method="GET",
                                framework="remix",
                                source_type="remix_context",
                                notes="Remix Context Active URL",
                            )
                        )
                except Exception:
                    pass

        return routes

    # =========================================================================
    # 4. SvelteKit
    # =========================================================================
    def harvest_sveltekit(self, html_content: Optional[str] = None, probe_remote: bool = True) -> List[DiscoveredRoute]:
        """Harvest SvelteKit server loaders (__data.json) and immutable manifest."""
        routes: List[DiscoveredRoute] = []

        # 1. Extract from HTML
        if html_content:
            data_json_matches = re.finditer(r'["\'](/[^"\']*/__data\.json)["\']', html_content)
            for dm in data_json_matches:
                p = dm.group(1)
                routes.append(
                    DiscoveredRoute(
                        path=p,
                        method="GET",
                        framework="sveltekit",
                        source_type="sveltekit_data_json",
                        notes="SvelteKit server-load data endpoint",
                    )
                )

        # 2. Probe immutable manifest if probe_remote enabled
        if probe_remote:
            manifest_urls = [
                f"{self.base_url}/_app/immutable/manifest.json",
                f"{self.base_url}/_app/version.json",
            ]

            for url in manifest_urls:
                content = self._fetch_text(url)
                if not content:
                    continue

                try:
                    data = json.loads(content)
                    if isinstance(data, dict):
                        nodes = data.get("nodes", [])
                        for node in nodes:
                            if isinstance(node, str) and node.startswith("/"):
                                routes.append(
                                    DiscoveredRoute(
                                        path=node,
                                        method="GET",
                                        framework="sveltekit",
                                        source_type="sveltekit_manifest",
                                        params=self._extract_path_params(node),
                                        notes="Discovered from SvelteKit immutable manifest",
                                    )
                                )
                except Exception:
                    pass

        return routes

    # =========================================================================
    # 5. Angular (Ivy & TransferState)
    # =========================================================================
    def harvest_angular(self, html_content: Optional[str] = None) -> List[DiscoveredRoute]:
        """Harvest Angular state transfers (NG_STATE) and client routes."""
        routes: List[DiscoveredRoute] = []

        if html_content:
            state_match = re.search(r'<script[^>]+id=["\'](?:serverApp-state|ng-state)["\'][^>]*>(.*?)</script>', html_content, re.DOTALL)
            if state_match:
                try:
                    state_json = json.loads(state_match.group(1))
                    for k, v in state_json.items():
                        if k.startswith("/") or k.startswith("http"):
                            parsed_path = urllib.parse.urlparse(k).path or k
                            routes.append(
                                DiscoveredRoute(
                                    path=parsed_path,
                                    method="GET",
                                    framework="angular",
                                    source_type="angular_transfer_state",
                                    notes="Angular TransferState hydrated API key",
                                )
                            )
                except Exception:
                    pass

        return routes

    # =========================================================================
    # Helper Utilities
    # =========================================================================
    def _fetch_text(self, url: str) -> Optional[str]:
        """Safely fetch HTTP text response with tight timeout."""
        if not httpx or not url:
            return None
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                **self.request_headers,
            }
            from backend_api.utils.rate_limiter import rate_limited_call

            resp = rate_limited_call(
                url,
                lambda: httpx.get(
                    url,
                    timeout=self.timeout,
                    verify=not settings.ALLOW_INSECURE_TLS,
                    follow_redirects=False,
                    headers=headers,
                ),
            )
            if self.response_guard:
                self.response_guard(resp.status_code, str(resp.url), resp.text)
            if resp.status_code == 200:
                return resp.text
        except Exception:
            pass
        return None

    def _extract_next_build_id(self, html_content: Optional[str]) -> Optional[str]:
        """Extract Next.js buildId from HTML script tags or __NEXT_DATA__."""
        if not html_content:
            return None
        match = re.search(r'/_next/static/([a-zA-Z0-9_-]{16,64})/_buildManifest\.js', html_content)
        if match:
            return match.group(1)
        match_json = re.search(r'"buildId"\s*:\s*"([a-zA-Z0-9_-]+)"', html_content)
        if match_json:
            return match_json.group(1)
        return None

    def _extract_path_params(self, path: str) -> List[str]:
        """Extract dynamic parameterized tokens like [id], :id, {id} from path."""
        params = []
        bracket_matches = re.findall(r'\[\s*\.{0,3}\s*([a-zA-Z0-9_]+)\s*\]', path)
        params.extend(bracket_matches)
        colon_matches = re.findall(r':([a-zA-Z0-9_]+)', path)
        params.extend(colon_matches)
        brace_matches = re.findall(r'\{([a-zA-Z0-9_]+)\}', path)
        params.extend(brace_matches)
        return list(dict.fromkeys(params))
