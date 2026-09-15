"""Ultimate modern reconnaissance and endpoint discovery engine for XSS Boss.

Features:
- Multi-source passive OSINT aggregation (Wayback Machine, AlienVault OTX, URLScan.io)
- Active metadata & manifest harvesting (robots.txt, sitemap.xml, Next.js _buildManifest)
- Source map (.map) exposure auditing and route extraction
- OpenAPI / Swagger specification parsing and GraphQL endpoint discovery
- Intelligent binary asset noise filtering and strict scope validation
- Deep client-side JavaScript parameter mining for modern SPAs (React, Next.js, Vue)
"""
import concurrent.futures
import contextvars
import json
import re
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Set

from sqlalchemy.orm import Session

from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from backend_api.models.target import Target
from backend_api.config import settings
from backend_api.services.auth_session_service import AuthSessionService
from backend_api.services.recon_service import ReconService
from backend_api.utils.logger import logger
from backend_api.utils.scope_guard import is_url_in_scope
from recon_engine.framework_harvester import FrameworkHarvester
from recon_engine.api_discovery import APIDiscovery
from recon_engine.sourcemap_analyzer import SourceMapAnalyzer


# High-value parameter dictionary targeting modern SPA redirects, state handling, and XSS sinks
COMMON_XSS_PARAMS = [
    # Classic query & search
    "q", "query", "search", "term", "keyword", "s",
    # Redirects, navigation & state transfer (Crucial for DOM XSS)
    "url", "redirect", "redirect_uri", "redirectUrl", "redirect_url",
    "originUrl", "origin_url", "targetUrl", "target_url", "dest", "destination",
    "goto", "return", "returnUrl", "return_url", "r", "next", "continue", "continueUrl",
    "relayState", "forward", "referrer", "backUrl", "checkoutUrl", "cartUrl",
    "cartRedirectPayload", "listingId", "marketplaceKey", "state", "callbackUrl",
    # Debug & privileged modes
    "debug", "admin", "test", "dev", "preview", "enable", "mode", "view",
    # Files & resources
    "file", "path", "page", "id", "doc", "template", "include", "src",
    # JSONP & callbacks
    "callback", "cb", "jsonp", "output", "format", "lang", "locale"
]

# Static binary extensions to filter out from recon results
STATIC_MEDIA_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".tiff",
    ".mp4", ".mp3", ".avi", ".mov", ".flv", ".wmv", ".webm",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".css", ".less", ".scss", ".sass",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".rar", ".7z"
}


class AdvancedRecon:
    """Orchestrates passive OSINT, active manifest scraping, and JS endpoint/parameter mining."""

    def __init__(
        self,
        db: Session,
        target_id: int,
        *,
        auth_identity: Optional[str] = None,
        session_auth: Optional[Dict[str, Any]] = None,
    ):
        self.db = db
        self.target_id = target_id
        self.target = db.query(Target).filter(Target.id == target_id).first()
        self.auth_identity = auth_identity
        # A crawler-renewed session takes precedence over the original static material.
        self.auth_info = session_auth or (self.target.auth_info if self.target else None)
        self.imported_endpoint_ids: Set[int] = set()
        self.discovered_urls: Set[str] = set()
        self.interventions: List[Dict[str, Any]] = []

    def _active_headers(self, url: str, defaults: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers = dict(defaults or {})
        if not self.auth_info or not self.target:
            return headers
        context = AuthSessionService.request_context_for_url(
            self.auth_info,
            url,
            self.target.base_url,
            self.auth_identity,
        )
        headers.update(context)
        return headers

    def _guard_active_response(self, status_code: int, final_url: str, body_text: str) -> None:
        if self.interventions:
            return
        patterns = ()
        identity = self.auth_identity
        if self.auth_info:
            try:
                material = AuthSessionService.material(self.auth_info, self.auth_identity)
                patterns = material.login_url_patterns
                identity = material.label
            except Exception:
                pass
        reason = AuthSessionService.response_intervention_reason(
            status_code=status_code,
            final_url=final_url,
            body_text=body_text,
            login_url_patterns=patterns,
        )
        if reason:
            self.interventions.append({
                "kind": "authentication_challenge",
                "identity": identity,
                "reason": reason,
                "url": final_url,
            })

    def _fetch_active_text(
        self,
        url: str,
        *,
        timeout: float,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[bytes] = None,
        method: str = "GET",
        max_bytes: int = 5 * 1024 * 1024,
    ) -> str:
        """Fetch one active target resource with origin-bound auth and bounded evidence."""
        if self.interventions:
            return ""
        if self.target and not is_url_in_scope(self.target, url):
            return ""
        merged = self._active_headers(url, headers)
        import httpx

        from backend_api.utils.rate_limiter import rate_limiter
        from backend_api.utils.stealth import get_http_proxy_kwargs

        with httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            verify=not settings.ALLOW_INSECURE_TLS,
            **get_http_proxy_kwargs(rotated=True),
        ) as client:
            rate_limiter.wait_for_slot(url)
            response_reported = False
            try:
                with client.stream(
                    method,
                    url,
                    content=data,
                    headers=merged,
                ) as response:
                    rate_limiter.report_response(url, response)
                    response_reported = True
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        if len(body) + len(chunk) > max_bytes:
                            return ""
                        body.extend(chunk)
                    encoding = response.encoding or "utf-8"
                    text = bytes(body).decode(encoding, errors="replace")
                    self._guard_active_response(
                        response.status_code,
                        str(response.url),
                        text,
                    )
                    return text if response.status_code == 200 else ""
            except Exception:
                if not response_reported:
                    rate_limiter.report_error(url)
                raise

    def _is_relevant_url(self, url: str) -> bool:
        """Filter out non-exploitable binary media files and enforce scope."""
        if not url or not url.startswith(("http://", "https://")):
            return False

        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lower()

        # If URL has query parameters, it's dynamic and always relevant
        if not parsed.query:
            # Check against static media extension blacklist
            for ext in STATIC_MEDIA_EXTENSIONS:
                if path.endswith(ext):
                    return False

        # Enforce scope if target is defined
        if self.target:
            try:
                return is_url_in_scope(self.target, url)
            except Exception:
                pass

        return True

    def import_url(self, url: str) -> bool:
        """Parse url and save as GET endpoint in database."""
        if not self._is_relevant_url(url):
            return False

        try:
            parsed = urllib.parse.urlparse(url)
            query_params = {
                k: v[0] if len(v) == 1 else v
                for k, v in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items()
            }
            request_data = {
                "method": "GET",
                "url": url,
                "headers": {},
                "query": query_params,
                "body": "",
                "json": None
            }
            endpoint = ReconService.create_endpoint_from_request(
                self.db,
                self.target_id,
                "GET",
                url,
                request_data
            )
            if endpoint and endpoint.id:
                self.imported_endpoint_ids.add(endpoint.id)
                self.discovered_urls.add(url)
                return True
            return False
        except Exception:
            return False

    def run_all(self, base_url: str) -> int:
        """Run all advanced discovery steps."""
        if not self.target:
            return 0

        imported_count = 0
        logger.info(f"[Advanced Recon] Launching full modern recon on {base_url}...")

        # 1. Multi-source passive OSINT scraping (Wayback + AlienVault OTX + URLScan + crt.sh)
        try:
            passive_urls = self.fetch_passive_urls(base_url)
            logger.info(f"[Advanced Recon] Discovered {len(passive_urls)} endpoints from passive OSINT sources.")
            for url in passive_urls:
                if self.import_url(url):
                    imported_count += 1
            
            ct_urls = self.fetch_certificate_transparency_domains(base_url)
            logger.info(f"[Advanced Recon] Discovered {len(ct_urls)} in-scope domains from Certificate Transparency.")
            for url in ct_urls:
                if self.import_url(url):
                    imported_count += 1
        except Exception as e:
            logger.warning(f"[Advanced Recon] Passive OSINT collection failed: {e}")

        # 2. Active metadata & manifest harvesting (robots.txt, sitemap.xml)
        try:
            manifest_urls = self.fetch_robots_and_sitemaps(base_url)
            logger.info(f"[Advanced Recon] Discovered {len(manifest_urls)} endpoints from robots.txt & sitemaps.")
            for url in manifest_urls:
                if self.import_url(url):
                    imported_count += 1
        except Exception as e:
            logger.warning(f"[Advanced Recon] Manifest harvesting failed: {e}")

        # 3. Modern Next.js build manifests & source maps
        try:
            app_urls = self.discover_manifests_and_sourcemaps(base_url)
            logger.info(f"[Advanced Recon] Discovered {len(app_urls)} endpoints from build manifests / source maps.")
            for url in app_urls:
                if self.import_url(url):
                    imported_count += 1
        except Exception as e:
            logger.warning(f"[Advanced Recon] Manifest / source map audit failed: {e}")

        # 4. API specification & schema discovery (OpenAPI, Swagger, GraphQL)
        try:
            api_urls = self.probe_api_specs(base_url)
            logger.info(f"[Advanced Recon] Discovered {len(api_urls)} endpoints from API specs / schemas.")
            for url in api_urls:
                if self.import_url(url):
                    imported_count += 1
        except Exception as e:
            logger.warning(f"[Advanced Recon] API spec discovery failed: {e}")

        # 5. Client-side JS link and parameter mining
        try:
            js_links = self.discover_and_parse_js(base_url)
            logger.info(f"[Advanced Recon] Discovered {len(js_links)} endpoints inside JS files.")
            for url in js_links:
                if self.import_url(url):
                    imported_count += 1
        except Exception as e:
            logger.warning(f"[Advanced Recon] JS link discovery failed: {e}")

        # 6. Mine high-impact common parameters on target endpoints
        try:
            self.mine_parameters()
        except Exception as e:
            logger.warning(f"[Advanced Recon] Parameter mining failed: {e}")

        logger.info(f"[Advanced Recon] Recon completed! Total unique imported endpoints: {imported_count}")
        return imported_count

    # =========================================================================
    # 1. Multi-Source Passive OSINT
    # =========================================================================

    def fetch_archive_urls(self, base_url: str) -> List[str]:
        """Fetch historical URLs from Wayback Machine CDX API."""
        domain = urllib.parse.urlparse(base_url).hostname
        if not domain:
            return []
        urls = []
        cdx_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&fl=original&limit=1000"
        try:
            req = urllib.request.Request(cdx_url, headers={"User-Agent": "XSSBoss-Recon/1.0"})
            with urllib.request.urlopen(req, timeout=6.0) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                if len(data) > 1:
                    for row in data[1:]:
                        if row and row[0]:
                            urls.append(row[0])
        except Exception as e:
            logger.debug(f"[Passive Recon] Wayback query failed: {e}")
        return urls

    def fetch_passive_urls(self, base_url: str) -> List[str]:
        """Fetch historical URLs concurrently from Wayback, AlienVault OTX, and URLScan."""
        domain = urllib.parse.urlparse(base_url).hostname
        if not domain:
            return []

        all_urls: Set[str] = set()

        def fetch_wayback() -> List[str]:
            return self.fetch_archive_urls(base_url)

        def fetch_otx() -> List[str]:
            urls = []
            otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500"
            try:
                req = urllib.request.Request(otx_url, headers={"User-Agent": "XSSBoss-Recon/1.0"})
                with urllib.request.urlopen(req, timeout=6.0) as resp:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                    url_list = data.get("url_list", [])
                    for item in url_list:
                        u = item.get("url")
                        if u:
                            urls.append(u)
            except Exception as e:
                logger.debug(f"[Passive Recon] AlienVault OTX query failed: {e}")
            return urls

        def fetch_urlscan() -> List[str]:
            urls = []
            urlscan_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"
            try:
                req = urllib.request.Request(urlscan_url, headers={"User-Agent": "XSSBoss-Recon/1.0"})
                with urllib.request.urlopen(req, timeout=6.0) as resp:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                    results = data.get("results", [])
                    for res in results:
                        page = res.get("page", {})
                        u = page.get("url")
                        if u:
                            urls.append(u)
            except Exception as e:
                logger.debug(f"[Passive Recon] URLScan query failed: {e}")
            return urls

        # Run passive queries concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            future_wayback = executor.submit(fetch_wayback)
            future_otx = executor.submit(fetch_otx)
            future_urlscan = executor.submit(fetch_urlscan)

            for f in concurrent.futures.as_completed([future_wayback, future_otx, future_urlscan]):
                try:
                    for u in f.result():
                        if self._is_relevant_url(u):
                            all_urls.add(u)
                except Exception:
                    pass

        return list(all_urls)

    # =========================================================================
    # 2. Robots & Sitemap Harvesting
    # =========================================================================

    def fetch_robots_and_sitemaps(self, base_url: str) -> List[str]:
        """Harvest disallowed routes and sitemap links from robots.txt and sitemap.xml."""
        discovered: Set[str] = set()
        sitemaps_to_crawl: Set[str] = set()

        # 1. Fetch robots.txt
        robots_url = urllib.parse.urljoin(base_url, "/robots.txt")
        try:
            text = self._fetch_active_text(
                robots_url, timeout=4.0, headers={"User-Agent": "Mozilla/5.0"}
            )
            for line in text.splitlines():
                line = line.strip()
                if line.lower().startswith(("disallow:", "allow:")):
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        path = parts[1].strip()
                        if path and not path.startswith("*"):
                            full_url = urllib.parse.urljoin(base_url, path)
                            if self._is_relevant_url(full_url):
                                discovered.add(full_url)
                elif line.lower().startswith("sitemap:"):
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        s_url = parts[1].strip()
                        if s_url.startswith("http"):
                            sitemaps_to_crawl.add(s_url)
        except Exception:
            pass

        # Default sitemap.xml fallback
        sitemaps_to_crawl.add(urllib.parse.urljoin(base_url, "/sitemap.xml"))

        # 2. Fetch sitemaps
        for sm_url in list(sitemaps_to_crawl)[:3]:
            try:
                xml_content = self._fetch_active_text(
                    sm_url, timeout=4.0, headers={"User-Agent": "Mozilla/5.0"}
                )
                root = ET.fromstring(xml_content)
                # Extract all <loc> values
                for elem in root.iter():
                    if elem.tag.endswith("loc") and elem.text:
                        loc_url = elem.text.strip()
                        if self._is_relevant_url(loc_url):
                            discovered.add(loc_url)
            except Exception:
                pass

        return list(discovered)

    # =========================================================================
    # 3. Modern Framework Manifests & Source Map Exposure
    # =========================================================================

    def discover_manifests_and_sourcemaps(self, base_url: str) -> List[str]:
        """Harvest Next.js, Nuxt, Remix, and SvelteKit routes and check for exposed source maps (.map)."""
        discovered: Set[str] = set()

        # 1. Use FrameworkHarvester for Next.js, Nuxt 3, Remix, SvelteKit, Angular
        try:
            harvester = FrameworkHarvester(
                base_url,
                timeout=6.0,
                request_headers=self._active_headers(base_url),
                response_guard=self._guard_active_response,
            )
            routes = harvester.harvest_all()
            for r in routes:
                full_url = urllib.parse.urljoin(base_url, r.path)
                if self._is_relevant_url(full_url):
                    discovered.add(full_url)
        except Exception as e:
            logger.debug(f"[Framework Harvester] Error: {e}")

        # 2. Check for exposed source maps (.map) on registered script bundles
        endpoints = self.db.query(Endpoint).filter(Endpoint.target_id == self.target_id).all()
        js_endpoints = [ep.url_pattern for ep in endpoints if ep.url_pattern.split("?")[0].endswith(".js")]

        for js_url in js_endpoints[:10]:
            try:
                sm_analyzer = SourceMapAnalyzer(
                    timeout=4.0,
                    request_headers=self._active_headers(js_url),
                    response_guard=self._guard_active_response,
                )
                findings = sm_analyzer.analyze_script_for_sourcemap(js_url)
                for f in findings:
                    for ep_path in f.discovered_endpoints:
                        full_ep = urllib.parse.urljoin(base_url, ep_path)
                        if self._is_relevant_url(full_ep):
                            discovered.add(full_ep)
            except Exception:
                pass

        return list(discovered)

    # =========================================================================
    # 4. OpenAPI, Swagger & GraphQL Specification Probes
    # =========================================================================

    def probe_api_specs(self, base_url: str) -> List[str]:
        """Probe for Swagger, OpenAPI, and GraphQL endpoint declarations using APIDiscovery."""
        discovered: Set[str] = set()
        try:
            api_disc = APIDiscovery(
                base_url,
                timeout=6.0,
                request_headers=self._active_headers(base_url),
                response_guard=self._guard_active_response,
            )
            endpoints = api_disc.discover_all()
            for ep in endpoints:
                if self._is_relevant_url(ep.url):
                    discovered.add(ep.url)
        except Exception as e:
            logger.debug(f"[API Discovery] Error: {e}")

        # Direct probe with urllib for OpenAPI/Swagger endpoints
        for path in ["/openapi.json", "/swagger.json", "/api-docs", "/v2/api-docs", "/v3/api-docs"]:
            spec_url = urllib.parse.urljoin(base_url, path)
            try:
                raw = self._fetch_active_text(
                    spec_url,
                    timeout=4.0,
                    headers={"User-Agent": "XSSBoss-Recon/1.0", "Accept": "application/json"},
                )
                data = json.loads(raw)
                paths = data.get("paths", {})
                if isinstance(paths, dict):
                    for p in paths:
                        full_ep = urllib.parse.urljoin(base_url, p)
                        if self._is_relevant_url(full_ep):
                            discovered.add(full_ep)
            except Exception:
                continue

        return list(discovered)

    def fetch_certificate_transparency_domains(self, base_url: str) -> List[str]:
        """Query crt.sh Certificate Transparency logs for related in-scope subdomains."""
        domain = urllib.parse.urlparse(base_url).hostname
        if not domain:
            return []
        
        parts = domain.split('.')
        root_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain

        discovered_subdomains: Set[str] = set()
        crt_url = f"https://crt.sh/?q=%.{root_domain}&output=json"
        try:
            req = urllib.request.Request(crt_url, headers={"User-Agent": "XSSBoss-Recon/1.0"})
            with urllib.request.urlopen(req, timeout=6.0) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                for entry in data:
                    name_val = entry.get("name_value", "")
                    for sub in name_val.split("\n"):
                        sub = sub.strip().lower()
                        if sub and not sub.startswith("*.") and root_domain in sub:
                            sub_url = f"https://{sub}"
                            if self._is_relevant_url(sub_url):
                                discovered_subdomains.add(sub_url)
        except Exception as e:
            logger.debug(f"[Passive Recon] Certificate Transparency lookup skipped: {e}")

        return list(discovered_subdomains)[:50]

    def probe_graphql_schema(self, base_url: str) -> List[str]:
        """Probe GraphQL endpoints for introspection and extract query/mutation entry points."""
        discovered: Set[str] = set()
        gql_candidates = ["/graphql", "/api/graphql", "/v1/graphql"]

        introspection_query = json.dumps({
            "query": "{ __schema { queryType { fields { name } } mutationType { fields { name } } } }"
        }).encode("utf-8")

        for cand in gql_candidates:
            cand_url = urllib.parse.urljoin(base_url, cand)
            try:
                raw = self._fetch_active_text(
                    cand_url,
                    timeout=4.0,
                    data=introspection_query,
                    headers={"Content-Type": "application/json", "User-Agent": "XSSBoss-Recon/1.0"},
                    method="POST",
                )
                data = json.loads(raw)
                schema = data.get("data", {}).get("__schema", {})
                discovered.add(cand_url)
                for t in ["queryType", "mutationType"]:
                    fields = (schema.get(t) or {}).get("fields", [])
                    for f in fields:
                        field_name = f.get("name")
                        if field_name:
                            query_url = f"{cand_url}?query={{{field_name}}}"
                            discovered.add(query_url)
            except Exception:
                pass

        return list(discovered)

    # =========================================================================
    # 5. Client-side JS Link & Parameter Mining
    # =========================================================================

    def discover_and_parse_js(self, base_url: str) -> List[str]:
        """Find JS files in the page, extract relative paths/endpoints, and mine parameters."""
        endpoints = self.db.query(Endpoint).filter(Endpoint.target_id == self.target_id).all()
        js_files = {ep.url_pattern for ep in endpoints if ep.url_pattern.split("?")[0].endswith(".js")}

        discovered_urls = []
        link_regex = re.compile(r"""(?:"|')(/[^"'\s\)]+)(?:"|')""")

        # Modern parameter extraction patterns
        param_regexes = [
            re.compile(r"""\bget\(\s*(?:"|')([a-zA-Z0-9_\-]{1,32})(?:"|')\s*\)"""),
            re.compile(r"""\b(?:getParameterByName|getQueryParam|getParam|getCookie)\(\s*(?:"|')([a-zA-Z0-9_\-]{1,32})(?:"|')\s*\)"""),
            re.compile(r"""\b(?:queryParams|query|params|args)\[\s*(?:"|')([a-zA-Z0-9_\-]{1,32})(?:"|')\s*\]"""),
            re.compile(r"""\b[a-zA-Z0-9_$]*(?:Params|Query|Args)\s*\.\s*([a-zA-Z0-9_\-]{1,32})\b"""),
            re.compile(r"""(?:const|let|var)\s*\{\s*([a-zA-Z0-9_\-,\s]+)\s*\}\s*=\s*(?:urlParams|queryParams|params|args|searchParams)"""),
            re.compile(r"""\brouter\.query\.([a-zA-Z0-9_\-]{1,32})\b"""),
            re.compile(r"""\b(?:useSearchParams|searchParams)\(\)\.get\(\s*(?:"|')([a-zA-Z0-9_\-]{1,32})(?:"|')\s*\)"""),
            re.compile(r"""\bsearchParams\.get\(\s*(?:"|')([a-zA-Z0-9_\-]{1,32})(?:"|')\s*\)""")
        ]

        mined_params: Set[str] = set()
        html_endpoints = [ep for ep in endpoints if not ep.url_pattern.split("?")[0].endswith(".js")]

        def fetch_script_content(js_url: str):
            try:
                full_js_url = urllib.parse.urljoin(base_url, js_url)
                return js_url, self._fetch_active_text(
                    full_js_url, timeout=3.0, headers={"User-Agent": "XSSBoss-Recon/1.0"}
                )
            except Exception:
                return js_url, ""

        def fetch_html_inline_scripts(html_url: str):
            try:
                full_html_url = urllib.parse.urljoin(base_url, html_url)
                html_content = self._fetch_active_text(
                    full_html_url, timeout=3.0, headers={"User-Agent": "XSSBoss-Recon/1.0"}
                )
                inline_scripts = re.findall(r'<script(?![^>]*\bsrc\b)[^>]*>(.*?)</script>', html_content, flags=re.IGNORECASE | re.DOTALL)
                return html_url, "\n".join(inline_scripts)
            except Exception:
                return html_url, ""

        js_list = list(js_files)[:25]
        html_list = [ep.url_pattern for ep in html_endpoints][:15]

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            future_to_url = {
                executor.submit(contextvars.copy_context().run, fetch_script_content, url): url
                for url in js_list
            }
            future_to_html = {
                executor.submit(contextvars.copy_context().run, fetch_html_inline_scripts, url): url
                for url in html_list
            }
            all_futures = {**future_to_url, **future_to_html}

            for future in concurrent.futures.as_completed(all_futures):
                resource_url, content = future.result()
                if not content:
                    continue
                try:
                    # 1. Scrape URLs/Paths
                    matches = link_regex.findall(content)
                    for path in matches:
                        full_url = urllib.parse.urljoin(base_url, path)
                        if self._is_relevant_url(full_url):
                            discovered_urls.append(full_url)

                    # 2. Mine parameters
                    for regex in param_regexes:
                        param_matches = regex.findall(content)
                        for p in param_matches:
                            sub_params = [sp.strip() for sp in p.split(",")] if "," in p else [p]
                            for sp in sub_params:
                                if sp and len(sp) > 1 and sp not in ["true", "false", "null", "undefined"]:
                                    mined_params.add(sp)
                except Exception:
                    pass

        # Register mined custom parameters to all target GET endpoints
        if mined_params:
            logger.info(f"[Advanced Recon] Mined custom query parameters from scripts: {list(mined_params)}")
            target_name = self.target.name if self.target else "Recon Engine"
            try:
                from backend_api.services.learned_dictionary_service import LearnedDictionaryService
                LearnedDictionaryService.register_batch(mined_params, source=target_name)
            except Exception as le_err:
                logger.warning(f"[Advanced Recon] Auto-learn dictionary registration warning: {le_err}")

            get_endpoints = [ep for ep in endpoints if ep.method == "GET" and not ep.url_pattern.split("?")[0].endswith(".js")]
            for ep in get_endpoints:
                for param_name in mined_params:
                    exists = self.db.query(Param).filter(
                        Param.endpoint_id == ep.id,
                        Param.name == param_name
                    ).first()
                    if not exists:
                        param = Param(
                            endpoint_id=ep.id,
                            name=param_name,
                            location="query",
                            is_controllable=True
                        )
                        self.db.add(param)
            self.db.commit()

        return list(set(discovered_urls))

    # =========================================================================
    # 6. Common Parameter Seeding
    # =========================================================================

    def mine_parameters(self):
        """Append common and auto-learned hidden parameters to target endpoints."""
        endpoints = self.db.query(Endpoint).filter(Endpoint.target_id == self.target_id).all()
        fuzz_params = list(COMMON_XSS_PARAMS)
        try:
            from backend_api.services.learned_dictionary_service import LearnedDictionaryService
            learned_names = LearnedDictionaryService.get_fuzzing_param_names()
            fuzz_params = list(dict.fromkeys(COMMON_XSS_PARAMS + learned_names))
        except Exception:
            pass

        for ep in endpoints:
            if ep.url_pattern.split("?")[0].endswith(tuple(STATIC_MEDIA_EXTENSIONS)):
                continue
            for param_name in fuzz_params:
                exists = self.db.query(Param).filter(
                    Param.endpoint_id == ep.id,
                    Param.name == param_name
                ).first()
                if not exists:
                    param = Param(
                        endpoint_id=ep.id,
                        name=param_name,
                        location="query",
                        is_controllable=True
                    )
                    self.db.add(param)
        self.db.commit()
        logger.info(f"[Advanced Recon] Successfully seeded {len(fuzz_params)} common/learned hidden parameters on {len(endpoints)} endpoint(s).")

    # =========================================================================
    # 7. Google Dorking Engine (Learned from PDF Research)
    # =========================================================================

    @staticmethod
    def generate_target_dorks(domain: str) -> List[Dict[str, str]]:
        """Generate high-yield Google/OSINT dorks targeting vulnerabilities, secrets, and XSS reflections."""
        clean_domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        categories = [
            ("xss_reflection", f'site:{clean_domain} inurl:(q|query|search|redirect|url|return|dest)=', "Reflection parameters prone to XSS and Open Redirects"),
            ("exposed_api", f'site:{clean_domain} inurl:(api|swagger|graphql|v1|v2|openapi)', "Exposed API endpoints and documentation schema"),
            ("sensitive_files", f'site:{clean_domain} ext:(env|log|sql|bak|yml|yaml|json|conf|config)', "Accidental exposures of secrets and database backups"),
            ("directory_listing", f'site:{clean_domain} intitle:"index of"', "Enabled web directory indexing revealing source files"),
            ("admin_portals", f'site:{clean_domain} inurl:(admin|login|portal|dashboard|auth)', "Administrative entry points and login planes"),
            ("oauth_redirects", f'site:{clean_domain} inurl:(redirect_uri|callback|oauth|authorize)', "OAuth authorization flows for redirect manipulation"),
        ]
        return [{"category": cat, "dork": dork, "description": desc} for cat, dork, desc in categories]
