"""Advanced recon and endpoint discovery engine for XSS Boss.

Queries Wayback Machine archives, scans JavaScript files for hidden paths,
and injects common parameter probes into discovered endpoints.
"""
import re
import urllib.request
import urllib.parse
from typing import List, Set, Dict, Any
from sqlalchemy.orm import Session
from backend_api.models.target import Target
from backend_api.services.recon_service import ReconService
from backend_api.utils.logger import logger
from backend_api.config import settings

# Common parameters to mine for XSS entry points
COMMON_XSS_PARAMS = [
    "q", "query", "search", "term", "keyword",
    "url", "redirect", "next", "dest", "destination", "goto", "return", "r",
    "debug", "admin", "test", "dev", "file", "path", "page", "id",
    "callback", "cb", "jsonp", "output", "format", "lang"
]

class AdvancedRecon:
    """Orchestrates passive OSINT, Wayback scraping, and JS link mining."""
    
    def __init__(self, db: Session, target_id: int):
        self.db = db
        self.target_id = target_id
        self.target = db.query(Target).filter(Target.id == target_id).first()
        
    def run_all(self, base_url: str) -> int:
        """Run all advanced discovery steps."""
        if not self.target:
            return 0
        
        imported_count = 0
        try:
            # 1. Archive scraping
            archive_urls = self.fetch_archive_urls(base_url)
            logger.info(f"[Advanced Recon] Discovered {len(archive_urls)} historical URLs from archives.")
            for url in archive_urls:
                if self.import_url(url):
                    imported_count += 1
            
            # 2. JS link finding on all same-host URLs
            js_links = self.discover_and_parse_js(base_url)
            logger.info(f"[Advanced Recon] Discovered {len(js_links)} endpoints inside JS files.")
            for url in js_links:
                if self.import_url(url):
                    imported_count += 1
                    
            # 3. Mine common parameters for discovered endpoints
            self.mine_parameters()
            
        except Exception as e:
            logger.warning(f"Advanced recon failed: {e}", exc_info=True)
            
        return imported_count

    def fetch_archive_urls(self, base_url: str) -> List[str]:
        """Fetch historical URLs from Wayback Machine CDX API."""
        domain = urllib.parse.urlparse(base_url).hostname
        if not domain:
            return []
            
        archive_urls = []
        cdx_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&fl=original&limit=500"
        try:
            req = urllib.request.Request(
                cdx_url, 
                headers={"User-Agent": "XSSBoss-Recon/1.0"}
            )
            with urllib.request.urlopen(req, timeout=5.0) as response:
                import json
                data = json.loads(response.read().decode("utf-8", errors="ignore"))
                if len(data) > 1:
                    for row in data[1:]:
                        if row and row[0]:
                            archive_urls.append(row[0])
        except Exception as exc:
            logger.info(f"[Advanced Recon] Wayback Machine query skipped: {exc}")
            
        return archive_urls

    def discover_and_parse_js(self, base_url: str) -> List[str]:
        """Find JS files in the page, extract relative paths/endpoints, and mine parameters."""
        from backend_api.models.endpoint import Endpoint
        from backend_api.models.param import Param
        
        endpoints = self.db.query(Endpoint).filter(Endpoint.target_id == self.target_id).all()
        
        js_files = set()
        for ep in endpoints:
            if ep.url_pattern.split("?")[0].endswith(".js"):
                js_files.add(ep.url_pattern)
                
        discovered_urls = []
        link_regex = re.compile(r"""(?:"|')(/[^"'\s\)]+)(?:"|')""")
        
        # Query parameter extraction patterns
        param_regexes = [
            # URLSearchParams.get("param") or searchParams.get('param')
            re.compile(r"""\bget\(\s*(?:"|')([a-zA-Z0-9_\-]{1,32})(?:"|')\s*\)"""),
            # getParameterByName("param") or getQueryParam("param")
            re.compile(r"""\b(?:getParameterByName|getQueryParam|getParam|getCookie)\(\s*(?:"|')([a-zA-Z0-9_\-]{1,32})(?:"|')\s*\)"""),
            # queryParams["param"] or params['param']
            re.compile(r"""\b(?:queryParams|query|params|args)\[\s*(?:"|')([a-zA-Z0-9_\-]{1,32})(?:"|')\s*\]""")
        ]
        
        mined_params = set()
        
        for js_url in list(js_files)[:15]:  # Limit to 15 JS files max
            try:
                full_js_url = urllib.parse.urljoin(base_url, js_url)
                req = urllib.request.Request(
                    full_js_url,
                    headers={"User-Agent": "XSSBoss-Recon/1.0"}
                )
                with urllib.request.urlopen(req, timeout=5.0) as response:
                    content = response.read().decode("utf-8", errors="ignore")
                    
                    # 1. Scrape URLs/Paths
                    matches = link_regex.findall(content)
                    for path in matches:
                        full_url = urllib.parse.urljoin(base_url, path)
                        discovered_urls.append(full_url)
                        
                    # 2. Mine client-side parameters
                    for regex in param_regexes:
                        param_matches = regex.findall(content)
                        for p in param_matches:
                            if p and len(p) > 1 and p not in ["true", "false", "null", "undefined"]:
                                mined_params.add(p)
                                
            except Exception as js_err:
                logger.info(f"[Advanced Recon] Could not scrape script {js_url}: {js_err}")
                
        # Register mined custom parameters to all target GET endpoints (excluding JS files themselves)
        if mined_params:
            logger.info(f"[Advanced Recon] Mined custom query parameters from JS files: {list(mined_params)}")
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

    def mine_parameters(self):
        """Append common hidden parameters to target endpoints."""
        from backend_api.models.endpoint import Endpoint
        from backend_api.models.param import Param
        
        endpoints = self.db.query(Endpoint).filter(Endpoint.target_id == self.target_id).all()
        for ep in endpoints:
            for param_name in COMMON_XSS_PARAMS:
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
        logger.info(f"[Advanced Recon] Successfully mined common hidden parameters on {len(endpoints)} endpoint(s).")

    def import_url(self, url: str) -> bool:
        """Parse url and save as GET endpoint in database."""
        try:
            parsed = urllib.parse.urlparse(url)
            request_data = {
                "method": "GET",
                "url": url,
                "headers": {},
                "query": {
                    k: v[0] if len(v) == 1 else v
                    for k, v in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items()
                },
                "body": "",
                "json": None
            }
            ReconService.create_endpoint_from_request(
                self.db,
                self.target_id,
                "GET",
                url,
                request_data
            )
            return True
        except Exception:
            return False
