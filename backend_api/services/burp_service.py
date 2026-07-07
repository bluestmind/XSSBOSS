"""Burp Suite integration service."""
import re
import time
import xml.etree.ElementTree as ET
import httpx
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from urllib.parse import quote, urlparse, urlunparse

from backend_api.services.recon_service import ReconService
from backend_api.config import settings
from backend_api.models.target import Target
from backend_api.utils.logger import logger
from recon_engine.burp_import import BurpImporter

class BurpService:
    """Orchestrate Burp Suite integrations."""
    BURP_API_VERSIONS = ("v0.1", "v1")
    SCAN_PREFLIGHT_TIMEOUT = httpx.Timeout(12.0, connect=4.0)

    @staticmethod
    def _canonical_seed_url(url: str) -> str:
        """Normalize a scanner seed URL while preserving path/query."""
        parsed = urlparse((url or "").strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"Burp scan seed must be an absolute http(s) URL: {url}")

        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path or "/"
        return urlunparse((scheme, netloc, path, "", parsed.query, ""))

    @staticmethod
    def _scheme_variant(url: str, scheme: str) -> str:
        parsed = urlparse(BurpService._canonical_seed_url(url))
        return urlunparse((scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))

    @staticmethod
    def _same_host(url_a: str, url_b: str) -> bool:
        return (urlparse(url_a).hostname or "").lower() == (urlparse(url_b).hostname or "").lower()

    @staticmethod
    def preflight_seed_url(url: str, proxy_url: Optional[str] = None) -> Dict[str, Any]:
        """Check a seed URL through the same Burp proxy path used by XSS Boss probes."""
        seed_url = BurpService._canonical_seed_url(url)
        kwargs: Dict[str, Any] = {
            "timeout": BurpService.SCAN_PREFLIGHT_TIMEOUT,
            "follow_redirects": True,
            "trust_env": False,
            "verify": False,
        }
        if proxy_url:
            kwargs["proxies"] = proxy_url

        headers = {
            "User-Agent": "XSSBoss-Burp-Seed-Preflight/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        try:
            with httpx.Client(**kwargs) as client:
                response = client.get(seed_url, headers=headers)
            return {
                "url": seed_url,
                "reachable": response.status_code < 500,
                "status_code": response.status_code,
                "final_url": str(response.url),
                "error": None,
            }
        except Exception as exc:
            return {
                "url": seed_url,
                "reachable": False,
                "status_code": None,
                "final_url": None,
                "error": f"{type(exc).__name__}: {exc}",
            }

    @staticmethod
    def prepare_scan_seed_urls(target_urls: List[str], proxy_url: Optional[str] = None) -> Dict[str, Any]:
        """Build Burp scanner seeds, preferring a preflight-confirmed final URL."""
        seed_urls: List[str] = []
        preflights: List[Dict[str, Any]] = []

        def add_seed(candidate: Optional[str]) -> None:
            if not candidate:
                return
            try:
                normalized = BurpService._canonical_seed_url(candidate)
            except ValueError:
                return
            if normalized not in seed_urls:
                seed_urls.append(normalized)

        for raw_url in target_urls:
            original = BurpService._canonical_seed_url(raw_url)
            preflight = BurpService.preflight_seed_url(original, proxy_url=proxy_url)
            preflights.append(preflight)

            final_url = preflight.get("final_url")
            if preflight.get("reachable") and final_url and BurpService._same_host(original, final_url):
                add_seed(final_url)

            add_seed(original)
            parsed = urlparse(original)
            alternate_scheme = "http" if parsed.scheme == "https" else "https"
            add_seed(BurpService._scheme_variant(original, alternate_scheme))

        return {
            "urls": seed_urls,
            "preflights": preflights,
        }

    @staticmethod
    def import_xml(db: Session, target_id: int, xml_content: str) -> int:
        """Parse Burp XML export contents and import to target.
        
        Args:
            db: Session
            target_id: Target ID
            xml_content: Raw XML string
            
        Returns:
            Number of endpoints imported
        """
        try:
            root = ET.fromstring(xml_content.encode('utf-8', errors='ignore'))
            requests = []
            
            for item in root.findall('.//item'):
                request_data = BurpImporter._parse_item(item)
                if request_data:
                    requests.append(request_data)
            
            count = 0
            for request_data in requests:
                try:
                    ReconService.create_endpoint_from_request(
                        db,
                        target_id,
                        request_data['method'],
                        request_data['url'],
                        request_data,
                        {'body': request_data.get('response')} if 'response' in request_data else None
                    )
                    count += 1
                except Exception as e:
                    logger.error(f"Error importing XML request to target={target_id}: {e}")
                    continue
            return count
        except Exception as e:
            logger.error(f"Failed parsing Burp XML upload: {e}", exc_info=True)
            raise ValueError(f"Invalid Burp Suite XML: {str(e)}")

    @staticmethod
    def _base_url(api_url: str) -> str:
        """Strip any Burp API version suffix from a user-entered base URL."""
        api_url = api_url.rstrip("/")
        return re.sub(r'/(?:[^/]+/)?v\d+(?:\.\d+)?/?$', '', api_url)

    @staticmethod
    def _build_url(api_url: str, api_key: Optional[str], path: str, version: str = "v0.1") -> str:
        """Build a normalized Burp REST API URL.
        
        Burp Suite's scanner REST API builds the URL as:
        - http://<host>:<port>/v0.1/<path>

        API keys are sent via the Authorization header. Older Burp versions also
        accepted path-based keys; those are handled by _build_legacy_url.
        """
        api_url = BurpService._base_url(api_url)
        path = path.lstrip("/")
        return f"{api_url}/{version}/{path}"

    @staticmethod
    def _build_legacy_url(api_url: str, api_key: Optional[str], path: str, version: str = "v0.1") -> str:
        """Build a Burp REST URL for older key-in-path authentication."""
        if not api_key:
            return BurpService._build_url(api_url, api_key, path, version)

        api_url = BurpService._base_url(api_url)
        path = path.lstrip("/")
        return f"{api_url}/{api_key}/{version}/{path}"

    @staticmethod
    def _http_fallback_url(api_url: str) -> Optional[str]:
        """Return an HTTP fallback for local Burp URLs accidentally entered as HTTPS."""
        if re.match(r"^https://(?:127\.0\.0\.1|localhost)(?::\d+)?(?:/|$)", api_url, re.IGNORECASE):
            return "http://" + api_url[len("https://"):]
        return None

    @staticmethod
    def _is_plain_http_ssl_error(exc: Exception) -> bool:
        """Detect the common TLS error caused by using HTTPS for Burp's HTTP REST port."""
        message = str(exc).lower()
        return "ssl" in message and (
            "unexpected_eof_while_reading" in message
            or "wrong version number" in message
            or "eof occurred in violation of protocol" in message
        )

    @staticmethod
    def _is_invalid_api_version(resp: httpx.Response) -> bool:
        return resp.status_code == 400 and "invalid api version" in resp.text.lower()

    @staticmethod
    def _normalize_task_id(task_id: Optional[str]) -> str:
        """Validate and encode a Burp scan task ID for use in /scan/{task_id}."""
        task_id = (task_id or "").strip()
        if not task_id:
            raise ValueError(
                "Burp Desktop REST API does not expose a sitemap or scan-list endpoint. "
                "Start a scan first, then sync using the task ID returned by Burp."
            )
        if re.match(r"^https?://", task_id, re.IGNORECASE):
            raise ValueError(
                "The Burp Scan Task ID field contains a URL. Use the task ID returned after launching a scan, "
                "not the REST API URL."
            )
        if "/" in task_id or "\\" in task_id:
            raise ValueError("Burp scan task ID must be a single identifier, not a URL or path.")
        return quote(task_id, safe="")

    @staticmethod
    def _request_burp(
        client: httpx.Client,
        method: str,
        api_url: str,
        api_key: Optional[str],
        path: str,
        **kwargs: Any,
    ) -> Tuple[httpx.Response, str]:
        """Request Burp REST API, falling back to legacy path-key auth if needed."""
        last_resp = None
        last_url = ""

        for version in BurpService.BURP_API_VERSIONS:
            url = BurpService._build_url(api_url, api_key, path, version)
            try:
                resp = client.request(method, url, **kwargs)
            except httpx.TransportError as exc:
                fallback_api_url = BurpService._http_fallback_url(api_url)
                if not fallback_api_url or not BurpService._is_plain_http_ssl_error(exc):
                    raise

                fallback_url = BurpService._build_url(fallback_api_url, api_key, path, version)
                logger.info("Burp REST API TLS handshake failed at %s; retrying plain HTTP", url)
                resp = client.request(method, fallback_url, **kwargs)
                api_url = fallback_api_url
                url = fallback_url

            last_resp = resp
            last_url = url

            if not BurpService._is_invalid_api_version(resp):
                break

            logger.info("Burp REST API rejected version in %s; trying next supported version", url)

        if last_resp is None:
            raise RuntimeError("Burp REST API request was not attempted")

        if api_key and last_resp.status_code in (401, 403, 404):
            version = re.search(r"/(v\d+(?:\.\d+)?)/", last_url)
            legacy_version = version.group(1) if version else BurpService.BURP_API_VERSIONS[0]
            fallback_auth_url = BurpService._build_legacy_url(api_url, api_key, path, legacy_version)
            if fallback_auth_url != last_url:
                logger.info(
                    "Burp REST API request to %s returned HTTP %s; retrying legacy key-in-path URL",
                    last_url,
                    last_resp.status_code,
                )
                fallback_resp = client.request(method, fallback_auth_url, **kwargs)
                if fallback_resp.status_code < 400:
                    return fallback_resp, fallback_auth_url

        return last_resp, last_url

    @staticmethod
    def import_from_rest(
        db: Session,
        target_id: int,
        api_url: str,
        api_key: Optional[str] = None,
        task_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Query a Burp Suite REST API scan task and import issue URLs."""
        if not getattr(settings, "BURP_ENABLED", True):
            return {
                "status": "disabled",
                "tasks_checked": 0,
                "task_id": "",
                "imported_endpoints": 0,
                "scanned_urls": []
            }
            
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        encoded_task_id = BurpService._normalize_task_id(task_id)
        task_path = f"scan/{encoded_task_id}"
        task_url = BurpService._build_url(api_url, api_key, task_path)
        logger.info(f"Querying Burp REST API scan task: {task_url}")
        
        try:
            with httpx.Client(timeout=10.0, headers=headers, verify=False, trust_env=False) as client:
                task_resp, task_url = BurpService._request_burp(client, "GET", api_url, api_key, task_path)
                if task_resp.status_code != 200:
                    raise Exception(f"Burp API returned HTTP {task_resp.status_code} from {task_url}: {task_resp.text}")

                task_data = task_resp.json()
                issue_events = task_data.get("issue_events", []) or []
                imported_endpoints = 0
                scanned_urls = []

                for event in issue_events:
                    issue = event.get("issue") or event
                    if not isinstance(issue, dict):
                        continue

                    full_url = issue.get("url") or issue.get("path") or issue.get("origin")
                    if not full_url:
                        continue
                    if not full_url.startswith(("http://", "https://")):
                        origin = issue.get("origin", "").rstrip("/")
                        path = full_url if full_url.startswith("/") else f"/{full_url}"
                        full_url = f"{origin}{path}" if origin else full_url
                    if not full_url.startswith(("http://", "https://")):
                        continue

                    scanned_urls.append(full_url)
                    parsed = urlparse(full_url)
                    from urllib.parse import parse_qs
                    request_data = {
                        "method": "GET",
                        "url": full_url,
                        "headers": {},
                        "query": {
                            k: v[0] if len(v) == 1 else v
                            for k, v in parse_qs(parsed.query, keep_blank_values=True).items()
                        },
                        "body": "",
                        "json": None
                    }

                    try:
                        endpoint = ReconService.create_endpoint_from_request(
                            db,
                            target_id,
                            "GET",
                            full_url,
                            request_data,
                            None
                        )
                        imported_endpoints += 1

                        # Try to extract parameter info from issue details.
                        from backend_api.models.param import Param
                        from backend_api.models.context import Context, ContextType

                        param_name = None
                        param_loc = 'query'
                        issue_desc = issue.get("description", "") or ""
                        issue_loc = issue.get("caption", "") or issue.get("name", "") or ""

                        if issue_loc:
                            m = re.search(r"(query|body|json|header|cookie|parameter|input|field)\s+['\"]?([^'\"\s\]]+)['\"]?", issue_loc, re.IGNORECASE)
                            if m:
                                param_loc = m.group(1).lower()
                                param_name = m.group(2)
                                if param_loc in ('parameter', 'input', 'field'):
                                    param_loc = 'query'

                        if not param_name and issue_desc:
                            m = re.search(r"(?:parameter|input|field|cookie|header)\s+<b>([^<]+)</b>", issue_desc, re.IGNORECASE)
                            if m:
                                param_name = m.group(1)
                                if 'body' in issue_desc.lower() or 'post' in issue_desc.lower():
                                    param_loc = 'body'
                                elif 'cookie' in issue_desc.lower():
                                    param_loc = 'cookie'
                                elif 'header' in issue_desc.lower():
                                    param_loc = 'header'

                        if param_name:
                            param = db.query(Param).filter(
                                Param.endpoint_id == endpoint.id,
                                Param.name == param_name,
                                Param.location == param_loc
                            ).first()

                            if not param:
                                param = Param(
                                    endpoint_id=endpoint.id,
                                    name=param_name,
                                    location=param_loc,
                                    is_controllable=True,
                                    burp_flagged=True
                                )
                                db.add(param)
                                db.flush()
                            else:
                                param.burp_flagged = True
                                db.flush()

                            for ctx_type in [ContextType.HTML_TEXT, ContextType.ATTR_QUOTED]:
                                existing_ctx = db.query(Context).filter(
                                    Context.param_id == param.id,
                                    Context.context_type == ctx_type.value
                                ).first()
                                if not existing_ctx:
                                    db.add(Context(
                                        param_id=param.id,
                                        endpoint_id=endpoint.id,
                                        context_type=ctx_type.value,
                                        snippet=f"[Pre-seeded from Burp REST Issue: {issue.get('name', 'Scanner Alert')}]"
                                    ))
                    except Exception as err:
                        logger.error(f"Failed importing Burp REST task endpoint/issues: {err}", exc_info=True)
                        continue
                                    
                scan_metrics = task_data.get("scan_metrics") or {}
                return {
                    "status": "success",
                    "tasks_checked": 1,
                    "task_id": task_id.strip() if task_id else "",
                    "scan_status": task_data.get("scan_status"),
                    "message": task_data.get("message"),
                    "scan_caption": scan_metrics.get("crawl_and_audit_caption"),
                    "scan_metrics": scan_metrics,
                    "imported_endpoints": imported_endpoints,
                    "scanned_urls": list(set(scanned_urls))
                }
        except Exception as e:
            logger.error(f"Error querying Burp REST API: {e}", exc_info=True)
            raise ValueError(f"Failed to fetch scan data from Burp REST API: {str(e)}")

    @staticmethod
    def trigger_scan(
        api_url: str,
        target_urls: List[str],
        api_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """Trigger a new scan task inside Burp Suite via the REST API."""
        if not getattr(settings, "BURP_ENABLED", True):
            logger.info("Burp Suite scan trigger skipped: Burp integration is disabled.")
            return {"status": "disabled", "task_id": None}
            
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
            
        scan_url = BurpService._build_url(api_url, api_key, "scan")
        seed_info = BurpService.prepare_scan_seed_urls(target_urls, proxy_url=settings.PROXY_URL)
        seed_urls = seed_info["urls"] or target_urls
        payload = {
            "urls": seed_urls,
            "scan_configurations": [],
            "protocol_option": "httpAndHttps",
        }
        
        try:
            with httpx.Client(timeout=10.0, headers=headers, verify=False, trust_env=False) as client:
                resp, scan_url = BurpService._request_burp(client, "POST", api_url, api_key, "scan", json=payload)
                if resp.status_code == 400 and "protocol" in resp.text.lower():
                    fallback_payload = {
                        "urls": seed_urls,
                        "scan_configurations": [],
                    }
                    logger.info("Burp REST API rejected protocol_option; retrying scan with basic payload")
                    resp, scan_url = BurpService._request_burp(
                        client,
                        "POST",
                        api_url,
                        api_key,
                        "scan",
                        json=fallback_payload,
                    )
                if resp.status_code not in (200, 201):
                    raise Exception(f"Burp API returned HTTP {resp.status_code}: {resp.text}")
                
                location = resp.headers.get("Location")
                task_id = None
                if location:
                    task_id = location.split("/")[-1]

                try:
                    data = resp.json() if resp.content else {}
                except ValueError:
                    data = {}

                return {
                    "status": "scan_started",
                    "task_id": task_id or data.get("id") or data.get("task_id"),
                    "location": location,
                    "seed_urls": seed_urls,
                    "preflights": seed_info["preflights"],
                    "details": data
                }
        except Exception as e:
            logger.error(f"Error triggering scan on Burp REST API: {e}", exc_info=True)
            raise ValueError(f"Failed to trigger Burp scan: {str(e)}")

    @staticmethod
    def auto_scan_and_sync(
        db: Session,
        target_id: int,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        poll_attempts: int = 4,
        poll_delay_seconds: float = 2.0,
    ) -> Dict[str, Any]:
        """Start a Burp scan for a target and sync the created task automatically."""
        target = db.query(Target).filter(Target.id == target_id).first()
        if not target:
            raise ValueError(f"Target {target_id} not found")

        api_url = api_url or settings.BURP_API_URL
        api_key = api_key if api_key is not None else settings.BURP_API_KEY
        scan = BurpService.trigger_scan(api_url=api_url, target_urls=[target.base_url], api_key=api_key)
        task_id = scan.get("task_id")
        if not task_id:
            raise ValueError("Burp started the scan but did not return a task ID in the Location header.")

        last_result = None
        for attempt in range(max(1, poll_attempts)):
            if attempt:
                time.sleep(poll_delay_seconds)
            last_result = BurpService.import_from_rest(
                db=db,
                target_id=target_id,
                api_url=api_url,
                api_key=api_key,
                task_id=task_id,
            )
            if last_result.get("imported_endpoints", 0) > 0:
                break

        return {
            "status": "success",
            "task_id": task_id,
            "target_url": target.base_url,
            "scan": scan,
            "sync": last_result or {},
        }

    @staticmethod
    def get_scan_tasks(api_url: str, api_key: Optional[str] = None) -> List[Dict[str, Any]]:
        """Burp Desktop REST API does not expose a scan-list endpoint."""
        return []

    @staticmethod
    def get_scan_task(api_url: str, task_id: str, api_key: Optional[str] = None) -> Dict[str, Any]:
        """Retrieve details of a specific scan task."""
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
            
        encoded_task_id = BurpService._normalize_task_id(task_id)
        url = BurpService._build_url(api_url, api_key, f"scan/{encoded_task_id}")
        
        try:
            with httpx.Client(timeout=10.0, headers=headers, verify=False, trust_env=False) as client:
                resp, url = BurpService._request_burp(client, "GET", api_url, api_key, f"scan/{encoded_task_id}")
                if resp.status_code != 200:
                    raise Exception(f"Burp API returned HTTP {resp.status_code}: {resp.text}")
                return resp.json()
        except Exception as e:
            logger.error(f"Error fetching scan task {task_id}: {e}", exc_info=True)
            raise ValueError(f"Failed to fetch Burp scan task: {str(e)}")

    @staticmethod
    def cancel_scan_task(api_url: str, task_id: str, api_key: Optional[str] = None) -> bool:
        """Cancel/delete a specific scan task."""
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
            
        encoded_task_id = BurpService._normalize_task_id(task_id)
        url = BurpService._build_url(api_url, api_key, f"scan/{encoded_task_id}")
        
        try:
            with httpx.Client(timeout=10.0, headers=headers, verify=False, trust_env=False) as client:
                resp, url = BurpService._request_burp(client, "DELETE", api_url, api_key, f"scan/{encoded_task_id}")
                if resp.status_code not in (200, 202, 204):
                    raise Exception(f"Burp API returned HTTP {resp.status_code}: {resp.text}")
                return True
        except Exception as e:
            logger.error(f"Error canceling scan task {task_id}: {e}", exc_info=True)
            raise ValueError(f"Failed to cancel Burp scan task: {str(e)}")

    @staticmethod
    def get_issue_definitions(api_url: str, api_key: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve security issue definitions library from Burp Knowledge Base."""
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
            
        url = BurpService._build_url(api_url, api_key, "knowledge_base/issue_definitions")
        
        try:
            with httpx.Client(timeout=10.0, headers=headers, verify=False, trust_env=False) as client:
                resp, url = BurpService._request_burp(client, "GET", api_url, api_key, "knowledge_base/issue_definitions")
                if resp.status_code != 200:
                    raise Exception(f"Burp API returned HTTP {resp.status_code}: {resp.text}")
                
                data = resp.json()
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict):
                    return data.get("issue_definitions", []) or []
                return []
        except Exception as e:
            logger.error(f"Error fetching issue definitions: {e}", exc_info=True)
            raise ValueError(f"Failed to fetch Burp issue definitions: {str(e)}")

    @staticmethod
    def auto_forward_finding(db: Session, finding) -> None:
        """Automatically push a verified finding to the Burp Suite Repeater and Findings queues."""
        try:
            from backend_api.routers.burp import repeater_queue, findings_queue
            from urllib.parse import urlparse
            import json
            
            poc = finding.poc_request or {}
            # Handles different shapes of poc_request between standard, stored, and modern findings
            url = poc.get("url") or poc.get("target_url") or (finding.endpoint.url_pattern if finding.endpoint else "")
            if not url:
                return
                
            method = poc.get("method") or poc.get("probe_family") or (finding.endpoint.method if finding.endpoint else "GET")
            if method == "postMessage":
                method = "GET"
            headers = poc.get("headers") or (finding.endpoint.auth_context if finding.endpoint else {}) or {}
            
            body = None
            if finding.param:
                if finding.param.location == "body":
                    body = f"{finding.param.name}={finding.best_payload}"
                elif finding.param.location == "json":
                    body_dict = (finding.endpoint.sample_request_body if finding.endpoint else {}) or {}
                    if isinstance(body_dict, dict):
                        body_dict = body_dict.copy()
                    else:
                        body_dict = {}
                    body_dict[finding.param.name] = finding.best_payload
                    body = json.dumps(body_dict)
                    headers["Content-Type"] = "application/json"
                
            parsed = urlparse(url)
            secure = parsed.scheme == 'https'
            host = parsed.hostname or ''
            port = parsed.port or (443 if secure else 80)
            
            path_with_query = parsed.path
            if parsed.query:
                path_with_query += f"?{parsed.query}"
            if not path_with_query:
                path_with_query = "/"
                
            headers_copy = {k: v for k, v in headers.items() if k.lower() != 'host'}
            headers_copy['Host'] = parsed.netloc if parsed.netloc else host
            
            raw_lines = [f"{method} {path_with_query} HTTP/1.1"]
            for k, v in headers_copy.items():
                raw_lines.append(f"{k}: {v}")
            raw_lines.append("")
            if body:
                raw_lines.append(body)
            else:
                raw_lines.append("")
                
            raw_request = "\r\n".join(raw_lines)
            label = f"Auto-XSSBoss {finding.id} ({finding.param.name if finding.param else 'unknown'})"
            
            # De-duplicate pushes
            if not any(item.get("label") == label for item in repeater_queue):
                repeater_queue.append({
                    "host": host,
                    "port": port,
                    "secure": secure,
                    "raw_request": raw_request,
                    "label": label,
                    "tool": "repeater"
                })
                
                # Reconstruct raw response
                raw_vuln_type = str(getattr(finding, "vuln_type", None) or "xss").lower()
                vuln_labels = {
                    "xss": "XSS",
                    "blind_xss": "Blind XSS",
                    "ssrf_oob": "SSRF",
                    "open_redirect": "Open Redirect",
                    "cors_misconfiguration": "CORS Misconfiguration",
                    "path_traversal_lfi": "Path Traversal / LFI",
                    "sqli_error_based": "SQL Injection",
                }
                vuln_type = vuln_labels.get(raw_vuln_type, raw_vuln_type.replace("_", " ").title())
                raw_resp_body = finding.poc_html or f"<html><body>XSS Boss Verified {vuln_type} Finding: {finding.best_payload}</body></html>"
                raw_response_lines = [
                    "HTTP/1.1 200 OK",
                    "Content-Type: text/html; charset=utf-8",
                    f"Content-Length: {len(raw_resp_body)}",
                    "",
                    raw_resp_body
                ]
                raw_response = "\r\n".join(raw_response_lines)
                
                evidence_refs = finding.evidence_refs or {}
                sink_details = evidence_refs.get('sink_details', {}) or {}
                sink_type = sink_details.get('sink_type', 'unknown')
                js_location = sink_details.get('js_location', 'unknown')
                notes = sink_details.get('notes', '')

                findings_queue.append({
                    "id": finding.id,
                    "name": f"XSS Boss: Verified {vuln_type} ({finding.param.location if finding.param else 'unknown'} parameter '{finding.param.name if finding.param else 'unknown'}')",
                    "severity": finding.severity if isinstance(finding.severity, str) else (finding.severity.value if finding.severity else "high"),
                    "confidence": "Certain",
                    "url": url,
                    "detail": finding.report_text or f"Verified {vuln_type} vulnerability found by XSS Boss.",
                    "remediation": "Validate user-controlled input, restrict trust decisions to allowlisted values, and apply the remediation guidance in the report detail.",
                    "host": host,
                    "port": port,
                    "secure": secure,
                    "raw_request": raw_request,
                    "raw_response": raw_response,
                    "sink_type": sink_type,
                    "js_location": js_location,
                    "notes": notes
                })
                logger.info(f"Auto-forwarded verified finding {finding.id} to Burp Repeater & Issues queues.")
        except Exception as e:
            logger.error(f"Failed to auto-forward finding {finding.id if finding else 'None'} to Burp: {e}", exc_info=True)
