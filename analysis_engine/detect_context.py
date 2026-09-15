"""Reflection + context detection."""
from typing import List, Dict, Any, Optional
import httpx
from sqlalchemy.orm import Session

from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from backend_api.models.context import Context, ContextType
from backend_api.utils.marker import MarkerGenerator
from backend_api.utils.context_detector import ContextDetector
from backend_api.utils.html_parser import HTMLParser
from backend_api.utils.request_builder import RequestBuilder
from backend_api.services.context_service import ContextService
from backend_api.utils.logger import logger
from backend_api.config import settings
from backend_api.utils.stealth import get_http_proxy_kwargs
from analysis_engine.filter_profiler import FilterProfiler, FilterProfile

CONTEXT_PROBE_TIMEOUT = httpx.Timeout(4.0, connect=2.0)


def _probe_kwargs() -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {
        "timeout": CONTEXT_PROBE_TIMEOUT,
        "trust_env": False,
        "follow_redirects": True,
        "verify": not settings.ALLOW_INSECURE_TLS,
    }
    proxy_kwargs = get_http_proxy_kwargs(rotated=True)
    kwargs.update(proxy_kwargs)
    return kwargs


class ContextDetectorEngine:
    """Engine for detecting reflection contexts."""
    
    def __init__(self, db: Session):
        """Initialize with database session.
        
        Args:
            db: SQLAlchemy database session
        """
        self.db = db
    
    def detect_contexts_for_endpoint(
        self,
        endpoint_id: int,
        timeout: int = 10
    ) -> List[Context]:
        """Detect contexts for all parameters in an endpoint.
        
        Args:
            endpoint_id: Endpoint ID
            timeout: Request timeout in seconds
            
        Returns:
            List of created Context records
        """
        endpoint = self.db.query(Endpoint).filter(Endpoint.id == endpoint_id).first()
        if not endpoint:
            raise ValueError(f"Endpoint {endpoint_id} not found")
        
        params = self.db.query(Param).filter(Param.endpoint_id == endpoint_id).all()
        if not params:
            logger.info(
                "Skipping context probes for endpoint %s because recon found no controllable parameters",
                endpoint_id,
            )
            return []

        contexts = []
        
        for param in params:
            param_contexts = self.detect_contexts_for_param(param.id, timeout)
            contexts.extend(param_contexts)
        
        return contexts
    
    def detect_contexts_for_param(
        self,
        param_id: int,
        timeout: int = 10
    ) -> List[Context]:
        """Detect contexts for a specific parameter.
        
        Args:
            param_id: Parameter ID
            timeout: Request timeout in seconds
            
        Returns:
            List of created Context records
        """
        param = self.db.query(Param).filter(Param.id == param_id).first()
        if not param:
            raise ValueError(f"Parameter {param_id} not found")
        
        endpoint = param.endpoint
        
        # Generate unique marker
        marker = MarkerGenerator.generate()
        logger.info(f"Generated marker {marker} for param {param_id}")
        
        # Build request with marker
        from backend_api.utils.request_builder import RequestBuilder
        
        # Get base request data from endpoint
        url = endpoint.url_pattern
        method = endpoint.method
        
        # Get all path parameters for this endpoint to resolve placeholders in the URL pattern
        all_params = self.db.query(Param).filter(Param.endpoint_id == endpoint.id).all()
        path_params = {
            p.name: (p.sample_value or "1")
            for p in all_params
            if p.location == "path"
        }
        for p_name, p_val in path_params.items():
            placeholder = f"{{{p_name}}}"
            if param.location == "path" and param.name == p_name:
                url = url.replace(placeholder, marker)
            else:
                url = url.replace(placeholder, p_val)
        
        # Build headers and cookies from auth_context
        headers = (endpoint.auth_context or {}).copy()
        cookies = {}
        
        # Extract cookies from headers if present
        if 'Cookie' in headers:
            cookie_str = headers.pop('Cookie')
            for cookie_pair in cookie_str.split(';'):
                if '=' in cookie_pair:
                    key, value = cookie_pair.split('=', 1)
                    cookies[key.strip()] = value.strip()
                    
        # Create base request data with all sample values for other parameters
        params_dict = {}
        body_dict = None
        json_dict = None
        
        if endpoint.sample_request_body and isinstance(endpoint.sample_request_body, dict):
            if any(p.location == "json" for p in all_params):
                json_dict = endpoint.sample_request_body.copy()
            elif any(p.location == "body" for p in all_params):
                body_dict = endpoint.sample_request_body.copy()
                
        for p in all_params:
            if p.location == param.location and p.name == param.name:
                continue
            if p.location == "query":
                params_dict[p.name] = p.sample_value or ""
            elif p.location == "body":
                if body_dict is None:
                    body_dict = {}
                body_dict[p.name] = p.sample_value or ""
            elif p.location == "json":
                if json_dict is None:
                    json_dict = {}
                keys = p.name.split('.')
                current = json_dict
                for key in keys[:-1]:
                    if key not in current or not isinstance(current[key], dict):
                        current[key] = {}
                    current = current[key]
                current[keys[-1]] = p.sample_value or ""
            elif p.location == "header":
                headers[p.name] = p.sample_value or ""
            elif p.location == "cookie":
                cookies[p.name] = p.sample_value or ""
        
        # Build and send HTTP request
        try:
            from backend_api.utils.rate_limiter import rate_limiter
            rate_limiter.wait_for_slot(url)

            # Use httpx directly for request
            if param.location == "query":
                params_dict[param.name] = marker
                # Build URL with all query parameters
                from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl
                url_parts = list(urlparse(url))
                query = dict(parse_qsl(url_parts[4], keep_blank_values=True))
                query.update(params_dict)
                url_parts[4] = urlencode(query, doseq=True)
                url_with_query = urlunparse(url_parts)
                
                response = httpx.request(
                    method=method,
                    url=url_with_query,
                    headers=headers,
                    cookies=cookies,
                    **_probe_kwargs()
                )
            elif param.location == "body":
                if body_dict is None:
                    body_dict = {}
                body_dict[param.name] = marker
                response = httpx.request(
                    method=method,
                    url=url,
                    headers=headers,
                    cookies=cookies,
                    data=body_dict,
                    **_probe_kwargs()
                )
            elif param.location == "json":
                if json_dict is None:
                    json_dict = {}
                keys = param.name.split('.')
                current = json_dict
                for key in keys[:-1]:
                    if key not in current or not isinstance(current[key], dict):
                        current[key] = {}
                    current = current[key]
                current[keys[-1]] = marker
                response = httpx.request(
                    method=method,
                    url=url,
                    headers=headers,
                    cookies=cookies,
                    json=json_dict,
                    **_probe_kwargs()
                )
            elif param.location == "header":
                headers[param.name] = marker
                response = httpx.request(
                    method=method,
                    url=url,
                    headers=headers,
                    cookies=cookies,
                    **_probe_kwargs()
                )
            elif param.location == "cookie":
                cookies[param.name] = marker
                response = httpx.request(
                    method=method,
                    url=url,
                    headers=headers,
                    cookies=cookies,
                    **_probe_kwargs()
                )
            elif param.location == "path":
                # Path parameters are already resolved in the URL
                response = httpx.request(
                    method=method,
                    url=url,
                    headers=headers,
                    cookies=cookies,
                    **_probe_kwargs()
                )
            else:
                raise ValueError(f"Unknown parameter location: {param.location}")

            if response.status_code in (429, 403):
                rate_limiter.report_error(url, is_rate_limit=True)
            elif response.status_code < 400:
                rate_limiter.report_success(url)

            if response.status_code >= 400:
                # If blocked by WAF/bot-protection on GET or query/path, try browser-based fallback
                if (
                    response.status_code in (401, 403, 429, 503)
                    and method.upper() == 'GET'
                    and param.location in ['query', 'path']
                ):
                    try:
                        logger.info(f"HTTP {response.status_code} encountered. Attempting browser probe fallback for param {param_id}...")
                        from selenium import webdriver
                        from browser_workers.selenium_config import SeleniumConfig
                        opts = SeleniumConfig.get_chrome_options()
                        b_driver = webdriver.Chrome(options=opts)
                        try:
                            b_driver.set_page_load_timeout(timeout)
                            probe_target_url = url_with_query if param.location == "query" else url
                            rate_limiter.wait_for_slot(probe_target_url)
                            try:
                                b_driver.get(probe_target_url)
                            except Exception:
                                rate_limiter.report_error(probe_target_url)
                                raise
                            else:
                                rate_limiter.report_success(probe_target_url)
                            response_text = b_driver.page_source
                            content_type = "text/html"
                        finally:
                            b_driver.quit()
                    except Exception as be:
                        logger.warning(f"Browser probe fallback failed for param {param_id}: {be}")
                        return []
                else:
                    logger.warning(f"Request failed with status {response.status_code} for param {param_id}")
                    return []  # Request failed
            else:
                # Analyze response
                response_text = response.text
                content_type = response.headers.get('Content-Type', '').lower()
            
            # Detect contexts
            contexts_data = []
            
            # HTML contexts
            if 'text/html' in content_type or marker in response_text:
                contexts_data.extend(
                    ContextDetector.classify_reflection(response_text, marker)
                )
            
            # JSON contexts
            stripped_text = response_text.strip()
            if 'application/json' in content_type or (stripped_text.startswith('{') or stripped_text.startswith('[')):
                contexts_data.extend(
                    ContextDetector.detect_json_reflection(response_text, marker)
                )
            
            # Do not classify the request's own query string as a reflection.
            # URL execution contexts require an observed redirect/location sink;
            # merely seeing our marker in response.url is true for every query
            # probe and masks real DOM source->sink analysis (for example
            # URLSearchParams('next') flowing into innerHTML).
            if response.history and marker in str(response.url):
                contexts_data.extend(ContextDetector.detect_url_reflection(str(response.url), marker))
            
            # Create context records
            created_contexts = []
            for ctx_data in contexts_data:
                context = ContextService.create_context(
                    self.db,
                    param_id=param.id,
                    endpoint_id=endpoint.id,
                    context_type=ctx_data['context_type'],
                    tag=ctx_data.get('tag'),
                    attribute=ctx_data.get('attribute'),
                    script_path=ctx_data.get('script_path'),
                    snippet=ctx_data.get('snippet')
                )
                created_contexts.append(context)
                logger.info(f"Created context {context.id} for param {param_id}: {ctx_data['context_type']}")
            
            return created_contexts
        
        except (httpx.TimeoutException, httpx.ConnectError, httpx.ProxyError) as e:
            logger.warning(f"Context probe failed for param {param_id} at {endpoint.url_pattern}: {type(e).__name__}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error detecting contexts for param {param_id}: {e}", exc_info=True)
            return []
    
    def detect_contexts_for_target(
        self,
        target_id: int,
        timeout: int = 10
    ) -> Dict[int, List[Context]]:
        """Detect contexts for all endpoints in a target.
        
        Args:
            target_id: Target ID
            timeout: Request timeout in seconds
            
        Returns:
            Dictionary mapping endpoint_id to list of contexts
        """
        endpoints = self.db.query(Endpoint).filter(Endpoint.target_id == target_id).all()
        
        results = {}
        for endpoint in endpoints:
            contexts = self.detect_contexts_for_endpoint(endpoint.id, timeout)
            results[endpoint.id] = contexts
        
        return results

    def profile_param_filter(self, param_id: int) -> FilterProfile:
        """Actively profile the character filter & escaping rules for a parameter."""
        param = self.db.query(Param).filter(Param.id == param_id).first()
        if not param:
            raise ValueError(f"Parameter {param_id} not found")
        
        endpoint = param.endpoint
        headers = (endpoint.auth_context or {}).copy()
        profiler = FilterProfiler()
        return profiler.profile_endpoint_param(
            url=endpoint.url_pattern,
            method=endpoint.method,
            param_name=param.name,
            location=param.location,
            headers=headers,
        )
