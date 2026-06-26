"""HTTP request construction utilities."""
from typing import Dict, Any, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
import httpx


class RequestBuilder:
    """Build HTTP requests from endpoint and parameter data."""

    @staticmethod
    def url_with_query_param(url: str, param_name: str, param_value: str) -> str:
        """Return URL with one query parameter replaced instead of duplicated."""
        url_parts = list(urlparse(url))
        query = dict(parse_qsl(url_parts[4], keep_blank_values=True))
        query[param_name] = param_value
        url_parts[4] = urlencode(query, doseq=True)
        return urlunparse(url_parts)
    
    @staticmethod
    def build_request(
        method: str,
        url: str,
        param_name: str,
        param_value: str,
        param_location: str,
        base_headers: Optional[Dict[str, str]] = None,
        base_cookies: Optional[Dict[str, str]] = None,
        base_body: Optional[Dict[str, Any]] = None,
        base_json: Optional[Dict[str, Any]] = None
    ) -> httpx.Request:
        """Build an HTTP request with injected payload."""
        headers = base_headers.copy() if base_headers else {}
        cookies = base_cookies.copy() if base_cookies else {}
        
        if param_location == "query":
            # Add to query parameters
            url = RequestBuilder.url_with_query_param(url, param_name, param_value)
            params = None
            body = None
            json_data = None
        elif param_location == "body":
            # Add to form body
            body = base_body.copy() if base_body else {}
            body[param_name] = param_value
            json_data = None
            params = None
        elif param_location == "json":
            # Add to JSON body
            json_data = base_json.copy() if base_json else {}
            # Handle nested keys (e.g., "user.name")
            keys = param_name.split('.')
            current = json_data
            for key in keys[:-1]:
                if key not in current:
                    current[key] = {}
                current = current[key]
            current[keys[-1]] = param_value
            body = None
            params = None
        elif param_location == "header":
            # Add to headers
            headers[param_name] = param_value
            body = base_body
            json_data = base_json
            params = None
        elif param_location == "cookie":
            # Add to cookies
            cookies[param_name] = param_value
            body = base_body
            json_data = base_json
            params = None
        elif param_location == "path":
            # Replace placeholder in URL
            url = url.replace(f"{{{param_name}}}", param_value)
            body = base_body
            json_data = base_json
            params = None
        else:
            raise ValueError(f"Unknown parameter location: {param_location}")
        
        # Build request
        request = httpx.Request(
            method=method,
            url=url,
            headers=headers,
            cookies=cookies,
            params=params,
            data=body,
            json=json_data
        )
        
        return request
