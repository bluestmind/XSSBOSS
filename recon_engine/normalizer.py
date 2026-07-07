"""Request normalization to endpoint patterns."""
from typing import Dict, Any, List, Optional
import re
from urllib.parse import urlparse, parse_qs, urlencode
from recon_engine.utils.request_signature import RequestSignature


class RequestNormalizer:
    """Normalize requests to endpoint patterns."""
    
    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL by replacing dynamic values with placeholders.
        
        Args:
            url: Original URL
            
        Returns:
            Normalized URL pattern
        """
        return RequestSignature.normalize_url(url)
    
    @staticmethod
    def create_endpoint_signature(
        method: str,
        url: str,
        content_type: Optional[str] = None
    ) -> str:
        """Create a unique signature for an endpoint.
        
        Args:
            method: HTTP method
            url: Request URL
            content_type: Content-Type header (optional)
            
        Returns:
            Unique signature string
        """
        return RequestSignature.create_signature(method, url, content_type)
    
    @staticmethod
    def extract_path_params(url: str) -> List[str]:
        """Extract path parameter names from normalized URL.
        
        Args:
            url: Normalized URL with placeholders
            
        Returns:
            List of parameter names
        """
        return RequestSignature.extract_path_params(url)
    
    @staticmethod
    def extract_query_params(url: str) -> Dict[str, Any]:
        """Extract query parameters from URL.
        
        Args:
            url: Request URL
            
        Returns:
            Dictionary of query parameters
        """
        return RequestSignature.extract_query_params(url)
    
    @staticmethod
    def detect_body_type(headers: Dict[str, str], body: Any) -> str:
        """Detect if body is JSON, form, or other.
        
        Args:
            headers: Request headers
            body: Request body (string or dict)
            
        Returns:
            Body type: 'json', 'form', or 'other'
        """
        content_type = headers.get('Content-Type', '').lower()
        
        if 'application/json' in content_type:
            return 'json'
        elif 'application/x-www-form-urlencoded' in content_type:
            return 'form'
        elif 'multipart/form-data' in content_type:
            return 'form'
        elif isinstance(body, dict):
            return 'json'
        else:
            return 'other'
    
    @staticmethod
    def safe_parse_headers(header_text: str) -> Dict[str, str]:
        """Safely parse headers from text.
        
        Args:
            header_text: Header text (one per line, key: value)
            
        Returns:
            Dictionary of headers
        """
        headers = {}
        for line in header_text.split('\n'):
            line = line.strip()
            if not line:
                continue
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        return headers
    
    @staticmethod
    def extract_parameters(
        request_data: Dict[str, Any],
        method: str
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Extract all parameters from request.
        
        Args:
            request_data: Request data dictionary
            method: HTTP method
            
        Returns:
            Dictionary with 'query', 'body', 'json', 'path', 'header', 'cookie' lists
        """
        from backend_api.models.param import ParamLocation
        
        params = {
            'query': [],
            'body': [],
            'json': [],
            'path': [],
            'header': [],
            'cookie': []
        }
        
        # Query parameters
        query_dict = {}
        if 'query' in request_data and request_data['query']:
            if isinstance(request_data['query'], dict):
                query_dict.update(request_data['query'])
                
        # Parse query params from URL if present
        url = request_data.get('url')
        if url:
            try:
                url_query = RequestNormalizer.extract_query_params(url)
                if url_query:
                    for k, v in url_query.items():
                        if k not in query_dict:
                            query_dict[k] = v
            except Exception:
                pass
                
        for key, value in query_dict.items():
            params['query'].append({
                'name': key,
                'location': ParamLocation.QUERY.value,
                'sample_value': str(value) if value is not None else None
            })
        
        # Path parameters
        if url:
            normalized_url = RequestNormalizer.normalize_url(url)
            path_params = RequestNormalizer.extract_path_params(normalized_url)
            
            # Map original URL segments to normalized URL placeholders to find sample values
            try:
                orig_parsed = urlparse(url)
                norm_parsed = urlparse(normalized_url)
                orig_segments = orig_parsed.path.strip('/').split('/')
                norm_segments = norm_parsed.path.strip('/').split('/')
                
                segment_map = {}
                if len(orig_segments) == len(norm_segments):
                    for orig_seg, norm_seg in zip(orig_segments, norm_segments):
                        if norm_seg.startswith('{') and norm_seg.endswith('}'):
                            param_name = norm_seg[1:-1]
                            segment_map[param_name] = orig_seg
                
                for param_name in path_params:
                    params['path'].append({
                        'name': param_name,
                        'location': ParamLocation.PATH.value,
                        'sample_value': segment_map.get(param_name)
                    })
            except Exception:
                for param_name in path_params:
                    params['path'].append({
                        'name': param_name,
                        'location': ParamLocation.PATH.value,
                        'sample_value': None
                    })
        
        # Body parameters (form data)
        if 'body' in request_data and isinstance(request_data['body'], dict):
            for key, value in request_data['body'].items():
                params['body'].append({
                    'name': key,
                    'location': ParamLocation.BODY.value,
                    'sample_value': str(value) if value is not None else None
                })
        
        # JSON body (nested extraction)
        if 'json' in request_data and request_data['json']:
            def extract_json_params(obj, prefix=''):
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        full_key = f"{prefix}.{key}" if prefix else key
                        if isinstance(value, (dict, list)):
                            extract_json_params(value, full_key)
                        else:
                            params['json'].append({
                                'name': full_key,
                                'location': ParamLocation.JSON.value,
                                'sample_value': str(value) if value is not None else None
                            })
                elif isinstance(obj, list):
                    for i, item in enumerate(obj):
                        extract_json_params(item, f"{prefix}[{i}]")
            
            extract_json_params(request_data['json'])
        
        # Headers (excluding standard ones)
        if 'headers' in request_data:
            excluded_headers = {
                'content-type', 'content-length', 'host', 'user-agent',
                'accept', 'accept-encoding', 'accept-language', 'connection',
                'cache-control', 'pragma', 'referer', 'origin'
            }
            for key, value in request_data['headers'].items():
                if key.lower() not in excluded_headers:
                    params['header'].append({
                        'name': key,
                        'location': ParamLocation.HEADER.value,
                        'sample_value': str(value) if value is not None else None
                    })
        
        # Cookies
        if 'headers' in request_data:
            cookie_header = request_data['headers'].get('Cookie', '')
            if cookie_header:
                for cookie_pair in cookie_header.split(';'):
                    if '=' in cookie_pair:
                        key, value = cookie_pair.split('=', 1)
                        params['cookie'].append({
                            'name': key.strip(),
                            'location': ParamLocation.COOKIE.value,
                            'sample_value': value.strip() if value is not None else None
                        })
        
        return params
