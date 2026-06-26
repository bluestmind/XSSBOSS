"""Marker generation and injection utilities."""
import uuid
from typing import Dict, Any


class MarkerGenerator:
    """Generate unique markers for XSS testing."""
    
    PREFIX = "XSSFUZZ_"
    
    @staticmethod
    def generate() -> str:
        """Generate a unique marker.
        
        Returns:
            Unique marker string in format XSSFUZZ_<uuid>
        """
        return f"{MarkerGenerator.PREFIX}{uuid.uuid4().hex}"
    
    @staticmethod
    def is_marker(value: str) -> bool:
        """Check if a string is a marker.
        
        Args:
            value: String to check
            
        Returns:
            True if string is a marker
        """
        return isinstance(value, str) and value.startswith(MarkerGenerator.PREFIX)
    
    @staticmethod
    def extract_id(marker: str) -> str:
        """Extract the UUID part from a marker.
        
        Args:
            marker: Marker string
            
        Returns:
            UUID hex string or None if not a marker
        """
        if MarkerGenerator.is_marker(marker):
            return marker[len(MarkerGenerator.PREFIX):]
        return None
    
    @staticmethod
    def inject_into_request(
        request_data: Dict[str, Any],
        param_name: str,
        param_location: str,
        marker: str
    ) -> Dict[str, Any]:
        """Inject marker into request data.
        
        Args:
            request_data: Original request data
            param_name: Parameter name to inject into
            param_location: Parameter location (query, body, json, etc.)
            marker: Marker to inject
            
        Returns:
            Modified request data with marker injected
        """
        modified = request_data.copy()
        
        if param_location == "query":
            if 'query' not in modified:
                modified['query'] = {}
            modified['query'][param_name] = marker
        elif param_location == "body":
            if 'body' not in modified:
                modified['body'] = {}
            if isinstance(modified['body'], dict):
                modified['body'][param_name] = marker
        elif param_location == "json":
            if 'json' not in modified:
                modified['json'] = {}
            # Handle nested keys (e.g., "user.name")
            keys = param_name.split('.')
            json_data = modified['json'].copy() if isinstance(modified.get('json'), dict) else {}
            current = json_data
            for key in keys[:-1]:
                if key not in current:
                    current[key] = {}
                current = current[key]
            current[keys[-1]] = marker
            modified['json'] = json_data
        elif param_location == "header":
            if 'headers' not in modified:
                modified['headers'] = {}
            modified['headers'][param_name] = marker
        elif param_location == "cookie":
            if 'headers' not in modified:
                modified['headers'] = {}
            cookie_header = modified['headers'].get('Cookie', '')
            if cookie_header:
                # Append to existing cookies
                modified['headers']['Cookie'] = f"{cookie_header}; {param_name}={marker}"
            else:
                modified['headers']['Cookie'] = f"{param_name}={marker}"
        elif param_location == "path":
            if 'url' in modified:
                modified['url'] = modified['url'].replace(f"{{{param_name}}}", marker)
        
        return modified
