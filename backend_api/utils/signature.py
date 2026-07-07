"""Request signature normalization."""
from typing import Dict, Any, Optional
import re
from urllib.parse import urlparse, parse_qs, urlencode


class RequestSignature:
    """Normalize requests to signatures for deduplication."""
    
    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL by replacing dynamic values."""
        parsed = urlparse(url)
        path = parsed.path
        
        # Replace UUIDs
        path = re.sub(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            '{uuid}',
            path,
            flags=re.IGNORECASE
        )
        
        # Replace numeric IDs
        path = re.sub(r'/\d+/', '/{id}/', path)
        path = re.sub(r'/\d+$', '/{id}', path)
        
        # Normalize query string (sort params)
        query = parse_qs(parsed.query)
        normalized_query = urlencode(sorted(query.items()))
        
        return f"{parsed.scheme}://{parsed.netloc}{path}?{normalized_query}" if normalized_query else f"{parsed.scheme}://{parsed.netloc}{path}"
    
    @staticmethod
    def create_signature(
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Dict[str, Any]] = None
    ) -> str:
        """Create a signature for a request."""
        normalized_url = RequestSignature.normalize_url(url)
        
        # Include method and normalized URL
        signature_parts = [method.upper(), normalized_url]
        
        # Optionally include content-type
        if headers:
            content_type = headers.get('Content-Type', '')
            if content_type:
                signature_parts.append(content_type.split(';')[0].strip())
        
        return '|'.join(signature_parts)

