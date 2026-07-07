"""Request signature utilities."""
from typing import Dict, Any, Optional, List
import re
from urllib.parse import urlparse, parse_qs, urlencode


class RequestSignature:
    """Request signature generation and normalization."""
    
    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL by replacing dynamic values with placeholders.
        
        Args:
            url: Original URL
            
        Returns:
            Normalized URL with placeholders
        """
        parsed = urlparse(url)
        path = parsed.path
        
        # Replace UUIDs (8-4-4-4-12 format)
        path = re.sub(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            '{uuid}',
            path,
            flags=re.IGNORECASE
        )
        
        # Replace date hierarchies in path (must run before generic number replacements)
        path = re.sub(r'/\d{4}[/-]\d{2}[/-]\d{2}(?=/|$)', '/{date}', path)

        # Replace numeric IDs in path
        path = re.sub(r'/\d+/', '/{id}/', path)
        path = re.sub(r'/\d+$', '/{id}', path)
        
        # Replace common hash patterns (MongoDB ObjectId, MD5, etc.)
        path = re.sub(r'/[a-z0-9]{24}/', '/{hash}/', path)  # MongoDB ObjectId-like
        path = re.sub(r'/[a-z0-9]{32}/', '/{hash}/', path)  # MD5-like
        path = re.sub(r'/[a-z0-9]{40}/', '/{hash}/', path)  # SHA1-like

        # Replace JWT tokens in path
        path = re.sub(r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', '{jwt}', path)

        # Replace alphanumeric product/listing slugs (6-12 chars, e.g. /052R4E, /P123456)
        path = re.sub(r'/([A-Z0-9]{6,12})(?=/|$)', '/{slug}', path)
        
        # Reconstruct URL
        normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
        
        # Endpoint identity is the method/path plus its input names, not the
        # current sample values. Keeping values here created a new endpoint for
        # every crawl, probe, and payload and broke run-level deduplication.
        if parsed.query:
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            normalized_query = urlencode([(key, "") for key in sorted(query_params)])
            normalized = f"{normalized}?{normalized_query}"
        
        return normalized
    
    @staticmethod
    def create_signature(
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
        normalized_url = RequestSignature.normalize_url(url)
        
        parts = [method.upper(), normalized_url]
        
        if content_type:
            # Include content type in signature (for POST/PUT)
            parts.append(content_type.split(';')[0].strip())
        
        return '|'.join(parts)
    
    @staticmethod
    def extract_path_params(url: str) -> List[str]:
        """Extract path parameter names from normalized URL.
        
        Args:
            url: Normalized URL with placeholders
            
        Returns:
            List of parameter names found in path
        """
        parsed = urlparse(url)
        path = parsed.path
        
        # Find placeholders
        params = re.findall(r'\{(\w+)\}', path)
        return params
    
    @staticmethod
    def extract_query_params(url: str) -> Dict[str, Any]:
        """Extract query parameters from URL.
        
        Args:
            url: Request URL
            
        Returns:
            Dictionary of query parameters
        """
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        return {k: v[0] if len(v) == 1 else v for k, v in query_params.items()}

