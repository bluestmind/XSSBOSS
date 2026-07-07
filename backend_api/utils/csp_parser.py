"""Content Security Policy (CSP) parsing and evaluation utility."""
from typing import Dict, List, Any, Optional, Set


class CSPParser:
    """Parse and evaluate Content Security Policy headers to optimize fuzzing vectors."""
    
    @staticmethod
    def parse_header(csp_header: str) -> Dict[str, List[str]]:
        """Parse raw CSP header string into a structured dictionary.
        
        Args:
            csp_header: Raw Content-Security-Policy header value
            
        Returns:
            Dictionary mapping directive names to lists of source values
        """
        if not csp_header:
            return {}
            
        directives = {}
        # Clean and split directives
        parts = [p.strip() for p in csp_header.split(';') if p.strip()]
        
        for part in parts:
            tokens = part.split()
            if not tokens:
                continue
            directive_name = tokens[0].lower()
            directive_values = [v.replace("'", "").replace('"', "") for v in tokens[1:]]
            directives[directive_name] = directive_values
            
        return directives

    @staticmethod
    def evaluate_csp(directives: Dict[str, List[str]]) -> Dict[str, Any]:
        """Evaluate parsed directives to determine security rules.
        
        Args:
            directives: Parsed directives dictionary
            
        Returns:
            Dictionary mapping rules to boolean/allowance flags
        """
        if not directives:
            return {
                'allow_inline_scripts': True,
                'allow_event_handlers': True,
                'allow_eval': True,
                'allow_javascript_urls': True,
                'has_csp': False
            }
            
        # script-src falls back to default-src
        script_src = directives.get('script-src')
        if script_src is None:
            script_src = directives.get('default-src', [])
            
        # Check standard tokens
        unsafe_inline = 'unsafe-inline' in script_src
        unsafe_eval = 'unsafe-eval' in script_src
        strict_dynamic = 'strict-dynamic' in script_src
        
        # Check for presence of nonces or hashes (which disable unsafe-inline in CSP2/3)
        has_nonce = any(src.startswith('nonce-') for src in script_src)
        has_hash = any(src.startswith('sha256-') or src.startswith('sha384-') or src.startswith('sha512-') for src in script_src)
        
        # In CSP2/CSP3: nonces, hashes, or strict-dynamic disable unsafe-inline
        allow_inline = unsafe_inline and not (has_nonce or has_hash or strict_dynamic)
        
        # Event handlers are generally disabled unless unsafe-inline is permitted and not ignored.
        allow_events = allow_inline
        
        # javascript: URL protocol vectors are governed by script-src
        # If unsafe-inline is disabled or ignored, javascript: URLs are also blocked in modern browsers.
        allow_js_urls = allow_inline
        
        return {
            'allow_inline_scripts': allow_inline,
            'allow_event_handlers': allow_events,
            'allow_eval': unsafe_eval,
            'allow_javascript_urls': allow_js_urls,
            'has_csp': True
        }
