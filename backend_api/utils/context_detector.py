"""Context classification logic."""
from typing import Dict, Any, List, Optional
from bs4 import NavigableString
from backend_api.models.context import ContextType
from backend_api.utils.html_parser import HTMLParser
from backend_api.utils.js_parser import JSParser


class ContextDetector:
    """Detect and classify reflection contexts."""
    
    @staticmethod
    def classify_reflection(
        html_content: str,
        marker: str
    ) -> List[Dict[str, Any]]:
        """Classify where and how a marker is reflected.
        
        Args:
            html_content: HTML response content
            marker: Marker string to find
            
        Returns:
            List of context dictionaries
        """
        contexts = []
        
        # Find in HTML
        html_results = HTMLParser.find_all_markers(html_content, marker)
        
        # Text nodes
        for result in html_results.get('text', []):
            snippet = HTMLParser.extract_snippet(result.get('node'), max_length=200)
            contexts.append({
                'context_type': ContextType.HTML_TEXT,
                'tag': result.get('tag'),
                'attribute': None,
                'script_path': None,
                'snippet': snippet
            })
        
        # Attributes
        for result in html_results.get('attributes', []):
            attr_name = result.get('attribute')
            is_event_handler = result.get('is_event_handler', False)
            is_quoted = result.get('quoted', False)
            
            snippet = HTMLParser.extract_snippet(result.get('node'), max_length=200)
            
            if is_event_handler:
                # Event handler attribute
                contexts.append({
                    'context_type': ContextType.EVENT_HANDLER_ATTR,
                    'tag': result.get('tag'),
                    'attribute': attr_name,
                    'script_path': None,
                    'snippet': snippet
                })
            else:
                # Regular attribute
                if is_quoted:
                    contexts.append({
                        'context_type': ContextType.ATTR_QUOTED,
                        'tag': result.get('tag'),
                        'attribute': attr_name,
                        'script_path': None,
                        'snippet': snippet
                    })
                else:
                    contexts.append({
                        'context_type': ContextType.ATTR_UNQUOTED,
                        'tag': result.get('tag'),
                        'attribute': attr_name,
                        'script_path': None,
                        'snippet': snippet
                    })
        
        # Script content
        for result in html_results.get('scripts', []):
            script_content = result.get('content', '')
            script_src = result.get('src')
            
            # Check if marker is in string literal
            js_string_results = JSParser.find_marker_in_string(script_content, marker)
            for js_result in js_string_results:
                snippet = js_result.get('content', '')[:200]
                contexts.append({
                    'context_type': ContextType.JS_STRING_LITERAL,
                    'tag': 'script',
                    'attribute': None,
                    'script_path': script_src,
                    'snippet': snippet
                })
            
            # Check if marker is in identifier (rare)
            js_id_results = JSParser.find_marker_in_identifier(script_content, marker)
            for js_result in js_id_results:
                snippet = js_result.get('content', '')[:200]
                contexts.append({
                    'context_type': ContextType.JS_IDENTIFIER,
                    'tag': 'script',
                    'attribute': None,
                    'script_path': script_src,
                    'snippet': snippet
                })
        
        return contexts
    
    @staticmethod
    def detect_json_reflection(
        json_content: str,
        marker: str
    ) -> List[Dict[str, Any]]:
        """Detect marker in JSON content.
        
        Args:
            json_content: JSON content string
            marker: Marker string to find
            
        Returns:
            List of context dictionaries
        """
        import json
        contexts = []
        
        try:
            data = json.loads(json_content)
            
            def find_in_value(obj, path=""):
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        find_in_value(value, f"{path}.{key}" if path else key)
                elif isinstance(obj, list):
                    for i, item in enumerate(obj):
                        find_in_value(item, f"{path}[{i}]")
                elif isinstance(obj, str) and marker in obj:
                    snippet = obj[:200]
                    contexts.append({
                        'context_type': ContextType.JSON_VALUE,
                        'tag': None,
                        'attribute': None,
                        'script_path': None,
                        'snippet': snippet
                    })
            
            find_in_value(data)
        except (json.JSONDecodeError, TypeError):
            pass
        
        return contexts
    
    @staticmethod
    def detect_url_reflection(
        url: str,
        marker: str
    ) -> List[Dict[str, Any]]:
        """Detect marker in URL components.
        
        Args:
            url: URL string
            marker: Marker string to find
            
        Returns:
            List of context dictionaries
        """
        from urllib.parse import urlparse
        contexts = []
        
        parsed = urlparse(url)
        
        # Check query string
        if marker in parsed.query:
            contexts.append({
                'context_type': ContextType.URL_QUERY,
                'tag': None,
                'attribute': None,
                'script_path': None,
                'snippet': parsed.query[:200]
            })
        
        # Check fragment
        if marker in parsed.fragment:
            contexts.append({
                'context_type': ContextType.URL_FRAGMENT,
                'tag': None,
                'attribute': None,
                'script_path': None,
                'snippet': parsed.fragment[:200]
            })
        
        return contexts
    
    @staticmethod
    def classify_node(node: Any) -> Optional[ContextType]:
        """Classify a single node's context type.
        
        Args:
            node: BeautifulSoup node
            
        Returns:
            ContextType or None
        """
        if isinstance(node, NavigableString):
            return ContextType.HTML_TEXT
        
        if hasattr(node, 'attrs'):
            # Check if it's an attribute
            # This is a simplified version - full classification done in classify_reflection
            return None
        
        return None
