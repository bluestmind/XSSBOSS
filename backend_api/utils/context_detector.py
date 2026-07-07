"""Context classification logic."""
from typing import Dict, Any, List, Optional
from bs4 import NavigableString
from backend_api.models.context import ContextType
from backend_api.utils.html_parser import HTMLParser
from backend_api.utils.js_parser import JSParser
from analysis_engine.enhanced_context_classifier import EnhancedContextClassifier, ClassifiedContext


class ContextDetector:
    """Detect and classify reflection contexts."""
    
    @staticmethod
    def classify_reflection(
        html_content: str,
        marker: str
    ) -> List[Dict[str, Any]]:
        """Classify where and how a marker is reflected using EnhancedContextClassifier.
        
        Args:
            html_content: HTML response content
            marker: Marker string to find
            
        Returns:
            List of context dictionaries
        """
        contexts = []
        
        # Run EnhancedContextClassifier for deep fine-grained classification
        classified_list = EnhancedContextClassifier.classify_all_reflections(html_content, marker)
        for cl in classified_list:
            contexts.append({
                'context_type': cl.context_type,
                'tag': cl.tag,
                'attribute': cl.attribute,
                'script_path': None,
                'snippet': cl.snippet,
                'quote_char': cl.quote_char,
                'breakout_sequence': cl.breakout_sequence,
                'is_html_entity_decoded': cl.is_html_entity_decoded,
                'is_js_executable': cl.is_js_executable,
                'requires_closing_tag': cl.requires_closing_tag,
                'metadata': cl.metadata,
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
                        'snippet': snippet,
                        'quote_char': '"',
                        'breakout_sequence': '",',
                        'is_html_entity_decoded': False,
                        'is_js_executable': False,
                        'requires_closing_tag': False,
                        'metadata': {'json_path': path},
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
                'snippet': parsed.query[:200],
                'quote_char': None,
                'breakout_sequence': '&',
                'is_html_entity_decoded': False,
                'is_js_executable': False,
                'requires_closing_tag': False,
                'metadata': {'url_component': 'query'},
            })
        
        # Check fragment
        if marker in parsed.fragment:
            contexts.append({
                'context_type': ContextType.URL_FRAGMENT,
                'tag': None,
                'attribute': None,
                'script_path': None,
                'snippet': parsed.fragment[:200],
                'quote_char': None,
                'breakout_sequence': '#',
                'is_html_entity_decoded': False,
                'is_js_executable': False,
                'requires_closing_tag': False,
                'metadata': {'url_component': 'fragment'},
            })
        
        return contexts
    
    @staticmethod
    def classify_node(node: Any) -> Optional[ContextType]:
        """Classify a single node's context type."""
        if isinstance(node, NavigableString):
            return ContextType.HTML_TEXT
        return None
