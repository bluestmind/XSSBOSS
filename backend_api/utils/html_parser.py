"""HTML parsing utilities."""
import re
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup, Tag, NavigableString
from lxml import html, etree


class HTMLParser:
    """HTML parsing and analysis utilities."""
    
    @staticmethod
    def parse_html(html_content: str) -> BeautifulSoup:
        """Parse HTML content using BeautifulSoup with lxml parser.
        
        Args:
            html_content: HTML content string
            
        Returns:
            BeautifulSoup object
        """
        return BeautifulSoup(html_content, 'lxml')
    
    @staticmethod
    def find_marker_in_text(html_content: str, marker: str) -> List[Dict[str, Any]]:
        """Find marker in HTML text nodes.
        
        Args:
            html_content: HTML content
            marker: Marker string to find
            
        Returns:
            List of dictionaries with match information
        """
        soup = HTMLParser.parse_html(html_content)
        results = []
        
        # Search in text nodes
        for element in soup.find_all(string=True):
            if marker in element:
                parent = element.parent
                results.append({
                    'type': 'text',
                    'tag': parent.name if parent else None,
                    'content': str(element),
                    'position': str(element).find(marker),
                    'node': element,
                    'parent': parent
                })
        
        return results
    
    @staticmethod
    def find_marker_in_attributes(html_content: str, marker: str) -> List[Dict[str, Any]]:
        """Find marker in HTML attributes.
        
        Args:
            html_content: HTML content
            marker: Marker string to find
            
        Returns:
            List of dictionaries with match information
        """
        soup = HTMLParser.parse_html(html_content)
        results = []
        
        # Search in attributes
        for element in soup.find_all():
            if not isinstance(element, Tag):
                continue
                
            for attr_name, attr_value in element.attrs.items():
                if isinstance(attr_value, list):
                    attr_value = ' '.join(attr_value)
                if isinstance(attr_value, str) and marker in attr_value:
                    # Check if quoted in the raw outer HTML representation
                    raw_tag = str(element)
                    double_quoted_pattern = rf'{re.escape(attr_name)}\s*=\s*"[^"]*{re.escape(marker)}'
                    single_quoted_pattern = rf'{re.escape(attr_name)}\s*=\s*\'[^\']*{re.escape(marker)}'
                    
                    is_double_quoted = bool(re.search(double_quoted_pattern, raw_tag, re.IGNORECASE))
                    is_single_quoted = bool(re.search(single_quoted_pattern, raw_tag, re.IGNORECASE))
                    is_quoted = is_double_quoted or is_single_quoted
                    
                    # Check if event handler
                    is_event_handler = attr_name.startswith('on') and len(attr_name) > 2
                    
                    results.append({
                        'type': 'attribute',
                        'tag': element.name,
                        'attribute': attr_name,
                        'value': attr_value,
                        'quoted': is_quoted,
                        'is_event_handler': is_event_handler,
                        'node': element
                    })
        
        return results
    
    @staticmethod
    def find_marker_in_script(html_content: str, marker: str) -> List[Dict[str, Any]]:
        """Find marker in script tags.
        
        Args:
            html_content: HTML content
            marker: Marker string to find
            
        Returns:
            List of dictionaries with match information
        """
        soup = HTMLParser.parse_html(html_content)
        results = []
        
        # Search in script content
        for script in soup.find_all('script'):
            script_content = script.string or ""
            if marker in script_content:
                results.append({
                    'type': 'script',
                    'src': script.get('src'),
                    'content': script_content,
                    'position': script_content.find(marker),
                    'node': script
                })
        
        return results
    
    @staticmethod
    def find_all_markers(html_content: str, marker: str) -> Dict[str, List[Dict[str, Any]]]:
        """Find marker in all possible locations.
        
        Args:
            html_content: HTML content
            marker: Marker string to find
            
        Returns:
            Dictionary with 'text', 'attributes', 'scripts' keys
        """
        return {
            'text': HTMLParser.find_marker_in_text(html_content, marker),
            'attributes': HTMLParser.find_marker_in_attributes(html_content, marker),
            'scripts': HTMLParser.find_marker_in_script(html_content, marker)
        }
    
    @staticmethod
    def extract_snippet(node: Any, max_length: int = 200) -> str:
        """Extract HTML snippet around a node.
        
        Args:
            node: BeautifulSoup node
            max_length: Maximum snippet length
            
        Returns:
            HTML snippet string
        """
        try:
            if hasattr(node, 'parent') and node.parent:
                # Get outerHTML of parent element
                snippet = str(node.parent)
            elif hasattr(node, '__str__'):
                snippet = str(node)
            else:
                snippet = str(node)
            
            # Truncate if too long
            if len(snippet) > max_length:
                marker_pos = snippet.find('XSSFUZZ_')
                if marker_pos >= 0:
                    start = max(0, marker_pos - 50)
                    end = min(len(snippet), marker_pos + 150)
                    snippet = snippet[start:end]
                else:
                    snippet = snippet[:max_length]
            
            return snippet
        except Exception as e:
            return f"<error extracting snippet: {e}>"
