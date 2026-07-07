"""JavaScript parsing utilities."""
from typing import List, Dict, Any, Optional
import re
from urllib.parse import urljoin, urlparse

try:
    import httpx
except ImportError:
    httpx = None


class JSParser:
    """JavaScript parsing and analysis utilities."""
    
    # Dangerous sink patterns (regex)
    DANGEROUS_SINKS = [
        {
            'pattern': r'\.innerHTML\s*=',
            'type': 'innerHTML',
            'description': 'innerHTML assignment'
        },
        {
            'pattern': r'\.outerHTML\s*=',
            'type': 'outerHTML',
            'description': 'outerHTML assignment'
        },
        {
            'pattern': r'\.insertAdjacentHTML\s*\(',
            'type': 'insertAdjacentHTML',
            'description': 'insertAdjacentHTML call'
        },
        {
            'pattern': r'\beval\s*\(',
            'type': 'eval',
            'description': 'eval() call'
        },
        {
            'pattern': r'new\s+Function\s*\(',
            'type': 'Function',
            'description': 'new Function() call'
        },
        {
            'pattern': r'setTimeout\s*\([^,)]*["\']',
            'type': 'setTimeout',
            'description': 'setTimeout with string'
        },
        {
            'pattern': r'setInterval\s*\([^,)]*["\']',
            'type': 'setInterval',
            'description': 'setInterval with string'
        },
        {
            'pattern': r'document\.write\s*\(',
            'type': 'document.write',
            'description': 'document.write() call'
        },
        {
            'pattern': r'document\.writeln\s*\(',
            'type': 'document.writeln',
            'description': 'document.writeln() call'
        },
        {
            'pattern': r'\.createContextualFragment\s*\(',
            'type': 'Range.createContextualFragment',
            'description': 'Range.createContextualFragment() DOM parsing sink'
        },
        {
            'pattern': r'new\s+DOMParser\s*\(\s*\)\s*\.parseFromString\s*\(',
            'type': 'DOMParser.parseFromString',
            'description': 'DOMParser.parseFromString() parser sink'
        },
        {
            'pattern': r'\.parseFromString\s*\([^,]+,\s*["\']text/html["\']',
            'type': 'DOMParser.parseFromString',
            'description': 'DOMParser.parseFromString(text/html) parser sink'
        },
        {
            'pattern': r'\.setHTMLUnsafe\s*\(',
            'type': 'setHTMLUnsafe',
            'description': 'setHTMLUnsafe() HTML sink'
        },
        {
            'pattern': r'\.setHTML\s*\(',
            'type': 'setHTML',
            'description': 'setHTML() HTML sink'
        },
        {
            'pattern': r'\$\([^)]+\)\.html\s*\(',
            'type': 'jQuery_html',
            'description': 'jQuery .html() call'
        },
        {
            'pattern': r'\.href\s*=\s*["\']javascript:',
            'type': 'href',
            'description': 'href with javascript: protocol'
        },
        {
            'pattern': r'\.src\s*=\s*["\']javascript:',
            'type': 'src',
            'description': 'src with javascript: protocol'
        },
        {
            'pattern': r'location\s*\.\s*(href|replace|assign)\s*=\s*',
            'type': 'location_redirect',
            'description': 'location redirect assignment'
        },
        {
            'pattern': r'window\s*\.\s*open\s*\(',
            'type': 'window_open',
            'description': 'window.open() call'
        },
        {
            'pattern': r'dangerouslySetInnerHTML\s*:',
            'type': 'dangerouslySetInnerHTML',
            'description': 'React dangerouslySetInnerHTML assignment'
        },
        {
            'pattern': r'\.setAttribute\s*\(\s*["\'](on\w+|src|href)["\']',
            'type': 'setAttribute',
            'description': 'setAttribute event handler/resource call'
        },
        {
            'pattern': r'\$\([^)]+\)\.(append|prepend|wrap|after|before)\s*\(',
            'type': 'jQuery_insertion',
            'description': 'jQuery DOM insertion call'
        }
    ]

    DOM_SOURCES = [
        {
            'pattern': r'\blocation\s*\.\s*(hash|search|href|pathname)\b',
            'type': 'location',
            'description': 'URL-controlled location source'
        },
        {
            'pattern': r'new\s+URLSearchParams\s*\(\s*(?:location\.)?(search|hash)',
            'type': 'URLSearchParams',
            'description': 'URLSearchParams source'
        },
        {
            'pattern': r'\bwindow\s*\.\s*name\b',
            'type': 'window.name',
            'description': 'window.name source'
        },
        {
            'pattern': r'\bdocument\s*\.\s*referrer\b',
            'type': 'document.referrer',
            'description': 'document.referrer source'
        },
        {
            'pattern': r'\bdocument\s*\.\s*cookie\b',
            'type': 'document.cookie',
            'description': 'document.cookie source'
        },
        {
            'pattern': r'\b(?:localStorage|sessionStorage)\s*\.\s*getItem\s*\(',
            'type': 'web_storage',
            'description': 'localStorage/sessionStorage source'
        },
        {
            'pattern': r'\baddEventListener\s*\(\s*["\']message["\']',
            'type': 'postMessage',
            'description': 'postMessage message-event source'
        },
        {
            'pattern': r'\bonmessage\s*=',
            'type': 'postMessage',
            'description': 'postMessage onmessage source'
        },
        {
            'pattern': r'\bevent\s*\.\s*data\b|\bmessageEvent\s*\.\s*data\b',
            'type': 'message.data',
            'description': 'web message data source'
        },
        {
            'pattern': r'(__proto__|constructor|prototype)',
            'type': 'prototype_pollution_candidate',
            'description': 'prototype pollution candidate source/gadget'
        },
    ]

    DOM_CLOBBERING_GADGETS = [
        {
            'pattern': r'\bwindow\s*\.\s*[a-zA-Z_$][\w$]*\s*\.\s*(href|src|innerHTML|html|content|url)\b',
            'type': 'window_named_property',
            'description': 'window named property dereference that may be DOM-clobberable'
        },
        {
            'pattern': r'\bdocument\s*\.\s*forms\s*\.\s*[a-zA-Z_$][\w$]*',
            'type': 'document_forms_named_property',
            'description': 'document.forms named property access'
        },
        {
            'pattern': r'\bdocument\s*\.\s*all\s*\.\s*[a-zA-Z_$][\w$]*',
            'type': 'document_all_named_property',
            'description': 'document.all named property access'
        },
        {
            'pattern': r'\b[a-zA-Z_$][\w$]*\s*\.\s*(href|src|innerHTML|html|content|url)\b',
            'type': 'implicit_named_property_candidate',
            'description': 'implicit global/member access that may be clobberable'
        },
    ]

    PROTOTYPE_POLLUTION_GADGETS = [
        {
            'pattern': r'\bObject\.assign\s*\(',
            'type': 'object_assign_merge',
            'description': 'Object.assign merge candidate'
        },
        {
            'pattern': r'\b(?:_|lodash)\.merge\s*\(',
            'type': 'lodash_merge',
            'description': 'lodash merge candidate'
        },
        {
            'pattern': r'\b(?:_|jQuery|\$)\.extend\s*\(\s*true\s*,',
            'type': 'deep_extend',
            'description': 'deep extend merge candidate'
        },
        {
            'pattern': r'for\s*\(\s*(?:var|let|const)?\s*[a-zA-Z_$][\w$]*\s+in\s+[^)]+\)\s*{[^}]*\[[^\]]+\]\s*=',
            'type': 'for_in_assignment_merge',
            'description': 'for-in assignment merge candidate'
        },
        {
            'pattern': r'\b(config|options|settings|state)\s*\.\s*(html|innerHTML|template|srcdoc|href|src|sequence)\b',
            'type': 'polluted_property_read',
            'description': 'read of a commonly polluted gadget property'
        },
    ]
    
    @staticmethod
    def fetch_js_file(url: str, base_url: Optional[str] = None, timeout: int = 10) -> Optional[str]:
        """Fetch JavaScript file from URL.
        
        Args:
            url: JavaScript file URL (absolute or relative)
            base_url: Base URL for resolving relative URLs
            timeout: Request timeout
            
        Returns:
            JavaScript content or None if fetch fails
        """
        try:
            if httpx is None:
                raise RuntimeError("httpx is required to fetch JavaScript files")

            # Resolve relative URLs
            if base_url and not url.startswith(('http://', 'https://')):
                url = urljoin(base_url, url)
            
            response = httpx.get(url, timeout=timeout, follow_redirects=True)
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '').lower()
                if 'javascript' in content_type or 'application/javascript' in content_type or url.endswith('.js'):
                    return response.text
            return None
        except Exception as e:
            print(f"Error fetching JS file {url}: {e}")
            return None
    
    @staticmethod
    def find_dangerous_sinks(js_content: str) -> List[Dict[str, Any]]:
        """Find dangerous sink patterns in JavaScript code using regex.
        
        Args:
            js_content: JavaScript code content
            
        Returns:
            List of sink dictionaries
        """
        sinks = []
        
        for sink_def in JSParser.DANGEROUS_SINKS:
            pattern = sink_def['pattern']
            matches = re.finditer(pattern, js_content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_num = js_content[:match.start()].count('\n') + 1
                col_num = match.start() - js_content.rfind('\n', 0, match.start()) - 1
                
                sinks.append({
                    'type': sink_def['type'],
                    'pattern': pattern,
                    'match': match.group(),
                    'position': match.start(),
                    'line': line_num,
                    'column': col_num,
                    'description': sink_def['description'],
                    'context': JSParser._extract_context(js_content, match.start(), match.end())
                })
        
        return sinks

    @staticmethod
    def find_dom_sources(js_content: str) -> List[Dict[str, Any]]:
        """Find likely attacker-controlled DOM sources in JavaScript code."""
        sources = []

        for source_def in JSParser.DOM_SOURCES:
            pattern = source_def['pattern']
            matches = re.finditer(pattern, js_content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_num = js_content[:match.start()].count('\n') + 1
                col_num = match.start() - js_content.rfind('\n', 0, match.start()) - 1

                sources.append({
                    'type': source_def['type'],
                    'pattern': pattern,
                    'match': match.group(),
                    'position': match.start(),
                    'line': line_num,
                    'column': col_num,
                    'description': source_def['description'],
                    'context': JSParser._extract_context(js_content, match.start(), match.end())
                })

        return sources

    @staticmethod
    def _find_pattern_group(js_content: str, definitions: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """Find a pattern group and return normalized match records."""
        results = []
        for item in definitions:
            matches = re.finditer(item['pattern'], js_content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            for match in matches:
                line_num = js_content[:match.start()].count('\n') + 1
                col_num = match.start() - js_content.rfind('\n', 0, match.start()) - 1
                results.append({
                    'type': item['type'],
                    'pattern': item['pattern'],
                    'match': match.group()[:500],
                    'position': match.start(),
                    'line': line_num,
                    'column': col_num,
                    'description': item['description'],
                    'context': JSParser._extract_context(js_content, match.start(), match.end())
                })
        return results

    @staticmethod
    def find_dom_clobbering_gadgets(js_content: str) -> List[Dict[str, Any]]:
        """Find possible DOM clobbering gadget candidates."""
        return JSParser._find_pattern_group(js_content, JSParser.DOM_CLOBBERING_GADGETS)

    @staticmethod
    def find_prototype_pollution_gadgets(js_content: str) -> List[Dict[str, Any]]:
        """Find possible client-side prototype pollution sources/gadgets."""
        return JSParser._find_pattern_group(js_content, JSParser.PROTOTYPE_POLLUTION_GADGETS)

    @staticmethod
    def find_modern_dom_signals(js_content: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Find modern client-side XSS signals in JavaScript or HTML content."""
        from backend_api.utils.modern_xss_profiles import ModernXSSProfiles

        return {
            'sources': JSParser.find_dom_sources(js_content),
            'sinks': JSParser.find_dangerous_sinks(js_content),
            'dom_clobbering_gadgets': JSParser.find_dom_clobbering_gadgets(js_content),
            'prototype_pollution_gadgets': JSParser.find_prototype_pollution_gadgets(js_content),
            'fingerprint': ModernXSSProfiles.fingerprint_html(js_content, headers or {}),
        }
    
    @staticmethod
    def _extract_context(js_content: str, start: int, end: int, context_lines: int = 3) -> str:
        """Extract context around a match.
        
        Args:
            js_content: JavaScript content
            start: Match start position
            end: Match end position
            context_lines: Number of lines before/after to include
            
        Returns:
            Context string
        """
        lines = js_content.split('\n')
        start_line = js_content[:start].count('\n')
        end_line = js_content[:end].count('\n')
        
        context_start = max(0, start_line - context_lines)
        context_end = min(len(lines), end_line + context_lines + 1)
        
        context = '\n'.join(lines[context_start:context_end])
        return context
    
    @staticmethod
    def parse_with_esprima(js_content: str) -> Optional[Dict[str, Any]]:
        """Parse JavaScript with esprima-python (if available).
        
        Args:
            js_content: JavaScript code content
            
        Returns:
            Parsed AST or None if esprima not available
        """
        try:
            import esprima
            try:
                ast = esprima.parseScript(js_content, loc=True)
            except Exception:
                # Fallback to module parsing to support ES6 imports/exports
                ast = esprima.parseModule(js_content, loc=True)
            return ast
        except ImportError:
            return None
        except Exception as e:
            print(f"Error parsing with esprima: {e}")
            return None
    
    @staticmethod
    def find_sinks_in_ast(ast: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find dangerous sinks in AST (if esprima available).
        
        Args:
            ast: Parsed AST from esprima
            
        Returns:
            List of sink dictionaries
        """
        sinks = []
        
        def traverse(node, parent=None):
            if not isinstance(node, dict):
                return
            
            node_type = node.get('type')
            
            # Check for innerHTML/outerHTML assignments
            if node_type == 'AssignmentExpression':
                left = node.get('left', {})
                if left.get('type') == 'MemberExpression':
                    prop = left.get('property', {})
                    prop_name = prop.get('name', '')
                    if prop_name in ['innerHTML', 'outerHTML']:
                        loc = node.get('loc', {})
                        sinks.append({
                            'type': prop_name,
                            'line': loc.get('start', {}).get('line'),
                            'column': loc.get('start', {}).get('column'),
                            'ast_node': node
                        })
            
            # Check for function calls
            elif node_type == 'CallExpression':
                callee = node.get('callee', {})
                callee_name = callee.get('name', '')
                
                if callee_name in ['eval', 'setTimeout', 'setInterval', 'document.write']:
                    loc = node.get('loc', {})
                    sinks.append({
                        'type': callee_name,
                        'line': loc.get('start', {}).get('line'),
                        'column': loc.get('start', {}).get('column'),
                        'ast_node': node
                    })
                
                # Check for new Function()
                if callee.get('type') == 'NewExpression':
                    func_name = callee.get('callee', {}).get('name', '')
                    if func_name == 'Function':
                        loc = node.get('loc', {})
                        sinks.append({
                            'type': 'Function',
                            'line': loc.get('start', {}).get('line'),
                            'column': loc.get('start', {}).get('column'),
                            'ast_node': node
                        })
            
            # Recursively traverse children
            for key, value in node.items():
                if isinstance(value, dict):
                    traverse(value, node)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            traverse(item, node)
        
        traverse(ast)
        return sinks
    
    @staticmethod
    def find_marker_in_string(js_content: str, marker: str) -> List[Dict[str, Any]]:
        """Find marker in JavaScript string literals.
        
        Args:
            js_content: JavaScript code content
            marker: Marker string to find
            
        Returns:
            List of match dictionaries
        """
        results = []
        
        # Match string literals (single, double, template)
        string_patterns = [
            r'["\']([^"\']*' + re.escape(marker) + r'[^"\']*)["\']',  # Single/double quotes
            r'`([^`]*' + re.escape(marker) + r'[^`]*)`',  # Template literals
        ]
        
        for pattern in string_patterns:
            matches = re.finditer(pattern, js_content)
            for match in matches:
                line_num = js_content[:match.start()].count('\n') + 1
                results.append({
                    'type': 'string_literal',
                    'content': match.group(1),
                    'position': match.start(),
                    'line': line_num
                })
        
        return results
    
    @staticmethod
    def find_marker_in_identifier(js_content: str, marker: str) -> List[Dict[str, Any]]:
        """Find marker in JavaScript identifiers (rare but dangerous).
        
        Args:
            js_content: JavaScript code content
            marker: Marker string to find
            
        Returns:
            List of match dictionaries
        """
        results = []
        
        # Match identifier patterns containing marker
        pattern = r'\b([a-zA-Z_$][a-zA-Z0-9_$]*' + re.escape(marker) + r'[a-zA-Z0-9_$]*)\b'
        matches = re.finditer(pattern, js_content)
        
        for match in matches:
            line_num = js_content[:match.start()].count('\n') + 1
            results.append({
                'type': 'identifier',
                'content': match.group(1),
                'position': match.start(),
                'line': line_num
            })
        
        return results
    
    @staticmethod
    def extract_js_files_from_html(html_content: str, base_url: str) -> List[str]:
        """Extract JavaScript file URLs from HTML.
        
        Args:
            html_content: HTML content
            base_url: Base URL for resolving relative URLs
            
        Returns:
            List of JavaScript file URLs
        """
        from bs4 import BeautifulSoup
        
        soup = BeautifulSoup(html_content, 'lxml')
        js_urls = []
        
        # Find script tags with src
        for script in soup.find_all('script', src=True):
            src = script.get('src')
            if src:
                if not src.startswith(('http://', 'https://')):
                    src = urljoin(base_url, src)
                js_urls.append(src)
        
        return js_urls
