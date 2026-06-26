"""Sink mapping utilities."""
from typing import List, Dict, Any, Optional
import re
from backend_api.models.sink import SinkType, DetectedVia
from backend_api.utils.js_parser import JSParser
from backend_api.utils.logger import logger


class SinkMapper:
    """Map data flows to dangerous JavaScript sinks."""
    
    @staticmethod
    def analyze_js_file(
        js_url: str,
        base_url: Optional[str] = None,
        use_ast: bool = True
    ) -> List[Dict[str, Any]]:
        """Analyze JavaScript file for dangerous sinks.
        
        Args:
            js_url: JavaScript file URL
            base_url: Base URL for resolving relative URLs
            use_ast: Whether to use AST parsing (if esprima available)
            
        Returns:
            List of sink dictionaries
        """
        # Fetch JS file
        js_content = JSParser.fetch_js_file(js_url, base_url)
        if not js_content:
            return []
        
        sinks = []
        
        # Try AST parsing first (more accurate)
        if use_ast:
            ast = JSParser.parse_with_esprima(js_content)
            if ast:
                ast_sinks = JSParser.find_sinks_in_ast(ast)
                for sink in ast_sinks:
                    sinks.append({
                        'sink_type': sink['type'],
                        'js_location': js_url,
                        'line': sink.get('line'),
                        'column': sink.get('column'),
                        'detected_via': DetectedVia.STATIC.value,
                        'context': sink.get('ast_node')
                    })
        
        # Fallback to regex (always run for coverage)
        regex_sinks = JSParser.find_dangerous_sinks(js_content)
        for sink in regex_sinks:
            # Avoid duplicates if AST already found it
            if not any(
                s.get('sink_type') == sink['type'] and
                s.get('js_location') == js_url and
                s.get('line') == sink['line']
                for s in sinks
            ):
                sinks.append({
                    'sink_type': sink['type'],
                    'js_location': js_url,
                    'line': sink.get('line'),
                    'column': sink.get('column'),
                    'detected_via': DetectedVia.STATIC.value,
                    'context': sink.get('context')
                })
        
        return sinks
    
    @staticmethod
    def analyze_html_for_js_files(
        html_content: str,
        base_url: str,
        use_ast: bool = True
    ) -> List[Dict[str, Any]]:
        """Extract and analyze JavaScript files from HTML.
        
        Args:
            html_content: HTML content
            base_url: Base URL
            use_ast: Whether to use AST parsing
            
        Returns:
            List of sink dictionaries from all JS files
        """
        js_urls = JSParser.extract_js_files_from_html(html_content, base_url)
        all_sinks = []
        
        for js_url in js_urls:
            try:
                sinks = SinkMapper.analyze_js_file(js_url, base_url, use_ast)
                all_sinks.extend(sinks)
                logger.info(f"Found {len(sinks)} sinks in {js_url}")
            except Exception as e:
                logger.error(f"Error analyzing JS file {js_url}: {e}")
                continue
        
        return all_sinks
    
    @staticmethod
    def generate_dynamic_wrapper_script(marker: str) -> str:
        """Generate JavaScript code to wrap dangerous sinks for dynamic analysis.
        
        Args:
            marker: Marker string to detect (XSSFUZZ_*)
            
        Returns:
            JavaScript code to inject
        """
        return f"""
(function() {{
    const marker = '{marker}';
    const oracleUrl = window.__ORACLE_URL__ || '/api/v1/oracle';
    
    // Wrap innerHTML setter
    const originalInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (originalInnerHTML && originalInnerHTML.set) {{
        Object.defineProperty(Element.prototype, 'innerHTML', {{
            set: function(value) {{
                if (typeof value === 'string' && value.includes(marker)) {{
                    // Record sink hit
                    const sinkInfo = {{
                        type: 'innerHTML',
                        element: this.tagName,
                        value: value.substring(0, 200),
                        stack: new Error().stack
                    }};
                    console.log('SINK HIT: innerHTML', sinkInfo);
                    // Send to oracle
                    if (typeof fetch !== 'undefined') {{
                        fetch(oracleUrl + '?token=' + encodeURIComponent(marker) + '&sink=innerHTML&data=' + encodeURIComponent(JSON.stringify(sinkInfo))).catch(() => {{}});
                    }}
                }}
                originalInnerHTML.set.call(this, value);
            }},
            get: originalInnerHTML.get
        }});
    }}
    
    // Wrap outerHTML setter
    const originalOuterHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
    if (originalOuterHTML && originalOuterHTML.set) {{
        Object.defineProperty(Element.prototype, 'outerHTML', {{
            set: function(value) {{
                if (typeof value === 'string' && value.includes(marker)) {{
                    const sinkInfo = {{
                        type: 'outerHTML',
                        element: this.tagName,
                        value: value.substring(0, 200),
                        stack: new Error().stack
                    }};
                    console.log('SINK HIT: outerHTML', sinkInfo);
                    if (typeof fetch !== 'undefined') {{
                        fetch(oracleUrl + '?token=' + encodeURIComponent(marker) + '&sink=outerHTML&data=' + encodeURIComponent(JSON.stringify(sinkInfo))).catch(() => {{}});
                    }}
                }}
                originalOuterHTML.set.call(this, value);
            }},
            get: originalOuterHTML.get
        }});
    }}
    
    // Wrap insertAdjacentHTML
    const originalInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
    if (originalInsertAdjacentHTML) {{
        Element.prototype.insertAdjacentHTML = function(position, html) {{
            if (typeof html === 'string' && html.includes(marker)) {{
                const sinkInfo = {{
                    type: 'insertAdjacentHTML',
                    element: this.tagName,
                    position: position,
                    value: html.substring(0, 200),
                    stack: new Error().stack
                }};
                console.log('SINK HIT: insertAdjacentHTML', sinkInfo);
                if (typeof fetch !== 'undefined') {{
                    fetch(oracleUrl + '?token=' + encodeURIComponent(marker) + '&sink=insertAdjacentHTML&data=' + encodeURIComponent(JSON.stringify(sinkInfo))).catch(() => {{}});
                }}
            }}
            return originalInsertAdjacentHTML.call(this, position, html);
        }};
    }}
    
    // Wrap eval
    const originalEval = window.eval;
    window.eval = function(code) {{
        if (typeof code === 'string' && code.includes(marker)) {{
            const sinkInfo = {{
                type: 'eval',
                value: code.substring(0, 200),
                stack: new Error().stack
            }};
            console.log('SINK HIT: eval', sinkInfo);
            if (typeof fetch !== 'undefined') {{
                fetch(oracleUrl + '?token=' + encodeURIComponent(marker) + '&sink=eval&data=' + encodeURIComponent(JSON.stringify(sinkInfo))).catch(() => {{}});
            }}
        }}
        return originalEval.call(this, code);
    }};
    
    // Wrap Function constructor
    const originalFunction = window.Function;
    window.Function = function(...args) {{
        const code = args[args.length - 1];
        if (typeof code === 'string' && code.includes(marker)) {{
            const sinkInfo = {{
                type: 'Function',
                value: code.substring(0, 200),
                stack: new Error().stack
            }};
            console.log('SINK HIT: Function', sinkInfo);
            if (typeof fetch !== 'undefined') {{
                fetch(oracleUrl + '?token=' + encodeURIComponent(marker) + '&sink=Function&data=' + encodeURIComponent(JSON.stringify(sinkInfo))).catch(() => {{}});
            }}
        }}
        return originalFunction.apply(this, args);
    }};
    
    // Wrap setTimeout
    const originalSetTimeout = window.setTimeout;
    window.setTimeout = function(func, delay, ...args) {{
        if (typeof func === 'string' && func.includes(marker)) {{
            const sinkInfo = {{
                type: 'setTimeout',
                value: func.substring(0, 200),
                stack: new Error().stack
            }};
            console.log('SINK HIT: setTimeout', sinkInfo);
            if (typeof fetch !== 'undefined') {{
                fetch(oracleUrl + '?token=' + encodeURIComponent(marker) + '&sink=setTimeout&data=' + encodeURIComponent(JSON.stringify(sinkInfo))).catch(() => {{}});
            }}
        }}
        return originalSetTimeout.call(this, func, delay, ...args);
    }};
    
    // Wrap setInterval
    const originalSetInterval = window.setInterval;
    window.setInterval = function(func, delay, ...args) {{
        if (typeof func === 'string' && func.includes(marker)) {{
            const sinkInfo = {{
                type: 'setInterval',
                value: func.substring(0, 200),
                stack: new Error().stack
            }};
            console.log('SINK HIT: setInterval', sinkInfo);
            if (typeof fetch !== 'undefined') {{
                fetch(oracleUrl + '?token=' + encodeURIComponent(marker) + '&sink=setInterval&data=' + encodeURIComponent(JSON.stringify(sinkInfo))).catch(() => {{}});
            }}
        }}
        return originalSetInterval.call(this, func, delay, ...args);
    }};
    
    // Wrap document.write
    const originalDocumentWrite = document.write;
    document.write = function(...args) {{
        const content = args.join('');
        if (typeof content === 'string' && content.includes(marker)) {{
            const sinkInfo = {{
                type: 'document.write',
                value: content.substring(0, 200),
                stack: new Error().stack
            }};
            console.log('SINK HIT: document.write', sinkInfo);
            if (typeof fetch !== 'undefined') {{
                fetch(oracleUrl + '?token=' + encodeURIComponent(marker) + '&sink=document.write&data=' + encodeURIComponent(JSON.stringify(sinkInfo))).catch(() => {{}});
            }}
        }}
        return originalDocumentWrite.apply(this, args);
    }};
}})();
"""
    
    @staticmethod
    def map_taint_path(
        marker: str,
        js_content: str,
        sink_position: int
    ) -> Optional[List[str]]:
        """Map taint path from marker to sink (basic static analysis).
        
        Args:
            marker: Marker string
            js_content: JavaScript content
            sink_position: Position of sink in code
            
        Returns:
            List of variable names in taint path or None
        """
        # This is a simplified version - full taint tracking would require more sophisticated analysis
        # For now, we'll extract variable names between marker and sink
        
        marker_pos = js_content.find(marker)
        if marker_pos == -1 or marker_pos >= sink_position:
            return None
        
        # Extract code between marker and sink
        code_snippet = js_content[marker_pos:sink_position]
        
        # Find variable assignments
        var_pattern = r'(\w+)\s*=\s*[^;]+'
        matches = re.findall(var_pattern, code_snippet)
        
        return matches[:10]  # Limit to first 10 variables
