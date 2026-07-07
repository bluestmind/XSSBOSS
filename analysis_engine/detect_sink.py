"""Sink detection engine."""
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
import httpx

from backend_api.models.endpoint import Endpoint
from backend_api.models.context import Context
from backend_api.models.sink import Sink, SinkType, DetectedVia
from backend_api.utils.sink_mapper import SinkMapper
from backend_api.utils.js_parser import JSParser
from backend_api.services.sink_service import SinkService
from backend_api.utils.logger import logger


class SinkDetectorEngine:
    """Engine for detecting dangerous sinks."""
    
    def __init__(self, db: Session):
        """Initialize with database session.
        
        Args:
            db: SQLAlchemy database session
        """
        self.db = db
    
    def detect_sinks_for_endpoint(
        self,
        endpoint_id: int,
        use_ast: bool = True,
        timeout: int = 10
    ) -> List[Sink]:
        """Detect sinks for all contexts in an endpoint.
        
        Args:
            endpoint_id: Endpoint ID
            use_ast: Whether to use AST parsing
            timeout: Request timeout
            
        Returns:
            List of created Sink records
        """
        endpoint = self.db.query(Endpoint).filter(Endpoint.id == endpoint_id).first()
        if not endpoint:
            raise ValueError(f"Endpoint {endpoint_id} not found")
        
        contexts = self.db.query(Context).filter(Context.endpoint_id == endpoint_id).all()
        sinks = []
        
        for context in contexts:
            try:
                context_sinks = self.detect_sinks_for_context(context.id, use_ast, timeout)
                sinks.extend(context_sinks)
            except Exception as e:
                logger.error(f"Error detecting sinks for context {context.id}: {e}", exc_info=True)
                continue
        
        return sinks
    
    def detect_sinks_for_context(
        self,
        context_id: int,
        use_ast: bool = True,
        timeout: int = 10
    ) -> List[Sink]:
        """Detect sinks for a specific context.
        
        Args:
            context_id: Context ID
            use_ast: Whether to use AST parsing
            timeout: Request timeout
            
        Returns:
            List of created Sink records
        """
        context = self.db.query(Context).filter(Context.id == context_id).first()
        if not context:
            raise ValueError(f"Context {context_id} not found")
        
        endpoint = context.endpoint
        
        # Get base URL from endpoint
        url_pattern = endpoint.url_pattern
        # Extract base URL (simplified - in production might need better parsing)
        if url_pattern.startswith('http'):
            base_url = '/'.join(url_pattern.split('/')[:3])
        else:
            base_url = url_pattern
        
        # Fetch HTML response to find JS files
        try:
            # Build request (use sample request if available)
            method = endpoint.method
            headers = (endpoint.auth_context or {}).copy()
            cookies = {}
            
            # Extract cookies from headers
            if 'Cookie' in headers:
                cookie_str = headers.pop('Cookie')
                for cookie_pair in cookie_str.split(';'):
                    if '=' in cookie_pair:
                        key, value = cookie_pair.split('=', 1)
                        cookies[key.strip()] = value.strip()
            
            # Send request to get HTML
            response = httpx.request(
                method=method,
                url=url_pattern,
                headers=headers,
                cookies=cookies,
                timeout=timeout,
                follow_redirects=True
            )
            
            if response.status_code >= 400:
                logger.warning(f"Request failed with status {response.status_code} for endpoint {endpoint.id}")
                return []
            
            html_content = response.text
            content_type = response.headers.get('Content-Type', '').lower()
            
            # Only analyze HTML responses
            if 'text/html' not in content_type:
                return []
            
            # Extract and analyze JS files
            js_sinks = SinkMapper.analyze_html_for_js_files(html_content, base_url, use_ast)
            
            # Create Sink records
            created_sinks = []
            for sink_data in js_sinks:
                # Map sink type
                sink_type_str = sink_data.get('sink_type', '')
                try:
                    sink_type = SinkType(sink_type_str)
                except ValueError:
                    # Try to map to known types
                    sink_type_map = {
                        'innerHTML': SinkType.INNERHTML,
                        'outerHTML': SinkType.OUTERHTML,
                        'insertAdjacentHTML': SinkType.INSERT_ADJACENT_HTML,
                        'eval': SinkType.EVAL,
                        'Function': SinkType.FUNCTION,
                        'setTimeout': SinkType.SET_TIMEOUT,
                        'setInterval': SinkType.SET_INTERVAL,
                        'document.write': SinkType.DOCUMENT_WRITE,
                        'jQuery_html': SinkType.JQUERY_HTML,
                        'href': SinkType.HREF,
                        'src': SinkType.SRC,
                    }
                    sink_type = sink_type_map.get(sink_type_str, SinkType.INNERHTML)
                
                # Build js_location string
                js_location = sink_data.get('js_location', '')
                if sink_data.get('line'):
                    js_location += f":{sink_data['line']}"
                if sink_data.get('column'):
                    js_location += f":{sink_data['column']}"
                
                # Create sink record
                sink = SinkService.create_sink(
                    self.db,
                    context_id=context.id,
                    sink_type=sink_type.value,
                    js_location=js_location,
                    taint_path=None,  # Would be populated by dynamic analysis
                    detected_via=DetectedVia.STATIC.value,
                    notes=f"Detected via static analysis in {sink_data.get('js_location', 'unknown')}"
                )
                created_sinks.append(sink)
                logger.info(f"Created sink {sink.id} for context {context.id}: {sink_type.value}")
            
            return created_sinks
            
        except Exception as e:
            logger.error(f"Error detecting sinks for context {context_id}: {e}", exc_info=True)
            return []
    
    def generate_dynamic_wrapper(
        self,
        marker: str
    ) -> str:
        """Generate dynamic wrapper script for browser injection.
        
        Args:
            marker: Marker string to detect
            
        Returns:
            JavaScript wrapper code
        """
        return SinkMapper.generate_dynamic_wrapper_script(marker)
    
    def detect_sinks_for_target(
        self,
        target_id: int,
        use_ast: bool = True,
        timeout: int = 10
    ) -> Dict[int, List[Sink]]:
        """Detect sinks for all endpoints in a target.
        
        Args:
            target_id: Target ID
            use_ast: Whether to use AST parsing
            timeout: Request timeout
            
        Returns:
            Dictionary mapping endpoint_id to list of sinks
        """
        endpoints = self.db.query(Endpoint).filter(Endpoint.target_id == target_id).all()
        
        results = {}
        for endpoint in endpoints:
            sinks = self.detect_sinks_for_endpoint(endpoint.id, use_ast, timeout)
            results[endpoint.id] = sinks
        
        return results
