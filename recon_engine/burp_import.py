"""Burp Suite XML import."""
import xml.etree.ElementTree as ET
import base64
from typing import List, Dict, Any, Optional
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote


class BurpImporter:
    """Import requests from Burp Suite XML export."""
    
    @staticmethod
    def parse_burp_xml(xml_path: str) -> List[Dict[str, Any]]:
        """Parse Burp Suite XML export file.
        
        Args:
            xml_path: Path to Burp XML export file
            
        Returns:
            List of parsed request dictionaries
        """
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        requests = []
        
        # Burp XML structure: <items><item>...</item></items>
        for item in root.findall('.//item'):
            request_data = BurpImporter._parse_item(item)
            if request_data:
                requests.append(request_data)
        
        return requests
    
    @staticmethod
    def _parse_item(item: ET.Element) -> Optional[Dict[str, Any]]:
        """Parse a single item element from Burp XML.
        
        Args:
            item: XML element representing a request/response pair
            
        Returns:
            Dictionary with request data or None if parsing fails
        """
        try:
            # Extract URL
            url_elem = item.find('url')
            if url_elem is None or url_elem.text is None:
                return None
            url = url_elem.text
            
            # Extract method
            method_elem = item.find('method')
            method = method_elem.text if method_elem is not None and method_elem.text else 'GET'
            
            # Extract request
            request_elem = item.find('request')
            if request_elem is None:
                return None
            
            # Decode base64 request if needed
            request_text = request_elem.text or ""
            if request_elem.get('base64') == 'true':
                try:
                    request_text = base64.b64decode(request_text).decode('utf-8', errors='ignore')
                except Exception as e:
                    print(f"Error decoding base64 request: {e}")
                    return None
            
            # Parse request
            request_data = BurpImporter._parse_request(request_text, method, url)
            
            # Extract response
            response_elem = item.find('response')
            if response_elem is not None:
                response_text = response_elem.text or ""
                if response_elem.get('base64') == 'true':
                    try:
                        response_text = base64.b64decode(response_text).decode('utf-8', errors='ignore')
                    except Exception as e:
                        print(f"Error decoding base64 response: {e}")
                        response_text = ""
                request_data['response'] = response_text
            
            return request_data
            
        except Exception as e:
            print(f"Error parsing item: {e}")
            return None
    
    @staticmethod
    def _parse_request(request_text: str, method: str, url: str) -> Dict[str, Any]:
        """Parse HTTP request text into structured data.
        
        Args:
            request_text: Raw HTTP request text
            method: HTTP method
            url: Request URL
            
        Returns:
            Dictionary with parsed request data
        """
        lines = request_text.split('\n')
        if not lines:
            return {
                'method': method,
                'url': url,
                'headers': {},
                'query': {},
                'body': None,
                'json': None
            }
        
        # Parse headers
        headers = {}
        body_start = 0
        
        for i, line in enumerate(lines[1:], 1):  # Skip first line (method + path)
            line = line.strip()
            if not line:
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        # Parse body
        body = None
        json_data = None
        if body_start < len(lines):
            body_text = '\n'.join(lines[body_start:]).strip()
            if body_text:
                # Check if JSON
                content_type = headers.get('Content-Type', '').lower()
                if 'application/json' in content_type:
                    try:
                        import json
                        json_data = json.loads(body_text)
                    except json.JSONDecodeError:
                        body = body_text
                elif 'application/x-www-form-urlencoded' in content_type:
                    # Parse form data
                    form_params = {}
                    for pair in body_text.split('&'):
                        if '=' in pair:
                            key, value = pair.split('=', 1)
                            form_params[unquote(key)] = unquote(value)
                    body = form_params
                else:
                    body = body_text
        
        # Parse query parameters from URL
        query_params = {}
        if '?' in url:
            parsed = urlparse(url)
            query_params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
        
        return {
            'method': method,
            'url': url,
            'headers': headers,
            'query': query_params,
            'body': body,
            'json': json_data
        }
    
    @staticmethod
    def import_to_database(
        xml_path: str,
        target_id: int,
        db_session
    ) -> int:
        """Import Burp XML (history or issues) to database.
        
        Args:
            xml_path: Path to Burp XML file
            target_id: Target ID to attach endpoints to
            db_session: SQLAlchemy database session
            
        Returns:
            Number of endpoints imported
        """
        from backend_api.services.recon_service import ReconService
        from backend_api.models.param import Param
        from backend_api.models.context import Context, ContextType
        import re
        
        # Detect if it's an issues export or standard proxy history
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
        except Exception as e:
            print(f"Error reading XML file: {e}")
            return 0
            
        # Parse issues XML if root contains issue elements
        issues = root.findall('.//issue')
        if issues:
            count = 0
            for issue in issues:
                try:
                    # Parse host and path
                    host_elem = issue.find('host')
                    path_elem = issue.find('path')
                    if host_elem is None or path_elem is None:
                        continue
                    
                    protocol = host_elem.get('protocol', 'http')
                    host = host_elem.text or ""
                    path = path_elem.text or ""
                    full_url = f"{protocol}://{host}{path}"
                    
                    # Parse request details if available
                    req_elem = issue.find('.//request')
                    method = 'GET'
                    request_text = ""
                    if req_elem is not None:
                        method = req_elem.get('method', 'GET')
                        request_text = req_elem.text or ""
                        if req_elem.get('base64') == 'true':
                            try:
                                request_text = base64.b64decode(request_text).decode('utf-8', errors='ignore')
                            except Exception:
                                pass
                                
                    request_data = BurpImporter._parse_request(request_text, method, full_url) if request_text else {
                        'method': method,
                        'url': full_url,
                        'headers': {},
                        'query': {},
                        'body': None,
                        'json': None
                    }
                    
                    # Extract query parameters if present in URL
                    if "?" in full_url:
                        parsed = urlparse(full_url)
                        request_data["query"] = {
                            k: v[0] if len(v) == 1 else v 
                            for k, v in parse_qs(parsed.query, keep_blank_values=True).items()
                        }
                    
                    # Create endpoint record
                    endpoint = ReconService.create_endpoint_from_request(
                        db_session,
                        target_id,
                        method,
                        full_url,
                        request_data
                    )
                    
                    # Try to parse parameter details
                    param_name = None
                    param_loc = 'query'
                    
                    # 1. Try from <location> element
                    loc_elem = issue.find('location')
                    if loc_elem is not None and loc_elem.text:
                        loc_text = loc_elem.text
                        m = re.search(r"(query|body|json|header|cookie|parameter|input|field)\s+['\"]?([^'\"\s\]]+)['\"]?", loc_text, re.IGNORECASE)
                        if m:
                            param_loc = m.group(1).lower()
                            param_name = m.group(2)
                            if param_loc in ('parameter', 'input', 'field'):
                                param_loc = 'query'
                                
                    # 2. Try from <issueDetail> element
                    if not param_name:
                        detail_elem = issue.find('issueDetail')
                        if detail_elem is not None and detail_elem.text:
                            detail_text = detail_elem.text
                            m = re.search(r"(?:parameter|input|field|cookie|header)\s+<b>([^<]+)</b>", detail_text, re.IGNORECASE)
                            if m:
                                param_name = m.group(1)
                                if 'body' in detail_text.lower() or 'post' in detail_text.lower():
                                    param_loc = 'body'
                                elif 'cookie' in detail_text.lower():
                                    param_loc = 'cookie'
                                elif 'header' in detail_text.lower():
                                    param_loc = 'header'
                    
                    if param_name:
                        # Find the param and flag it
                        param = db_session.query(Param).filter(
                            Param.endpoint_id == endpoint.id,
                            Param.name == param_name,
                            Param.location == param_loc
                        ).first()
                        
                        if not param:
                            # Create parameter if missing
                            param = Param(
                                endpoint_id=endpoint.id,
                                name=param_name,
                                location=param_loc,
                                is_controllable=True,
                                burp_flagged=True
                            )
                            db_session.add(param)
                            db_session.flush()
                        else:
                            param.burp_flagged = True
                            db_session.flush()
                            
                        # Pre-seed reflection contexts for target parameter to force fuzzing execution
                        for ctx_type in [ContextType.HTML_TEXT, ContextType.ATTR_QUOTED]:
                            existing_ctx = db_session.query(Context).filter(
                                Context.param_id == param.id,
                                Context.context_type == ctx_type.value
                            ).first()
                            if not existing_ctx:
                                new_ctx = Context(
                                    param_id=param.id,
                                    endpoint_id=endpoint.id,
                                    context_type=ctx_type.value,
                                    snippet=f"[Pre-seeded from Burp Suite Issue: {issue.findtext('name', 'Scanner Alert')}]"
                                )
                                db_session.add(new_ctx)
                                
                    count += 1
                except Exception as e:
                    print(f"Error importing XML issue: {e}")
                    continue
            
            db_session.commit()
            return count
            
        # Standard proxy history parsing path
        requests = BurpImporter.parse_burp_xml(xml_path)
        count = 0
        
        for request_data in requests:
            try:
                ReconService.create_endpoint_from_request(
                    db_session,
                    target_id,
                    request_data['method'],
                    request_data['url'],
                    request_data,
                    {'body': request_data.get('response')} if 'response' in request_data else None
                )
                count += 1
            except Exception as e:
                print(f"Error importing request: {e}")
                continue
        
        return count
