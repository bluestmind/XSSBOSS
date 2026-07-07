"""HAR file import."""
import json
import base64
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, unquote


class HARImporter:
    """Import requests from HAR (HTTP Archive) files."""
    
    @staticmethod
    def parse_har(har_path: str) -> List[Dict[str, Any]]:
        """Parse HAR file.
        
        Args:
            har_path: Path to HAR file
            
        Returns:
            List of parsed request dictionaries
        """
        with open(har_path, 'r', encoding='utf-8') as f:
            har_data = json.load(f)
        
        requests = []
        
        # HAR structure: log.entries[]
        if 'log' in har_data and 'entries' in har_data['log']:
            for entry in har_data['log']['entries']:
                request_data = HARImporter._parse_entry(entry)
                if request_data:
                    requests.append(request_data)
        
        return requests
    
    @staticmethod
    def _parse_entry(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a single HAR entry.
        
        Args:
            entry: HAR entry dictionary
            
        Returns:
            Dictionary with request data or None if parsing fails
        """
        try:
            request_obj = entry.get('request', {})
            response_obj = entry.get('response', {})
            
            # Extract URL
            url = request_obj.get('url', '')
            if not url:
                return None
            
            # Extract method
            method = request_obj.get('method', 'GET')
            
            # Parse headers
            headers = {}
            for header in request_obj.get('headers', []):
                headers[header['name']] = header['value']
            
            # Parse query string
            query_params = {}
            if 'queryString' in request_obj:
                for param in request_obj['queryString']:
                    param_name = param.get('name', '')
                    param_value = param.get('value', '')
                    if param_name:
                        query_params[param_name] = param_value
            
            # Parse post data
            body = None
            json_data = None
            if 'postData' in request_obj:
                post_data = request_obj['postData']
                mime_type = post_data.get('mimeType', '').lower()
                text = post_data.get('text', '')
                
                if 'application/json' in mime_type and text:
                    try:
                        json_data = json.loads(text)
                    except json.JSONDecodeError:
                        body = text
                elif 'application/x-www-form-urlencoded' in mime_type:
                    # Parse form data
                    form_params = {}
                    for param in post_data.get('params', []):
                        param_name = param.get('name', '')
                        param_value = param.get('value', '')
                        if param_name:
                            form_params[param_name] = param_value
                    body = form_params
                elif text:
                    body = text
            
            # Parse response
            response_body = None
            if 'content' in response_obj:
                content = response_obj['content']
                response_text = content.get('text', '')
                encoding = content.get('encoding', '')
                
                if encoding == 'base64':
                    try:
                        response_text = base64.b64decode(response_text).decode('utf-8', errors='ignore')
                    except Exception as e:
                        print(f"Error decoding base64 response: {e}")
                        response_text = ""
                response_body = response_text
            
            return {
                'method': method,
                'url': url,
                'headers': headers,
                'query': query_params,
                'body': body,
                'json': json_data,
                'response': response_body
            }
            
        except Exception as e:
            print(f"Error parsing HAR entry: {e}")
            return None
    
    @staticmethod
    def import_to_database(
        har_path: str,
        target_id: int,
        db_session
    ) -> int:
        """Import HAR file to database.
        
        Args:
            har_path: Path to HAR file
            target_id: Target ID to attach endpoints to
            db_session: SQLAlchemy database session
            
        Returns:
            Number of endpoints imported
        """
        from backend_api.services.recon_service import ReconService
        
        requests = HARImporter.parse_har(har_path)
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
