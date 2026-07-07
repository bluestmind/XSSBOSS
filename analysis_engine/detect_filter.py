"""Filter profiling engine."""
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from backend_api.models.filter_profile import FilterProfile
from backend_api.utils.filter_profiler import FilterProfiler
from backend_api.services.filter_service import FilterService
from backend_api.utils.logger import logger


class FilterDetectorEngine:
    """Engine for detecting filter behavior."""
    
    def __init__(self, db: Session):
        """Initialize with database session.
        
        Args:
            db: SQLAlchemy database session
        """
        self.db = db
    
    def profile_endpoint(
        self,
        endpoint_id: int,
        timeout: int = 10
    ) -> List[FilterProfile]:
        """Profile filter behavior for all parameters in an endpoint.
        
        Args:
            endpoint_id: Endpoint ID
            timeout: Request timeout in seconds
            
        Returns:
            List of created FilterProfile records
        """
        endpoint = self.db.query(Endpoint).filter(Endpoint.id == endpoint_id).first()
        if not endpoint:
            raise ValueError(f"Endpoint {endpoint_id} not found")
        
        params = self.db.query(Param).filter(Param.endpoint_id == endpoint_id).all()
        profiles = []
        
        for param in params:
            try:
                profile = self.profile_param(param.id, timeout)
                if profile:
                    profiles.append(profile)
            except Exception as e:
                logger.error(f"Error profiling param {param.id}: {e}", exc_info=True)
                continue
        
        return profiles
    
    def profile_param(
        self,
        param_id: int,
        timeout: int = 10
    ) -> Optional[FilterProfile]:
        """Profile filter behavior for a specific parameter.
        
        Args:
            param_id: Parameter ID
            timeout: Request timeout in seconds
            
        Returns:
            Created FilterProfile record or None
        """
        param = self.db.query(Param).filter(Param.id == param_id).first()
        if not param:
            raise ValueError(f"Parameter {param_id} not found")
        
        endpoint = param.endpoint
        
        # Check if profile already exists
        existing = (
            self.db.query(FilterProfile)
            .filter(FilterProfile.endpoint_id == endpoint.id)
            .first()
        )
        
        if existing:
            logger.info(f"Filter profile already exists for endpoint {endpoint.id}")
            return existing
        
        # Get request data
        url = endpoint.url_pattern  # In production, might need to resolve placeholders
        method = endpoint.method
        headers = (endpoint.auth_context or {}).copy()
        cookies = {}
        
        # Extract cookies from headers if present
        if 'Cookie' in headers:
            cookie_str = headers.pop('Cookie')
            for cookie_pair in cookie_str.split(';'):
                if '=' in cookie_pair:
                    key, value = cookie_pair.split('=', 1)
                    cookies[key.strip()] = value.strip()
        
        base_body = None
        base_json = None
        if endpoint.sample_request_body:
            if isinstance(endpoint.sample_request_body, dict):
                content_type = headers.get('Content-Type', '').lower()
                if 'application/json' in content_type:
                    base_json = endpoint.sample_request_body
                else:
                    base_body = endpoint.sample_request_body
        
        # Profile the parameter
        logger.info(f"Profiling filter for param {param_id} in endpoint {endpoint.id}")
        
        try:
            profile_data = FilterProfiler.profile_endpoint_param(
                method=method,
                url=url,
                param_name=param.name,
                param_location=param.location,
                headers=headers,
                cookies=cookies,
                base_body=base_body,
                base_json=base_json,
                timeout=timeout
            )
            
            # Create FilterProfile record
            filter_profile = FilterService.create_filter_profile(
                self.db,
                endpoint_id=endpoint.id,
                summary=profile_data['summary'],
                blocked_tokens=profile_data['blocked_tokens'],
                allowed_tokens=profile_data['allowed_tokens'],
                normalization_behavior=profile_data['normalization_behavior'],
                waf_detected=profile_data['waf_detected'],
                sanitizer_detected=profile_data['sanitizer_detected'],
                csp_rules=profile_data.get('csp_rules'),
                probe_results=profile_data['probe_results']
            )
            
            logger.info(f"Created filter profile {filter_profile.id} for endpoint {endpoint.id}")
            return filter_profile
            
        except Exception as e:
            logger.error(f"Error profiling param {param_id}: {e}", exc_info=True)
            return None
    
    def profile_target(
        self,
        target_id: int,
        timeout: int = 10
    ) -> Dict[int, List[FilterProfile]]:
        """Profile filter behavior for all endpoints in a target.
        
        Args:
            target_id: Target ID
            timeout: Request timeout in seconds
            
        Returns:
            Dictionary mapping endpoint_id to list of profiles
        """
        endpoints = self.db.query(Endpoint).filter(Endpoint.target_id == target_id).all()
        
        results = {}
        for endpoint in endpoints:
            profiles = self.profile_endpoint(endpoint.id, timeout)
            results[endpoint.id] = profiles
        
        return results
