"""Recon service - orchestrates recon pipeline."""
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from backend_api.models.target import Target
from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param, ParamLocation
from backend_api.utils.errors import NotFoundError, ValidationError
from backend_api.utils.scope_guard import is_url_in_scope
from recon_engine.normalizer import RequestNormalizer


class ReconService:
    """Service for reconnaissance operations."""
    
    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL to pattern (replace dynamic values with placeholders).
        
        Args:
            url: Original URL
            
        Returns:
            Normalized URL pattern
        """
        return RequestNormalizer.normalize_url(url)
    
    @staticmethod
    def extract_params_from_request(
        request_data: Dict[str, Any],
        method: str
    ) -> List[Dict[str, Any]]:
        """Extract parameters from request data.
        
        Args:
            request_data: Request data dictionary
            method: HTTP method
            
        Returns:
            List of parameter dictionaries
        """
        extracted = RequestNormalizer.extract_parameters(request_data, method)
        
        # Flatten into single list
        params = []
        for location_params in extracted.values():
            params.extend(location_params)
        
        return params
    
    @staticmethod
    def create_endpoint_from_request(
        db: Session,
        target_id: int,
        method: str,
        url: str,
        request_data: Dict[str, Any],
        response_data: Dict[str, Any] = None
    ) -> Endpoint:
        """Create endpoint and params from request data.
        
        Args:
            db: Database session
            target_id: Target ID
            method: HTTP method
            url: Request URL
            request_data: Request data dictionary
            response_data: Response data dictionary (optional)
            
        Returns:
            Created or existing Endpoint
        """
        # Normalize URL
        url_pattern = ReconService.normalize_url(url)

        target = db.query(Target).filter(Target.id == target_id).first()
        if not target:
            raise NotFoundError("Target", target_id)

        if not is_url_in_scope(target, url_pattern):
            raise ValidationError("Request URL is outside the target's configured bug bounty scope")
        
        # Get content type for signature
        content_type = request_data.get('headers', {}).get('Content-Type', '')
        
        # Create signature for deduplication
        signature = RequestNormalizer.create_endpoint_signature(
            method, url, content_type
        )
        
        # Check if endpoint already exists (by signature or pattern)
        existing = (
            db.query(Endpoint)
            .filter(Endpoint.target_id == target_id)
            .filter(Endpoint.method == method)
            .filter(Endpoint.url_pattern == url_pattern)
            .first()
        )
        
        if existing:
            # Update existing endpoint with new sample data
            if not existing.sample_request_body:
                existing.sample_request_body = request_data.get('body') or request_data.get('json')
            if not existing.sample_response_body and response_data:
                existing.sample_response_body = response_data.get('body')
            if not existing.auth_context:
                existing.auth_context = request_data.get('headers', {})
            endpoint = existing
            db.flush()
        else:
            # Create new endpoint
            endpoint = Endpoint(
                target_id=target_id,
                method=method,
                url_pattern=url_pattern,
                sample_request_body=request_data.get('body') or request_data.get('json'),
                sample_response_body=response_data.get('body') if response_data else None,
                auth_context=request_data.get('headers', {})
            )
            db.add(endpoint)
            db.flush()
        
        # Extract and create parameters
        params_data = ReconService.extract_params_from_request(request_data, method)
        for param_data in params_data:
            # Check if param already exists
            existing_param = (
                db.query(Param)
                .filter(Param.endpoint_id == endpoint.id)
                .filter(Param.name == param_data['name'])
                .filter(Param.location == param_data['location'])
                .first()
            )
            
            if not existing_param:
                param = Param(
                    endpoint_id=endpoint.id,
                    name=param_data['name'],
                    location=param_data['location'],
                    sample_value=param_data.get('sample_value'),
                    is_controllable=True
                )
                db.add(param)
                db.flush() # get ID
                
                # Perform parameter profiling via ChatGPT
                try:
                    sample_resp = response_data.get('body', '') if response_data else ''
                    if sample_resp:
                        from backend_api.services.llm_service import LLMService
                        prediction = LLMService.predict_parameter_context(endpoint, param, sample_resp)
                        if prediction:
                            from backend_api.services.context_service import ContextService
                            ContextService.create_context(
                                db,
                                param_id=param.id,
                                endpoint_id=endpoint.id,
                                context_type=prediction.get('context_type', 'HTML_TEXT'),
                                tag=prediction.get('tag'),
                                attribute=prediction.get('attribute'),
                                snippet=prediction.get('snippet')
                            )
                except Exception as llm_err:
                    import logging
                    logging.getLogger("backend_api").warning(f"Failed to profile parameter context: {llm_err}")
        
        db.commit()
        db.refresh(endpoint)
        return endpoint
