"""Filter service - filter profiling coordination."""
from sqlalchemy.orm import Session
from typing import Dict, Any, Optional, List
from backend_api.models.filter_profile import FilterProfile
from backend_api.models.endpoint import Endpoint


class FilterService:
    """Service for filter profiling operations."""
    
    @staticmethod
    def create_filter_profile(
        db: Session,
        endpoint_id: int,
        summary: Optional[str] = None,
        blocked_tokens: Optional[List[str]] = None,
        allowed_tokens: Optional[List[str]] = None,
        normalization_behavior: Optional[List[str]] = None,
        waf_detected: bool = False,
        sanitizer_detected: Optional[str] = None,
        csp_rules: Optional[Dict[str, Any]] = None,
        probe_results: Optional[List[Dict[str, Any]]] = None
    ) -> FilterProfile:
        """Create a filter profile.
        
        Args:
            db: Database session
            endpoint_id: Endpoint ID
            summary: Human-readable summary
            blocked_tokens: List of blocked tokens
            allowed_tokens: List of allowed tokens
            normalization_behavior: List of normalization behaviors
            waf_detected: Whether WAF was detected
            sanitizer_detected: Sanitizer name if detected
            csp_rules: Parsed Content-Security-Policy rules
            probe_results: List of probe result dictionaries
            
        Returns:
            Created FilterProfile record
        """
        profile = FilterProfile(
            endpoint_id=endpoint_id,
            summary=summary,
            blocked_tokens=blocked_tokens or [],
            allowed_tokens=allowed_tokens or [],
            normalization_behavior=normalization_behavior or [],
            waf_detected=waf_detected,
            sanitizer_detected=sanitizer_detected,
            csp_rules=csp_rules or {},
            probe_results=probe_results or []
        )
        db.add(profile)
        db.commit()
        db.refresh(profile)
        return profile
    
    @staticmethod
    def get_filter_profile_for_endpoint(
        db: Session,
        endpoint_id: int
    ) -> Optional[FilterProfile]:
        """Get the latest filter profile for an endpoint."""
        return (
            db.query(FilterProfile)
            .filter(FilterProfile.endpoint_id == endpoint_id)
            .order_by(FilterProfile.profiled_at.desc())
            .first()
        )
    
    @staticmethod
    def update_filter_profile(
        db: Session,
        profile_id: int,
        **updates
    ) -> FilterProfile:
        """Update a filter profile."""
        profile = db.query(FilterProfile).filter(FilterProfile.id == profile_id).first()
        if not profile:
            raise ValueError(f"Filter profile {profile_id} not found")
        
        for key, value in updates.items():
            if hasattr(profile, key):
                setattr(profile, key, value)
        
        db.commit()
        db.refresh(profile)
        return profile

