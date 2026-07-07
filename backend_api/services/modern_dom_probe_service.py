"""Modern DOM XSS probe generation service."""
from typing import Any, Dict, Optional

import httpx
from sqlalchemy.orm import Session

from backend_api.models.endpoint import Endpoint
from backend_api.utils.js_parser import JSParser
from backend_api.utils.modern_xss_profiles import ModernXSSProfiles
from backend_api.utils.scope_guard import is_endpoint_in_scope
from backend_api.utils.tokenizer import Tokenizer


class ModernDOMProbeService:
    """Build opt-in modern DOM XSS probes for an in-scope endpoint."""

    @staticmethod
    def build_probes(
        db: Session,
        endpoint_id: int,
        payload_template: Optional[str] = None,
        token: Optional[str] = None,
        include_live_fingerprint: bool = True,
    ) -> Dict[str, Any]:
        """Generate modern probe families for an endpoint."""
        endpoint = db.query(Endpoint).filter(Endpoint.id == endpoint_id).first()
        if not endpoint:
            raise ValueError(f"Endpoint {endpoint_id} not found")
        if not is_endpoint_in_scope(endpoint):
            raise ValueError("Endpoint is outside the target's configured scope")

        probe_token = token or Tokenizer.generate_token()
        target_url = endpoint.url_pattern
        html_content = endpoint.sample_response_body or ""
        headers: Dict[str, str] = {}
        live_error = None

        if include_live_fingerprint and endpoint.method.upper() == "GET":
            try:
                response = httpx.get(
                    target_url,
                    headers=endpoint.auth_context or {},
                    follow_redirects=True,
                    timeout=10,
                )
                html_content = response.text
                headers = dict(response.headers)
            except Exception as exc:
                live_error = str(exc)

        fingerprint = ModernXSSProfiles.fingerprint_html(html_content, headers)
        modern_signals = JSParser.find_modern_dom_signals(html_content, headers)

        detected_frameworks = [f["name"] for f in fingerprint.get("frameworks", [])]

        return {
            "endpoint_id": endpoint.id,
            "target_url": target_url,
            "token": probe_token,
            "live_fingerprint_error": live_error,
            "fingerprint": fingerprint,
            "signals": {
                "sources": modern_signals["sources"],
                "sinks": modern_signals["sinks"],
                "dom_clobbering_gadgets": modern_signals["dom_clobbering_gadgets"],
                "prototype_pollution_gadgets": modern_signals["prototype_pollution_gadgets"],
            },
            "post_message": ModernXSSProfiles.generate_post_message_probes(
                target_url,
                probe_token,
                payload_template,
            ),
            "prototype_pollution": ModernXSSProfiles.generate_prototype_pollution_probes(
                target_url,
                probe_token,
                payload_template,
            ),
            "dom_clobbering": ModernXSSProfiles.generate_dom_clobbering_payloads(probe_token),
            "sanitizer_mxss": ModernXSSProfiles.generate_sanitizer_mxss_payloads(probe_token),
            "framework_specific": ModernXSSProfiles.generate_framework_payloads(probe_token, detected_frameworks),
            "operator_notes": [
                "Use these probes only on explicitly authorized in-scope assets.",
                "Prototype pollution and DOM clobbering probes are opt-in because they can disturb fragile client-side state.",
                "Confirmed value comes from oracle execution, stored/cross-role verification, and clear impact evidence.",
            ],
        }
