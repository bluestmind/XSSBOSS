"""Auditors that verify vulnerabilities from browser execution results."""
from typing import Any, Dict, Optional
from urllib.parse import urlparse


REDIRECT_PARAM_HINTS = {
    "next",
    "url",
    "uri",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "return",
    "return_url",
    "returnurl",
    "continue",
    "destination",
    "dest",
    "target",
    "to",
    "r",
    "callback",
    "callback_url",
}


def is_redirect_candidate_param(name: str) -> bool:
    """Return whether a parameter name commonly carries navigation targets."""
    normalized = (name or "").strip().lower().replace("-", "_")
    return normalized in REDIRECT_PARAM_HINTS or normalized.endswith("_url") or normalized.endswith("_uri")


class BrowserResultAuditor:
    """Inspect one browser execution result for non-XSS browser-verifiable findings."""

    @staticmethod
    def audit(test_case: Any, test_case_data: Dict[str, Any], result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Return vulnerability metadata if this browser result confirms a finding."""
        redirect = BrowserResultAuditor._detect_open_redirect(test_case, test_case_data, result)
        if redirect:
            return redirect
        return None

    @staticmethod
    def _detect_open_redirect(test_case: Any, test_case_data: Dict[str, Any], result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        payload = str(getattr(test_case, "payload", "") or test_case_data.get("payload") or "")
        final_url = str(result.get("final_url") or "")
        request_url = str(test_case_data.get("url") or "")

        if not payload or not final_url:
            return None

        payload_host = (urlparse(payload).hostname or "").lower()
        if not payload_host and payload.startswith("//"):
            payload_host = (urlparse(f"https:{payload}").hostname or "").lower()
        if not payload_host:
            return None

        final_host = (urlparse(final_url).hostname or "").lower()
        request_host = (urlparse(request_url).hostname or "").lower()
        if not final_host or final_host == request_host or final_host != payload_host:
            return None

        param = getattr(test_case, "param", None)
        if param and not is_redirect_candidate_param(getattr(param, "name", "")):
            return None

        return {
            "vuln_type": "open_redirect",
            "title": "Open Redirect",
            "scanner_module": "open_redirect_auditor",
            "confidence": "certain",
            "severity": "medium",
            "evidence_summary": f"Browser navigation ended on external host {final_host} after injecting redirect payload.",
            "details": {
                "payload": payload,
                "request_url": request_url,
                "final_url": final_url,
                "payload_host": payload_host,
                "final_host": final_host,
            },
        }
