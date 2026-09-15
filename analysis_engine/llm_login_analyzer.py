"""LLM login analyzer — read a login page and figure out how to authenticate.

The deterministic ``discover_login_form`` (regex/HTML parser) handles standard login forms. This is
the *fallback* for the ones it can't crack — React/SPA logins with no ``<form>``, custom widgets,
unusual field names — where a model that can read the page wins. It asks the local, uncensored
WhiteRabbitNeo (security_data stays local) to return the selectors + an optional multi-step sequence,
and flags MFA/CAPTCHA so the caller escalates instead of guessing.

The LLM only *proposes* selectors/steps; the deterministic ``AuthSessionService`` executor still
performs the login and verifies it. The LLM is never in the "am I logged in" path.
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional

_PROMPT = """You are an offensive security engineer automating login for an AUTHORIZED penetration test.
Read this login page and determine exactly how to authenticate.

Return ONLY a JSON object, no prose:
{{
  "username_selector": "CSS selector for the username/email input",
  "password_selector": "CSS selector for the password input",
  "submit_selector": "CSS selector for the submit button",
  "steps": [
    {{"action": "fill", "selector": "...", "value": "{{{{USERNAME}}}}"}},
    {{"action": "fill", "selector": "...", "value": "{{{{PASSWORD}}}}"}},
    {{"action": "click", "selector": "..."}}
  ],
  "mfa_detected": false,
  "notes": "e.g. multi-step: email first then Continue then password"
}}
Use "{{{{USERNAME}}}}" / "{{{{PASSWORD}}}}" as value placeholders. If the flow is multi-step (email, then
Continue, then password), express it in "steps" with navigate/fill/click actions in order.
If a CAPTCHA or MFA challenge is present, set "mfa_detected": true.

LOGIN PAGE HTML:
{html}
"""


def _coerce_json(raw: Any) -> Optional[Dict[str, Any]]:
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        return None
    try:
        return json.loads(raw)
    except Exception:
        pass
    # lenient: grab the first {...} block
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            return None
    return None


class LlmLoginAnalyzer:
    """LLM-assisted login-form understanding (fallback to deterministic discovery)."""

    @staticmethod
    def analyze(html: str, query_fn: Optional[Callable[[str], Any]] = None) -> Optional[Dict[str, Any]]:
        """Return {username_selector, password_selector, submit_selector, steps, mfa_detected} or None.

        ``query_fn(prompt) -> str|dict`` is injectable for testing; by default it calls the local LLM
        with ``security_data=True`` so the page never leaves the machine.
        """
        if not html or not html.strip():
            return None
        prompt = _PROMPT.format(html=html[:6000])
        try:
            if query_fn is None:
                from backend_api.services.llm_service import LLMService
                query_fn = lambda p: LLMService.query_model(p, expect_json=True, security_data=True)
            data = _coerce_json(query_fn(prompt))
        except Exception:
            return None
        if not isinstance(data, dict):
            return None

        result: Dict[str, Any] = {
            "username_selector": str(data.get("username_selector") or "").strip(),
            "password_selector": str(data.get("password_selector") or "").strip(),
            "submit_selector": str(data.get("submit_selector") or "").strip(),
            "steps": data.get("steps") if isinstance(data.get("steps"), list) else [],
            "mfa_detected": bool(data.get("mfa_detected", False)),
            "notes": str(data.get("notes") or ""),
        }
        # Must at least locate a password field to be useful.
        if not result["password_selector"] and not any(
            "password" in str(s.get("value", "")).lower() or "pass" in str(s.get("selector", "")).lower()
            for s in result["steps"]
        ):
            return None
        return result

    @staticmethod
    def selectors(result: Optional[Dict[str, Any]]) -> Optional[Dict[str, str]]:
        """Extract just the three selectors (the shape AuthSessionService._login_selectors wants)."""
        if not result:
            return None
        u, p, s = result.get("username_selector"), result.get("password_selector"), result.get("submit_selector")
        if not (u and p):
            return None
        return {"username_selector": u, "password_selector": p,
                "submit_selector": s or "button[type='submit'],input[type='submit']"}
