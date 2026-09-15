"""
Active Character Filter & Sanitizer Profiler for XSS Boss.

Probes and profiles target inputs to identify which characters are reflected raw,
HTML-entity-encoded, backslash-escaped, or stripped by filters and WAFs.
"""
from __future__ import annotations

import enum
import html
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import httpx
except ImportError:
    httpx = None

from backend_api.utils.logger import logger
from backend_api.config import settings
from backend_api.utils.rate_limiter import rate_limited_call


class CharacterState(str, enum.Enum):
    """Reflected state of a tested character."""
    ALLOWED_RAW = "ALLOWED_RAW"
    HTML_ENTITY_ENCODED = "HTML_ENTITY_ENCODED"
    BACKSLASH_ESCAPED = "BACKSLASH_ESCAPED"
    STRIPPED = "STRIPPED"
    URL_ENCODED = "URL_ENCODED"
    NORMALIZED = "NORMALIZED"
    UNKNOWN = "UNKNOWN"


@dataclass
class FilterProfile:
    """Comprehensive character filter & transformation profile."""
    allowed_characters: Set[str] = field(default_factory=set)
    blocked_characters: Set[str] = field(default_factory=set)
    escaped_characters: Set[str] = field(default_factory=set)
    encoded_characters: Set[str] = field(default_factory=set)
    stripped_characters: Set[str] = field(default_factory=set)
    character_matrix: Dict[str, CharacterState] = field(default_factory=dict)
    quotes_escaped: bool = False
    angle_brackets_encoded: bool = False
    parentheses_allowed: bool = True
    backticks_allowed: bool = True
    semicolons_allowed: bool = True
    slashes_allowed: bool = True
    recommended_evasions: List[str] = field(default_factory=list)
    sanitizer_detected: Optional[str] = None
    verified_cve_bypasses: List[str] = field(default_factory=list)


# Test probing canary structure
CANARY_PREFIX = "xB0ss"
CANARY_SUFFIX = "Zz9"

TEST_CHARACTERS = [
    "<", ">", '"', "'", "`", "/", "\\", "(", ")", ";", ":", "=", "{", "}", "[", "]"
]


class FilterProfiler:
    """Active character filter and sanitization profiler."""

    def __init__(self, timeout: float = 4.0):
        self.timeout = timeout

    @staticmethod
    def analyze_reflection(reflected_response: str, tested_char: str, canary: str) -> CharacterState:
        """
        Analyze how a single tested character was transformed in the reflected response.
        """
        raw_probe = f"{CANARY_PREFIX}{tested_char}{CANARY_SUFFIX}"
        
        # 1. Check if reflected untouched
        if raw_probe in reflected_response:
            return CharacterState.ALLOWED_RAW

        # 2. Check for Backslash escaping (e.g. \" or \')
        escaped_probe = f"{CANARY_PREFIX}\\{tested_char}{CANARY_SUFFIX}"
        if escaped_probe in reflected_response:
            return CharacterState.BACKSLASH_ESCAPED

        # 3. Check for HTML entity encoding (e.g. &quot;, &#34;, &#x22;, &lt;, &gt;)
        html_named = html.escape(tested_char)
        html_num = f"&#{ord(tested_char)};"
        html_hex = f"&#x{ord(tested_char):x};"
        html_hex_upper = f"&#x{ord(tested_char):X};"

        for entity_form in [html_named, html_num, html_hex, html_hex_upper]:
            if f"{CANARY_PREFIX}{entity_form}{CANARY_SUFFIX}" in reflected_response:
                return CharacterState.HTML_ENTITY_ENCODED

        # 4. Check for URL encoding (%22, %3C, etc.)
        url_enc = urllib.parse.quote(tested_char)
        if f"{CANARY_PREFIX}{url_enc}{CANARY_SUFFIX}" in reflected_response:
            return CharacterState.URL_ENCODED

        # 5. Check if character was stripped completely
        stripped_probe = f"{CANARY_PREFIX}{CANARY_SUFFIX}"
        if stripped_probe in reflected_response:
            return CharacterState.STRIPPED

        return CharacterState.UNKNOWN

    @staticmethod
    def build_profile_from_matrix(matrix: Dict[str, CharacterState]) -> FilterProfile:
        """Construct a structured FilterProfile from character test results."""
        profile = FilterProfile(character_matrix=matrix)

        for char, state in matrix.items():
            if state == CharacterState.ALLOWED_RAW:
                profile.allowed_characters.add(char)
            elif state == CharacterState.BACKSLASH_ESCAPED:
                profile.escaped_characters.add(char)
            elif state == CharacterState.HTML_ENTITY_ENCODED:
                profile.encoded_characters.add(char)
                profile.blocked_characters.add(char)
            elif state == CharacterState.STRIPPED:
                profile.stripped_characters.add(char)
                profile.blocked_characters.add(char)

        # Evaluate high-level flags
        profile.quotes_escaped = ('"' in profile.escaped_characters) or ("'" in profile.escaped_characters)
        profile.angle_brackets_encoded = ("<" in profile.encoded_characters) or (">" in profile.encoded_characters)
        profile.parentheses_allowed = ("(" in profile.allowed_characters) and (")" in profile.allowed_characters)
        profile.backticks_allowed = "`" in profile.allowed_characters
        profile.semicolons_allowed = ";" in profile.allowed_characters
        profile.slashes_allowed = "/" in profile.allowed_characters

        # Formulate evasion recommendations
        evasions = []
        if profile.quotes_escaped:
            evasions.append("string_fromcharcode")
            if profile.backticks_allowed:
                evasions.append("backtick_template_literals")
            evasions.append("html_entities_in_event_handler")

        if not profile.parentheses_allowed:
            evasions.append("parentheseless_throw_onerror")
            if profile.backticks_allowed:
                evasions.append("tagged_template_literals")

        if profile.angle_brackets_encoded:
            evasions.append("attribute_event_handler_injection")
            evasions.append("srcdoc_double_decoding")

        if not profile.slashes_allowed:
            evasions.append("spaceless_svg_tags")

        profile.recommended_evasions = evasions
        return profile

    def profile_endpoint_param(
        self,
        url: str,
        method: str = "GET",
        param_name: str = "q",
        location: str = "query",
        headers: Optional[Dict[str, str]] = None,
    ) -> FilterProfile:
        """
        Actively probe an endpoint parameter across the character matrix.
        """
        matrix: Dict[str, CharacterState] = {}
        if not httpx:
            return FilterProfile()

        client_headers = (headers or {}).copy()
        client_headers.setdefault("User-Agent", "Mozilla/5.0")

        # 1. Single combined canary probe to minimize network traffic
        combined_payload = "".join(f"{CANARY_PREFIX}{ch}{CANARY_SUFFIX}" for ch in TEST_CHARACTERS)
        
        proxy_kwargs = {}
        try:
            from backend_api.utils.stealth import get_http_proxy_kwargs
            proxy_kwargs = get_http_proxy_kwargs(rotated=True)
        except Exception:
            pass

        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=True,
                verify=not settings.ALLOW_INSECURE_TLS,
                **proxy_kwargs,
            ) as client:
                if method.upper() == "GET":
                    resp = rate_limited_call(
                        url,
                        lambda: client.get(
                            url,
                            params={param_name: combined_payload},
                            headers=client_headers,
                        ),
                    )
                else:
                    resp = rate_limited_call(
                        url,
                        lambda: client.post(
                            url,
                            data={param_name: combined_payload},
                            headers=client_headers,
                        ),
                    )

                resp_text = resp.text
                for ch in TEST_CHARACTERS:
                    state = FilterProfiler.analyze_reflection(resp_text, ch, CANARY_PREFIX)
                    matrix[ch] = state

        except Exception as e:
            logger.debug(f"Filter profile probe error on {url}: {e}")
            # Fallback to all allowed
            for ch in TEST_CHARACTERS:
                matrix[ch] = CharacterState.ALLOWED_RAW

        profile = FilterProfiler.build_profile_from_matrix(matrix)
        
        # Automata Learner: Minimal-Pair Differential Reverse-Engineering
        try:
            from analysis_engine.automata_learner import AutomataLearner
            def remote_transform(probe_str: str) -> str:
                try:
                    with httpx.Client(
                        timeout=self.timeout,
                        follow_redirects=False,
                        verify=not settings.ALLOW_INSECURE_TLS,
                        **proxy_kwargs,
                    ) as client:
                        if method.upper() == "GET":
                            r = rate_limited_call(
                                url,
                                lambda: client.get(
                                    url,
                                    params={param_name: probe_str},
                                    headers=client_headers,
                                ),
                            )
                        else:
                            r = rate_limited_call(
                                url,
                                lambda: client.post(
                                    url,
                                    data={param_name: probe_str},
                                    headers=client_headers,
                                ),
                            )
                        return r.text
                except Exception:
                    return ""

            s_prof = AutomataLearner.learn_sanitizer(remote_transform)
            if s_prof and s_prof.library_name != "Custom/Unknown Sanitizer":
                profile.sanitizer_detected = f"{s_prof.library_name} ({s_prof.version_range})"
                profile.verified_cve_bypasses = s_prof.verified_cve_bypasses
        except Exception as auto_err:
            logger.debug(f"AutomataLearner probe skipped or failed: {auto_err}")

        return profile
