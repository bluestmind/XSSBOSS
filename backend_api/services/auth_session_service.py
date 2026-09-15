"""Authenticated identity and browser-session orchestration.

``Target.auth_info`` remains the operator-owned configuration source.  This
service normalizes both the legacy flat header format and the structured
multi-identity format, applies state to browsers, performs declared login
flows, detects expired sessions/challenges, and exposes request material to
all non-browser probes.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from html.parser import HTMLParser
import fnmatch
import json
import re
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from backend_api.utils.logger import logger


class AuthConfigurationError(ValueError):
    """The operator supplied an invalid or unsafe authentication definition."""


class HumanInterventionRequired(RuntimeError):
    """A browser challenge cannot be completed safely without the operator."""

    def __init__(self, reason: str, *, url: Optional[str] = None, identity: Optional[str] = None):
        super().__init__(reason)
        self.reason = reason
        self.url = url
        self.identity = identity


@dataclass(frozen=True)
class AuthMaterial:
    label: str
    role: str
    headers: Dict[str, str]
    cookies: Dict[str, Any]
    local_storage: Dict[str, str]
    session_storage: Dict[str, str]
    login: Dict[str, Any]
    health_check_url: Optional[str]
    login_url_patterns: tuple[str, ...]
    allowed_auth_origins: tuple[str, ...]

    def browser_spec(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "role": self.role,
            "headers": deepcopy(self.headers),
            "cookies": deepcopy(self.cookies),
            "local_storage": deepcopy(self.local_storage),
            "session_storage": deepcopy(self.session_storage),
            "login": deepcopy(self.login),
            "health_check_url": self.health_check_url,
            "login_url_patterns": list(self.login_url_patterns),
            "allowed_auth_origins": list(self.allowed_auth_origins),
        }


class _LoginFormScanner(HTMLParser):
    """Collect input/button controls (with their enclosing form) to locate a login form."""

    def __init__(self) -> None:
        super().__init__()
        self.controls: List[Dict[str, str]] = []  # ordered: {tag,type,name,id,in_form}
        self._form_depth = 0

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._form_depth += 1
        elif tag in ("input", "button"):
            self.controls.append({
                "tag": tag,
                "type": a.get("type", "").lower(),
                "name": a.get("name", ""),
                "id": a.get("id", ""),
                "in_form": bool(self._form_depth),
            })

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form_depth:
            self._form_depth -= 1


class AuthSessionService:
    """Single source of truth for authenticated target operation."""

    RESERVED = {
        "default_identity", "identities", "headers", "cookies", "local_storage",
        "session_storage", "login", "health_check_url", "login_url_patterns",
        "allowed_auth_origins", "workflows", "browser_profile", "revisit_identities",
        "label", "role", "authenticated", "final_url",
    }
    SECRET_KEYS = {
        "authorization", "cookie", "cookies", "password", "passwd", "secret",
        "token", "access_token", "refresh_token", "api_key", "apikey", "username",
    }
    CHALLENGE_MARKERS = (
        "captcha", "recaptcha", "hcaptcha", "turnstile", "one-time code", "otp",
        "two-factor", "two factor", "multi-factor", "mfa", "security key",
        "verification code", "verify your identity", "approve sign in",
    )
    DEFAULT_LOGIN_PATTERNS = (
        "*/login*", "*/signin*", "*/sign-in*", "*/auth/login*", "*/account/login*",
    )

    @staticmethod
    def _string_map(value: Any) -> Dict[str, str]:
        if not isinstance(value, dict):
            return {}
        return {str(k): str(v) for k, v in value.items() if v is not None}

    @staticmethod
    def _cookie_map(value: Any) -> Dict[str, Any]:
        if isinstance(value, str):
            result: Dict[str, Any] = {}
            for pair in value.split(";"):
                if "=" in pair:
                    name, cookie_value = pair.split("=", 1)
                    result[name.strip()] = cookie_value.strip()
            return result
        return deepcopy(value) if isinstance(value, dict) else {}

    @classmethod
    def normalize(cls, auth_info: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        raw = deepcopy(auth_info) if isinstance(auth_info, dict) else {}
        identities_value = raw.get("identities")
        identities: Dict[str, Dict[str, Any]] = {}

        if isinstance(identities_value, list):
            for index, item in enumerate(identities_value):
                if isinstance(item, dict):
                    label = str(item.get("label") or item.get("name") or f"identity-{index + 1}")
                    identities[label] = item
        elif isinstance(identities_value, dict):
            identities = {
                str(label): value for label, value in identities_value.items()
                if isinstance(value, dict)
            }

        if not identities:
            legacy_headers = cls._string_map(raw.get("headers"))
            for key, value in raw.items():
                if key not in cls.RESERVED and isinstance(value, (str, int, float, bool)):
                    legacy_headers[str(key)] = str(value)
            single_label = str(raw.get("label") or "default")
            legacy_cookie_header = legacy_headers.pop("Cookie", None)
            if legacy_cookie_header is None:
                legacy_cookie_header = legacy_headers.pop("cookie", None)
            identities[single_label] = {
                "role": str(raw.get("role") or "default"),
                "headers": legacy_headers,
                "cookies": raw.get("cookies") or legacy_cookie_header or {},
                "local_storage": raw.get("local_storage") or {},
                "session_storage": raw.get("session_storage") or {},
                "login": raw.get("login") or {},
                "health_check_url": raw.get("health_check_url"),
                "login_url_patterns": raw.get("login_url_patterns") or [],
                "allowed_auth_origins": raw.get("allowed_auth_origins") or [],
            }

        normalized: Dict[str, Dict[str, Any]] = {}
        for label, value in identities.items():
            headers = cls._string_map(value.get("headers"))
            cookie_header = headers.pop("Cookie", None)
            if cookie_header is None:
                cookie_header = headers.pop("cookie", None)
            cookies = cls._cookie_map(value.get("cookies") or cookie_header)
            login = deepcopy(value.get("login")) if isinstance(value.get("login"), dict) else {}
            normalized[label] = {
                "role": str(value.get("role") or label),
                "headers": headers,
                "cookies": cookies,
                "local_storage": cls._string_map(value.get("local_storage")),
                "session_storage": cls._string_map(value.get("session_storage")),
                "login": login,
                "health_check_url": value.get("health_check_url") or raw.get("health_check_url"),
                "login_url_patterns": tuple(
                    str(item) for item in (
                        value.get("login_url_patterns") or raw.get("login_url_patterns") or cls.DEFAULT_LOGIN_PATTERNS
                    )
                ),
                "allowed_auth_origins": cls._normalize_allowed_origins(
                    value.get("allowed_auth_origins") or raw.get("allowed_auth_origins") or []
                ),
            }

        requested_default = str(raw.get("default_identity") or "")
        default_identity = requested_default if requested_default in normalized else next(iter(normalized))
        return {
            "default_identity": default_identity,
            "identities": normalized,
            "workflows": deepcopy(raw.get("workflows")) if isinstance(raw.get("workflows"), list) else [],
            "revisit_identities": [str(v) for v in raw.get("revisit_identities", [])],
        }

    @classmethod
    def material(cls, auth_info: Optional[Dict[str, Any]], identity: Optional[str] = None) -> AuthMaterial:
        normalized = cls.normalize(auth_info)
        label = identity or normalized["default_identity"]
        if label not in normalized["identities"]:
            raise AuthConfigurationError(f"Unknown authentication identity: {label}")
        value = normalized["identities"][label]
        return AuthMaterial(
            label=label,
            role=value["role"],
            headers=deepcopy(value["headers"]),
            cookies=deepcopy(value["cookies"]),
            local_storage=deepcopy(value["local_storage"]),
            session_storage=deepcopy(value["session_storage"]),
            login=deepcopy(value["login"]),
            health_check_url=value["health_check_url"],
            login_url_patterns=tuple(value["login_url_patterns"]),
            allowed_auth_origins=tuple(value["allowed_auth_origins"]),
        )

    @classmethod
    def identity_labels(cls, auth_info: Optional[Dict[str, Any]]) -> list[str]:
        normalized = cls.normalize(auth_info)
        ordered = [normalized["default_identity"]]
        requested = normalized.get("revisit_identities") or []
        for label in [*requested, *normalized["identities"].keys()]:
            if label in normalized["identities"] and label not in ordered:
                ordered.append(label)
        return ordered

    @staticmethod
    def _cookie_value(value: Any) -> str:
        return str(value.get("value", "")) if isinstance(value, dict) else str(value)

    @classmethod
    def request_context(
        cls,
        auth_info: Optional[Dict[str, Any]],
        identity: Optional[str] = None,
        endpoint_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, str]:
        material = cls.material(auth_info, identity)
        headers = dict(material.headers)
        cookies = {name: cls._cookie_value(value) for name, value in material.cookies.items()}
        for key, value in (endpoint_context or {}).items():
            if str(key).lower() == "cookie":
                cookies.update(cls._cookie_map(value))
            elif value is not None:
                headers[str(key)] = str(value)
        if cookies:
            headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in cookies.items())
        return headers

    @classmethod
    def request_context_for_url(
        cls,
        auth_info: Optional[Dict[str, Any]],
        request_url: str,
        base_url: str,
        identity: Optional[str] = None,
        endpoint_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, str]:
        """Return session material only for an explicitly authorized origin.

        Authentication headers and raw Cookie headers are bearer credentials.  Callers
        performing discovery frequently encounter third-party script, sitemap, and redirect
        URLs, so a URL-less header merge is unsafe there.  This helper fails closed unless the
        destination is the target origin or one of the identity's exact
        ``allowed_auth_origins``.
        """
        material = cls.material(auth_info, identity)
        if not cls._allowed_url(request_url, base_url, material.allowed_auth_origins):
            return {}
        return cls.request_context(auth_info, material.label, endpoint_context)

    @classmethod
    def split_request_context(cls, context: Optional[Dict[str, Any]]) -> tuple[Dict[str, str], Dict[str, str]]:
        headers: Dict[str, str] = {}
        cookies: Dict[str, str] = {}
        for key, value in (context or {}).items():
            if str(key).lower() == "cookie":
                cookies.update({k: cls._cookie_value(v) for k, v in cls._cookie_map(value).items()})
            elif value is not None:
                headers[str(key)] = str(value)
        return headers, cookies

    @staticmethod
    def _origin(url: str) -> str:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or not parsed.hostname:
            raise AuthConfigurationError("Authentication URLs must be absolute HTTP(S) URLs")
        if parsed.username is not None or parsed.password is not None:
            raise AuthConfigurationError("Authentication origins must not contain user information")
        try:
            port = parsed.port
        except ValueError as error:
            raise AuthConfigurationError("Authentication origin contains an invalid port") from error
        host = parsed.hostname.rstrip(".").lower()
        if not host:
            raise AuthConfigurationError("Authentication origin contains an invalid host")
        rendered_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
        default_port = 443 if scheme == "https" else 80
        return f"{scheme}://{rendered_host}{f':{port}' if port and port != default_port else ''}"

    @classmethod
    def _normalize_allowed_origins(cls, values: Iterable[Any]) -> tuple[str, ...]:
        """Validate and canonicalize exact origins; wildcards and URL paths are rejected."""
        if isinstance(values, str):
            values = [values]
        normalized: list[str] = []
        for raw_value in values:
            value = str(raw_value or "").strip()
            if not value:
                continue
            parsed = urlparse(value)
            if "*" in value or parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
                raise AuthConfigurationError(
                    "allowed_auth_origins entries must be exact HTTP(S) origins without paths or wildcards"
                )
            origin = cls._origin(value)
            if origin not in normalized:
                normalized.append(origin)
        return tuple(normalized)

    @classmethod
    def _allowed_url(cls, url: str, base_url: str, allowed_origins: Iterable[str]) -> bool:
        try:
            origin = cls._origin(url)
            base_origin = cls._origin(base_url)
        except AuthConfigurationError:
            return False
        allowed = set()
        for value in allowed_origins:
            try:
                allowed.add(cls._origin(str(value)))
            except AuthConfigurationError:
                continue
        return origin == base_origin or origin in allowed

    @classmethod
    def response_intervention_reason(
        cls,
        *,
        status_code: Optional[int],
        final_url: Optional[str],
        body_text: str,
        login_url_patterns: Iterable[str] = (),
    ) -> Optional[str]:
        """Describe an authentication/anti-bot response that requires an operator."""
        barrier = cls.operational_barrier_reason(status_code, body_text)
        if barrier:
            return barrier
        if cls.is_auth_wall(
            status_code=status_code,
            final_url=final_url,
            body_text=body_text,
            login_url_patterns=login_url_patterns,
        ):
            return "authenticated session expired or login is required"
        return None

    @classmethod
    def is_auth_wall(
        cls,
        *,
        status_code: Optional[int] = None,
        final_url: Optional[str] = None,
        body_text: str = "",
        login_url_patterns: Iterable[str] = (),
    ) -> bool:
        if status_code == 401:
            return True
        url = (final_url or "").lower()
        patterns = tuple(login_url_patterns) or cls.DEFAULT_LOGIN_PATTERNS
        if url and any(fnmatch.fnmatch(url, pattern.lower()) for pattern in patterns):
            return True
        text = (body_text or "").lower()[:20000]
        return "name=\"password\"" in text and any(marker in text for marker in ("sign in", "log in", "login"))

    @classmethod
    def challenge_reason(cls, body_text: str) -> Optional[str]:
        text = (body_text or "")[:100000]
        text = re.sub(r"<script\b[^>]*>.*?</script>", " ", text, flags=re.IGNORECASE | re.DOTALL)
        text = re.sub(r"<style\b[^>]*>.*?</style>", " ", text, flags=re.IGNORECASE | re.DOTALL).lower()
        return next((marker for marker in cls.CHALLENGE_MARKERS if marker in text), None)

    @classmethod
    def operational_barrier_reason(
        cls, status_code: Optional[int], body_text: str
    ) -> Optional[str]:
        challenge = cls.challenge_reason(body_text)
        if challenge:
            return f"authentication challenge: {challenge}"
        text = (body_text or "").lower()[:30000]
        if status_code == 429 or "too many requests" in text:
            return "target rate limit or temporary ban"
        waf_markers = ("request blocked", "temporarily blocked", "waf", "cloudflare ray id", "access denied")
        if status_code == 403 and any(marker in text for marker in waf_markers):
            return "WAF or anti-bot block"
        return None

    @classmethod
    def _login_value(cls, login: Dict[str, Any], value: Any) -> str:
        rendered = str(value or "")
        replacements = {
            "{{USERNAME}}": str(login.get("username") or ""),
            "{{PASSWORD}}": str(login.get("password") or ""),
        }
        for marker, replacement in replacements.items():
            rendered = rendered.replace(marker, replacement)
        return rendered

    @classmethod
    def _login_url(cls, base_url: str, material: AuthMaterial) -> Optional[str]:
        value = material.login.get("url") or material.login.get("login_url")
        if not value:
            return None
        url = urljoin(base_url, str(value))
        if not cls._allowed_url(url, base_url, material.allowed_auth_origins):
            raise AuthConfigurationError(f"Login URL is outside allowed authentication origins: {url}")
        return url

    @staticmethod
    def _control_selector(control: Dict[str, str]) -> Optional[str]:
        if control.get("id"):
            return f"#{control['id']}"
        if control.get("name"):
            return f"{control['tag']}[name='{control['name']}']"
        if control.get("type"):
            return f"{control['tag']}[type='{control['type']}']"
        return None

    _USERNAME_HINTS = ("user", "email", "login", "account", "phone", "id")

    @classmethod
    def discover_login_form(cls, html: str) -> Optional[Dict[str, str]]:
        """Auto-detect username/password/submit selectors from a login page's HTML.

        Enables a scope that supplies only credentials (no selectors) to authenticate on the
        common case where the operator did not — or could not — declare field selectors.
        Returns a selector dict or ``None`` when no password field is present.
        """
        scanner = _LoginFormScanner()
        try:
            scanner.feed(html or "")
        except Exception:
            return None
        controls = scanner.controls
        password_idx = next(
            (i for i, c in enumerate(controls) if c["tag"] == "input" and c["type"] == "password"),
            None,
        )
        if password_idx is None:
            return None
        password_sel = cls._control_selector(controls[password_idx])
        if not password_sel:
            return None

        # Username: the best text-like input before the password field (closest wins),
        # preferring names/ids that look like an identity field.
        prior = controls[:password_idx]
        text_inputs = [c for c in prior if c["tag"] == "input" and c["type"] in ("", "text", "email", "tel")]
        username_ctl = None
        for c in reversed(text_inputs):
            blob = f"{c['name']} {c['id']}".lower()
            if any(h in blob for h in cls._USERNAME_HINTS):
                username_ctl = c
                break
        if username_ctl is None and text_inputs:
            username_ctl = text_inputs[-1]
        username_sel = cls._control_selector(username_ctl) if username_ctl else None
        if not username_sel:
            return None

        # Submit: an explicit submit control, else the last button in a form.
        submit_ctl = next(
            (c for c in controls if c["type"] == "submit" or (c["tag"] == "button" and c["in_form"])),
            None,
        )
        submit_sel = cls._control_selector(submit_ctl) if submit_ctl else None
        if not submit_sel:
            submit_sel = "button[type='submit'],input[type='submit']"
        return {"username_selector": username_sel, "password_selector": password_sel, "submit_selector": submit_sel}

    @classmethod
    def _login_selectors(cls, html: str, login: Dict[str, Any]) -> Dict[str, str]:
        """Resolve selectors: explicit config → deterministic discovery → LLM fallback → defaults."""
        discovered = cls.discover_login_form(html) or {}
        # LLM fallback (local WhiteRabbitNeo): only when deterministic discovery AND explicit config
        # both come up empty — i.e. a custom/SPA login the regex parser can't read. Fast path skips it.
        if not discovered and not (login.get("username_selector") and login.get("password_selector")):
            try:
                from backend_api.config import settings
                if getattr(settings, "LLM_ENABLED", False):
                    from analysis_engine.llm_login_analyzer import LlmLoginAnalyzer
                    llm_selectors = LlmLoginAnalyzer.selectors(LlmLoginAnalyzer.analyze(html))
                    if llm_selectors:
                        discovered = llm_selectors
                        logger.info("LLM login-analyzer resolved selectors for a non-standard login form")
            except Exception as e:
                logger.debug(f"LLM login analysis skipped: {e}")
        return {
            "username_selector": login.get("username_selector") or discovered.get("username_selector")
            or "input[name='username'],input[name='email'],input[type='email']",
            "password_selector": login.get("password_selector") or discovered.get("password_selector")
            or "input[name='password'],input[type='password']",
            "submit_selector": login.get("submit_selector") or discovered.get("submit_selector")
            or "button[type='submit'],input[type='submit']",
        }

    @classmethod
    def authenticate_selenium(
        cls,
        driver,
        base_url: str,
        auth_info: Optional[Dict[str, Any]],
        identity: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Apply static state and renew an expired Selenium session when configured."""
        material = cls.material(auth_info, identity)
        # Selenium's Network.setExtraHTTPHeaders is global and would copy
        # bearer credentials to third-party subresources. Cookie/storage login
        # can proceed; origin-bound raw headers require the Playwright backend.
        header_auth_omitted = bool(material.headers)
        if header_auth_omitted:
            logger.warning(
                "Origin-bound authentication headers require Playwright; "
                "continuing the Selenium crawl without raw auth headers"
            )

        needs_origin = bool(material.cookies or material.local_storage or material.session_storage)
        if needs_origin:
            driver.get(cls._origin(base_url) + "/")
            for name, raw_cookie in material.cookies.items():
                cookie = dict(raw_cookie) if isinstance(raw_cookie, dict) else {"value": str(raw_cookie)}
                cookie["name"] = str(name)
                cookie.setdefault("path", "/")
                if cookie.get("sameSite") not in {None, "Strict", "Lax", "None"}:
                    cookie.pop("sameSite", None)
                driver.add_cookie(cookie)
            for storage_name, values in (("localStorage", material.local_storage), ("sessionStorage", material.session_storage)):
                if values:
                    driver.execute_script(
                        f"for (const [k,v] of Object.entries(arguments[0])) {storage_name}.setItem(k,v);",
                        values,
                    )

        health_url = urljoin(base_url, str(material.health_check_url or base_url))
        if not cls._allowed_url(health_url, base_url, material.allowed_auth_origins):
            raise AuthConfigurationError("Health-check URL is outside allowed authentication origins")
        driver.get(health_url)
        source = driver.page_source or ""
        challenge = cls.challenge_reason(source)
        if challenge:
            raise HumanInterventionRequired(
                f"Authentication challenge detected: {challenge}",
                url=driver.current_url,
                identity=material.label,
            )

        login_url = cls._login_url(base_url, material)
        expired = cls.is_auth_wall(
            final_url=driver.current_url,
            body_text=source,
            login_url_patterns=material.login_url_patterns,
        )
        if material.login and (expired or bool(material.login.get("force"))):
            if not login_url:
                login_url = driver.current_url if expired else None
            if not login_url:
                raise AuthConfigurationError("Login credentials were supplied without a login URL")
            cls._execute_selenium_login(driver, base_url, material, login_url)

        captured = {item["name"]: item["value"] for item in driver.get_cookies()}
        merged = dict(material.cookies)
        merged.update(captured)
        return {
            **material.browser_spec(),
            "cookies": merged,
            "authenticated": not cls.is_auth_wall(
                final_url=driver.current_url,
                body_text=driver.page_source or "",
                login_url_patterns=material.login_url_patterns,
            ),
            "header_auth_omitted": header_auth_omitted,
            "final_url": driver.current_url,
        }

    @classmethod
    def _execute_selenium_login(cls, driver, base_url: str, material: AuthMaterial, login_url: str) -> None:
        from selenium.webdriver.common.by import By

        driver.get(login_url)
        login = material.login
        challenge = cls.challenge_reason(driver.page_source or "")
        if challenge:
            raise HumanInterventionRequired(
                f"Authentication challenge detected: {challenge}", url=driver.current_url, identity=material.label
            )
        steps = login.get("steps") if isinstance(login.get("steps"), list) else []
        if steps:
            cls.execute_selenium_steps(driver, base_url, material, steps)
        else:
            selectors = cls._login_selectors(driver.page_source or "", login)
            username = driver.find_element(By.CSS_SELECTOR, selectors["username_selector"])
            password = driver.find_element(By.CSS_SELECTOR, selectors["password_selector"])
            username.clear()
            username.send_keys(str(login.get("username") or ""))
            password.clear()
            password.send_keys(str(login.get("password") or ""))
            driver.find_element(By.CSS_SELECTOR, selectors["submit_selector"]).click()
        time.sleep(max(0.0, min(10.0, float(login.get("wait_seconds", 1.0)))))
        challenge = cls.challenge_reason(driver.page_source or "")
        if challenge:
            raise HumanInterventionRequired(
                f"Authentication challenge detected after credential submission: {challenge}",
                url=driver.current_url,
                identity=material.label,
            )
        success_selector = login.get("success_selector")
        if success_selector:
            driver.find_element(By.CSS_SELECTOR, str(success_selector))
        elif cls.is_auth_wall(
            final_url=driver.current_url,
            body_text=driver.page_source or "",
            login_url_patterns=material.login_url_patterns,
        ):
            raise HumanInterventionRequired(
                "Login did not leave the authentication page; credentials, MFA, or selectors require review",
                url=driver.current_url,
                identity=material.label,
            )

    @classmethod
    def execute_selenium_steps(
        cls, driver, base_url: str, material: AuthMaterial, steps: Iterable[Dict[str, Any]]
    ) -> None:
        from selenium.webdriver.common.by import By
        from selenium.webdriver.common.keys import Keys

        for step in steps:
            if not isinstance(step, dict):
                continue
            action = str(step.get("action") or "").lower()
            if action == "navigate":
                url = urljoin(driver.current_url or base_url, str(step.get("url") or ""))
                if not cls._allowed_url(url, base_url, material.allowed_auth_origins):
                    raise AuthConfigurationError(f"Workflow navigation is outside allowed origins: {url}")
                driver.get(url)
            elif action == "fill":
                element = driver.find_element(By.CSS_SELECTOR, str(step.get("selector") or ""))
                element.clear()
                element.send_keys(cls._login_value(material.login, step.get("value")))
            elif action == "click":
                driver.find_element(By.CSS_SELECTOR, str(step.get("selector") or "")).click()
            elif action == "press":
                element = driver.find_element(By.CSS_SELECTOR, str(step.get("selector") or "body"))
                key = str(step.get("key") or "ENTER").upper()
                element.send_keys(getattr(Keys, key, step.get("key") or Keys.ENTER))
            elif action == "wait":
                time.sleep(max(0.0, min(10.0, float(step.get("seconds", 0.5)))))
            else:
                raise AuthConfigurationError(f"Unsupported authentication workflow action: {action}")

    @classmethod
    def workflows_for(cls, auth_info: Optional[Dict[str, Any]], identity: str) -> list[Dict[str, Any]]:
        normalized = cls.normalize(auth_info)
        result = []
        for workflow in normalized.get("workflows", []):
            if not isinstance(workflow, dict) or not isinstance(workflow.get("steps"), list):
                continue
            workflow_identity = str(workflow.get("identity") or normalized["default_identity"])
            if workflow_identity == identity and workflow.get("enabled", True):
                result.append(deepcopy(workflow))
        return result

    @classmethod
    def stored_render_urls(
        cls,
        auth_info: Optional[Dict[str, Any]],
        submit_url: str,
        base_url: str,
    ) -> list[str]:
        """Resolve declared plant→render edges for stored-XSS closed-loop checks."""
        normalized = cls.normalize(auth_info)
        allowed = []
        for identity in normalized["identities"].values():
            allowed.extend(identity.get("allowed_auth_origins") or [])
        results = []
        for workflow in normalized.get("workflows", []):
            if not isinstance(workflow, dict):
                continue
            pattern = str(workflow.get("submit_pattern") or "*")
            if not fnmatch.fnmatch(submit_url, pattern):
                continue
            values = workflow.get("render_urls") or workflow.get("render_url") or []
            if isinstance(values, str):
                values = [values]
            for value in values if isinstance(values, list) else []:
                url = urljoin(base_url, str(value))
                if not cls._allowed_url(url, base_url, allowed):
                    raise AuthConfigurationError(f"Stored render URL is outside allowed origins: {url}")
                if url not in results:
                    results.append(url)
        return results

    @classmethod
    def authenticate_playwright(
        cls,
        page,
        context,
        base_url: str,
        auth_spec: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Apply identity state to a Playwright context and renew it if expired."""
        material = cls.material(auth_spec)
        origin = cls._origin(base_url)
        cls._bind_playwright_headers(context, base_url, material)
        cookies = []
        for name, raw_cookie in material.cookies.items():
            cookie = dict(raw_cookie) if isinstance(raw_cookie, dict) else {"value": str(raw_cookie)}
            cookie["name"] = str(name)
            if "url" not in cookie and "domain" not in cookie:
                cookie["url"] = origin
            cookie_url = cookie.get("url")
            cookie_domain = str(cookie.get("domain") or "").lstrip(".").rstrip(".").lower()
            if cookie_url and not cls._allowed_url(str(cookie_url), base_url, material.allowed_auth_origins):
                raise AuthConfigurationError("Cookie URL is outside allowed authentication origins")
            if cookie_domain:
                allowed_hosts = {
                    urlparse(value).hostname.rstrip(".").lower()
                    for value in (origin, *material.allowed_auth_origins)
                    if urlparse(value).hostname
                }
                if cookie_domain not in allowed_hosts:
                    raise AuthConfigurationError("Cookie domain is outside allowed authentication origins")
            if cookie.get("sameSite") not in {None, "Strict", "Lax", "None"}:
                cookie.pop("sameSite", None)
            cookies.append(cookie)
        if cookies:
            context.add_cookies(cookies)

        if material.local_storage or material.session_storage:
            local_values = json.dumps(material.local_storage)
            session_values = json.dumps(material.session_storage)
            storage_origins = json.dumps([origin, *material.allowed_auth_origins])
            context.add_init_script(f"""
                (() => {{
                    const allowedOrigins = new Set({storage_origins});
                    if (!allowedOrigins.has(location.origin)) return;
                    const localValues = {local_values};
                    const sessionValues = {session_values};
                    for (const [key, value] of Object.entries(localValues)) localStorage.setItem(key, value);
                    for (const [key, value] of Object.entries(sessionValues)) sessionStorage.setItem(key, value);
                }})();
            """)

        health_url = urljoin(base_url, str(material.health_check_url or base_url))
        if not cls._allowed_url(health_url, base_url, material.allowed_auth_origins):
            raise AuthConfigurationError("Health-check URL is outside allowed authentication origins")
        response = page.goto(health_url)
        source = page.content()
        challenge = cls.challenge_reason(source)
        if challenge:
            raise HumanInterventionRequired(
                f"Authentication challenge detected: {challenge}", url=page.url, identity=material.label
            )
        expired = cls.is_auth_wall(
            status_code=response.status if response else None,
            final_url=page.url,
            body_text=source,
            login_url_patterns=material.login_url_patterns,
        )
        if material.login and (expired or bool(material.login.get("force"))):
            login_url = cls._login_url(base_url, material) or (page.url if expired else None)
            if not login_url:
                raise AuthConfigurationError("Login credentials were supplied without a login URL")
            cls._execute_playwright_login(page, base_url, material, login_url)

        return {
            "identity": material.label,
            "role": material.role,
            "authenticated": not cls.is_auth_wall(
                final_url=page.url,
                body_text=page.content(),
                login_url_patterns=material.login_url_patterns,
            ),
            "cookies": context.cookies(),
            "final_url": page.url,
        }

    @classmethod
    def bind_playwright_headers(
        cls,
        context,
        base_url: str,
        headers: Dict[str, Any],
        allowed_auth_origins: Iterable[str] = (),
    ) -> None:
        """Attach headers only to exact authorized origins and preserve route chains."""
        if not headers or not hasattr(context, "route"):
            return
        configured = dict(getattr(context, "_xssboss_auth_headers", {}) or {})
        configured.update({str(key): str(value) for key, value in headers.items()})
        origins = list(getattr(context, "_xssboss_auth_origins", ()) or ())
        origins.extend(str(value) for value in allowed_auth_origins)
        origins = list(cls._normalize_allowed_origins(origins))
        configured_names = {key.lower() for key in configured}

        def route_auth_headers(route) -> None:
            request_headers = dict(getattr(route.request, "headers", {}) or {})
            for key in list(request_headers):
                if key.lower() in configured_names:
                    del request_headers[key]
            if cls._allowed_url(route.request.url, base_url, origins):
                request_headers.update(configured)
            fallback = getattr(route, "fallback", None)
            if callable(fallback):
                fallback(headers=request_headers)
            else:
                route.continue_(headers=request_headers)

        previous = getattr(context, "_xssboss_auth_route", None)
        if previous is not None and hasattr(context, "unroute"):
            try:
                context.unroute("**/*", previous)
            except Exception:
                pass
        context.route("**/*", route_auth_headers)
        try:
            setattr(context, "_xssboss_auth_route", route_auth_headers)
            setattr(context, "_xssboss_auth_headers", configured)
            setattr(context, "_xssboss_auth_origins", tuple(origins))
        except Exception:
            pass

    @classmethod
    def _bind_playwright_headers(cls, context, base_url: str, material: AuthMaterial) -> None:
        """Apply one identity's browser headers only to authorized origins."""
        cls.bind_playwright_headers(
            context,
            base_url,
            material.headers,
            material.allowed_auth_origins,
        )

    @classmethod
    def _execute_playwright_login(cls, page, base_url: str, material: AuthMaterial, login_url: str) -> None:
        page.goto(login_url)
        challenge = cls.challenge_reason(page.content())
        if challenge:
            raise HumanInterventionRequired(
                f"Authentication challenge detected: {challenge}", url=page.url, identity=material.label
            )
        login = material.login
        steps = login.get("steps") if isinstance(login.get("steps"), list) else []
        if steps:
            for step in steps:
                if not isinstance(step, dict):
                    continue
                action = str(step.get("action") or "").lower()
                if action == "navigate":
                    url = urljoin(page.url or base_url, str(step.get("url") or ""))
                    if not cls._allowed_url(url, base_url, material.allowed_auth_origins):
                        raise AuthConfigurationError(f"Login navigation is outside allowed origins: {url}")
                    page.goto(url)
                elif action == "fill":
                    page.fill(str(step.get("selector") or ""), cls._login_value(login, step.get("value")))
                elif action == "click":
                    page.click(str(step.get("selector") or ""))
                elif action == "press":
                    page.press(str(step.get("selector") or "body"), str(step.get("key") or "Enter"))
                elif action == "wait":
                    page.wait_for_timeout(int(max(0, min(10000, float(step.get("seconds", 0.5)) * 1000))))
                else:
                    raise AuthConfigurationError(f"Unsupported authentication workflow action: {action}")
        else:
            selectors = cls._login_selectors(page.content(), login)
            page.fill(selectors["username_selector"], str(login.get("username") or ""))
            page.fill(selectors["password_selector"], str(login.get("password") or ""))
            page.click(selectors["submit_selector"])
        page.wait_for_timeout(int(max(0, min(10000, float(login.get("wait_seconds", 1.0)) * 1000))))
        source = page.content()
        challenge = cls.challenge_reason(source)
        if challenge:
            raise HumanInterventionRequired(
                f"Authentication challenge detected after credential submission: {challenge}",
                url=page.url,
                identity=material.label,
            )
        success_selector = login.get("success_selector")
        if success_selector:
            page.wait_for_selector(str(success_selector))
        elif cls.is_auth_wall(
            final_url=page.url,
            body_text=source,
            login_url_patterns=material.login_url_patterns,
        ):
            raise HumanInterventionRequired(
                "Login did not leave the authentication page; credentials, MFA, or selectors require review",
                url=page.url,
                identity=material.label,
            )

    @classmethod
    def sanitize_public(cls, value: Any, parent_key: str = "") -> Any:
        """Redact credentials and live session material from API responses/logs."""
        if isinstance(value, dict):
            output = {}
            for key, item in value.items():
                lowered = str(key).lower()
                if lowered in cls.SECRET_KEYS or any(marker in lowered for marker in ("password", "secret", "token", "cookie")):
                    output[key] = "***configured***" if item not in (None, "", {}, []) else item
                else:
                    output[key] = cls.sanitize_public(item, lowered)
            return output
        if isinstance(value, list):
            return [cls.sanitize_public(item, parent_key) for item in value]
        return value
