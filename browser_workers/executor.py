"""Playwright execution engine."""
import hashlib
import time
import json
import re
import threading
from itertools import islice
from typing import Dict, Any, Optional, List
from pathlib import Path
from urllib.parse import quote, unquote, urlencode, urlparse, urlsplit

from playwright.sync_api import sync_playwright
from browser_workers.selenium_config import SeleniumConfig
from browser_workers.oracle_inject import get_oracle_script
from backend_api.utils.logger import logger
from backend_api.config import settings
from backend_api.utils.response_security import analyze_response
from backend_api.utils.stealth import (
    get_next_user_agent,
    get_random_waf_bypass_headers,
    get_next_proxy
)


# undetected_chromedriver patches one process-global executable path. Parallel
# constructors can race while renaming that file on Windows, so serialize only
# the constructor/patch phase; browser execution remains fully parallel.
_UC_LAUNCH_LOCK = threading.Lock()


class BrowserExecutor:
    """Execute test cases in real browsers via Playwright."""
    
    def __init__(self, oracle_url: str = "http://localhost:8001/api/v1/oracle"):
        """Initialize browser executor.
        
        Args:
            oracle_url: Oracle server URL for callbacks
        """
        self.oracle_url = oracle_url
        self.playwright = None
        self.browser = None
        self.uc_driver = None

    @staticmethod
    def _is_main_navigation_response(response: Any, page: Any) -> bool:
        """Select only the top-level navigation response for response posture."""
        try:
            request = response.request
            return bool(
                request.is_navigation_request()
                and request.frame == page.main_frame
            )
        except Exception:
            return False

    @staticmethod
    def _cookie_attribute_metadata(cookies: Any) -> List[Dict[str, Any]]:
        """Drop cookie identifiers and values before metadata leaves the browser context."""
        observations: List[Dict[str, Any]] = []
        for item in cookies if isinstance(cookies, list) else []:
            if not isinstance(item, dict):
                continue
            raw_expires = item.get("expires")
            expiration_declared = bool(
                isinstance(raw_expires, (int, float)) and raw_expires > 0
            )
            raw_name = str(item.get("name") or "")
            name_prefix = (
                "__Host-" if raw_name.startswith("__Host-")
                else "__Secure-" if raw_name.startswith("__Secure-")
                else None
            )
            observations.append({
                "secure": item.get("secure") if isinstance(item.get("secure"), bool) else None,
                "httpOnly": item.get("httpOnly") if isinstance(item.get("httpOnly"), bool) else None,
                "sameSite": str(item.get("sameSite")) if item.get("sameSite") is not None else None,
                "partitioned": item.get("partitioned") if isinstance(item.get("partitioned"), bool) else None,
                "domain": bool(item.get("domain")),
                "path": "/" if item.get("path") == "/" else "<scoped>" if item.get("path") else None,
                "expires": True if expiration_declared else None,
                "name_prefix": name_prefix,
            })
        return observations[:100]

    @staticmethod
    def _build_response_posture(
        *,
        url: str,
        status_code: Any,
        headers: Any,
        cookie_metadata: Any,
        metadata_observed: bool,
        request_has_credentials: bool,
        source: str,
    ) -> Dict[str, Any]:
        """Create a passive posture artifact with explicit capture coverage."""
        posture = analyze_response(
            url=url,
            status_code=status_code if metadata_observed else None,
            headers=headers if metadata_observed and isinstance(headers, dict) else {},
            cookie_metadata=cookie_metadata if metadata_observed else None,
            browser_telemetry={"request_has_credentials": bool(request_has_credentials)},
            source=source,
        )
        posture["assessment"]["metadata_observed"] = bool(metadata_observed)
        posture["assessment"]["browser_policy_modified"] = bool(settings.BYPASS_CSP)
        if settings.BYPASS_CSP:
            posture["limitations"].insert(
                0,
                "The browser execution environment removed CSP headers; posture describes captured target metadata, not the modified enforcement environment.",
            )
        if not metadata_observed:
            posture["limitations"].insert(
                0,
                "This browser engine did not expose the main navigation response metadata.",
            )
        return posture

    def __del__(self):
        """Best-effort cleanup for short-lived local verification threads."""
        try:
            self.stop()
        except Exception:
            # Interpreter shutdown may already have torn down logging/modules.
            pass

    @staticmethod
    def _terminate_owned_uc_tree(driver: Any) -> None:
        """Terminate only the UC Chrome tree owned by this driver.

        undetected_chromedriver uses ``os.kill(pid, 15)`` which can leave the
        headless Chrome process alive on Windows.  Validate both its recorded
        PID and unique temporary profile before using psutil as a fallback.
        """
        browser_pid = getattr(driver, "browser_pid", None)
        user_data_dir = str(getattr(driver, "user_data_dir", "") or "")
        if not isinstance(browser_pid, int) or browser_pid <= 0 or not user_data_dir:
            return

        try:
            import psutil

            root = psutil.Process(browser_pid)
            command_line = " ".join(root.cmdline())
            if user_data_dir.casefold() not in command_line.casefold():
                logger.warning(
                    "Refusing to terminate Chrome PID %s: profile ownership did not match",
                    browser_pid,
                )
                return

            owned = root.children(recursive=True) + [root]
            for process in reversed(owned):
                try:
                    process.terminate()
                except psutil.NoSuchProcess:
                    pass
            _, alive = psutil.wait_procs(owned, timeout=2)
            for process in alive:
                try:
                    process.kill()
                except psutil.NoSuchProcess:
                    pass
            if alive:
                psutil.wait_procs(alive, timeout=2)
        except ImportError:
            logger.warning("psutil unavailable; could not verify UC Chrome process cleanup")
        except Exception as error:
            logger.warning("Could not terminate owned UC Chrome PID %s: %s", browser_pid, error)

    @staticmethod
    def _detach_uc_finalizer(driver: Any) -> None:
        """Remove UC's process-global finalizer for an already-stopped driver.

        UC registers the driver itself as a finalizer argument, keeping every
        completed driver alive until interpreter shutdown.  Detaching the one
        entry whose watched object is exactly this driver prevents long local
        acceptance runs from hanging during Python finalization.
        """
        try:
            from weakref import finalize

            registry = getattr(finalize, "_registry", {})
            for registered in list(registry):
                details = registered.peek()
                if details and details[0] is driver:
                    registered.detach()
        except Exception as error:
            logger.debug("Could not detach UC finalizer: %s", error)

    @staticmethod
    def _resolve_proxy_server(rotated_proxy: Optional[str] = None) -> Optional[Dict[str, str]]:
        """Resolve proxy option favoring explicit Burp worker proxy, rotated proxy, or default."""
        from backend_api.utils.proxy_health import effective_worker_proxy

        proxy = effective_worker_proxy(rotated_proxy)
        return {"server": proxy} if proxy else None

    @classmethod
    def create_runtime_lineage_envelope(
        cls, test_case_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Pin transport-visible inputs for all arms of one A/A/B series."""
        request_headers, requested_user_agent = cls._prepare_browser_headers(
            test_case_data
        )
        return {
            "version": 1,
            "headers": request_headers,
            "user_agent": requested_user_agent or get_next_user_agent(),
            "proxy": cls._resolve_proxy_server(get_next_proxy()),
        }

    @staticmethod
    def _validated_runtime_lineage_envelope(
        test_case_data: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Accept only the runner's bounded, control-character-free envelope."""
        probe = test_case_data.get("runtime_lineage_probe")
        envelope = test_case_data.get("_runtime_lineage_execution_envelope")
        if (
            not isinstance(probe, dict)
            or probe.get("inert") is not True
            or test_case_data.get("suppress_artifacts") is not True
            or not isinstance(envelope, dict)
            or envelope.get("version") != 1
        ):
            return None
        user_agent = envelope.get("user_agent")
        headers = envelope.get("headers")
        proxy = envelope.get("proxy")
        if (
            not isinstance(user_agent, str)
            or not user_agent
            or len(user_agent) > 512
            or any(character in user_agent for character in "\r\n\0")
            or not isinstance(headers, dict)
            or len(headers) > 64
        ):
            return None
        safe_headers: Dict[str, str] = {}
        for key, value in headers.items():
            if (
                not isinstance(key, str)
                or not key
                or len(key) > 128
                or not isinstance(value, str)
                or len(value) > 8192
                or any(character in key or character in value for character in "\r\n\0")
            ):
                return None
            safe_headers[key] = value
        if proxy is not None:
            if not isinstance(proxy, dict) or set(proxy) != {"server"}:
                return None
            server = proxy.get("server")
            if (
                not isinstance(server, str)
                or not server
                or len(server) > 2048
                or any(character in server for character in "\r\n\0")
            ):
                return None
            proxy = {"server": server}
        return {
            "headers": safe_headers,
            "user_agent": user_agent,
            "proxy": proxy,
        }

    @staticmethod
    def _click_token_javascript_links_playwright(page: Any, token: str) -> None:
        """Use a trusted browser input click for token-bearing javascript URLs."""
        links = page.locator("a[href^='javascript:']")
        for index in range(min(links.count(), 20)):
            link = links.nth(index)
            href = link.get_attribute("href") or ""
            if token in href:
                try:
                    link.click(timeout=1500)
                except Exception as error:
                    logger.debug("Trusted Playwright link click failed: %s", error)

    @staticmethod
    def _click_token_javascript_links_uc(driver: Any, token: str) -> None:
        """Use WebDriver input dispatch for token-bearing javascript URLs."""
        from selenium.webdriver.common.by import By

        for link in driver.find_elements(By.CSS_SELECTOR, "a[href^='javascript:']")[:20]:
            href = link.get_attribute("href") or ""
            if token in href:
                try:
                    link.click()
                except Exception as error:
                    logger.debug("Trusted WebDriver link click failed: %s", error)

    @staticmethod
    def _active_browser_interactions_allowed(test_case_data: Dict[str, Any]) -> bool:
        """Keep controlled lineage arms navigation-only; disable clicks and steps."""
        return (
            "runtime_lineage_probe" not in test_case_data
            and "_runtime_lineage_execution_envelope" not in test_case_data
        )

    @staticmethod
    def _controlled_probe_request_allowed(
        expected_url: str,
        request_url: str,
        method: str,
        *,
        resource_type: str,
        is_navigation: bool,
        belongs_to_primary_page: bool,
        is_main_frame: bool,
    ) -> bool:
        """Allow one same-path main navigation and passive page-owned resources.

        Unexpected methods, origins, frames, or resource types fail closed in the
        route interceptor and invalidate the complete arm.
        """
        if method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            return False
        if not belongs_to_primary_page:
            return False
        try:
            expected = urlsplit(expected_url)
            observed = urlsplit(request_url)
            expected_port = expected.port or (
                443 if expected.scheme.lower() == "https" else 80
            )
            observed_port = observed.port or (
                443 if observed.scheme.lower() == "https" else 80
            )
        except (TypeError, ValueError):
            return False
        same_origin = (
            expected.scheme.lower(),
            (expected.hostname or "").lower(),
            expected_port,
        ) == (
            observed.scheme.lower(),
            (observed.hostname or "").lower(),
            observed_port,
        )
        if not same_origin:
            return False
        if not is_navigation:
            return resource_type in {
                "script", "stylesheet", "image", "media", "font",
                "manifest", "texttrack",
            }
        if not is_main_frame:
            return False
        return (
            expected.path or "/",
        ) == (
            observed.path or "/",
        )

    @staticmethod
    def _navigation_url_allowed(
        test_case_data: Dict[str, Any],
        request_url: str,
        *,
        allow_auth_origin: bool = False,
    ) -> bool:
        """Authorize a top-level navigation against exact program scope."""
        from types import SimpleNamespace

        from backend_api.utils.scope_guard import is_url_in_scope

        base_url = str(
            test_case_data.get("target_base_url")
            or test_case_data.get("url")
            or ""
        )
        target = SimpleNamespace(
            base_url=base_url,
            scope_tags=test_case_data.get("target_scope_tags"),
        )
        if is_url_in_scope(target, request_url):
            return True
        if allow_auth_origin:
            from backend_api.services.auth_session_service import AuthSessionService

            auth_spec = test_case_data.get("auth_spec") or {}
            return AuthSessionService._allowed_url(
                request_url,
                base_url,
                auth_spec.get("allowed_auth_origins") or (),
            )
        return False

    @staticmethod
    def _capture_enabled(mode: str, oracle_hit: bool) -> bool:
        """Return whether evidence should be captured for this execution."""
        normalized = (mode or "").strip().lower()
        if normalized in {"all", "true", "1", "yes", "on"}:
            return True
        if normalized == "hits":
            return oracle_hit
        return False

    @staticmethod
    def _runtime_coverage_requested(mode: str) -> bool:
        """Return whether CDP coverage should be enabled for this run."""
        return (mode or "").strip().lower() not in {
            "", "off", "false", "0", "no", "none", "disabled",
        }

    @staticmethod
    def _safe_lineage_observation(item: Any) -> Optional[Dict[str, Any]]:
        """Allowlist one source-free inert A/A/B observation."""
        if not isinstance(item, dict) or item.get("inert") is not True:
            return None
        safe_id = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
        fingerprint = re.compile(r"^[0-9a-fA-F]{64}$")
        run_id = item.get("run_id")
        arm = str(item.get("arm") or item.get("variant") or "").upper()
        candidate_id = item.get("candidate_id")
        sink_fingerprint = item.get("sink_fingerprint")
        stimulus_fingerprint = item.get("stimulus_fingerprint")
        observation_fingerprint = item.get("observation_fingerprint")
        if not isinstance(run_id, str) or not safe_id.fullmatch(run_id):
            return None
        if arm not in {"A", "B"}:
            return None
        if not all(
            isinstance(value, str) and fingerprint.fullmatch(value)
            for value in (
                candidate_id,
                sink_fingerprint,
                stimulus_fingerprint,
                observation_fingerprint,
            )
        ):
            return None
        return {
            "run_id": run_id,
            "arm": arm,
            "inert": True,
            "candidate_id": candidate_id.lower(),
            "sink_fingerprint": sink_fingerprint.lower(),
            "stimulus_fingerprint": stimulus_fingerprint.lower(),
            "observation_fingerprint": observation_fingerprint.lower(),
        }

    @staticmethod
    def _lineage_probe_stimulus_is_materialized(
        test_case_data: Dict[str, Any],
        probe: Dict[str, Any],
        stimulus: str,
    ) -> bool:
        """Prove the declared inert stimulus is in the request input being sent."""
        location = probe.get("parameter_location")
        parameter_name = probe.get("parameter_name")
        if (
            not isinstance(parameter_name, str)
            or not parameter_name
            or len(parameter_name) > 255
            or test_case_data.get("param_name") != parameter_name
        ):
            return False
        if location == "query":
            params = test_case_data.get("params")
            return isinstance(params, dict) and params.get(parameter_name) == stimulus
        if location == "fragment":
            url = test_case_data.get("url")
            if not isinstance(url, str):
                return False
            try:
                return unquote(urlsplit(url).fragment) == stimulus
            except (TypeError, ValueError):
                return False
        return False

    @classmethod
    def _build_runtime_lineage_report(
        cls,
        payloads: Any,
        test_case_data: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Reduce page ledgers to bounded, source-free causal evidence."""
        if not isinstance(payloads, list):
            return None

        events: List[Dict[str, Any]] = []
        dropped_events = 0
        frame_count = 0
        id_fields = {
            "event_id",
            "source_id",
            "sink_id",
            "context_id",
            "parent_context_id",
            "source_context_id",
            "sink_context_id",
            "async_context_id",
            "parent_async_context_id",
        }
        for frame_index, payload in enumerate(payloads[:16]):
            if not isinstance(payload, dict):
                continue
            frame_count += 1
            raw_dropped = payload.get("dropped_events")
            if isinstance(raw_dropped, int) and not isinstance(raw_dropped, bool):
                dropped_events += max(0, min(raw_dropped, 1_000_000))
            frame_events = payload.get("events")
            if isinstance(frame_events, list):
                remaining = max(0, 257 - len(events))
                for item in islice(frame_events, remaining):
                    if not isinstance(item, dict):
                        continue
                    # Every document owns an independent ledger whose counters
                    # start at one. Namespace identifiers before aggregation so
                    # unrelated frames cannot form a synthetic causal edge.
                    namespaced = dict(item)
                    for field in id_fields:
                        value = namespaced.get(field)
                        if isinstance(value, str):
                            namespaced[field] = f"frame-{frame_index}:{value}"
                    events.append(namespaced)
            if len(events) >= 257:
                break
        if frame_count == 0:
            return None

        from analysis_engine.runtime_lineage import analyze

        events = events[:257]
        preliminary = analyze(events)
        raw_prior_observations = test_case_data.get("runtime_lineage_observations")
        if not isinstance(raw_prior_observations, list):
            raw_prior_observations = []
        safe_observations = [
            observation
            for item in raw_prior_observations[:24]
            if (observation := cls._safe_lineage_observation(item)) is not None
        ]

        # A/A/B probes must be explicitly marked inert by their scheduler. The
        # executor never guesses that an arbitrary payload is safe or inert.
        current_observations: List[Dict[str, Any]] = []
        probe = test_case_data.get("runtime_lineage_probe")
        if isinstance(probe, dict) and probe.get("inert") is True:
            run_id = probe.get("run_id")
            arm = str(probe.get("arm") or probe.get("variant") or "").upper()
            declared_stimulus = probe.get("stimulus")
            actual_stimulus = test_case_data.get("payload")
            supplied_fingerprint = probe.get("stimulus_fingerprint")
            stimulus_fingerprint = None
            if (
                isinstance(declared_stimulus, str)
                and isinstance(actual_stimulus, str)
                and declared_stimulus == actual_stimulus
                and re.fullmatch(r"[A-Za-z0-9]{1,96}", actual_stimulus)
                and cls._lineage_probe_stimulus_is_materialized(
                    test_case_data,
                    probe,
                    actual_stimulus,
                )
            ):
                computed_fingerprint = hashlib.sha256(
                    actual_stimulus.encode("ascii")
                ).hexdigest()
                if supplied_fingerprint is None or (
                    isinstance(supplied_fingerprint, str)
                    and supplied_fingerprint.lower() == computed_fingerprint
                ):
                    stimulus_fingerprint = computed_fingerprint

            sink_events = {
                item.get("sink_id") or item.get("event_id"): item
                for item in events
                if item.get("kind") == "sink"
            }
            for flow in (
                (preliminary.get("causal_flows") or [])[:8]
                if stimulus_fingerprint is not None
                else []
            ):
                sink_event = sink_events.get(flow.get("sink_id"))
                observation_fingerprint = (
                    sink_event.get("observation_fingerprint")
                    if isinstance(sink_event, dict)
                    else None
                )
                candidate = {
                    "run_id": run_id,
                    "arm": arm,
                    "inert": True,
                    "candidate_id": flow.get("candidate_id"),
                    "sink_fingerprint": flow.get("sink_fingerprint"),
                    "stimulus_fingerprint": stimulus_fingerprint,
                    "observation_fingerprint": observation_fingerprint,
                }
                normalized = cls._safe_lineage_observation(candidate)
                if normalized is not None:
                    current_observations.append(normalized)

        retained_observations = (safe_observations + current_observations)[-24:]
        report = analyze(events, retained_observations)
        report["available"] = True
        report["value_free"] = True
        report["collection"] = {
            "frames_observed": frame_count,
            "events_exported": min(len(events), 256),
            "browser_dropped_events": dropped_events,
        }
        if current_observations:
            # Safe handoff material for a scheduler's next inert arm.
            report["probe_observations"] = retained_observations
        if dropped_events:
            report.setdefault("budget_exhausted", []).append("browser_events")
        return report

    @classmethod
    def _collect_runtime_lineage_playwright(
        cls,
        page: Any,
        test_case_data: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        payloads: List[Dict[str, Any]] = []
        frames = getattr(page, "frames", None)
        frame_list = frames if isinstance(frames, list) else [page]
        for frame in frame_list[:16]:
            try:
                payload = frame.evaluate(
                    "() => typeof window.__XSS_CAUSAL_LINEAGE_JSON__ === 'function' "
                    "? window.__XSS_CAUSAL_LINEAGE_JSON__() "
                    ": (typeof window.__XSS_CAUSAL_LINEAGE__ === 'function' "
                    "? window.__XSS_CAUSAL_LINEAGE__() : null)"
                )
                if isinstance(payload, str):
                    if len(payload) > 1_000_000:
                        continue
                    try:
                        payload = json.loads(payload)
                    except (TypeError, ValueError):
                        continue
                if isinstance(payload, dict):
                    payloads.append(payload)
            except Exception as error:
                logger.debug("Runtime lineage frame collection failed: %s", error)
        return cls._build_runtime_lineage_report(payloads, test_case_data)

    @classmethod
    def _collect_runtime_lineage_uc(
        cls,
        driver: Any,
        test_case_data: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        try:
            payload = driver.execute_script(
                "return typeof window.__XSS_CAUSAL_LINEAGE_JSON__ === 'function' "
                "? window.__XSS_CAUSAL_LINEAGE_JSON__() "
                ": (typeof window.__XSS_CAUSAL_LINEAGE__ === 'function' "
                "? window.__XSS_CAUSAL_LINEAGE__() : null);"
            )
        except Exception as error:
            logger.debug("UC runtime lineage collection failed: %s", error)
            return None
        if isinstance(payload, str):
            if len(payload) > 1_000_000:
                return None
            try:
                payload = json.loads(payload)
            except (TypeError, ValueError):
                return None
        return cls._build_runtime_lineage_report(
            [payload] if isinstance(payload, dict) else [],
            test_case_data,
        )

    @staticmethod
    def _prepare_browser_headers(test_case_data: Dict[str, Any]) -> tuple[Dict[str, str], Optional[str]]:
        """Merge opt-in bypass headers with endpoint auth headers.

        Explicit endpoint headers win. Browser-managed or unsafe transport headers
        are excluded, and User-Agent is returned separately so JavaScript-visible
        navigator state matches the network header in Playwright.
        """
        merged: Dict[str, str] = {
            str(key): str(value)
            for key, value in get_random_waf_bypass_headers().items()
            if value is not None
        }
        for key, value in (test_case_data.get("headers") or {}).items():
            if value is not None:
                for existing_key in list(merged):
                    if existing_key.lower() == str(key).lower():
                        del merged[existing_key]
                merged[str(key)] = str(value)

        blocked = {"cookie", "host", "content-length", "connection"}
        cleaned: Dict[str, str] = {}
        user_agent = None
        for key, value in merged.items():
            lowered = key.lower()
            if lowered == "user-agent":
                user_agent = value
            elif lowered not in blocked and not lowered.startswith(":"):
                cleaned[key] = value
        return cleaned, user_agent

    @staticmethod
    def _origin_for_url(url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}/"

    @staticmethod
    def _navigate_with_method(
        page,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: Any = None,
        json_data: Any = None,
    ) -> None:
        """Navigate with the real HTTP method while preserving response CSP/origin.

        Intercepting the main navigation avoids rendering API responses through
        ``document.write`` on ``about:blank``, which bypassed normal browser security
        semantics and caused both false positives and authenticated POST misses.
        """
        normalized_method = (method or "GET").upper()
        if normalized_method == "GET":
            page.goto(url)
            return

        request_headers = dict(headers or {})
        header_names = {key.lower() for key in request_headers}
        post_data = None
        if json_data is not None:
            post_data = json.dumps(json_data)
            if "content-type" not in header_names:
                request_headers["Content-Type"] = "application/json"
        elif body is not None:
            post_data = urlencode(body, doseq=True) if isinstance(body, dict) else str(body)
            if "content-type" not in header_names:
                request_headers["Content-Type"] = "application/x-www-form-urlencoded"

        main_request_sent = False

        def intercept(route):
            nonlocal main_request_sent
            if not main_request_sent and route.request.is_navigation_request():
                main_request_sent = True
                continued_headers = dict(route.request.headers)
                continued_headers.update(request_headers)
                continued_headers.pop("content-length", None)
                route.continue_(
                    method=normalized_method,
                    headers=continued_headers,
                    post_data=post_data,
                )
            else:
                route.continue_()

        page.route("**/*", intercept)
        try:
            page.goto(url)
        finally:
            page.unroute("**/*", intercept)
    
    def start(self):
        """Start browser instance."""
        if settings.USE_UNDETECTED_CHROME:
            if self.uc_driver:
                return
            try:
                logger.info("Launching Undetected Chromedriver...")
                import undetected_chromedriver as uc
                options = uc.ChromeOptions()
                options.add_argument('--headless')
                options.add_argument('--disable-dev-shm-usage')

                from backend_api.utils.proxy_health import effective_worker_proxy

                effective_proxy = effective_worker_proxy()

                if effective_proxy:
                    options.add_argument(f"--proxy-server={effective_proxy}")
                
                # Fetch browser logging capabilities
                from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
                caps = DesiredCapabilities.CHROME.copy()
                caps['goog:loggingPrefs'] = {'browser': 'ALL'}
                
                with _UC_LAUNCH_LOCK:
                    self.uc_driver = uc.Chrome(options=options, desired_capabilities=caps)
                logger.info("Browser executor started using Undetected Chromedriver")
            except Exception as err:
                logger.error(f"Failed to start Undetected Chromedriver: {err}", exc_info=True)
                raise err
        else:
            if self.browser:
                return
                
            try:
                logger.info("Launching Playwright Chromium browser...")
                self.playwright = sync_playwright().start()
                
                # Clean launch arguments
                args = [arg for arg in SeleniumConfig.BROWSER_ARGS if not arg.startswith('--window-size=')]
                
                # Launch directly unless an actual browser-wide proxy is configured.
                # A synthetic "per-context" proxy makes every navigation fail when
                # proxying is disabled, and those failures used to be recorded as
                # ordinary oracle misses.
                from backend_api.utils.proxy_health import effective_worker_proxy

                launch_proxy_server = effective_worker_proxy()
                launch_options = {"headless": True, "args": args}
                if launch_proxy_server:
                    launch_options["proxy"] = {"server": launch_proxy_server}

                self.browser = self.playwright.chromium.launch(**launch_options)
                logger.info("Browser executor started using Playwright")
            except Exception as err:
                logger.error(f"Failed to start Playwright browser: {err}", exc_info=True)
                raise err

    def stop(self):
        """Stop browser instance."""
        if self.uc_driver:
            driver = self.uc_driver
            try:
                driver.quit()
            except Exception as e:
                logger.error(f"Error closing UC driver: {e}")
            finally:
                self._terminate_owned_uc_tree(driver)
                # undetected_chromedriver's own __del__ calls quit() again.
                # Make that second cleanup idempotent; on Windows it otherwise
                # emits a misleading WinError 6 after a successful scan.
                try:
                    driver.quit = lambda: None
                except Exception:
                    pass
                self._detach_uc_finalizer(driver)
            self.uc_driver = None
            logger.info("Undetected Chromedriver stopped")

        if self.browser:
            try:
                self.browser.close()
            except Exception as e:
                logger.error(f"Error closing browser: {e}")
            self.browser = None
            
        if self.playwright:
            try:
                self.playwright.stop()
            except Exception as e:
                logger.error(f"Error stopping Playwright: {e}")
            self.playwright = None
            
        logger.info("Browser executor stopped")

    @classmethod
    def _save_live_preview(cls, driver_or_page: Any, test_case_data: Dict[str, Any], oracle_hit: bool = False) -> None:
        """Capture and publish real-time browser preview frame and execution metadata for UI live monitor."""
        try:
            from pathlib import Path
            from datetime import datetime, UTC
            screenshots_dir = Path(__file__).resolve().parent.parent / "screenshots"
            screenshots_dir.mkdir(parents=True, exist_ok=True)
            live_path = screenshots_dir / "live_latest.png"
            meta_path = screenshots_dir / "live_metadata.json"

            # Capture screenshot from either Selenium/UC or Playwright
            if hasattr(driver_or_page, "save_screenshot"):
                driver_or_page.save_screenshot(str(live_path))
                current_url = getattr(driver_or_page, "current_url", "") or ""
                page_title = getattr(driver_or_page, "title", "") or ""
            elif hasattr(driver_or_page, "screenshot"):
                driver_or_page.screenshot(path=str(live_path))
                current_url = getattr(driver_or_page, "url", "") or ""
                page_title = ""
                try:
                    page_title = driver_or_page.title()
                except Exception:
                    pass
            else:
                return

            meta = {
                "url": current_url,
                "title": page_title,
                "test_case_id": test_case_data.get("test_case_id") or test_case_data.get("id"),
                "param_name": test_case_data.get("param_name") or "",
                "payload": str(test_case_data.get("payload") or "")[:250],
                "engine": "Undetected Chrome" if getattr(settings, "USE_UNDETECTED_CHROME", True) else "Playwright",
                "oracle_hit": bool(oracle_hit),
                "timestamp": datetime.now(UTC).isoformat(),
            }
            meta_path.write_text(json.dumps(meta), encoding="utf-8")
        except Exception as err:
            logger.debug(f"Live preview capture skipped: {err}")

    def execute_test_case(
        self,
        test_case_data: Dict[str, Any],
        screenshot_dir: Optional[Path] = None
    ) -> Dict[str, Any]:
        """Execute a test case in browser.
        
        Args:
            test_case_data: Test case data dictionary
            screenshot_dir: Directory to save screenshots
            
        Returns:
            Dictionary with execution results
        """
        controlled_probe_requested = (
            "runtime_lineage_probe" in test_case_data
            or "_runtime_lineage_execution_envelope" in test_case_data
        )
        lineage_envelope = (
            self._validated_runtime_lineage_envelope(test_case_data)
            if controlled_probe_requested
            else None
        )
        # Never reinterpret a malformed or unsupported controlled arm as an
        # ordinary browser run. That fallback would restore rotated identity,
        # service workers, active interactions, and unrestricted page requests.
        if controlled_probe_requested and (
            lineage_envelope is None or settings.USE_UNDETECTED_CHROME
        ):
            rejection = {
                "type": "RuntimeLineageProbeRejected",
                "message": "Controlled runtime-lineage envelope was invalid or unsupported",
            }
            return {
                "oracle_hit": False,
                "oracle_message": None,
                "duration_ms": 0,
                "screenshot_path": None,
                "dom_snapshot": None,
                "logs": {
                    "console": [],
                    "errors": [rejection["message"]],
                    "network_responses": [],
                    "request_failures": [],
                    "status_code": None,
                    "headers": {},
                    "final_url": None,
                    "tech_stack": {},
                    "cross_identity_revisits": [],
                    "execution_error": rejection,
                },
                "status_code": None,
                "headers": {},
                "final_url": None,
                "human_intervention": None,
                "execution_error": rejection,
                "runtime_lineage_probe_request_blocked": True,
            }
        if settings.USE_UNDETECTED_CHROME:
            return self._execute_test_case_uc(test_case_data, screenshot_dir)

        if not self.browser:
            self.start()
            
        start_time = time.time()
        oracle_hit = False
        oracle_message = None
        console_messages = []
        page_errors = []
        network_responses = []
        request_failures = []
        execution_error = None
        human_intervention = None
        cross_identity_results = []
        runtime_coverage_collector = None
        runtime_coverage_report = None
        dom_differential_collector = None
        dom_differential_report = None
        runtime_lineage_report = None
        cdp_session = None
        runtime_lineage_probe_request_blocked = False
        runtime_lineage_probe_request_count = 0
        runtime_lineage_probe_main_navigations = 0
        scope_navigation_blocked = False
        authentication_navigation_active = False
        
        # Ordinary cases rotate their network identity. Controlled A/A/B arms
        # reuse one validated envelope so the B stimulus is the only variable.
        rotated_proxy = None
        if lineage_envelope is not None:
            proxy_opt = lineage_envelope["proxy"]
            request_headers = lineage_envelope["headers"]
            requested_user_agent = lineage_envelope["user_agent"]
        else:
            rotated_proxy = get_next_proxy()
            proxy_opt = self._resolve_proxy_server(rotated_proxy)
            request_headers, requested_user_agent = self._prepare_browser_headers(
                test_case_data
            )

        # Fresh isolated context. Service workers are blocked for controlled arms
        # so prior registration or page-controlled worker state cannot add hidden
        # requests; failure to enforce any network guard invalidates the arm.
        context = self.browser.new_context(
            user_agent=requested_user_agent or get_next_user_agent(),
            viewport={"width": SeleniumConfig.VIEWPORT_WIDTH, "height": SeleniumConfig.VIEWPORT_HEIGHT},
            ignore_https_errors=settings.ALLOW_INSECURE_TLS,
            proxy=proxy_opt,
            extra_http_headers={},
            service_workers="block" if lineage_envelope is not None else "allow",
        )
        context.set_default_navigation_timeout(SeleniumConfig.NAVIGATION_TIMEOUT * 1000)
        context.set_default_timeout(SeleniumConfig.ACTION_TIMEOUT * 1000)
        
        def route_interceptor(route):
            nonlocal runtime_lineage_probe_request_blocked
            nonlocal runtime_lineage_probe_request_count
            nonlocal runtime_lineage_probe_main_navigations
            nonlocal scope_navigation_blocked
            try:
                request = route.request
                if lineage_envelope is not None:
                    runtime_lineage_probe_request_count += 1
                    is_navigation = bool(request.is_navigation_request())
                    belongs_to_primary_page = False
                    is_main_frame = False
                    try:
                        belongs_to_primary_page = request.frame.page == page
                        is_main_frame = (
                            belongs_to_primary_page
                            and request.frame == page.main_frame
                        )
                    except Exception:
                        belongs_to_primary_page = False
                    allowed = (
                        runtime_lineage_probe_request_count <= 256
                        and self._controlled_probe_request_allowed(
                        str(test_case_data.get("url") or ""),
                        request.url,
                        request.method,
                        resource_type=request.resource_type,
                        is_navigation=is_navigation,
                        belongs_to_primary_page=belongs_to_primary_page,
                        is_main_frame=is_main_frame,
                        )
                    )
                    if allowed and is_navigation and is_main_frame:
                        runtime_lineage_probe_main_navigations += 1
                        allowed = runtime_lineage_probe_main_navigations == 1
                    if not allowed:
                        runtime_lineage_probe_request_blocked = True
                        return route.abort()
                else:
                    try:
                        is_top_level_navigation = (
                            bool(request.is_navigation_request())
                            and request.frame == request.frame.page.main_frame
                        )
                    except Exception:
                        is_top_level_navigation = False
                    if (
                        is_top_level_navigation
                        and not self._navigation_url_allowed(
                            test_case_data,
                            request.url,
                            allow_auth_origin=authentication_navigation_active,
                        )
                    ):
                        scope_navigation_blocked = True
                        return route.abort()
                res_type = route.request.resource_type
                if res_type in ('image', 'media', 'font'):
                    return route.abort()

                if settings.BYPASS_CSP:
                    response = route.fetch()
                    headers = response.headers
                    for k in list(headers.keys()):
                        if k.lower() in ('content-security-policy', 'content-security-policy-report-only', 'x-webkit-csp', 'x-content-security-policy'):
                            del headers[k]
                    return route.fulfill(response=response, headers=headers)
                return route.continue_()
            except Exception:
                if lineage_envelope is not None:
                    runtime_lineage_probe_request_blocked = True
                    try:
                        route.abort()
                    except Exception:
                        pass
                    return
                try:
                    request = route.request
                    if (
                        bool(request.is_navigation_request())
                        and request.frame == request.frame.page.main_frame
                    ):
                        scope_navigation_blocked = True
                        route.abort()
                        return
                except Exception:
                    pass
                try:
                    route.continue_()
                except Exception:
                    pass

        context.route("**/*", route_interceptor)
        if request_headers:
            from backend_api.services.auth_session_service import AuthSessionService

            auth_spec_for_headers = test_case_data.get("auth_spec") or {}
            AuthSessionService.bind_playwright_headers(
                context,
                test_case_data.get("target_base_url") or test_case_data.get("url", ""),
                request_headers,
                auth_spec_for_headers.get("allowed_auth_origins") or (),
            )
        
        # Inject the oracle script into every new page/iframe document
        oracle_script = get_oracle_script()
        probe_network_guard = ""
        if lineage_envelope is not None:
            # Disable active page networking and worker constructors before page
            # code runs. Any attempted use is recorded and makes the runner reject
            # the arm; inability to read the guard state also fails closed.
            probe_network_guard = """
                (() => {
                    let blocked = false;
                    const deny = () => {
                        blocked = true;
                        throw new TypeError('Controlled lineage probe blocked active networking');
                    };
                    for (const name of [
                        'WebSocket', 'WebSocketStream', 'EventSource', 'Worker',
                        'SharedWorker', 'WebTransport', 'RTCPeerConnection'
                    ]) {
                        try {
                            Object.defineProperty(window, name, {
                                value: deny,
                                configurable: false,
                                enumerable: false,
                                writable: false
                            });
                        } catch (_) {}
                    }
                    try {
                        Object.defineProperty(window, 'fetch', {
                            value: deny,
                            configurable: false,
                            enumerable: false,
                            writable: false
                        });
                    } catch (_) {}
                    try {
                        Object.defineProperty(window, 'XMLHttpRequest', {
                            value: deny,
                            configurable: false,
                            enumerable: false,
                            writable: false
                        });
                    } catch (_) {}
                    try {
                        Object.defineProperty(navigator, 'sendBeacon', {
                            value: () => { blocked = true; return false; },
                            configurable: false,
                            enumerable: false,
                            writable: false
                        });
                    } catch (_) {}
                    Object.defineProperty(window, '__XSS_PROBE_NETWORK_BLOCKED__', {
                        get: () => blocked,
                        configurable: false,
                        enumerable: false
                    });
                })();
            """
        init_payload = f"""
            window.__XSS_TOKEN__ = {json.dumps(test_case_data['token'])};
            window.__ORACLE_URL__ = {json.dumps(self.oracle_url)};
            window.__XSS_FAKE_MESSAGE_ORIGIN__ = {json.dumps(test_case_data.get('fake_message_origin'))};
            window.__XSS_LINEAGE_PROBE__ = {json.dumps(lineage_envelope is not None)};
            {probe_network_guard}
            {oracle_script}
        """
        context.add_init_script(init_payload)
        
        # Set up a new page inside context
        page = context.new_page()

        # Capture V8 executed ranges before navigation so inline, dynamically
        # imported, blob, and eval-created scripts can be correlated later.
        # The collector persists hashes and offsets only; source remains in memory.
        if self._runtime_coverage_requested(settings.CAPTURE_RUNTIME_COVERAGE):
            try:
                from analysis_engine.runtime_coverage import RuntimeCoverageCollector

                cdp_session = context.new_cdp_session(page)
                runtime_coverage_collector = RuntimeCoverageCollector(
                    lambda method, params=None: cdp_session.send(method, params or {}),
                    test_case_data.get("target_base_url") or test_case_data.get("url", ""),
                )
                cdp_session.on(
                    "Runtime.executionContextCreated",
                    runtime_coverage_collector.on_execution_context_created,
                )
                cdp_session.on(
                    "Debugger.scriptParsed",
                    runtime_coverage_collector.on_script_parsed,
                )
                if not runtime_coverage_collector.start():
                    runtime_coverage_collector = None
            except Exception as coverage_error:
                logger.debug("Runtime coverage initialization failed: %s", coverage_error)
                runtime_coverage_collector = None

        if self._runtime_coverage_requested(settings.CAPTURE_DOM_DIFFERENTIAL):
            try:
                from analysis_engine.dom_snapshot_analyzer import (
                    DOMSnapshotDifferentialCollector,
                )

                if cdp_session is None:
                    cdp_session = context.new_cdp_session(page)
                dom_differential_collector = DOMSnapshotDifferentialCollector(
                    lambda method, params=None: cdp_session.send(method, params or {}),
                    test_case_data.get("token", ""),
                )
            except Exception as snapshot_error:
                logger.debug("DOM snapshot differential initialization failed: %s", snapshot_error)
                dom_differential_collector = None
        
        # Event listeners for log capture and response header extraction
        response_status = None
        response_headers = {}
        response_url = None

        def safe_network_url(raw_url):
            try:
                from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

                split = urlsplit(str(raw_url))
                sensitive = {"token", "access_token", "refresh_token", "api_key", "apikey", "password", "session", "sid", "csrf"}
                query = [
                    (key, "[REDACTED]" if key.lower() in sensitive else value)
                    for key, value in parse_qsl(split.query, keep_blank_values=True)
                ]
                return urlunsplit((split.scheme, split.netloc, split.path, urlencode(query), split.fragment))
            except Exception:
                return str(raw_url)[:2048]

        def on_console(msg):
            nonlocal oracle_hit, oracle_message
            text = msg.text
            console_messages.append({
                'type': msg.type.upper(),
                'text': text
            })
            if 'XSS Oracle: Execution detected' in text and (test_case_data.get('token') in text or test_case_data.get('token') == 'test_token'):
                oracle_hit = True
                oracle_message = text
                
        def on_page_error(err):
            page_errors.append(err.message)

        def on_response(res):
            nonlocal response_status, response_headers, response_url
            try:
                if len(network_responses) < 200:
                    network_responses.append({
                        "url": safe_network_url(res.url),
                        "status": res.status,
                        "method": res.request.method,
                        "resource_type": res.request.resource_type,
                        "navigation": bool(res.request.is_navigation_request()),
                    })
                # Subframe navigations and same-URL subresources must not overwrite
                # the top-level document's security posture.
                if self._is_main_navigation_response(res, page):
                    response_status = res.status
                    response_url = res.url
                    response_headers = {
                        k.lower(): ("[REDACTED]" if k.lower() in {"set-cookie", "authorization", "proxy-authorization"} else v)
                        for k, v in res.headers.items()
                    }
            except Exception:
                pass

        def on_request_failed(req):
            if len(request_failures) >= 100:
                return
            try:
                request_failures.append({
                    "url": safe_network_url(req.url),
                    "method": req.method,
                    "resource_type": req.resource_type,
                    "failure": req.failure,
                })
            except Exception:
                pass
            
        page.on("console", on_console)
        page.on("pageerror", on_page_error)
        page.on("response", on_response)
        page.on("requestfailed", on_request_failed)
        
        url = test_case_data['url']
        method = test_case_data.get('method', 'GET').upper()
        cookies = test_case_data.get('cookies', {})
        params = test_case_data.get('params', {})
        body = test_case_data.get('body')
        json_data = test_case_data.get('json')
        
        # Attach query parameters (stripping empty dummy strings from both base URL and params to prevent WAF / HTTP 414 / 446 errors)
        if params or "?" in url:
            from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl
            url_parts = list(urlparse(url))
            raw_query = dict(parse_qsl(url_parts[4], keep_blank_values=True))
            active_pname = test_case_data.get("param_name")
            query = {k: v for k, v in raw_query.items() if v != "" or k == active_pname}
            for k, v in (params or {}).items():
                if v != "" or k == active_pname:
                    query[k] = v
            url_parts[4] = urlencode(query)
            url = urlunparse(url_parts)
            
        try:
            # Set cookies directly on the context
            if cookies:
                from urllib.parse import urlparse
                domain = urlparse(url).hostname
                playwright_cookies = []
                for name, val in cookies.items():
                    playwright_cookies.append({
                        'name': name,
                        'value': val,
                        'domain': domain,
                        'path': '/'
                    })
                context.add_cookies(playwright_cookies)

            auth_spec = test_case_data.get("auth_spec")
            if auth_spec:
                from backend_api.services.auth_session_service import AuthSessionService

                authentication_navigation_active = True
                try:
                    AuthSessionService.authenticate_playwright(
                        page,
                        context,
                        test_case_data.get("target_base_url") or url,
                        auth_spec,
                    )
                finally:
                    authentication_navigation_active = False
                
            # Perform navigation or custom sequence steps execution
            steps = test_case_data.get('steps')
            if steps:
                self._execute_custom_steps(page, steps, test_case_data.get('payload', ''))
            else:
                self._navigate_with_method(
                    page=page,
                    url=url,
                    method=method,
                    headers=request_headers,
                    body=body,
                    json_data=json_data,
                )
                if auth_spec:
                    from copy import deepcopy
                    from backend_api.services.auth_session_service import AuthSessionService

                    if AuthSessionService.is_auth_wall(
                        status_code=response_status,
                        final_url=page.url,
                        body_text=page.content(),
                        login_url_patterns=auth_spec.get("login_url_patterns") or (),
                    ):
                        if not auth_spec.get("login"):
                            from backend_api.services.auth_session_service import HumanInterventionRequired

                            raise HumanInterventionRequired(
                                "Static authenticated session expired and no automated login flow is configured",
                                url=page.url,
                                identity=auth_spec.get("label"),
                            )
                        forced_spec = deepcopy(auth_spec)
                        forced_spec.setdefault("login", {})["force"] = True
                        authentication_navigation_active = True
                        try:
                            AuthSessionService.authenticate_playwright(
                                page,
                                context,
                                test_case_data.get("target_base_url") or url,
                                forced_spec,
                            )
                        finally:
                            authentication_navigation_active = False
                        self._navigate_with_method(
                            page=page,
                            url=url,
                            method=method,
                            headers=request_headers,
                            body=body,
                            json_data=json_data,
                        )
                    barrier = AuthSessionService.operational_barrier_reason(
                        response_status, page.content()
                    )
                    if barrier:
                        from backend_api.services.auth_session_service import HumanInterventionRequired

                        raise HumanInterventionRequired(
                            barrier,
                            url=page.url,
                            identity=auth_spec.get("label"),
                        )
                
            # If a stored_view_url is specified (Stored XSS path), execute secondary navigation step
            stored_view_url = test_case_data.get('stored_view_url')
            if stored_view_url:
                time.sleep(0.5)  # Let server-side persistence write finish
                page.goto(stored_view_url)
                observer_specs = test_case_data.get("stored_revisit_auth_specs") or []
                if observer_specs:
                    cross_identity_results = self._execute_cross_identity_revisits(
                        stored_view_url,
                        test_case_data.get("target_base_url") or url,
                        test_case_data["token"],
                        observer_specs,
                        test_case_data.get("target_scope_tags"),
                    )
                    hit = next((item for item in cross_identity_results if item.get("oracle_hit")), None)
                    if hit:
                        oracle_hit = True
                        oracle_message = f"XSS Oracle: Execution detected in identity {hit.get('identity')}"
                    blocked = next((item for item in cross_identity_results if item.get("human_intervention")), None)
                    if blocked and not human_intervention:
                        human_intervention = blocked["human_intervention"]

            if runtime_coverage_collector is not None:
                runtime_coverage_collector.snapshot("bootstrap")
            if dom_differential_collector is not None:
                dom_differential_collector.capture("bootstrap")

            # Trigger interactive event handlers (Unique technique: Automated DOM Event Fuzzing + postMessage Auditing)
            try:
                interaction_script = """
                    (payload) => {
                        try {
                            var token = window.__XSS_TOKEN__;
                            if (!token) return;
                            payload = payload || token;
                            
                            // 1. Dispatch standard user events to force HTML attribute event handlers (Shadow-DOM-Aware)
                            function findElementsRecursively(root) {
                                var elements = [];
                                try {
                                    var all = root.querySelectorAll('*');
                                    for (var i = 0; i < all.length; i++) {
                                        var el = all[i];
                                        elements.push(el);
                                        if (el.shadowRoot) {
                                            elements = elements.concat(findElementsRecursively(el.shadowRoot));
                                        }
                                    }
                                } catch (err) {}
                                return elements;
                            }
                            
                            // Dismiss consent banners if blocking interactions
                            try {
                                var consentSelectors = [
                                    '#uc-btn-accept-banner',
                                    '#onetrust-accept-btn-handler',
                                    '#didomi-notice-agree-button',
                                    '#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll',
                                    'button[data-testid="uc-accept-all-button"]'
                                ];
                                for (var c = 0; c < consentSelectors.length; c++) {
                                    var cBtn = document.querySelector(consentSelectors[c]);
                                    if (cBtn) { cBtn.click(); break; }
                                }
                            } catch (cErr) {}

                            var elements = findElementsRecursively(document);
                            for (var i = 0; i < elements.length; i++) {
                                var el = elements[i];
                                if (!el.attributes) continue;
                                for (var j = 0; j < el.attributes.length; j++) {
                                    var attr = el.attributes[j];
                                    if (attr.value && (attr.value.indexOf(token) !== -1 || (attr.name === 'href' && attr.value.toLowerCase().indexOf('javascript:') === 0))) {
                                        // If element is an anchor or button, invoke native .click() first
                                        // Native click triggers navigation on javascript: URIs
                                        try {
                                            if (typeof el.click === 'function') {
                                                el.click();
                                            }
                                        } catch (clickErr) {}

                                        var events = ['click', 'mouseover', 'focus', 'input', 'change'];
                                        for (var k = 0; k < events.length; k++) {
                                            try {
                                                var event = new Event(events[k], { bubbles: true, cancelable: true });
                                                el.dispatchEvent(event);
                                            } catch (e) {}
                                        }
                                        if (attr.name.indexOf('on') === 0) {
                                            var handler = attr.name.substring(2);
                                            try {
                                                var event = new Event(handler, { bubbles: true, cancelable: true });
                                                el.dispatchEvent(event);
                                            } catch (e) {}
                                        }
                                    }
                                }
                            }

                            // 2. Dispatch cross-origin and intra-frame messages to force registered postMessage listeners
                            try {
                                var msgPayloads = [
                                    payload,
                                    JSON.stringify({ type: 'xss', html: payload, content: payload, data: payload, payload: payload, message: payload }),
                                    { type: 'xss', html: payload, content: payload, data: payload, payload: payload, message: payload }
                                ];
                                for (var m = 0; m < msgPayloads.length; m++) {
                                    window.postMessage(msgPayloads[m], '*');
                                }
                            } catch (msgErr) {}
                        } catch (err) {}
                    }
                """
                if self._active_browser_interactions_allowed(test_case_data):
                    page.evaluate(interaction_script, test_case_data.get("payload") or "")
                    self._click_token_javascript_links_playwright(
                        page, test_case_data["token"]
                    )
            except Exception as trigger_err:
                logger.warning(f"Failed to execute automated DOM interactions: {trigger_err}")

            # Wait for potential callbacks
            time.sleep(SeleniumConfig.ORACLE_WAIT_TIMEOUT)

            # Dynamic timing extension: if token is present in DOM but oracle has not hit, wait longer
            if not oracle_hit:
                try:
                    if test_case_data['token'] in page.content():
                        logger.info(f"Token {test_case_data['token'][:8]} reflected in page source. Extending timeout by 3.0 seconds...")
                        time.sleep(3.0)
                except Exception:
                    pass

            if runtime_coverage_collector is not None:
                runtime_coverage_collector.snapshot("interaction")
            if dom_differential_collector is not None:
                dom_differential_collector.capture("interaction")
            
            # Map page console warnings and errors
            for entry in console_messages:
                msg_text = entry.get('text', '')
                msg_text_lower = msg_text.lower()
                if entry.get('type') == 'ERROR' or any(kw in msg_text_lower for kw in ['error', 'exception', 'syntax', 'unexpected', 'invalid', 'csp', 'violation', 'blocked', 'refused', 'unpermitted']):
                    page_errors.append(msg_text)
                    
        except Exception as e:
            from backend_api.services.auth_session_service import AuthConfigurationError, HumanInterventionRequired
            from backend_api.utils.stealth import mark_proxy_failed, mark_proxy_success

            err_str = str(e).lower()
            if any(k in err_str for k in ("proxy", "net::err_proxy", "net::err_tunnel", "net::err_connection_timed_out", "err_connection_refused")):
                mark_proxy_failed(rotated_proxy)
            elif not any(k in str(page_errors).lower() for k in ("net::err_proxy", "net::err_tunnel")):
                mark_proxy_success(rotated_proxy)

            if isinstance(e, HumanInterventionRequired):
                human_intervention = {
                    "kind": "authentication_challenge",
                    "reason": e.reason,
                    "identity": e.identity,
                    "url": e.url,
                }
            elif isinstance(e, AuthConfigurationError):
                human_intervention = {
                    "kind": "authentication_configuration",
                    "reason": str(e),
                    "identity": (test_case_data.get("auth_spec") or {}).get("label"),
                    "url": None,
                }
            execution_error = {
                "type": e.__class__.__name__,
                "message": str(e),
            }
            logger.error(f"Error during page execution: {e}", exc_info=True)

        if scope_navigation_blocked:
            execution_error = {
                "type": "OutOfScopeNavigationBlocked",
                "message": "A top-level browser navigation left the configured target scope",
            }

        if lineage_envelope is not None:
            try:
                runtime_lineage_probe_request_blocked = bool(
                    runtime_lineage_probe_request_blocked
                    or page.evaluate(
                        "() => window.__XSS_PROBE_NETWORK_BLOCKED__ === true"
                    )
                )
            except Exception:
                runtime_lineage_probe_request_blocked = True

        lineage_mode = getattr(settings, "CAPTURE_RUNTIME_LINEAGE", "all")
        if self._runtime_coverage_requested(lineage_mode):
            try:
                collected_report = self._collect_runtime_lineage_playwright(
                    page, test_case_data
                )
                if (
                    collected_report is not None
                    and self._capture_enabled(lineage_mode, oracle_hit)
                ):
                    runtime_lineage_report = collected_report
            except Exception as lineage_error:
                logger.debug("Runtime causal lineage finalization failed: %s", lineage_error)

        if runtime_coverage_collector is not None:
            try:
                if not runtime_coverage_collector.report().get("phases"):
                    runtime_coverage_collector.snapshot("early_exit")
                collected_report = runtime_coverage_collector.finish()
                if self._capture_enabled(settings.CAPTURE_RUNTIME_COVERAGE, oracle_hit):
                    runtime_coverage_report = collected_report
            except Exception as coverage_error:
                logger.debug("Runtime coverage finalization failed: %s", coverage_error)
        if dom_differential_collector is not None:
            try:
                if not dom_differential_collector.report().get("phases"):
                    dom_differential_collector.capture("early_exit")
                collected_report = dom_differential_collector.report()
                if self._capture_enabled(settings.CAPTURE_DOM_DIFFERENTIAL, oracle_hit):
                    dom_differential_report = collected_report
            except Exception as snapshot_error:
                logger.debug("DOM snapshot differential finalization failed: %s", snapshot_error)
            
        duration_ms = int((time.time() - start_time) * 1000)
        
        # Save live browser vision preview frame for real-time monitoring
        if not test_case_data.get("suppress_artifacts"):
            try:
                self._save_live_preview(page, test_case_data, oracle_hit)
            except Exception:
                pass

        # Capture screenshot
        screenshot_path = None
        if (
            not test_case_data.get("suppress_artifacts")
            and screenshot_dir
            and self._capture_enabled(settings.CAPTURE_SCREENSHOTS, oracle_hit)
        ):
            screenshot_dir.mkdir(parents=True, exist_ok=True)
            screenshot_path = screenshot_dir / f"test_case_{test_case_data.get('test_case_id', 'unknown')}.png"
            try:
                page.screenshot(path=str(screenshot_path))
            except Exception as e:
                logger.error(f"Error capturing screenshot: {e}")
                
        # Capture DOM snapshot
        dom_snapshot = None
        if (
            not test_case_data.get("suppress_artifacts")
            and self._capture_enabled(settings.CAPTURE_DOM_SNAPSHOT, oracle_hit)
        ):
            try:
                dom_snapshot = page.content()
            except Exception as e:
                logger.error(f"Error capturing DOM snapshot: {e}")
                
        # Capture client-side technology stack (Tech Stack & Gadget Profiling)
        tech_stack = {}
        try:
            detect_tech_script = """
                (function() {
                    var libs = {};
                    if (window.angular) libs['angular'] = window.angular.version ? window.angular.version.full : '1.x';
                    if (window.jQuery) libs['jquery'] = window.jQuery.fn.jquery;
                    if (window.$ && window.$.fn && window.$.fn.jquery) libs['jquery_alt'] = window.$.fn.jquery;
                    if (window.React || document.querySelector('[data-reactroot]')) libs['react'] = 'detected';
                    if (window.Vue) libs['vue'] = 'detected';
                    if (window.bootstrap) libs['bootstrap'] = 'detected';
                    else if (window.jQuery && window.jQuery.fn && window.jQuery.fn.tooltip && window.jQuery.fn.tooltip.Constructor) {
                        libs['bootstrap'] = window.jQuery.fn.tooltip.Constructor.VERSION || 'detected';
                    }
                    if (window.Alpine) libs['alpine'] = 'detected';
                    if (window.htmx) libs['htmx'] = window.htmx.version || 'detected';
                    return libs;
                })();
            """
            tech_stack = page.evaluate(detect_tech_script) or {}
        except Exception as tech_err:
            logger.warning(f"Failed to profile client-side tech stack: {tech_err}")

        # Clean close context
        final_url = None
        try:
            final_url = page.url
        except Exception:
            final_url = None

        cookie_metadata = []
        try:
            cookie_metadata = self._cookie_attribute_metadata(context.cookies())
        except Exception:
            cookie_metadata = []

        try:
            context.close()
        except Exception:
            pass

        metadata_observed = response_status is not None
        try:
            response_posture = self._build_response_posture(
                url=response_url or final_url or test_case_data.get('url', ''),
                status_code=response_status,
                headers=response_headers,
                cookie_metadata=cookie_metadata,
                metadata_observed=metadata_observed,
                request_has_credentials=bool(
                    cookies
                    or any(str(key).lower() == "authorization" for key in request_headers)
                ),
                source="main_navigation" if metadata_observed else "playwright_metadata_unavailable",
            )
        except Exception as posture_error:
            logger.debug("Response posture analysis failed: %s", posture_error)
            response_posture = None

        logs = {
            'console': console_messages[:50],
            'errors': list(set(page_errors))[:20],
            'network_responses': network_responses,
            'request_failures': request_failures,
            'status_code': response_status,
            'headers': response_headers,
            'final_url': safe_network_url(final_url) if final_url else None,
            'tech_stack': tech_stack,
            'cross_identity_revisits': cross_identity_results,
        }
        if response_posture is not None:
            logs['response_posture'] = response_posture
        if runtime_coverage_report is not None:
            logs['runtime_code_coverage'] = runtime_coverage_report
        if dom_differential_report is not None:
            logs['dom_marker_differential'] = dom_differential_report
        if runtime_lineage_report is not None:
            logs['runtime_lineage'] = runtime_lineage_report
        if execution_error:
            logs['execution_error'] = execution_error
        
        return {
            'oracle_hit': oracle_hit,
            'oracle_message': oracle_message,
            'duration_ms': duration_ms,
            'screenshot_path': str(screenshot_path) if screenshot_path else None,
            'dom_snapshot': dom_snapshot[:settings.DOM_SNAPSHOT_MAX_CHARS] if dom_snapshot else None,
            'logs': logs,
            'status_code': response_status,
            'headers': response_headers,
            'final_url': final_url,
            'human_intervention': human_intervention,
            'execution_error': execution_error,
            'runtime_lineage_probe_request_blocked': (
                runtime_lineage_probe_request_blocked
            ),
        }

    def _execute_custom_steps(self, page, steps: List[Dict[str, Any]], payload: str):
        """Execute custom multi-step actions in Playwright before checking for sink hits."""
        for i, step in enumerate(steps):
            action = step.get('action', '').lower()
            try:
                if action == 'navigate':
                    url = step.get('url', '')
                    if '{{PAYLOAD}}' in url:
                        url = url.replace('{{PAYLOAD}}', payload)
                    page.goto(url)
                elif action == 'click':
                    selector = step.get('selector', '')
                    page.click(selector)
                elif action == 'fill':
                    selector = step.get('selector', '')
                    value = step.get('value', '')
                    if '{{PAYLOAD}}' in value:
                        value = value.replace('{{PAYLOAD}}', payload)
                    page.fill(selector, value)
                elif action == 'check':
                    page.check(step.get('selector', ''))
                elif action == 'select':
                    selector = step.get('selector', '')
                    locator = page.locator(selector)
                    options = locator.locator('option:not([disabled])')
                    index = 1 if options.count() > 1 else 0
                    locator.select_option(index=index)
                elif action == 'press':
                    selector = step.get('selector', '')
                    key = step.get('key', 'Enter')
                    if selector:
                        page.press(selector, key)
                    else:
                        page.press('body', key)
                elif action == 'hover':
                    selector = step.get('selector', '')
                    page.hover(selector)
                elif action == 'wait':
                    seconds = float(step.get('seconds', 1.0))
                    time.sleep(seconds)
            except Exception as step_err:
                logger.warning(f"Error executing custom step {i} ({action}): {step_err}")

    def _execute_cross_identity_revisits(
        self,
        stored_view_url: str,
        target_base_url: str,
        token: str,
        auth_specs: List[Dict[str, Any]],
        target_scope_tags: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Open a stored render location in isolated observer identities."""
        from backend_api.services.auth_session_service import (
            AuthSessionService,
            HumanInterventionRequired,
        )

        results = []
        oracle_script = get_oracle_script()
        for auth_spec in auth_specs[:8]:
            identity = str(auth_spec.get("label") or auth_spec.get("role") or "observer")
            headers, _ = self._prepare_browser_headers({"headers": auth_spec.get("headers") or {}})
            observer_context = self.browser.new_context(
                user_agent=get_next_user_agent(),
                viewport={"width": SeleniumConfig.VIEWPORT_WIDTH, "height": SeleniumConfig.VIEWPORT_HEIGHT},
                ignore_https_errors=settings.ALLOW_INSECURE_TLS,
                extra_http_headers={},
            )
            observed = {"identity": identity, "oracle_hit": False, "final_url": None}
            observer_case = {
                "url": stored_view_url,
                "target_base_url": target_base_url,
                "target_scope_tags": target_scope_tags,
                "auth_spec": auth_spec,
            }
            auth_navigation_active = True

            def observer_scope_guard(route, row=observed):
                try:
                    request = route.request
                    top_level = (
                        bool(request.is_navigation_request())
                        and request.frame == request.frame.page.main_frame
                    )
                    if top_level and not self._navigation_url_allowed(
                        observer_case,
                        request.url,
                        allow_auth_origin=auth_navigation_active,
                    ):
                        row["scope_navigation_blocked"] = True
                        return route.abort()
                    fallback = getattr(route, "fallback", None)
                    return fallback() if callable(fallback) else route.continue_()
                except Exception:
                    row["scope_navigation_blocked"] = True
                    try:
                        return route.abort()
                    except Exception:
                        return None

            if hasattr(observer_context, "route"):
                observer_context.route("**/*", observer_scope_guard)
            AuthSessionService.bind_playwright_headers(
                observer_context,
                target_base_url,
                headers,
                auth_spec.get("allowed_auth_origins") or (),
            )
            observer_context.set_default_navigation_timeout(SeleniumConfig.NAVIGATION_TIMEOUT * 1000)
            observer_context.set_default_timeout(SeleniumConfig.ACTION_TIMEOUT * 1000)
            observer_context.add_init_script(f"""
                window.__XSS_TOKEN__ = {json.dumps(token)};
                window.__ORACLE_URL__ = {json.dumps(self.oracle_url)};
                {oracle_script}
            """)
            observer_page = observer_context.new_page()

            def on_console(message, row=observed):
                text = message.text
                if "XSS Oracle: Execution detected" in text and token in text:
                    row["oracle_hit"] = True

            observer_page.on("console", on_console)
            try:
                try:
                    AuthSessionService.authenticate_playwright(
                        observer_page, observer_context, target_base_url, auth_spec
                    )
                finally:
                    auth_navigation_active = False
                observer_page.goto(stored_view_url)
                observer_page.evaluate("""(token) => {
                    for (const element of document.querySelectorAll('*')) {
                        if ((element.outerHTML || '').includes(token)) {
                            for (const type of ['click', 'mouseover', 'focus', 'input', 'change']) {
                                try { element.dispatchEvent(new Event(type, {bubbles: true, cancelable: true})); } catch (_) {}
                            }
                        }
                    }
                }""", token)
                observer_page.wait_for_timeout(int(SeleniumConfig.ORACLE_WAIT_TIMEOUT * 1000))
                observed["final_url"] = observer_page.url
            except HumanInterventionRequired as error:
                observed["human_intervention"] = {
                    "kind": "authentication_challenge",
                    "reason": error.reason,
                    "identity": error.identity or identity,
                    "url": error.url,
                }
            except Exception as error:
                observed["error"] = str(error)[:500]
            finally:
                observer_context.close()
            results.append(observed)
        return results

    def execute_poc_html(
        self,
        poc_html: str,
        token: str,
        test_case_id: Any = "unknown",
        target_url: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        screenshot_dir: Optional[Path] = None,
        serve_http: bool = True,
        fake_message_origin: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute a standalone PoC HTML page with oracle instrumentation.

        This is useful for postMessage parent/iframe delivery pages and other
        browser-only client-side probes that are not ordinary HTTP requests.
        """
        if settings.USE_UNDETECTED_CHROME:
            return self._execute_poc_html_uc(
                poc_html, token, test_case_id, target_url, cookies, screenshot_dir, serve_http, fake_message_origin
            )

        if not self.browser:
            self.start()

        start_time = time.time()
        oracle_hit = False
        oracle_message = None
        console_messages = []
        page_errors = []
        human_intervention = None

        # Rotating proxy, User-Agent, and WAF bypass headers
        rotated_proxy = get_next_proxy()
        proxy_opt = self._resolve_proxy_server(rotated_proxy)

        context = self.browser.new_context(
            user_agent=get_next_user_agent(),
            viewport={"width": SeleniumConfig.VIEWPORT_WIDTH, "height": SeleniumConfig.VIEWPORT_HEIGHT},
            ignore_https_errors=settings.ALLOW_INSECURE_TLS,
            proxy=proxy_opt,
            extra_http_headers=get_random_waf_bypass_headers()
        )
        context.set_default_navigation_timeout(SeleniumConfig.NAVIGATION_TIMEOUT * 1000)
        context.set_default_timeout(SeleniumConfig.ACTION_TIMEOUT * 1000)

        def route_interceptor_async(route):
            try:
                res_type = route.request.resource_type
                if res_type in ('image', 'media', 'font'):
                    return route.abort()

                if settings.BYPASS_CSP:
                    response = route.fetch()
                    headers = response.headers
                    for k in list(headers.keys()):
                        if k.lower() in ('content-security-policy', 'content-security-policy-report-only', 'x-webkit-csp', 'x-content-security-policy'):
                            del headers[k]
                    return route.fulfill(response=response, headers=headers)
                return route.continue_()
            except Exception:
                try:
                    route.continue_()
                except Exception:
                    pass

        context.route("**/*", route_interceptor_async)

        # Inject oracle
        oracle_script = get_oracle_script()
        init_payload = f"""
            window.__XSS_TOKEN__ = {json.dumps(token)};
            window.__ORACLE_URL__ = {json.dumps(self.oracle_url)};
            window.__XSS_FAKE_MESSAGE_ORIGIN__ = {json.dumps(fake_message_origin)};
            {oracle_script}
        """
        context.add_init_script(init_payload)

        # Set up a new page inside context
        page = context.new_page()

        # Event handlers
        def on_console(msg):
            nonlocal oracle_hit, oracle_message
            text = msg.text
            console_messages.append({
                'type': msg.type.upper(),
                'text': text
            })
            if 'XSS Oracle: Execution detected' in text and (token in text or token == 'test_token'):
                oracle_hit = True
                oracle_message = text

        def on_page_error(err):
            page_errors.append(err.message)

        page.on("console", on_console)
        page.on("pageerror", on_page_error)

        try:
            if target_url:
                from urllib.parse import urlparse
                parsed_url = urlparse(target_url)
                domain = parsed_url.hostname
                playwright_cookies = []
                for name, val in (cookies or {}).items():
                    playwright_cookies.append({
                        'name': name,
                        'value': val,
                        'domain': domain,
                        'path': '/'
                    })
                context.add_cookies(playwright_cookies)

            if serve_http:
                from browser_workers.poc_server import LocalPoCServer
                server = LocalPoCServer(poc_html)
                poc_url = server.start()
                try:
                    page.goto(poc_url)
                    time.sleep(SeleniumConfig.ORACLE_WAIT_TIMEOUT)
                finally:
                    server.stop()
            else:
                data_url = "data:text/html;charset=utf-8," + quote(poc_html)
                page.goto(data_url)
                time.sleep(SeleniumConfig.ORACLE_WAIT_TIMEOUT)

            # Map page console warnings and errors
            for entry in console_messages:
                msg_text = entry.get('text', '')
                msg_text_lower = msg_text.lower()
                if entry.get('type') == 'ERROR' or any(kw in msg_text_lower for kw in ['error', 'exception', 'syntax', 'unexpected', 'invalid', 'csp', 'violation', 'blocked', 'refused', 'unpermitted']):
                    page_errors.append(msg_text)

        except Exception as e:
            logger.error(f"Error during PoC navigation: {e}", exc_info=True)

        duration_ms = int((time.time() - start_time) * 1000)

        # Capture screenshot
        screenshot_path = None
        if screenshot_dir and self._capture_enabled(settings.CAPTURE_SCREENSHOTS, oracle_hit):
            screenshot_dir.mkdir(parents=True, exist_ok=True)
            screenshot_path = screenshot_dir / f"modern_probe_{test_case_id}.png"
            try:
                page.screenshot(path=str(screenshot_path))
            except Exception as e:
                logger.error(f"Error capturing screenshot: {e}")

        # Capture DOM snapshot
        dom_snapshot = None
        if self._capture_enabled(settings.CAPTURE_DOM_SNAPSHOT, oracle_hit):
            try:
                dom_snapshot = page.content()
            except Exception as e:
                logger.error(f"Error capturing DOM snapshot: {e}")

        try:
            context.close()
        except Exception:
            pass

        return {
            'oracle_hit': oracle_hit,
            'oracle_message': oracle_message,
            'duration_ms': duration_ms,
            'screenshot_path': str(screenshot_path) if screenshot_path else None,
            'dom_snapshot': dom_snapshot[:settings.DOM_SNAPSHOT_MAX_CHARS] if dom_snapshot else None,
            'logs': {
                'console': console_messages[:50],
                'errors': list(set(page_errors))[:20],
            },
            'status_code': 200,
        }
    
    def _execute_test_case_uc(
        self,
        test_case_data: Dict[str, Any],
        screenshot_dir: Optional[Path] = None
    ) -> Dict[str, Any]:
        """Execute a test case using Undetected Chromedriver."""
        if not self.uc_driver:
            self.start()
            
        start_time = time.time()
        oracle_hit = False
        oracle_message = None
        console_messages = []
        page_errors = []
        human_intervention = None
        cross_identity_results = []
        execution_error = None
        runtime_coverage_collector = None
        runtime_coverage_report = None
        dom_differential_collector = None
        dom_differential_report = None
        runtime_lineage_report = None
        request_headers, requested_user_agent = self._prepare_browser_headers(test_case_data)
        credential_header_names = {
            "authorization", "proxy-authorization", "x-api-key", "x-auth-token"
        }
        auth_spec = test_case_data.get("auth_spec") or {}
        if auth_spec.get("headers") or any(
            str(name).lower() in credential_header_names for name in request_headers
        ):
            return {
                "oracle_hit": False,
                "oracle_message": None,
                "duration_ms": 0,
                "screenshot_path": None,
                "dom_snapshot": None,
                "logs": {"console": [], "errors": []},
                "status_code": None,
                "human_intervention": {
                    "kind": "authentication_configuration",
                    "reason": (
                        "Undetected Chrome cannot origin-bind raw authentication headers; "
                        "use the Playwright backend for this authenticated target"
                    ),
                    "identity": auth_spec.get("label"),
                    "url": test_case_data.get("url"),
                },
            }
        
        # Inject oracle script on new document evaluation using CDP
        oracle_script = get_oracle_script()
        init_payload = f"""
            window.__XSS_TOKEN__ = {json.dumps(test_case_data['token'])};
            window.__ORACLE_URL__ = {json.dumps(self.oracle_url)};
            window.__XSS_FAKE_MESSAGE_ORIGIN__ = {json.dumps(test_case_data.get('fake_message_origin'))};
            {oracle_script}
        """
        try:
            self.uc_driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {'source': init_payload})
        except Exception as cdp_err:
            logger.warning(f"Failed to register CDP injection: {cdp_err}")

        try:
            self.uc_driver.execute_cdp_cmd('Network.enable', {})
            self.uc_driver.execute_cdp_cmd('Network.setExtraHTTPHeaders', {'headers': request_headers})
            if requested_user_agent:
                self.uc_driver.execute_cdp_cmd(
                    'Network.setUserAgentOverride',
                    {'userAgent': requested_user_agent},
                )
        except Exception as cdp_err:
            logger.warning(f"Failed to apply authenticated request headers: {cdp_err}")

        # Set up console log monitoring hook (We can poll browser log levels)
        url = test_case_data['url']
        method = test_case_data.get('method', 'GET').upper()
        cookies = test_case_data.get('cookies', {})
        params = test_case_data.get('params', {})
        body = test_case_data.get('body')
        json_data = test_case_data.get('json')

        # Attach query parameters (stripping empty dummy strings from both base URL and params to prevent WAF / HTTP 414 / 446 errors)
        if params or "?" in url:
            from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl
            url_parts = list(urlparse(url))
            raw_query = dict(parse_qsl(url_parts[4], keep_blank_values=True))
            active_pname = test_case_data.get("param_name")
            query = {k: v for k, v in raw_query.items() if v != "" or k == active_pname}
            for k, v in (params or {}).items():
                if v != "" or k == active_pname:
                    query[k] = v
            url_parts[4] = urlencode(query)
            url = urlunparse(url_parts)

        if self._runtime_coverage_requested(settings.CAPTURE_RUNTIME_COVERAGE):
            try:
                from analysis_engine.runtime_coverage import RuntimeCoverageCollector

                runtime_coverage_collector = RuntimeCoverageCollector(
                    lambda cdp_method, cdp_params=None: self.uc_driver.execute_cdp_cmd(
                        cdp_method, cdp_params or {}
                    ),
                    test_case_data.get("target_base_url") or url,
                )
                if not runtime_coverage_collector.start():
                    runtime_coverage_collector = None
            except Exception as coverage_error:
                logger.debug("UC runtime coverage initialization failed: %s", coverage_error)
                runtime_coverage_collector = None

        if self._runtime_coverage_requested(settings.CAPTURE_DOM_DIFFERENTIAL):
            try:
                from analysis_engine.dom_snapshot_analyzer import (
                    DOMSnapshotDifferentialCollector,
                )

                dom_differential_collector = DOMSnapshotDifferentialCollector(
                    lambda cdp_method, cdp_params=None: self.uc_driver.execute_cdp_cmd(
                        cdp_method, cdp_params or {}
                    ),
                    test_case_data.get("token", ""),
                )
            except Exception as snapshot_error:
                logger.debug("UC DOM snapshot differential initialization failed: %s", snapshot_error)
                dom_differential_collector = None

        try:
            auth_spec = test_case_data.get("auth_spec")
            if auth_spec:
                from backend_api.services.auth_session_service import AuthSessionService

                AuthSessionService.authenticate_selenium(
                    self.uc_driver,
                    test_case_data.get("target_base_url") or url,
                    auth_spec,
                )

            # Undetected Chromedriver cookies require domain navigation first
            if cookies:
                self.uc_driver.get(self._origin_for_url(url))
                for name, val in cookies.items():
                    try:
                        self.uc_driver.add_cookie({'name': name, 'value': val})
                    except Exception:
                        pass

            steps = test_case_data.get('steps')
            if steps:
                self._execute_custom_steps_uc(self.uc_driver, steps, test_case_data.get('payload', ''))
            elif method == 'GET':
                self.uc_driver.get(url)
            elif method == 'POST':
                self.uc_driver.get(self._origin_for_url(url))
                if json_data:
                    post_script = f"""
                        var xhr = new XMLHttpRequest();
                        xhr.open('POST', {json.dumps(url)}, false);
                        xhr.setRequestHeader('Content-Type', 'application/json');
                        xhr.send(JSON.stringify({json.dumps(json_data)}));
                        document.open();
                        document.write(xhr.responseText);
                        document.close();
                    """
                    self.uc_driver.execute_script(post_script)
                elif body:
                    form_html = f"""
                        var form = document.createElement('form');
                        form.id = 'xss_post_form';
                        form.method = 'POST';
                        form.action = {json.dumps(url)};
                        var payload_data = {json.dumps(body)};
                        for (var key in payload_data) {{
                            if (payload_data.hasOwnProperty(key)) {{
                                var input = document.createElement('input');
                                input.type = 'hidden';
                                input.name = key;
                                input.value = payload_data[key];
                                form.appendChild(input);
                            }}
                        }}
                        document.body.appendChild(form);
                        form.submit();
                    """
                    self.uc_driver.execute_script(form_html)
                    time.sleep(1.0)
                else:
                    post_script = f"""
                        var xhr = new XMLHttpRequest();
                        xhr.open('POST', {json.dumps(url)}, false);
                        xhr.send();
                        document.open();
                        document.write(xhr.responseText);
                        document.close();
                    """
                    self.uc_driver.execute_script(post_script)
            else:
                self.uc_driver.get(self._origin_for_url(url))
                request_script = f"""
                    var xhr = new XMLHttpRequest();
                    xhr.open({json.dumps(method)}, {json.dumps(url)}, false);
                    xhr.send({json.dumps(body) if body else 'null'});
                    document.open();
                    document.write(xhr.responseText);
                    document.close();
                """
                self.uc_driver.execute_script(request_script)

            if auth_spec:
                from backend_api.services.auth_session_service import AuthSessionService, HumanInterventionRequired

                barrier = AuthSessionService.operational_barrier_reason(
                    None, self.uc_driver.page_source or ""
                )
                if barrier:
                    raise HumanInterventionRequired(
                        barrier,
                        url=self.uc_driver.current_url,
                        identity=auth_spec.get("label"),
                    )

            stored_view_url = test_case_data.get('stored_view_url')
            if stored_view_url:
                time.sleep(0.5)
                self.uc_driver.get(stored_view_url)
                from backend_api.services.auth_session_service import (
                    AuthSessionService,
                    HumanInterventionRequired,
                )

                for observer_spec in (test_case_data.get("stored_revisit_auth_specs") or [])[:8]:
                    identity = str(observer_spec.get("label") or observer_spec.get("role") or "observer")
                    observed = {"identity": identity, "oracle_hit": False, "final_url": None}
                    try:
                        self.uc_driver.delete_all_cookies()
                        AuthSessionService.authenticate_selenium(
                            self.uc_driver,
                            test_case_data.get("target_base_url") or url,
                            observer_spec,
                        )
                        self.uc_driver.get(stored_view_url)
                        self.uc_driver.execute_script("""
                            const token = arguments[0];
                            for (const element of document.querySelectorAll('*')) {
                                if ((element.outerHTML || '').includes(token)) {
                                    for (const type of ['click', 'mouseover', 'focus', 'input', 'change']) {
                                        try { element.dispatchEvent(new Event(type, {bubbles: true, cancelable: true})); } catch (_) {}
                                    }
                                }
                            }
                        """, test_case_data["token"])
                        time.sleep(SeleniumConfig.ORACLE_WAIT_TIMEOUT)
                        observed["final_url"] = self.uc_driver.current_url
                        for entry in self.uc_driver.get_log("browser"):
                            text = entry.get("message", "")
                            console_messages.append({"type": entry.get("level", "INFO"), "text": text})
                            if "XSS Oracle: Execution detected" in text and test_case_data["token"] in text:
                                observed["oracle_hit"] = True
                                oracle_hit = True
                                oracle_message = f"XSS Oracle: Execution detected in identity {identity}"
                    except HumanInterventionRequired as error:
                        observed["human_intervention"] = {
                            "kind": "authentication_challenge",
                            "reason": error.reason,
                            "identity": error.identity or identity,
                            "url": error.url,
                        }
                        human_intervention = human_intervention or observed["human_intervention"]
                    except Exception as error:
                        observed["error"] = str(error)[:500]
                    cross_identity_results.append(observed)

            if runtime_coverage_collector is not None:
                runtime_coverage_collector.snapshot("bootstrap")
            if dom_differential_collector is not None:
                dom_differential_collector.capture("bootstrap")

            # Trigger interactive events
            try:
                interaction_script = """
                    (function(payload) {
                        try {
                            var token = window.__XSS_TOKEN__;
                            if (!token) return;
                            payload = payload || token;
                            
                            function findElementsRecursively(root) {
                                var elements = [];
                                try {
                                    var all = root.querySelectorAll('*');
                                    for (var i = 0; i < all.length; i++) {
                                        var el = all[i];
                                        elements.push(el);
                                        if (el.shadowRoot) {
                                            elements = elements.concat(findElementsRecursively(el.shadowRoot));
                                        }
                                    }
                                } catch (err) {}
                                return elements;
                            }
                            
                            var elements = findElementsRecursively(document);
                            for (var i = 0; i < elements.length; i++) {
                                var el = elements[i];
                                if (!el.attributes) continue;
                                for (var j = 0; j < el.attributes.length; j++) {
                                    var attr = el.attributes[j];
                                    if (attr.value && attr.value.indexOf(token) !== -1) {
                                        var events = ['click', 'mouseover', 'focus', 'input', 'change'];
                                        for (var k = 0; k < events.length; k++) {
                                            try {
                                                var event = new Event(events[k], { bubbles: true, cancelable: true });
                                                el.dispatchEvent(event);
                                            } catch (e) {}
                                        }
                                        if (attr.name.indexOf('on') === 0) {
                                            var handler = attr.name.substring(2);
                                            try {
                                                var event = new Event(handler, { bubbles: true, cancelable: true });
                                                el.dispatchEvent(event);
                                            } catch (e) {}
                                        }
                                    }
                                }
                            }

                            try {
                                var msgPayloads = [
                                    payload,
                                    JSON.stringify({ type: 'xss', html: payload, content: payload, data: payload, payload: payload, message: payload }),
                                    { type: 'xss', html: payload, content: payload, data: payload, payload: payload, message: payload }
                                ];
                                for (var m = 0; m < msgPayloads.length; m++) {
                                    window.postMessage(msgPayloads[m], '*');
                                }
                            } catch (msgErr) {}
                        } catch (err) {}
                    })(arguments[0]);
                """
                if self._active_browser_interactions_allowed(test_case_data):
                    self.uc_driver.execute_script(
                        interaction_script, test_case_data.get("payload") or ""
                    )
                    self._click_token_javascript_links_uc(
                        self.uc_driver, test_case_data["token"]
                    )
            except Exception as trigger_err:
                logger.warning(f"Failed to execute automated DOM interactions: {trigger_err}")

            time.sleep(SeleniumConfig.ORACLE_WAIT_TIMEOUT)

            # Dynamic timing extension: if token is present in DOM but oracle has not hit, wait longer
            if not oracle_hit:
                try:
                    if test_case_data['token'] in self.uc_driver.page_source:
                        logger.info(f"Token {test_case_data['token'][:8]} reflected in page source. Extending timeout by 3.0 seconds...")
                        time.sleep(3.0)
                except Exception:
                    pass

            if runtime_coverage_collector is not None:
                runtime_coverage_collector.snapshot("interaction")
            if dom_differential_collector is not None:
                dom_differential_collector.capture("interaction")

            # Retrieve browser logs
            try:
                for entry in self.uc_driver.get_log('browser'):
                    text = entry.get('message', '')
                    console_messages.append({
                        'type': entry.get('level', 'INFO'),
                        'text': text
                    })
                    if 'XSS Oracle: Execution detected' in text and (test_case_data.get('token') in text or test_case_data.get('token') == 'test_token'):
                        oracle_hit = True
                        oracle_message = text
            except Exception:
                pass

            for entry in console_messages:
                msg_text = entry.get('text', '')
                msg_text_lower = msg_text.lower()
                if entry.get('type') in ['SEVERE', 'ERROR'] or any(kw in msg_text_lower for kw in ['error', 'exception', 'syntax', 'unexpected', 'invalid', 'csp', 'violation', 'blocked', 'refused', 'unpermitted']):
                    page_errors.append(msg_text)

        except Exception as e:
            from backend_api.services.auth_session_service import AuthConfigurationError, HumanInterventionRequired

            if isinstance(e, HumanInterventionRequired):
                human_intervention = {
                    "kind": "authentication_challenge",
                    "reason": e.reason,
                    "identity": e.identity,
                    "url": e.url,
                }
            elif isinstance(e, AuthConfigurationError):
                human_intervention = {
                    "kind": "authentication_configuration",
                    "reason": str(e),
                    "identity": (test_case_data.get("auth_spec") or {}).get("label"),
                    "url": None,
                }
            execution_error = {
                "type": e.__class__.__name__,
                "message": str(e),
            }
            logger.error(f"Error during UC page execution: {e}", exc_info=True)

        lineage_mode = getattr(settings, "CAPTURE_RUNTIME_LINEAGE", "all")
        if self._runtime_coverage_requested(lineage_mode):
            try:
                collected_report = self._collect_runtime_lineage_uc(
                    self.uc_driver, test_case_data
                )
                if (
                    collected_report is not None
                    and self._capture_enabled(lineage_mode, oracle_hit)
                ):
                    runtime_lineage_report = collected_report
            except Exception as lineage_error:
                logger.debug("UC runtime causal lineage finalization failed: %s", lineage_error)

        if runtime_coverage_collector is not None:
            try:
                if not runtime_coverage_collector.report().get("phases"):
                    runtime_coverage_collector.snapshot("early_exit")
                collected_report = runtime_coverage_collector.finish()
                if self._capture_enabled(settings.CAPTURE_RUNTIME_COVERAGE, oracle_hit):
                    runtime_coverage_report = collected_report
            except Exception as coverage_error:
                logger.debug("UC runtime coverage finalization failed: %s", coverage_error)
        if dom_differential_collector is not None:
            try:
                if not dom_differential_collector.report().get("phases"):
                    dom_differential_collector.capture("early_exit")
                collected_report = dom_differential_collector.report()
                if self._capture_enabled(settings.CAPTURE_DOM_DIFFERENTIAL, oracle_hit):
                    dom_differential_report = collected_report
            except Exception as snapshot_error:
                logger.debug("UC DOM snapshot differential finalization failed: %s", snapshot_error)

        duration_ms = int((time.time() - start_time) * 1000)

        # Save live browser vision preview frame for real-time monitoring
        if self.uc_driver and not test_case_data.get("suppress_artifacts"):
            self._save_live_preview(self.uc_driver, test_case_data, oracle_hit)

        # Capture screenshot
        screenshot_path = None
        if (
            not test_case_data.get("suppress_artifacts")
            and screenshot_dir
            and self._capture_enabled(settings.CAPTURE_SCREENSHOTS, oracle_hit)
        ):
            screenshot_dir.mkdir(parents=True, exist_ok=True)
            screenshot_path = screenshot_dir / f"test_case_{test_case_data.get('test_case_id', 'unknown')}.png"
            try:
                self.uc_driver.save_screenshot(str(screenshot_path))
            except Exception as e:
                logger.error(f"Error capturing UC screenshot: {e}")

        # Capture DOM snapshot
        dom_snapshot = None
        if (
            not test_case_data.get("suppress_artifacts")
            and self._capture_enabled(settings.CAPTURE_DOM_SNAPSHOT, oracle_hit)
        ):
            try:
                dom_snapshot = self.uc_driver.page_source
            except Exception as e:
                logger.error(f"Error capturing UC DOM snapshot: {e}")

        # Clean/Reset cookies and state
        final_url = None
        try:
            final_url = self.uc_driver.current_url
        except Exception:
            final_url = None

        try:
            self.uc_driver.delete_all_cookies()
        except Exception:
            pass

        try:
            self.uc_driver.execute_cdp_cmd('Network.setExtraHTTPHeaders', {'headers': {}})
        except Exception:
            pass

        logs = {
            'console': console_messages[:50],
            'errors': list(set(page_errors))[:20],
            'tech_stack': {},
            'cross_identity_revisits': cross_identity_results,
            'execution_error': execution_error,
            'response_posture': self._build_response_posture(
                url=final_url or test_case_data.get('url', ''),
                status_code=None,
                headers={},
                cookie_metadata=None,
                metadata_observed=False,
                request_has_credentials=bool(
                    test_case_data.get('cookies')
                    or any(
                        str(key).lower() == "authorization"
                        for key in (test_case_data.get('headers') or {})
                    )
                ),
                source="uc_metadata_unavailable",
            ),
        }
        if runtime_coverage_report is not None:
            logs['runtime_code_coverage'] = runtime_coverage_report
        if dom_differential_report is not None:
            logs['dom_marker_differential'] = dom_differential_report
        if runtime_lineage_report is not None:
            logs['runtime_lineage'] = runtime_lineage_report

        return {
            'oracle_hit': oracle_hit,
            'oracle_message': oracle_message,
            'duration_ms': duration_ms,
            'screenshot_path': str(screenshot_path) if screenshot_path else None,
            'dom_snapshot': dom_snapshot[:settings.DOM_SNAPSHOT_MAX_CHARS] if dom_snapshot else None,
            'logs': logs,
            'status_code': None,
            'headers': {},
            'final_url': final_url,
            'human_intervention': human_intervention,
            'execution_error': execution_error,
        }

    def _execute_custom_steps_uc(self, driver, steps: List[Dict[str, Any]], payload: str):
        """Execute custom multi-step actions in Selenium UC."""
        for i, step in enumerate(steps):
            action = step.get('action', '').lower()
            try:
                if action == 'navigate':
                    url = step.get('url', '')
                    if '{{PAYLOAD}}' in url:
                        url = url.replace('{{PAYLOAD}}', payload)
                    driver.get(url)
                elif action == 'click':
                    selector = step.get('selector', '')
                    from selenium.webdriver.common.by import By
                    element = driver.find_element(By.CSS_SELECTOR, selector)
                    element.click()
                elif action == 'fill':
                    selector = step.get('selector', '')
                    value = step.get('value', '')
                    if '{{PAYLOAD}}' in value:
                        value = value.replace('{{PAYLOAD}}', payload)
                    from selenium.webdriver.common.by import By
                    element = driver.find_element(By.CSS_SELECTOR, selector)
                    element.clear()
                    element.send_keys(value)
                elif action == 'check':
                    selector = step.get('selector', '')
                    from selenium.webdriver.common.by import By
                    element = driver.find_element(By.CSS_SELECTOR, selector)
                    if not element.is_selected():
                        element.click()
                elif action == 'select':
                    selector = step.get('selector', '')
                    from selenium.webdriver.common.by import By
                    from selenium.webdriver.support.ui import Select
                    select = Select(driver.find_element(By.CSS_SELECTOR, selector))
                    index = 1 if len(select.options) > 1 else 0
                    select.select_by_index(index)
                elif action == 'press':
                    selector = step.get('selector', '')
                    key_str = step.get('key', 'Enter')
                    from selenium.webdriver.common.by import By
                    from selenium.webdriver.common.keys import Keys
                    key = getattr(Keys, key_str.upper(), Keys.ENTER)
                    if selector:
                        element = driver.find_element(By.CSS_SELECTOR, selector)
                        element.send_keys(key)
                    else:
                        from selenium.webdriver.common.action_chains import ActionChains
                        ActionChains(driver).send_keys(key).perform()
                elif action == 'hover':
                    selector = step.get('selector', '')
                    from selenium.webdriver.common.by import By
                    from selenium.webdriver.common.action_chains import ActionChains
                    element = driver.find_element(By.CSS_SELECTOR, selector)
                    ActionChains(driver).move_to_element(element).perform()
                elif action == 'wait':
                    seconds = float(step.get('seconds', 1.0))
                    time.sleep(seconds)
            except Exception as step_err:
                logger.warning(f"Error executing custom UC step {i} ({action}): {step_err}")

    def _execute_poc_html_uc(
        self,
        poc_html: str,
        token: str,
        test_case_id: Any = "unknown",
        target_url: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        screenshot_dir: Optional[Path] = None,
        serve_http: bool = True,
        fake_message_origin: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute standalone PoC HTML page with Undetected Chromedriver."""
        if not self.uc_driver:
            self.start()

        start_time = time.time()
        oracle_hit = False
        oracle_message = None
        console_messages = []
        page_errors = []

        oracle_script = get_oracle_script()
        init_payload = f"""
            window.__XSS_TOKEN__ = {json.dumps(token)};
            window.__ORACLE_URL__ = {json.dumps(self.oracle_url)};
            window.__XSS_FAKE_MESSAGE_ORIGIN__ = {json.dumps(fake_message_origin)};
            {oracle_script}
        """
        try:
            self.uc_driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {'source': init_payload})
        except Exception as cdp_err:
            logger.warning(f"Failed to register CDP injection: {cdp_err}")

        try:
            if target_url:
                from urllib.parse import urlparse
                parsed_url = urlparse(target_url)
                domain = parsed_url.hostname
                self.uc_driver.get(target_url)
                for name, val in (cookies or {}).items():
                    try:
                        self.uc_driver.add_cookie({'name': name, 'value': val})
                    except Exception:
                        pass

            if serve_http:
                from browser_workers.poc_server import LocalPoCServer
                server = LocalPoCServer(poc_html)
                poc_url = server.start()
                try:
                    self.uc_driver.get(poc_url)
                    time.sleep(SeleniumConfig.ORACLE_WAIT_TIMEOUT)
                finally:
                    server.stop()
            else:
                data_url = "data:text/html;charset=utf-8," + quote(poc_html)
                self.uc_driver.get(data_url)
                time.sleep(SeleniumConfig.ORACLE_WAIT_TIMEOUT)

            try:
                for entry in self.uc_driver.get_log('browser'):
                    text = entry.get('message', '')
                    console_messages.append({
                        'type': entry.get('level', 'INFO'),
                        'text': text
                    })
                    if 'XSS Oracle: Execution detected' in text and (token in text or token == 'test_token'):
                        oracle_hit = True
                        oracle_message = text
            except Exception:
                pass

            for entry in console_messages:
                msg_text = entry.get('text', '')
                msg_text_lower = msg_text.lower()
                if entry.get('type') in ['SEVERE', 'ERROR'] or any(kw in msg_text_lower for kw in ['error', 'exception', 'syntax', 'unexpected', 'invalid', 'csp', 'violation', 'blocked', 'refused', 'unpermitted']):
                    page_errors.append(msg_text)

        except Exception as e:
            logger.error(f"Error during UC PoC navigation: {e}", exc_info=True)

        duration_ms = int((time.time() - start_time) * 1000)

        # Capture screenshot
        screenshot_path = None
        if screenshot_dir and self._capture_enabled(settings.CAPTURE_SCREENSHOTS, oracle_hit):
            screenshot_dir.mkdir(parents=True, exist_ok=True)
            screenshot_path = screenshot_dir / f"modern_probe_{test_case_id}.png"
            try:
                self.uc_driver.save_screenshot(str(screenshot_path))
            except Exception as e:
                logger.error(f"Error capturing UC screenshot: {e}")

        # Capture DOM snapshot
        dom_snapshot = None
        if self._capture_enabled(settings.CAPTURE_DOM_SNAPSHOT, oracle_hit):
            try:
                dom_snapshot = self.uc_driver.page_source
            except Exception as e:
                logger.error(f"Error capturing UC DOM snapshot: {e}")

        try:
            self.uc_driver.delete_all_cookies()
        except Exception:
            pass

        return {
            'oracle_hit': oracle_hit,
            'oracle_message': oracle_message,
            'duration_ms': duration_ms,
            'screenshot_path': str(screenshot_path) if screenshot_path else None,
            'dom_snapshot': dom_snapshot[:settings.DOM_SNAPSHOT_MAX_CHARS] if dom_snapshot else None,
            'logs': {
                'console': console_messages[:50],
                'errors': list(set(page_errors))[:20],
            },
            'status_code': 200,
        }

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
