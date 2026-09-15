"""Ultimate modern Selenium-based security crawler with CDP telemetry, API interception, and DOM XSS sensing."""
import hashlib
import heapq
import json
import re
import time
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse

from selenium import webdriver
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager

from backend_api.utils.logger import logger
from backend_api.utils.scope_guard import is_url_in_scope
from browser_workers.selenium_config import SeleniumConfig
from recon_engine.bundle_signal_schema import bounded_sanitizer_boundary_evidence


# CDP Instrumentation Script injected into every document before scripts execute
STEALTH_TELEMETRY_SCRIPT = """
(function() {
    if (window._xssboss_injected) return;
    window._xssboss_injected = true;

    window._xssboss_api_traffic = window._xssboss_api_traffic || [];
    window._xssboss_dom_telemetry = window._xssboss_dom_telemetry || [];
    window._spa_routes = window._spa_routes || [];

    // 1. Hook History API & hash routing
    const origPush = history.pushState;
    history.pushState = function(state, title, url) {
        if (url) {
            try {
                window._spa_routes.push(new URL(url, location.href).href);
            } catch(e) {}
        }
        return origPush.apply(this, arguments);
    };
    const origReplace = history.replaceState;
    history.replaceState = function(state, title, url) {
        if (url) {
            try {
                window._spa_routes.push(new URL(url, location.href).href);
            } catch(e) {}
        }
        return origReplace.apply(this, arguments);
    };
    window.addEventListener('hashchange', function() {
        window._spa_routes.push(location.href);
    });

    // 2. Intercept window.fetch for dynamic SPA API discovery
    const origFetch = window.fetch;
    if (origFetch) {
        window.fetch = function(resource, init) {
            try {
                let url = '';
                let method = 'GET';
                let headers = {};
                let body = null;

                if (typeof resource === 'string') {
                    url = resource;
                } else if (resource && resource.url) {
                    url = resource.url;
                    method = resource.method || 'GET';
                }

                if (init) {
                    if (init.method) method = init.method;
                    if (init.headers) {
                        try {
                            if (init.headers instanceof Headers) {
                                init.headers.forEach((v, k) => { headers[k] = v; });
                            } else if (typeof init.headers === 'object') {
                                headers = Object.assign({}, init.headers);
                            }
                        } catch(e) {}
                    }
                    if (init.body) {
                        try {
                            if (typeof init.body === 'string') {
                                body = init.body;
                            } else if (init.body instanceof FormData) {
                                body = '[FormData]';
                            } else if (init.body instanceof URLSearchParams) {
                                body = init.body.toString();
                            }
                        } catch(e) {}
                    }
                }

                if (url) {
                    const fullUrl = new URL(url, location.href).href;
                    window._xssboss_api_traffic.push({
                        type: 'fetch',
                        method: method.toUpperCase(),
                        url: fullUrl,
                        headers: headers,
                        body: body,
                        timestamp: Date.now()
                    });
                }
            } catch (err) {}
            return origFetch.apply(this, arguments);
        };
    }

    // 3. Intercept XMLHttpRequest for legacy/AJAX API discovery
    const origXhrOpen = XMLHttpRequest.prototype.open;
    const origXhrSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(method, url) {
        try {
            this._xssboss_method = method;
            this._xssboss_url = new URL(url, location.href).href;
        } catch (e) {}
        return origXhrOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function(body) {
        try {
            if (this._xssboss_url) {
                let bodyStr = null;
                if (typeof body === 'string') {
                    bodyStr = body;
                }
                window._xssboss_api_traffic.push({
                    type: 'xhr',
                    method: (this._xssboss_method || 'GET').toUpperCase(),
                    url: this._xssboss_url,
                    headers: {},
                    body: bodyStr,
                    timestamp: Date.now()
                });
            }
        } catch (e) {}
        return origXhrSend.apply(this, arguments);
    };

    // 4. Client-side DOM XSS Sinks & Sources Hooking
    function recordDomEvent(kind, target, val) {
        try {
            window._xssboss_dom_telemetry.push({
                kind: kind,
                target: target,
                value: typeof val === 'string' ? val.substring(0, 200) : String(val),
                pageUrl: location.href,
                timestamp: Date.now()
            });
        } catch (e) {}
    }

    try {
        const descInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
        if (descInnerHTML && descInnerHTML.set) {
            const origSetInnerHTML = descInnerHTML.set;
            descInnerHTML.set = function(val) {
                recordDomEvent('sink', 'innerHTML', val);
                return origSetInnerHTML.apply(this, arguments);
            };
            Object.defineProperty(Element.prototype, 'innerHTML', descInnerHTML);
        }
    } catch(e) {}

    try {
        const origDocWrite = document.write;
        document.write = function(val) {
            recordDomEvent('sink', 'document.write', val);
            return origDocWrite.apply(this, arguments);
        };
    } catch(e) {}

    try {
        const descHref = Object.getOwnPropertyDescriptor(HTMLAnchorElement.prototype, 'href');
        if (descHref && descHref.set) {
            const origSetHref = descHref.set;
            descHref.set = function(val) {
                recordDomEvent('sink', 'anchor.href', val);
                return origSetHref.apply(this, arguments);
            };
            Object.defineProperty(HTMLAnchorElement.prototype, 'href', descHref);
        }
    } catch(e) {}
})();
"""


class Crawler:
    """Ultimate Modern Headless Web Crawler with real-time CDP API interception."""

    DESTRUCTIVE_KEYWORDS = [
        'logout', 'signout', 'sign-out', 'log-off', 'log_off',
        'delete', 'destroy', 'remove-account', 'deactivate',
        'cancel-subscription', 'unsubscribe', 'disconnect',
        'signin', 'sign-in', 'login', 'log-in', 'auth', 'sso'
    ]
    COLLECTION_SEGMENTS = {
        'article', 'articles', 'blog', 'blogs', 'case-studies', 'docs', 'events',
        'items', 'jobs', 'listing', 'listings', 'news', 'post', 'posts', 'product',
        'products', 'resources', 'stories', 'story', 'users', 'videos',
    }
    FEATURE_SEGMENTS = {
        'account', 'admin', 'api', 'apply', 'callback', 'cart', 'checkout',
        'contact', 'dashboard', 'feedback', 'graphql', 'login', 'oauth', 'preview',
        'profile', 'redirect', 'register', 'search', 'settings', 'support', 'upload',
    }

    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        max_pages: int = 100,
        delay: float = 0.5,
        follow_external: bool = False,
        auth_identity: Optional[str] = None,
        progress_callback=None,
        decision_callback=None,
        template_sample_limit: int = 2,
        script_bundle_limit: int = 4,
    ):
        """Initialize crawler with modern defaults."""
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.delay = delay
        self.follow_external = follow_external
        self.visited: Set[str] = set()
        self.requests: List[Dict[str, Any]] = []
        self.saved_endpoint_ids: Set[int] = set()
        self.driver = None
        self.db_session = None
        self.target_id = None
        self._target_obj = None
        self._analyzed_scripts: Set[str] = set()
        self.research_signals: List[Dict[str, Any]] = []
        self.auth_identity = auth_identity
        self.progress_callback = progress_callback
        self.decision_callback = decision_callback
        self.template_sample_limit = max(1, int(template_sample_limit))
        self.script_bundle_limit = max(0, int(script_bundle_limit))
        self.auth_session: Dict[str, Any] = {}
        self.interventions: List[Dict[str, Any]] = []
        self.skipped_template_urls: List[Dict[str, Any]] = []
        self.route_template_counts: Dict[str, int] = {}
        self.feature_fingerprint_counts: Dict[str, int] = {}
        self.frontier_peak = 0

    def _emit_decision(self, event: Dict[str, Any]) -> None:
        """Expose scheduling and dedup decisions without coupling to the API."""
        if not self.decision_callback:
            return
        try:
            self.decision_callback(event)
        except Exception:
            logger.debug("Crawler decision callback failed", exc_info=True)

    @staticmethod
    def _canonical_crawl_key(url: str) -> str:
        """Deduplicate values while retaining distinct parameter-name surfaces."""
        parsed = urlparse(url)
        path = re.sub(r'/+', '/', parsed.path or '/')
        if path != '/':
            path = path.rstrip('/')
        query_names = sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)})
        query_shape = '&'.join(f"{name}=" for name in query_names)
        base = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"
        return f"{base}?{query_shape}" if query_shape else base

    @staticmethod
    def _safe_observation_url(url: str) -> str:
        """Retain routing evidence without credentials, query values, or fragments."""
        try:
            parsed = urlparse(str(url or ""))
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                return "<invalid-url>"
            hostname = parsed.hostname
            if ":" in hostname and not hostname.startswith("["):
                hostname = f"[{hostname}]"
            netloc = hostname
            if parsed.port is not None:
                netloc = f"{netloc}:{parsed.port}"
            return parsed._replace(
                scheme=parsed.scheme.lower(),
                netloc=netloc,
                params="",
                query="",
                fragment="",
            ).geturl()
        except (TypeError, ValueError):
            return "<invalid-url>"

    @classmethod
    def _route_template(cls, url: str) -> str:
        """Group likely content instances while preserving security-relevant routes."""
        parsed = urlparse(url)
        segments = [segment for segment in parsed.path.split('/') if segment]
        shaped: List[str] = []
        for index, segment in enumerate(segments):
            lowered = segment.lower()
            previous = segments[index - 1].lower() if index else ''
            is_identifier = bool(
                re.fullmatch(r'\d{2,}', segment)
                or re.fullmatch(r'[0-9a-f]{8,}', lowered)
                or re.fullmatch(r'[0-9a-f]{8}-[0-9a-f-]{20,}', lowered)
                or re.fullmatch(r'\d{4}/\d{1,2}/\d{1,2}', '/'.join(segments[index:index + 3]))
            )
            collection_item = previous in cls.COLLECTION_SEGMENTS and lowered not in cls.FEATURE_SEGMENTS
            single_content_page = (
                len(segments) == 1
                and lowered not in cls.FEATURE_SEGMENTS
                and lowered not in cls.COLLECTION_SEGMENTS
            )
            shaped.append(':item' if is_identifier or collection_item else ':content-page' if single_content_page else lowered)
        query_names = sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)})
        suffix = '?' + '&'.join(f"{name}=" for name in query_names) if query_names else ''
        return '/' + '/'.join(shaped) + suffix

    @classmethod
    def _url_priority(cls, url: str, depth: int) -> tuple[int, List[str]]:
        """Score URLs by likely unique attack surface, highest score first."""
        parsed = urlparse(url)
        route_shape = cls._route_template(url).lower()
        route_tokens = {token for token in re.split(r'[^a-z0-9]+', route_shape) if token}
        query_names = {name.lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
        score = 100 - (depth * 12)
        reasons = [f"depth_{depth}"]
        if parsed.query:
            score += 45
            reasons.append('query_parameters')
        matched = sorted(segment for segment in cls.FEATURE_SEGMENTS if segment in route_tokens)
        if matched:
            score += min(45, 15 + len(matched) * 6)
            reasons.append('feature_route:' + ','.join(matched[:4]))
        if query_names & {'return', 'returnto', 'next', 'url', 'uri', 'redirect', 'redirect_uri', 'callback'}:
            score += 30
            reasons.append('navigation_input')
        if parsed.fragment:
            score += 8
            reasons.append('fragment_input')
        return score, reasons

    def _page_feature_fingerprint(self) -> tuple[str, Dict[str, Any]]:
        """Fingerprint executable/input features, intentionally ignoring page text."""
        summary: Dict[str, Any] = {}
        try:
            summary = self.driver.execute_script("""
                return {
                    forms: document.forms.length,
                    inputs: Array.from(document.querySelectorAll('input')).map(e => [e.type || '', e.name || '']).sort(),
                    textareas: Array.from(document.querySelectorAll('textarea')).map(e => e.name || '').sort(),
                    selects: Array.from(document.querySelectorAll('select')).map(e => e.name || '').sort(),
                    buttons: document.querySelectorAll('button,[role=button]').length,
                    scripts: Array.from(document.scripts).map(s => { try { return new URL(s.src, location.href).pathname; } catch(e) { return ''; } }).filter(Boolean).sort(),
                    contenteditables: document.querySelectorAll('[contenteditable=true]').length,
                    iframes: document.querySelectorAll('iframe').length
                };
            """) or {}
        except Exception:
            summary = {}
        encoded = json.dumps(summary, sort_keys=True, default=str).encode('utf-8', errors='replace')
        return hashlib.sha256(encoded).hexdigest()[:16], summary

    def _start_driver(self):
        """Start Undetected Chrome / Selenium driver with stealth options and CDP telemetry hooks."""
        import os
        from backend_api.config import settings

        if settings.USE_UNDETECTED_CHROME:
            try:
                logger.info("Initializing Crawler with Undetected Chromedriver...")
                import undetected_chromedriver as uc
                options = uc.ChromeOptions()
                options.add_argument('--headless=new')
                options.add_argument('--no-sandbox')
                options.add_argument('--disable-setuid-sandbox')
                options.add_argument('--disable-dev-shm-usage')
                if settings.ALLOW_INSECURE_TLS:
                    options.add_argument('--ignore-certificate-errors')
                from backend_api.utils.proxy_health import effective_worker_proxy

                effective_proxy = effective_worker_proxy()
                if effective_proxy:
                    options.add_argument(f"--proxy-server={effective_proxy}")
                self.driver = uc.Chrome(options=options)
            except Exception as uc_err:
                logger.warning(f"Undetected Chromedriver crawler start failed ({uc_err}); falling back to standard Chrome")
                self.driver = None

        if not self.driver:
            options = SeleniumConfig.get_chrome_options()
            try:
                service = ChromeService(log_output=os.devnull)
                self.driver = webdriver.Chrome(service=service, options=options)
            except Exception:
                try:
                    driver_path = ChromeDriverManager().install()
                    service = ChromeService(executable_path=driver_path, log_output=os.devnull)
                    self.driver = webdriver.Chrome(service=service, options=options)
                except Exception as e:
                    raise RuntimeError(f"Failed to initialize Selenium Chrome webdriver: {e}")

        # Inject stealth telemetry on every newly created document
        try:
            self.driver.execute_cdp_cmd(
                'Page.addScriptToEvaluateOnNewDocument',
                {'source': STEALTH_TELEMETRY_SCRIPT}
            )
        except Exception as e:
            logger.warning(f"Failed to inject CDP telemetry script: {e}")

        self.driver.set_page_load_timeout(min(15, SeleniumConfig.NAVIGATION_TIMEOUT))
        self.driver.set_script_timeout(min(8, SeleniumConfig.NAVIGATION_TIMEOUT))
        self.driver.implicitly_wait(min(2, SeleniumConfig.ACTION_TIMEOUT))

    def _dismiss_consent_and_modals(self):
        """Dismiss CMP cookie banners, consent prompts, and obstructing overlays."""
        if not self.driver:
            return
        try:
            self.driver.execute_script("""
                const selectors = [
                    '#uc-btn-accept-banner',
                    '#onetrust-accept-btn-handler',
                    '#didomi-notice-agree-button',
                    '#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll',
                    'button[data-testid="uc-accept-all-button"]',
                    '.cookie-accept-btn',
                    '.cookie-banner button',
                    'button[aria-label="Accept all"]',
                    'button[aria-label="Accept cookies"]'
                ];
                for (const s of selectors) {
                    const btn = document.querySelector(s);
                    if (btn && btn.offsetParent !== null) {
                        try { btn.click(); break; } catch(e) {}
                    }
                }
            """)
        except Exception:
            pass

    def _is_safe_url(self, url: str) -> bool:
        """Ensure URL is in-scope and non-destructive."""
        if not url or not url.startswith(('http://', 'https://')):
            return False

        parsed = urlparse(url)
        url_lower = url.lower()

        # Check for destructive endpoints
        for kw in self.DESTRUCTIVE_KEYWORDS:
            if kw in url_lower:
                return False

        # In-scope check
        if self._target_obj:
            try:
                return is_url_in_scope(self._target_obj, url)
            except Exception:
                pass

        if not self.follow_external:
            parsed_base = urlparse(self.base_url)
            return parsed.netloc == parsed_base.netloc

        return True

    def _save_request(self, request_data: Dict[str, Any]):
        """Save discovered request to in-memory list and database."""
        url = request_data.get('url', '')
        if not self._is_safe_url(url):
            return

        if self._target_obj and self._target_obj.auth_info:
            try:
                from backend_api.services.auth_session_service import AuthSessionService

                auth_context = AuthSessionService.request_context(
                    self.auth_session or self._target_obj.auth_info,
                    endpoint_context=request_data.get("headers") or {},
                )
                request_data = {**request_data, "headers": auth_context}
            except Exception as auth_error:
                logger.warning("Could not apply target authentication to crawled request: %s", auth_error)

        self.requests.append(request_data)
        if self.db_session and self.target_id:
            try:
                from backend_api.services.recon_service import ReconService
                endpoint = ReconService.create_endpoint_from_request(
                    self.db_session,
                    self.target_id,
                    request_data['method'],
                    request_data['url'],
                    request_data,
                    response_data=(
                        {"body": request_data.get("response_body")}
                        if request_data.get("response_body") is not None
                        else None
                    ),
                )
                if endpoint and endpoint.id:
                    self.saved_endpoint_ids.add(endpoint.id)
            except Exception as e:
                # Log without halting crawl pipeline
                logger.debug(f"Could not import crawled request {url}: {e}")

    def _harvest_background_api_traffic(self):
        """Harvest background fetch/XHR network requests intercepted via CDP."""
        if not self.driver:
            return
        try:
            traffic = self.driver.execute_script("""
                const t = window._xssboss_api_traffic || [];
                window._xssboss_api_traffic = [];
                return t;
            """)
            if traffic and isinstance(traffic, list):
                for item in traffic:
                    req_url = item.get('url')
                    if not req_url or not self._is_safe_url(req_url):
                        continue

                    method = item.get('method', 'GET').upper()
                    parsed = urlparse(req_url)
                    query_params = dict(parse_qsl(parsed.query))

                    # Parse JSON or form body
                    body = item.get('body')
                    json_body = None
                    form_body = None
                    if body and isinstance(body, str):
                        try:
                            json_body = json.loads(body)
                        except Exception:
                            if '=' in body and not body.startswith('{'):
                                form_body = dict(parse_qsl(body))

                    self._save_request({
                        'method': method,
                        'url': req_url,
                        'headers': item.get('headers', {}),
                        'query': query_params,
                        'body': form_body,
                        'json': json_body
                    })
        except Exception as e:
            logger.debug(f"Error harvesting API traffic: {e}")

    def _harvest_dom_telemetry(self):
        """Harvest DOM XSS sink and source events intercepted client-side."""
        if not self.driver:
            return
        try:
            telemetry = self.driver.execute_script("""
                const events = window._xssboss_dom_telemetry || [];
                window._xssboss_dom_telemetry = [];
                return events;
            """)
            if telemetry and isinstance(telemetry, list):
                for evt in telemetry:
                    logger.info(
                        f"[DOM Telemetry] Detected client-side {evt.get('kind')} on {evt.get('target')} "
                        f"at {evt.get('pageUrl')}"
                    )
        except Exception:
            pass

    def _extract_framework_routes(self) -> List[str]:
        """Introspect Next.js, Nuxt, and modern SPA router state."""
        if not self.driver:
            return []
        routes = []
        try:
            fw_data = self.driver.execute_script("""
                const discovered = [];
                // 1. Next.js __NEXT_DATA__
                if (window.__NEXT_DATA__) {
                    try {
                        const page = window.__NEXT_DATA__.page;
                        if (page && page !== '/_error') discovered.push(page);
                        const query = window.__NEXT_DATA__.query;
                        if (query && typeof query === 'object') {
                            const qs = new URLSearchParams(query).toString();
                            if (qs) discovered.push(location.pathname + '?' + qs);
                        }
                    } catch(e) {}
                }
                // 2. Nuxt.js __NUXT__
                if (window.__NUXT__) {
                    try {
                        if (window.__NUXT__.state) {
                            const routePath = window.__NUXT__.state.route?.path;
                            if (routePath) discovered.push(routePath);
                        }
                    } catch(e) {}
                }
                // 3. JSON-LD structured metadata
                try {
                    const lds = document.querySelectorAll('script[type="application/ld+json"]');
                    for (const ld of lds) {
                        const content = JSON.parse(ld.innerText || '{}');
                        if (content.url) discovered.push(content.url);
                    }
                } catch(e) {}
                return discovered;
            """)
            if fw_data and isinstance(fw_data, list):
                for r in fw_data:
                    if r and isinstance(r, str):
                        full = urljoin(self.driver.current_url, r)
                        if self._is_safe_url(full):
                            routes.append(full)
        except Exception:
            pass

        try:
            from recon_engine.rsc_parser import RSCParser
            rsc_data = RSCParser.analyze_driver_rsc(self.driver)
            for r in rsc_data.get("internal_routes", []):
                full = urljoin(self.driver.current_url, r)
                if self._is_safe_url(full) and full not in routes:
                    routes.append(full)
        except Exception:
            pass
        return routes

    def _extract_all_links_and_attributes(self) -> List[str]:
        """Extract links recursively from Light DOM and Shadow DOM roots."""
        if not self.driver:
            return []
        try:
            urls = self.driver.execute_script("""
                function extractUrlsRecursively(root) {
                    let collected = [];
                    try {
                        const all = root.querySelectorAll('*');
                        for (let i = 0; i < all.length; i++) {
                            const el = all[i];
                            const tag = el.tagName.toLowerCase();

                            // 1. Standard navigation links
                            if (tag === 'a' && el.href) collected.push(el.href);
                            if (tag === 'area' && el.href) collected.push(el.href);

                            // 2. Embedded frames and resources
                            if ((tag === 'iframe' || tag === 'frame') && el.src) collected.push(el.src);

                            // 3. Modern data-attributes
                            const dataAttrs = ['data-url', 'data-href', 'data-endpoint', 'data-api', 'data-redirect', 'data-target'];
                            for (const attr of dataAttrs) {
                                const val = el.getAttribute(attr);
                                if (val && (val.startsWith('/') || val.startsWith('http'))) {
                                    collected.push(val);
                                }
                            }

                            // 4. Shadow DOM recursion
                            if (el.shadowRoot) {
                                collected = collected.concat(extractUrlsRecursively(el.shadowRoot));
                            }
                        }
                    } catch(e) {}
                    return collected;
                }
                return extractUrlsRecursively(document);
            """)
            cleaned = []
            if urls and isinstance(urls, list):
                curr = self.driver.current_url
                for u in urls:
                    if not u or not isinstance(u, str):
                        continue
                    full = urljoin(curr, u)
                    if self._is_safe_url(full) and full not in cleaned:
                        cleaned.append(full)
            return cleaned
        except Exception as e:
            logger.debug(f"Error extracting DOM links: {e}")
            return []

    def _interact_with_spa_elements(self):
        """Populate inputs and trigger safe interactive buttons/tabs to discover states."""
        if not self.driver:
            return
        try:
            # 1. Populate form inputs with safe probe values
            self.driver.execute_script("""
                function fillInputsRecursively(root) {
                    try {
                        const inputs = root.querySelectorAll('input, textarea, select');
                        for (let i = 0; i < inputs.length; i++) {
                            const el = inputs[i];
                            if (el.type === 'hidden' || el.type === 'submit' || el.type === 'button') continue;
                            if (!el.value) {
                                if (el.type === 'email') el.value = 'audit@example.com';
                                else if (el.type === 'number') el.value = '1';
                                else if (el.type === 'url') el.value = 'https://example.com';
                                else el.value = 'xssboss_probe';
                                el.dispatchEvent(new Event('input', { bubbles: true }));
                                el.dispatchEvent(new Event('change', { bubbles: true }));
                            }
                        }
                        const all = root.querySelectorAll('*');
                        for (let j = 0; j < all.length; j++) {
                            if (all[j].shadowRoot) fillInputsRecursively(all[j].shadowRoot);
                        }
                    } catch(e) {}
                }
                fillInputsRecursively(document);
            """)

            # 2. Click non-destructive interactive buttons
            original_url = self.driver.current_url
            interactive_elements = self.driver.find_elements(
                By.CSS_SELECTOR,
                "button:not([disabled]), [role='button'], [role='tab'], summary"
            )
            interaction_deadline = time.monotonic() + 5.0
            attempted = 0
            for elem in interactive_elements[:5]:
                if time.monotonic() >= interaction_deadline:
                    self._emit_decision({
                        'event_type': 'crawler_interaction_budget_exhausted',
                        'url': self.driver.current_url,
                        'attempted': attempted,
                        'budget_seconds': 5,
                    })
                    break
                try:
                    if elem.get_attribute("type") in ("submit", "reset"):
                        continue
                    if elem.tag_name.lower() == "a" or elem.get_attribute("href"):
                        continue
                    text = (elem.text or elem.get_attribute("aria-label") or "").lower()
                    if any(kw in text for kw in self.DESTRUCTIVE_KEYWORDS):
                        continue
                    attempted += 1
                    self.driver.execute_script("arguments[0].click();", elem)
                    time.sleep(0.1)
                    if self.driver.current_url != original_url:
                        self.driver.execute_script("window.history.back();")
                        time.sleep(0.1)
                except Exception:
                    continue
        except Exception:
            pass

    def _analyze_script_bundle(self, script_url: str):
        """Analyze downloaded JS chunk for hidden endpoints, parameters, and DOM sinks."""
        if self._target_obj and not is_url_in_scope(self._target_obj, script_url):
            self._emit_decision({
                "event_type": "crawler_bundle_skipped",
                "script_url": self._safe_observation_url(script_url),
                "reason": "script_url_out_of_scope",
            })
            return
        if script_url in self._analyzed_scripts:
            return
        self._analyzed_scripts.add(script_url)
        observed_script_url = self._safe_observation_url(script_url)
        started_at = time.monotonic()
        self._emit_decision({
            'event_type': 'crawler_bundle_started',
            'url': getattr(self.driver, 'current_url', None),
            'script_url': observed_script_url,
        })

        try:
            from recon_engine.bundle_analyzer import BundleAnalyzer
            content = None
            response_headers: Dict[str, str] = {}
            max_bundle_bytes = 2_000_000
            bundle_oversized = False

            # First attempt stealth download via active browser driver to bypass Akamai/Cloudflare
            if self.driver:
                try:
                    fetch_code = """
                        var scriptUrl = arguments[0];
                        var maxChars = arguments[1];
                        var callback = arguments[arguments.length - 1];
                        fetch(scriptUrl, {credentials: 'same-origin'})
                            .then(async function(r) {
                                var declaredLength = Number(r.headers.get('Content-Length') || 0);
                                if (declaredLength > maxChars) {
                                    callback({success: false, oversized: true, status: r.status});
                                    return;
                                }
                                var text = await r.text();
                                callback({
                                    success: r.ok,
                                    status: r.status,
                                    oversized: text.length > maxChars,
                                    content: text.slice(0, maxChars + 1),
                                    response_headers: {
                                        SourceMap: r.headers.get('SourceMap'),
                                        'X-SourceMap': r.headers.get('X-SourceMap')
                                    }
                                });
                            })
                            .catch(err => callback({success: false, error: String(err)}));
                    """
                    res = self.driver.execute_async_script(
                        fetch_code, script_url, max_bundle_bytes
                    )
                    if isinstance(res, dict):
                        bundle_oversized = bool(res.get("oversized"))
                        if res.get("success") and not bundle_oversized:
                            content = res.get("content")
                        raw_headers = res.get("response_headers")
                        if isinstance(raw_headers, dict):
                            response_headers = {
                                str(name): str(value)[:4096]
                                for name, value in raw_headers.items()
                                if name in {"SourceMap", "X-SourceMap"} and value
                            }
                except Exception:
                    pass

            if bundle_oversized:
                self._emit_decision({
                    'event_type': 'crawler_bundle_skipped',
                    'url': getattr(self.driver, 'current_url', None),
                    'script_url': observed_script_url,
                    'reason': 'bundle_size_limit_exceeded',
                    'limit_bytes': max_bundle_bytes,
                })
                return

            # Fallback to direct HTTP client if browser fetch is unavailable
            if not content:
                import httpx
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                if self._target_obj and self._target_obj.auth_info:
                    from backend_api.services.auth_session_service import AuthSessionService

                    headers = AuthSessionService.request_context_for_url(
                        self.auth_session or self._target_obj.auth_info,
                        script_url,
                        self.base_url,
                        endpoint_context=headers,
                    )
                from backend_api.config import settings
                with httpx.Client(
                    timeout=6,
                    verify=not settings.ALLOW_INSECURE_TLS,
                    headers=headers,
                ) as client:
                    from backend_api.utils.rate_limiter import rate_limiter
                    rate_limiter.wait_for_slot(script_url)
                    try:
                        with client.stream("GET", script_url) as res:
                            rate_limiter.report_response(script_url, res)
                            if res.status_code == 200:
                                for header_name in ("SourceMap", "X-SourceMap"):
                                    header_value = res.headers.get(header_name)
                                    if header_value:
                                        response_headers[header_name] = str(header_value)[:4096]
                                body = bytearray()
                                for chunk in res.iter_bytes():
                                    if len(body) + len(chunk) > max_bundle_bytes:
                                        bundle_oversized = True
                                        break
                                    body.extend(chunk)
                                if not bundle_oversized:
                                    content = bytes(body).decode("utf-8", errors="ignore")
                    except Exception:
                        rate_limiter.report_error(script_url)
                        raise

            if bundle_oversized:
                self._emit_decision({
                    'event_type': 'crawler_bundle_skipped',
                    'url': getattr(self.driver, 'current_url', None),
                    'script_url': observed_script_url,
                    'reason': 'bundle_size_limit_exceeded',
                    'limit_bytes': max_bundle_bytes,
                })
                return

            if content:
                html_context = ""
                if self.driver:
                    try:
                        html_context = str(self.driver.page_source or "")[:1_000_000]
                    except Exception:
                        html_context = ""
                analysis = BundleAnalyzer.analyze_script_content(
                    script_url,
                    content,
                    html_content=html_context,
                    response_headers=response_headers,
                )
                signal_categories = (
                    "dom_sources", "dom_sinks", "navigation_sinks", "eval_sinks",
                    "postmessage_listeners", "sensitive_tokens", "prototype_pollution",
                    "sanitizers", "vulnerable_libraries", "source_sink_flows",
                    "smart_taint_targets", "client_trust_findings",
                    "property_integrity_observations", "property_integrity_chains",
                )
                counts = {
                    category: len(analysis.get(category, []) or [])
                    for category in signal_categories
                }
                for category in (
                    "postmessage_unvalidated_sink",
                    "postmessage_weak_origin_validation",
                    "postmessage_wildcard_target",
                    "external_prototype_mutation",
                    "dom_named_property_to_sink",
                    "trusted_types_identity_policy",
                ):
                    counts[category] = int(
                        (analysis.get("client_trust_summary") or {}).get(category, 0) or 0
                    )
                for category in (
                    "dom_clobbering_chain",
                    "prototype_property_injection_chain",
                ):
                    counts[category] = int(
                        (analysis.get("property_integrity_summary") or {}).get(category, 0) or 0
                    )
                boundary_counts, boundary_findings = bounded_sanitizer_boundary_evidence(
                    analysis
                )
                counts.update(boundary_counts)
                self.research_signals.append({
                    "kind": "client_bundle",
                    "script_url": observed_script_url,
                    "size_bytes": analysis.get("size_bytes", 0),
                    "discovered_endpoints": list(analysis.get("internal_api_endpoints", []))[:50],
                    "discovered_parameters": list(
                        analysis.get("discovered_parameters", []) or []
                    )[:100],
                    "reachable_parameters": list(
                        analysis.get("reachable_params", []) or []
                    )[:100],
                    "vulnerable_libraries": list(
                        analysis.get("vulnerable_libraries", []) or []
                    )[:100],
                    "client_trust_findings": list(
                        analysis.get("client_trust_findings", []) or []
                    )[:100],
                    "property_integrity_chains": list(
                        analysis.get("property_integrity_chains", []) or []
                    )[:100],
                    "sanitizer_boundary_findings": boundary_findings,
                    "counts": counts,
                    "secret_indicator_count": counts["sensitive_tokens"],
                })
                for route in analysis["internal_api_endpoints"]:
                    full = urljoin(self.base_url, route)
                    if self._is_safe_url(full):
                        parsed = urlparse(full)
                        self._save_request({
                            'method': 'GET',
                            'url': full,
                            'headers': {},
                            'query': dict(parse_qsl(parsed.query)),
                            'body': None,
                            'json': None
                        })
                self._emit_decision({
                    'event_type': 'crawler_bundle_complete',
                    'url': getattr(self.driver, 'current_url', None),
                    'script_url': observed_script_url,
                    'duration_ms': round((time.monotonic() - started_at) * 1000),
                    'size_bytes': analysis.get('size_bytes', 0),
                    'discovered_endpoints': len(analysis.get('internal_api_endpoints', [])),
                    'sink_count': sum(len(analysis.get(category, [])) for category in signal_categories),
                })
            else:
                self._emit_decision({
                    'event_type': 'crawler_bundle_unavailable',
                    'url': getattr(self.driver, 'current_url', None),
                    'script_url': observed_script_url,
                    'duration_ms': round((time.monotonic() - started_at) * 1000),
                })
        except Exception as error:
            self._emit_decision({
                'event_type': 'crawler_bundle_error',
                'url': getattr(self.driver, 'current_url', None),
                'script_url': observed_script_url,
                'duration_ms': round((time.monotonic() - started_at) * 1000),
                'error': str(error),
            })

    def crawl(self) -> List[Dict[str, Any]]:
        """Start a priority-frontier crawl with template-aware sampling."""
        self._start_driver()
        try:
            if self._target_obj and self._target_obj.auth_info:
                if not self._authenticate():
                    return self.requests
                self._execute_declared_workflows()
            frontier: List[tuple[int, int, str, int, List[str]]] = []
            enqueued: Set[str] = set()
            order = 0

            def enqueue(candidate: str, depth: int) -> None:
                nonlocal order
                if depth > self.max_depth or not self._is_safe_url(candidate):
                    return
                key = self._canonical_crawl_key(candidate)
                if key in enqueued or key in self.visited:
                    return
                template = self._route_template(candidate)
                if self.route_template_counts.get(template, 0) >= self.template_sample_limit:
                    skipped = {
                        'event_type': 'crawler_template_skipped',
                        'url': candidate,
                        'depth': depth,
                        'route_template': template,
                        'reason': f"sample_limit_{self.template_sample_limit}_reached",
                    }
                    self.skipped_template_urls.append(skipped)
                    self._emit_decision(skipped)
                    return
                score, reasons = self._url_priority(candidate, depth)
                score -= self.route_template_counts.get(template, 0) * 35
                order += 1
                heapq.heappush(frontier, (-score, order, candidate, depth, reasons))
                enqueued.add(key)
                self.frontier_peak = max(self.frontier_peak, len(frontier))

            enqueue(self.base_url, 0)
            while frontier and len(self.visited) < self.max_pages:
                negative_score, _, page_url, depth, reasons = heapq.heappop(frontier)
                key = self._canonical_crawl_key(page_url)
                template = self._route_template(page_url)
                if key in self.visited:
                    continue
                if self.route_template_counts.get(template, 0) >= self.template_sample_limit:
                    skipped = {
                        'event_type': 'crawler_template_skipped',
                        'url': page_url,
                        'depth': depth,
                        'route_template': template,
                        'priority_score': -negative_score,
                        'reason': f"sample_limit_{self.template_sample_limit}_reached",
                    }
                    self.skipped_template_urls.append(skipped)
                    self._emit_decision(skipped)
                    continue
                self.route_template_counts[template] = self.route_template_counts.get(template, 0) + 1
                self._emit_decision({
                    'event_type': 'crawler_url_selected',
                    'url': page_url,
                    'depth': depth,
                    'route_template': template,
                    'priority_score': -negative_score,
                    'priority_reasons': reasons,
                    'frontier_size': len(frontier),
                })
                discovered = self._crawl_page(page_url, depth) or []
                for child_url in discovered:
                    enqueue(child_url, depth + 1)

            self._emit_decision({
                'event_type': 'crawler_frontier_complete',
                'visited_pages': len(self.visited),
                'page_budget': self.max_pages,
                'frontier_remaining': len(frontier),
                'frontier_peak': self.frontier_peak,
                'route_templates': len(self.route_template_counts),
                'template_urls_skipped': len(self.skipped_template_urls),
                'feature_fingerprints': len(self.feature_fingerprint_counts),
                'stop_reason': 'page_budget_reached' if len(self.visited) >= self.max_pages else 'frontier_exhausted',
            })
        finally:
            if self.driver:
                try:
                    self.driver.quit()
                except Exception:
                    pass
        return self.requests

    def _authenticate(self) -> bool:
        """Establish or renew the configured browser identity."""
        from backend_api.services.auth_session_service import (
            AuthConfigurationError,
            AuthSessionService,
            HumanInterventionRequired,
        )

        try:
            self.auth_session = AuthSessionService.authenticate_selenium(
                self.driver,
                self.base_url,
                self._target_obj.auth_info,
                self.auth_identity,
            )
            self.auth_identity = self.auth_session.get("label") or self.auth_identity
            self.research_signals.append({
                "kind": "authenticated_session",
                "identity": self.auth_identity,
                "role": self.auth_session.get("role"),
                "authenticated": bool(self.auth_session.get("authenticated")),
            })
            return bool(self.auth_session.get("authenticated"))
        except (HumanInterventionRequired, AuthConfigurationError) as challenge:
            self.interventions.append({
                "kind": "authentication_challenge" if isinstance(challenge, HumanInterventionRequired) else "authentication_configuration",
                "identity": getattr(challenge, "identity", None) or self.auth_identity,
                "reason": getattr(challenge, "reason", str(challenge)),
                "url": getattr(challenge, "url", None),
            })
            logger.warning(
                "Authenticated crawl paused for operator intervention: %s",
                getattr(challenge, "reason", str(challenge)),
            )
            return False

    def _execute_declared_workflows(self) -> None:
        """Complete operator-declared safe state-building workflows before graph crawl."""
        from backend_api.services.auth_session_service import AuthSessionService

        identity = self.auth_identity or AuthSessionService.material(self._target_obj.auth_info).label
        material = AuthSessionService.material(self.auth_session or self._target_obj.auth_info)
        for workflow in AuthSessionService.workflows_for(self._target_obj.auth_info, identity):
            try:
                AuthSessionService.execute_selenium_steps(
                    self.driver,
                    self.base_url,
                    material,
                    workflow["steps"],
                )
                current_url = self.driver.current_url
                if self._is_safe_url(current_url):
                    parsed = urlparse(current_url)
                    self._save_request({
                        "method": "GET",
                        "url": current_url,
                        "headers": {},
                        "query": dict(parse_qsl(parsed.query)),
                        "body": None,
                        "json": None,
                    })
                self._harvest_background_api_traffic()
                self.research_signals.append({
                    "kind": "workflow_completed",
                    "name": workflow.get("name") or "unnamed",
                    "identity": identity,
                    "final_url": current_url,
                })
            except Exception as error:
                self.interventions.append({
                    "kind": "workflow_blocked",
                    "identity": identity,
                    "reason": str(error),
                    "url": getattr(self.driver, "current_url", None),
                    "workflow": workflow.get("name") or "unnamed",
                })
                logger.warning("Declared workflow %s could not complete: %s", workflow.get("name"), error)
                break

    def _crawl_page(self, url: str, depth: int) -> List[str]:
        """Crawl a single page comprehensively."""
        if depth > self.max_depth or len(self.visited) >= self.max_pages:
            return []

        normalized = self._canonical_crawl_key(url)
        if normalized in self.visited:
            return []

        self.visited.add(normalized)
        page_started = time.monotonic()
        logger.info(f"[*] Crawling page: {url} (depth={depth}, visited={len(self.visited)})")
        if self.progress_callback:
            try:
                self.progress_callback(url, depth, len(self.visited), self.max_pages)
            except Exception:
                logger.debug("Crawler progress callback failed", exc_info=True)

        try:
            # Rate limiter integration
            try:
                from backend_api.utils.rate_limiter import CircuitOpenError, rate_limiter
                self._emit_decision({'event_type': 'crawler_rate_wait_started', 'url': url, 'depth': depth})
                rate_limiter.wait_for_slot(url)
            except CircuitOpenError:
                logger.warning(f"[-] Circuit breaker blocks navigation to {url}")
                return
            except Exception:
                pass

            self.driver.get(url)
            self._emit_decision({
                'event_type': 'crawler_navigation_complete',
                'url': url,
                'final_url': self.driver.current_url,
                'duration_ms': round((time.monotonic() - page_started) * 1000),
            })

            if self._target_obj and self._target_obj.auth_info:
                from backend_api.services.auth_session_service import AuthSessionService

                if AuthSessionService.is_auth_wall(
                    final_url=self.driver.current_url,
                    body_text=self.driver.page_source or "",
                    login_url_patterns=(self.auth_session or {}).get("login_url_patterns") or (),
                ):
                    if not self._authenticate():
                        return
                    rate_limiter.wait_for_slot(url)
                    try:
                        self.driver.get(url)
                    except Exception:
                        rate_limiter.report_error(url)
                        raise
                    else:
                        rate_limiter.report_success(url)
                    if AuthSessionService.is_auth_wall(
                        final_url=self.driver.current_url,
                        body_text=self.driver.page_source or "",
                        login_url_patterns=(self.auth_session or {}).get("login_url_patterns") or (),
                    ):
                        self.interventions.append({
                            "kind": "session_expired",
                            "identity": self.auth_identity,
                            "reason": "Session remained on the login wall after automatic renewal",
                            "url": self.driver.current_url,
                        })
                        return

                barrier = AuthSessionService.operational_barrier_reason(
                    None, self.driver.page_source or ""
                )
                if barrier:
                    self.interventions.append({
                        "kind": "anti_bot_barrier",
                        "identity": self.auth_identity,
                        "reason": barrier,
                        "url": self.driver.current_url,
                    })
                    return

            try:
                from backend_api.utils.rate_limiter import rate_limiter
                rate_limiter.report_success(url)
            except Exception:
                pass

            # Save visited page
            current_url = self.driver.current_url
            parsed_current = urlparse(current_url)
            self._save_request({
                'method': 'GET',
                'url': current_url,
                'headers': {},
                'query': dict(parse_qsl(parsed_current.query)),
                'body': None,
                'json': None,
                'response_body': self.driver.page_source or "",
            })

            # Dismiss modals & wait for SPA hydration
            self._dismiss_consent_and_modals()
            time.sleep(self.delay)

            # Harvest real-time background API traffic & DOM XSS telemetry
            self._harvest_background_api_traffic()
            self._harvest_dom_telemetry()

            feature_fingerprint, feature_summary = self._page_feature_fingerprint()
            feature_count = self.feature_fingerprint_counts.get(feature_fingerprint, 0) + 1
            self.feature_fingerprint_counts[feature_fingerprint] = feature_count
            self.research_signals.append({
                'kind': 'page_feature_fingerprint',
                'url': current_url,
                'route_template': self._route_template(current_url),
                'fingerprint': feature_fingerprint,
                'occurrence': feature_count,
                'features': feature_summary,
            })

            # Discover links and SPA routes
            next_urls = []
            next_urls.extend(self._extract_framework_routes())
            next_urls.extend(self._extract_all_links_and_attributes())
            self._emit_decision({
                'event_type': 'crawler_links_extracted',
                'url': current_url,
                'candidate_links': len(set(next_urls)),
                'feature_fingerprint': feature_fingerprint,
            })

            # Once the same executable/input shape has been sampled twice, retain
            # its request evidence but avoid repeated interaction and bundle work.
            if feature_count > self.template_sample_limit:
                self._emit_decision({
                    'event_type': 'crawler_feature_duplicate',
                    'url': current_url,
                    'feature_fingerprint': feature_fingerprint,
                    'occurrence': feature_count,
                    'action': 'skip_expensive_interactions',
                })
                return next_urls

            # Interactive exploration
            self._interact_with_spa_elements()
            self._harvest_background_api_traffic()
            self._emit_decision({
                'event_type': 'crawler_interactions_complete',
                'url': current_url,
                'captured_requests': len(self.requests),
            })

            # Client-side router history
            try:
                spa_routes = self.driver.execute_script("return window._spa_routes || [];")
                if spa_routes and isinstance(spa_routes, list):
                    for sr in spa_routes:
                        if self._is_safe_url(sr) and sr not in next_urls:
                            next_urls.append(sr)
            except Exception:
                pass

            # Analyze script chunks
            try:
                scripts = self.driver.find_elements(By.TAG_NAME, "script")
                bundles_analyzed = 0
                bundle_deadline = time.monotonic() + 18.0
                for s in scripts:
                    if time.monotonic() >= bundle_deadline:
                        self._emit_decision({
                            'event_type': 'crawler_bundle_budget_exhausted',
                            'url': current_url,
                            'analyzed': bundles_analyzed,
                            'budget_seconds': 18,
                        })
                        break
                    src = s.get_attribute("src")
                    if src and src.startswith(('http://', 'https://')):
                        parsed_src = urlparse(src)
                        parsed_base = urlparse(self.base_url)
                        if (
                            parsed_src.netloc == parsed_base.netloc
                            and src not in self._analyzed_scripts
                            and bundles_analyzed < self.script_bundle_limit
                        ):
                            self._analyze_script_bundle(src)
                            bundles_analyzed += 1
                            if bundles_analyzed >= self.script_bundle_limit:
                                break
            except Exception:
                pass

            self._emit_decision({
                'event_type': 'crawler_page_complete',
                'url': current_url,
                'depth': depth,
                'route_template': self._route_template(current_url),
                'feature_fingerprint': feature_fingerprint,
                'discovered_links': len(set(next_urls)),
                'saved_endpoints': len(self.saved_endpoint_ids),
                'captured_requests': len(self.requests),
                'duration_ms': round((time.monotonic() - page_started) * 1000),
            })
            return list(dict.fromkeys(next_urls))

        except TimeoutException:
            try:
                rate_limiter.report_error(url)
            except Exception:
                pass
            logger.warning(f"Timeout crawling {url}")
            self._emit_decision({'event_type': 'crawler_page_timeout', 'url': url, 'depth': depth, 'duration_ms': round((time.monotonic() - page_started) * 1000)})
        except Exception as e:
            try:
                rate_limiter.report_error(url)
            except Exception:
                pass
            logger.warning(f"Error crawling {url}: {e}")
            self._emit_decision({
                'event_type': 'crawler_page_error',
                'url': url,
                'depth': depth,
                'error': str(e),
                'duration_ms': round((time.monotonic() - page_started) * 1000),
            })
        return []

    def crawl_to_database(self, target_id: int, db_session) -> int:
        """Crawl and import endpoints to database in real-time."""
        self.target_id = target_id
        self.db_session = db_session
        try:
            from backend_api.models.target import Target
            self._target_obj = db_session.query(Target).filter(Target.id == target_id).first()
        except Exception:
            pass

        self.crawl()
        return len(self.saved_endpoint_ids)

    def close(self):
        """Safely shut down the browser driver."""
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
            self.driver = None
