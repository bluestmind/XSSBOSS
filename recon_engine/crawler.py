"""Ultimate modern Selenium-based security crawler with CDP telemetry, API interception, and DOM XSS sensing."""
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

    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        max_pages: int = 100,
        delay: float = 0.5,
        follow_external: bool = False
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

    def _start_driver(self):
        """Start Selenium Chrome driver with stealth options and CDP telemetry hooks."""
        options = SeleniumConfig.get_chrome_options()
        try:
            self.driver = webdriver.Chrome(options=options)
        except Exception:
            try:
                driver_path = ChromeDriverManager().install()
                service = ChromeService(executable_path=driver_path)
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

        self.driver.set_page_load_timeout(SeleniumConfig.NAVIGATION_TIMEOUT)
        self.driver.implicitly_wait(SeleniumConfig.ACTION_TIMEOUT)

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

        self.requests.append(request_data)
        if self.db_session and self.target_id:
            try:
                from backend_api.services.recon_service import ReconService
                endpoint = ReconService.create_endpoint_from_request(
                    self.db_session,
                    self.target_id,
                    request_data['method'],
                    request_data['url'],
                    request_data
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
            for elem in interactive_elements[:5]:
                try:
                    if elem.get_attribute("type") in ("submit", "reset"):
                        continue
                    if elem.tag_name.lower() == "a" or elem.get_attribute("href"):
                        continue
                    text = (elem.text or elem.get_attribute("aria-label") or "").lower()
                    if any(kw in text for kw in self.DESTRUCTIVE_KEYWORDS):
                        continue
                    elem.click()
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
        if script_url in self._analyzed_scripts:
            return
        self._analyzed_scripts.add(script_url)

        try:
            from recon_engine.bundle_analyzer import BundleAnalyzer
            content = None

            # First attempt stealth download via active browser driver to bypass Akamai/Cloudflare
            if self.driver:
                try:
                    fetch_code = f"""
                        var callback = arguments[arguments.length - 1];
                        fetch('{script_url}')
                            .then(r => r.text())
                            .then(text => callback({{success: true, content: text}}))
                            .catch(err => callback({{success: false, error: String(err)}}));
                    """
                    res = self.driver.execute_async_script(fetch_code)
                    if res and res.get("success"):
                        content = res.get("content")
                except Exception:
                    pass

            # Fallback to direct HTTP client if browser fetch is unavailable
            if not content:
                import httpx
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                with httpx.Client(timeout=6, verify=False, headers=headers) as client:
                    res = client.get(script_url)
                    if res.status_code == 200:
                        content = res.text

            if content:
                analysis = BundleAnalyzer.analyze_script_content(script_url, content)
                signal_categories = (
                    "dom_sources", "dom_sinks", "navigation_sinks", "eval_sinks",
                    "postmessage_listeners", "sensitive_tokens", "prototype_pollution",
                    "sanitizers",
                )
                self.research_signals.append({
                    "kind": "client_bundle",
                    "script_url": script_url,
                    "size_bytes": analysis.get("size_bytes", 0),
                    "discovered_endpoints": list(analysis.get("internal_api_endpoints", []))[:50],
                    "counts": {
                        category: len(analysis.get(category, []))
                        for category in signal_categories
                    },
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
        except Exception:
            pass

    def crawl(self) -> List[Dict[str, Any]]:
        """Start dynamic crawl session."""
        self._start_driver()
        try:
            self._crawl_page(self.base_url, depth=0)
        finally:
            if self.driver:
                try:
                    self.driver.quit()
                except Exception:
                    pass
        return self.requests

    def _crawl_page(self, url: str, depth: int):
        """Crawl a single page comprehensively."""
        if depth > self.max_depth or len(self.visited) >= self.max_pages:
            return

        parsed = urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if normalized in self.visited:
            return

        self.visited.add(normalized)
        logger.info(f"[*] Crawling page: {url} (depth={depth}, visited={len(self.visited)})")

        try:
            # Rate limiter integration
            try:
                from backend_api.utils.rate_limiter import CircuitOpenError, rate_limiter
                rate_limiter.wait_for_slot(url)
            except CircuitOpenError:
                logger.warning(f"[-] Circuit breaker blocks navigation to {url}")
                return
            except Exception:
                pass

            self.driver.get(url)

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
                'json': None
            })

            # Dismiss modals & wait for SPA hydration
            self._dismiss_consent_and_modals()
            time.sleep(self.delay)

            # Harvest real-time background API traffic & DOM XSS telemetry
            self._harvest_background_api_traffic()
            self._harvest_dom_telemetry()

            # Discover links and SPA routes
            next_urls = []
            next_urls.extend(self._extract_framework_routes())
            next_urls.extend(self._extract_all_links_and_attributes())

            # Interactive exploration
            self._interact_with_spa_elements()
            self._harvest_background_api_traffic()

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
                for s in scripts:
                    src = s.get_attribute("src")
                    if src and src.startswith(('http://', 'https://')):
                        parsed_src = urlparse(src)
                        parsed_base = urlparse(self.base_url)
                        if parsed_src.netloc == parsed_base.netloc:
                            self._analyze_script_bundle(src)
            except Exception:
                pass

            # Crawl discovered child URLs
            for child_url in next_urls:
                if len(self.visited) >= self.max_pages:
                    break
                child_norm = f"{urlparse(child_url).scheme}://{urlparse(child_url).netloc}{urlparse(child_url).path}"
                if child_norm not in self.visited and depth < self.max_depth:
                    self._crawl_page(child_url, depth + 1)

        except TimeoutException:
            logger.warning(f"Timeout crawling {url}")
        except Exception as e:
            logger.warning(f"Error crawling {url}: {e}")

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
