"""Playwright execution engine."""
import time
import json
from typing import Dict, Any, Optional, List
from pathlib import Path
from urllib.parse import quote

from playwright.sync_api import sync_playwright
from browser_workers.selenium_config import SeleniumConfig
from browser_workers.oracle_inject import get_oracle_script
from backend_api.utils.logger import logger
from backend_api.config import settings
from backend_api.utils.stealth import (
    get_next_user_agent,
    get_random_waf_bypass_headers,
    get_next_proxy
)


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
    def _capture_enabled(mode: str, oracle_hit: bool) -> bool:
        """Return whether evidence should be captured for this execution."""
        normalized = (mode or "").strip().lower()
        if normalized in {"all", "true", "1", "yes", "on"}:
            return True
        if normalized == "hits":
            return oracle_hit
        return False
    
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
                options.add_argument('--no-sandbox')
                options.add_argument('--disable-setuid-sandbox')
                options.add_argument('--disable-dev-shm-usage')
                options.add_argument('--disable-web-security')
                options.add_argument('--ignore-certificate-errors')
                
                if settings.PROXY_URL:
                    options.add_argument(f"--proxy-server={settings.PROXY_URL}")
                
                # Fetch browser logging capabilities
                from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
                caps = DesiredCapabilities.CHROME.copy()
                caps['goog:loggingPrefs'] = {'browser': 'ALL'}
                
                self.uc_driver = uc.Chrome(options=options, desired_capabilities=caps, version_main=149)
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
                
                proxy = None
                if settings.PROXY_URL:
                    proxy = {"server": settings.PROXY_URL}
                    
                self.browser = self.playwright.chromium.launch(
                    headless=True,
                    args=args,
                    proxy=proxy
                )
                logger.info("Browser executor started using Playwright")
            except Exception as err:
                logger.error(f"Failed to start Playwright browser: {err}", exc_info=True)
                raise err

    def stop(self):
        """Stop browser instance."""
        if self.uc_driver:
            try:
                self.uc_driver.quit()
            except Exception as e:
                logger.error(f"Error closing UC driver: {e}")
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
        if settings.USE_UNDETECTED_CHROME:
            return self._execute_test_case_uc(test_case_data, screenshot_dir)

        if not self.browser:
            self.start()
            
        start_time = time.time()
        oracle_hit = False
        oracle_message = None
        console_messages = []
        page_errors = []
        
        # Rotating proxy, User-Agent, and WAF bypass headers
        rotated_proxy = get_next_proxy()
        proxy_opt = None
        if rotated_proxy:
            proxy_opt = {"server": rotated_proxy}
        elif settings.PROXY_URL:
            proxy_opt = {"server": settings.PROXY_URL}

        # Fresh isolated browser context
        context = self.browser.new_context(
            user_agent=get_next_user_agent(),
            viewport={"width": SeleniumConfig.VIEWPORT_WIDTH, "height": SeleniumConfig.VIEWPORT_HEIGHT},
            ignore_https_errors=True,
            proxy=proxy_opt,
            extra_http_headers=get_random_waf_bypass_headers()
        )
        context.set_default_navigation_timeout(SeleniumConfig.NAVIGATION_TIMEOUT * 1000)
        context.set_default_timeout(SeleniumConfig.ACTION_TIMEOUT * 1000)
        
        if settings.BYPASS_CSP:
            def strip_csp(route):
                try:
                    response = route.fetch()
                    headers = response.headers
                    for k in list(headers.keys()):
                        if k.lower() in ('content-security-policy', 'content-security-policy-report-only', 'x-webkit-csp', 'x-content-security-policy'):
                            del headers[k]
                    route.fulfill(response=response, headers=headers)
                except Exception:
                    try:
                        route.continue_()
                    except Exception:
                        pass
            context.route("**/*", strip_csp)
        
        # Inject the oracle script into every new page/iframe document
        oracle_script = get_oracle_script()
        init_payload = f"""
            window.__XSS_TOKEN__ = {json.dumps(test_case_data['token'])};
            window.__ORACLE_URL__ = {json.dumps(self.oracle_url)};
            window.__XSS_FAKE_MESSAGE_ORIGIN__ = {json.dumps(test_case_data.get('fake_message_origin'))};
            {oracle_script}
        """
        context.add_init_script(init_payload)
        
        # Set up a new page inside context
        page = context.new_page()
        
        # Event listeners for log capture and response header extraction
        response_status = None
        response_headers = {}

        def on_console(msg):
            nonlocal oracle_hit, oracle_message
            text = msg.text
            console_messages.append({
                'type': msg.type.upper(),
                'text': text
            })
            if 'XSS Oracle: Execution detected' in text:
                oracle_hit = True
                oracle_message = text
                
        def on_page_error(err):
            page_errors.append(err.message)

        def on_response(res):
            nonlocal response_status, response_headers
            try:
                # Capture the main navigation request or anything hitting the target URL
                if res.request.is_navigation_request() or test_case_data.get('url', '') in res.url:
                    response_status = res.status
                    response_headers = {k.lower(): v for k, v in res.headers.items()}
            except Exception:
                pass
            
        page.on("console", on_console)
        page.on("pageerror", on_page_error)
        page.on("response", on_response)
        
        url = test_case_data['url']
        method = test_case_data.get('method', 'GET').upper()
        cookies = test_case_data.get('cookies', {})
        params = test_case_data.get('params', {})
        body = test_case_data.get('body')
        json_data = test_case_data.get('json')
        
        # Attach query parameters
        if params:
            from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl
            url_parts = list(urlparse(url))
            query = dict(parse_qsl(url_parts[4]))
            query.update(params)
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
                
            # Perform navigation or custom sequence steps execution
            steps = test_case_data.get('steps')
            if steps:
                self._execute_custom_steps(page, steps, test_case_data.get('payload', ''))
            elif method == 'GET':
                page.goto(url)
            elif method == 'POST':
                if json_data:
                    post_script = f"""
                        var xhr = new XMLHttpRequest();
                        xhr.open('POST', '{url}', false);
                        xhr.setRequestHeader('Content-Type', 'application/json');
                        xhr.send(JSON.stringify({json.dumps(json_data)}));
                        document.open();
                        document.write(xhr.responseText);
                        document.close();
                    """
                    page.evaluate(post_script)
                elif body:
                    form_html = f"""
                        var form = document.createElement('form');
                        form.id = 'xss_post_form';
                        form.method = 'POST';
                        form.action = '{url}';
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
                    page.evaluate(form_html)
                    time.sleep(1.0) # Transition
                else:
                    post_script = f"""
                        var xhr = new XMLHttpRequest();
                        xhr.open('POST', '{url}', false);
                        xhr.send();
                        document.open();
                        document.write(xhr.responseText);
                        document.close();
                    """
                    page.evaluate(post_script)
            else:
                # Other methods (PUT, DELETE, etc.)
                request_script = f"""
                    var xhr = new XMLHttpRequest();
                    xhr.open('{method}', '{url}', false);
                    xhr.send({json.dumps(body) if body else 'null'});
                    document.open();
                    document.write(xhr.responseText);
                    document.close();
                """
                page.evaluate(request_script)
                
            # If a stored_view_url is specified (Stored XSS path), execute secondary navigation step
            stored_view_url = test_case_data.get('stored_view_url')
            if stored_view_url:
                time.sleep(0.5)  # Let server-side persistence write finish
                page.goto(stored_view_url)

            # Trigger interactive event handlers (Unique technique: Automated DOM Event Fuzzing + postMessage Auditing)
            try:
                interaction_script = """
                    (function() {
                        try {
                            var token = window.__XSS_TOKEN__;
                            if (!token) return;
                            
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

                            // 2. Dispatch cross-origin and intra-frame messages to force registered postMessage listeners
                            try {
                                var msgPayloads = [
                                    token,
                                    JSON.stringify({ type: 'xss', data: token, payload: token, message: token }),
                                    { type: 'xss', data: token, payload: token, message: token }
                                ];
                                for (var m = 0; m < msgPayloads.length; m++) {
                                    window.postMessage(msgPayloads[m], '*');
                                }
                            } catch (msgErr) {}
                        } catch (err) {}
                    })();
                """
                page.evaluate(interaction_script)
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
            
            # Map page console warnings and errors
            for entry in console_messages:
                msg_text = entry.get('text', '')
                msg_text_lower = msg_text.lower()
                if entry.get('type') == 'ERROR' or any(kw in msg_text_lower for kw in ['error', 'exception', 'syntax', 'unexpected', 'invalid', 'csp', 'violation', 'blocked', 'refused', 'unpermitted']):
                    page_errors.append(msg_text)
                    
        except Exception as e:
            logger.error(f"Error during page execution: {e}", exc_info=True)
            
        duration_ms = int((time.time() - start_time) * 1000)
        
        # Capture screenshot
        screenshot_path = None
        if screenshot_dir and self._capture_enabled(settings.CAPTURE_SCREENSHOTS, oracle_hit):
            screenshot_dir.mkdir(parents=True, exist_ok=True)
            screenshot_path = screenshot_dir / f"test_case_{test_case_data.get('test_case_id', 'unknown')}.png"
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

        try:
            context.close()
        except Exception:
            pass

        logs = {
            'console': console_messages[:50],
            'errors': list(set(page_errors))[:20],
            'tech_stack': tech_stack,
        }
        
        return {
            'oracle_hit': oracle_hit,
            'oracle_message': oracle_message,
            'duration_ms': duration_ms,
            'screenshot_path': str(screenshot_path) if screenshot_path else None,
            'dom_snapshot': dom_snapshot[:settings.DOM_SNAPSHOT_MAX_CHARS] if dom_snapshot else None,
            'logs': logs,
            'status_code': response_status or 200,
            'headers': response_headers,
            'final_url': final_url,
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

        # Rotating proxy, User-Agent, and WAF bypass headers
        rotated_proxy = get_next_proxy()
        proxy_opt = None
        if rotated_proxy:
            proxy_opt = {"server": rotated_proxy}
        elif settings.PROXY_URL:
            proxy_opt = {"server": settings.PROXY_URL}

        context = self.browser.new_context(
            user_agent=get_next_user_agent(),
            viewport={"width": SeleniumConfig.VIEWPORT_WIDTH, "height": SeleniumConfig.VIEWPORT_HEIGHT},
            ignore_https_errors=True,
            proxy=proxy_opt,
            extra_http_headers=get_random_waf_bypass_headers()
        )
        context.set_default_navigation_timeout(SeleniumConfig.NAVIGATION_TIMEOUT * 1000)
        context.set_default_timeout(SeleniumConfig.ACTION_TIMEOUT * 1000)

        if settings.BYPASS_CSP:
            def strip_csp(route):
                try:
                    response = route.fetch()
                    headers = response.headers
                    for k in list(headers.keys()):
                        if k.lower() in ('content-security-policy', 'content-security-policy-report-only', 'x-webkit-csp', 'x-content-security-policy'):
                            del headers[k]
                    route.fulfill(response=response, headers=headers)
                except Exception:
                    try:
                        route.continue_()
                    except Exception:
                        pass
            context.route("**/*", strip_csp)

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
            if 'XSS Oracle: Execution detected' in text:
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

        # Set up console log monitoring hook (We can poll browser log levels)
        url = test_case_data['url']
        method = test_case_data.get('method', 'GET').upper()
        cookies = test_case_data.get('cookies', {})
        params = test_case_data.get('params', {})
        body = test_case_data.get('body')
        json_data = test_case_data.get('json')

        # Attach query parameters
        if params:
            from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl
            url_parts = list(urlparse(url))
            query = dict(parse_qsl(url_parts[4]))
            query.update(params)
            url_parts[4] = urlencode(query)
            url = urlunparse(url_parts)

        try:
            # Undetected Chromedriver cookies require domain navigation first
            if cookies:
                # Navigate to about:blank or dummy page on domain if possible, or just navigate first
                self.uc_driver.get(url)
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
                self.uc_driver.get("about:blank")
                if json_data:
                    post_script = f"""
                        var xhr = new XMLHttpRequest();
                        xhr.open('POST', '{url}', false);
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
                        form.action = '{url}';
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
                        xhr.open('POST', '{url}', false);
                        xhr.send();
                        document.open();
                        document.write(xhr.responseText);
                        document.close();
                    """
                    self.uc_driver.execute_script(post_script)
            else:
                self.uc_driver.get("about:blank")
                request_script = f"""
                    var xhr = new XMLHttpRequest();
                    xhr.open('{method}', '{url}', false);
                    xhr.send({json.dumps(body) if body else 'null'});
                    document.open();
                    document.write(xhr.responseText);
                    document.close();
                """
                self.uc_driver.execute_script(request_script)

            stored_view_url = test_case_data.get('stored_view_url')
            if stored_view_url:
                time.sleep(0.5)
                self.uc_driver.get(stored_view_url)

            # Trigger interactive events
            try:
                interaction_script = """
                    (function() {
                        try {
                            var token = window.__XSS_TOKEN__;
                            if (!token) return;
                            
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
                                    token,
                                    JSON.stringify({ type: 'xss', data: token, payload: token, message: token }),
                                    { type: 'xss', data: token, payload: token, message: token }
                                ];
                                for (var m = 0; m < msgPayloads.length; m++) {
                                    window.postMessage(msgPayloads[m], '*');
                                }
                            } catch (msgErr) {}
                        } catch (err) {}
                    })();
                """
                self.uc_driver.execute_script(interaction_script)
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

            # Retrieve browser logs
            try:
                for entry in self.uc_driver.get_log('browser'):
                    text = entry.get('message', '')
                    console_messages.append({
                        'type': entry.get('level', 'INFO'),
                        'text': text
                    })
                    if 'XSS Oracle: Execution detected' in text:
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
            logger.error(f"Error during UC page execution: {e}", exc_info=True)

        duration_ms = int((time.time() - start_time) * 1000)

        # Capture screenshot
        screenshot_path = None
        if screenshot_dir and self._capture_enabled(settings.CAPTURE_SCREENSHOTS, oracle_hit):
            screenshot_dir.mkdir(parents=True, exist_ok=True)
            screenshot_path = screenshot_dir / f"test_case_{test_case_data.get('test_case_id', 'unknown')}.png"
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

        return {
            'oracle_hit': oracle_hit,
            'oracle_message': oracle_message,
            'duration_ms': duration_ms,
            'screenshot_path': str(screenshot_path) if screenshot_path else None,
            'dom_snapshot': dom_snapshot[:settings.DOM_SNAPSHOT_MAX_CHARS] if dom_snapshot else None,
            'logs': {
                'console': console_messages[:50],
                'errors': list(set(page_errors))[:20],
                'tech_stack': {},
            },
            'status_code': 200,
            'headers': {},
            'final_url': final_url,
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
                    if 'XSS Oracle: Execution detected' in text:
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
