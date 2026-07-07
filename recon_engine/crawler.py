"""Selenium-based headless crawler."""
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service as ChromeService
from browser_workers.selenium_config import SeleniumConfig


class Crawler:
    """Headless web crawler using Selenium."""
    
    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        max_pages: int = 100,
        delay: float = 1.0,
        follow_external: bool = False
    ):
        """Initialize crawler."""
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.delay = delay
        self.follow_external = follow_external
        self.visited: Set[str] = set()
        self.requests: List[Dict[str, Any]] = []
        self.driver = None
        self.db_session = None
        self.target_id = None
        
    def _start_driver(self):
        """Helper to start driver instance."""
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
        
        # Inject SPA routing hooks via Chrome DevTools Protocol
        try:
            self.driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
                'source': """
                    window._spa_routes = window._spa_routes || [];
                    const origPush = history.pushState;
                    history.pushState = function(state, title, url) {
                        if (url) {
                            window._spa_routes.push(new URL(url, location.href).href);
                        }
                        return origPush.apply(this, arguments);
                    };
                    const origReplace = history.replaceState;
                    history.replaceState = function(state, title, url) {
                        if (url) {
                            window._spa_routes.push(new URL(url, location.href).href);
                        }
                        return origReplace.apply(this, arguments);
                    };
                    window.addEventListener('hashchange', function() {
                        window._spa_routes.push(location.href);
                    });
                """
            })
        except Exception as e:
            print(f"[-] Crawler: failed to inject SPA router hooks: {e}")

        self.driver.set_page_load_timeout(SeleniumConfig.NAVIGATION_TIMEOUT)
        self.driver.implicitly_wait(SeleniumConfig.ACTION_TIMEOUT)
        
    def _save_request(self, request_data: Dict[str, Any]):
        """Append to request list and save to DB in real-time if configured."""
        self.requests.append(request_data)
        if self.db_session and self.target_id:
            try:
                from backend_api.services.recon_service import ReconService
                ReconService.create_endpoint_from_request(
                    self.db_session,
                    self.target_id,
                    request_data['method'],
                    request_data['url'],
                    request_data
                )
            except Exception as e:
                print(f"Error importing crawled request on-the-fly: {e}")

    def crawl(self) -> List[Dict[str, Any]]:
        """Start crawling."""
        self._start_driver()
        try:
            self._crawl_page(self.base_url, depth=0)
        finally:
            if self.driver:
                self.driver.quit()
        return self.requests
        
    def _crawl_page(
        self,
        url: str,
        depth: int
    ):
        """Crawl a single page."""
        print(f"[*] Crawling page: {url} (depth={depth}, visited={len(self.visited)})")
        if depth > self.max_depth:
            return
        
        if len(self.visited) >= self.max_pages:
            return
        
        # Normalize URL
        parsed = urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        if normalized in self.visited:
            return
        
        self.visited.add(normalized)
        
        try:
            try:
                from backend_api.utils.rate_limiter import rate_limiter, CircuitOpenError
                rate_limiter.wait_for_slot(url)
            except CircuitOpenError as cb_err:
                print(f"[-] Crawler: circuit breaker blocks navigation to {url}: {cb_err}")
                return
            except Exception:
                pass

            # Navigate to page
            self.driver.get(url)
            
            try:
                from backend_api.utils.rate_limiter import rate_limiter
                rate_limiter.report_success(url)
            except Exception:
                pass
            
            # Store the navigated page as a discovered GET endpoint
            parsed_current = urlparse(url)
            query_params = dict(parse_qsl(parsed_current.query))
            self._save_request({
                'method': 'GET',
                'url': url,
                'headers': {},
                'query': query_params,
                'body': None,
                'json': None
            })
            
            # Wait a bit
            time.sleep(self.delay)
            
            # Extract links
            links = self.driver.find_elements(By.TAG_NAME, "a")
            hrefs = []
            for link in links:
                try:
                    href = link.get_attribute("href")
                    if href:
                        hrefs.append(href)
                except Exception:
                    continue
                    
            # Interactive SPA State-Space Auditing (Click buttons/interactive elements to trigger history changes)
            try:
                interactive_elements = self.driver.find_elements(By.CSS_SELECTOR, "button, [role='button'], input[type='button']")
                original_page_url = self.driver.current_url
                for element in interactive_elements[:15]:
                    try:
                        element.click()
                        time.sleep(0.1)
                        if self.driver.current_url != original_page_url:
                            self.driver.execute_script("window.history.back();")
                            time.sleep(0.1)
                    except Exception:
                        continue
            except Exception as e:
                print(f"Error executing interactive SPA crawling: {e}")

            # Extract client-side SPA routes from CDP telemetry
            try:
                spa_routes = self.driver.execute_script("return window._spa_routes || [];")
                for r in spa_routes:
                    if r and r not in hrefs:
                        hrefs.append(r)
            except Exception as e:
                print(f"Error fetching SPA routes: {e}")

            # Extract scripts (for advanced JS routes / parameters discovery)
            scripts = self.driver.find_elements(By.TAG_NAME, "script")
            for script in scripts:
                try:
                    src = script.get_attribute("src")
                    if src:
                        full_src = urljoin(url, src)
                        parsed_src = urlparse(full_src)
                        parsed_base = urlparse(self.base_url)
                        if parsed_src.netloc == parsed_base.netloc:
                            self._save_request({
                                'method': 'GET',
                                'url': full_src,
                                'headers': {},
                                'query': {},
                                'body': None,
                                'json': None
                            })
                except Exception:
                    continue

            # Extract forms
            forms = self.driver.find_elements(By.TAG_NAME, "form")
            for form in forms:
                try:
                    self._extract_form(form, url)
                except Exception as e:
                    print(f"Error extracting form: {e}")

            # Extract iframes — the vulnerable page may live inside a frame
            iframes = self.driver.find_elements(By.TAG_NAME, "iframe")
            for iframe in iframes:
                try:
                    src = iframe.get_attribute("src")
                    if src:
                        full_src = urljoin(url, src)
                        parsed_src = urlparse(full_src)
                        parsed_base = urlparse(self.base_url)
                        if self.follow_external or parsed_src.netloc == parsed_base.netloc:
                            if full_src not in hrefs:
                                hrefs.append(full_src)
                except Exception:
                    continue

            # Recursively crawl extracted links
            for href in hrefs:
                # Resolve relative URLs
                full_url = urljoin(url, href)
                
                # Check if external
                parsed_base = urlparse(self.base_url)
                parsed_link = urlparse(full_url)
                
                if not self.follow_external:
                    if parsed_link.netloc != parsed_base.netloc:
                        continue
                
                if full_url not in self.visited and depth < self.max_depth:
                    self._crawl_page(full_url, depth + 1)
                    
        except TimeoutException:
            print(f"Timeout crawling {url}")
            try:
                from backend_api.utils.rate_limiter import rate_limiter
                rate_limiter.report_error(url, is_rate_limit=False)
            except Exception:
                pass
        except Exception as e:
            print(f"Error crawling {url}: {e}")
            try:
                from backend_api.utils.rate_limiter import rate_limiter
                rate_limiter.report_error(url, is_rate_limit=False)
            except Exception:
                pass
            
    def _extract_form(self, form, base_url: str):
        """Extract form data."""
        action = form.get_attribute("action") or ""
        method = form.get_attribute("method") or "GET"
        full_url = urljoin(base_url, action)
        print(f"[+] Discovered form: {method.upper()} {full_url}")
        
        # Extract form fields
        inputs = form.find_elements(By.CSS_SELECTOR, "input, textarea, select")
        form_data = {}
        
        for input_elem in inputs:
            try:
                name = input_elem.get_attribute("name")
                input_type = input_elem.get_attribute("type") or "text"
                value = input_elem.get_attribute("value") or ""
                
                if name and input_type != "submit":
                    form_data[name] = value
            except Exception:
                continue
                
        # Store form request
        self._save_request({
            'method': method.upper(),
            'url': full_url,
            'headers': {},
            'query': form_data if method.upper() == 'GET' else {},
            'body': form_data if method.upper() != 'GET' else None,
            'json': None
        })
        
    def crawl_to_database(
        self,
        target_id: int,
        db_session
    ) -> int:
        """Crawl and import to database on-the-fly."""
        self.target_id = target_id
        self.db_session = db_session
        
        # This will trigger crawlings and save to database on-the-fly
        self.crawl()
        
        return len(self.requests)
