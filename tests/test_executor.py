import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path
from browser_workers.executor import BrowserExecutor
from backend_api.config import settings

class BrowserExecutorTests(unittest.TestCase):
    
    @patch('undetected_chromedriver.Chrome')
    def test_executor_uses_undetected_chrome_when_configured(self, mock_uc):
        # Configure setting
        with patch.object(settings, 'USE_UNDETECTED_CHROME', True):
            executor = BrowserExecutor(oracle_url="http://localhost:8001/api/v1/oracle")
            
            # Mock instances
            mock_driver = MagicMock()
            quit_mock = mock_driver.quit
            mock_uc.return_value = mock_driver
            
            # Start
            executor.start()
            
            # Verify undetected_chromedriver was called
            mock_uc.assert_called_once()
            self.assertIsNotNone(executor.uc_driver)
            self.assertEqual(executor.uc_driver, mock_driver)
            
            # Stop
            executor.stop()
            quit_mock.assert_called_once()
            self.assertIsNone(executor.uc_driver)

            # A repeated/destructor cleanup is a no-op, not a second quit.
            mock_driver.quit()
            quit_mock.assert_called_once()

    @patch('undetected_chromedriver.Chrome')
    def test_execute_test_case_uc_registers_cdp_and_navigates(self, mock_uc):
        with patch.object(settings, 'USE_UNDETECTED_CHROME', True):
            executor = BrowserExecutor(oracle_url="http://localhost:8001/api/v1/oracle")
            mock_driver = MagicMock()
            mock_uc.return_value = mock_driver
            
            # Setup logs mock
            mock_driver.get_log.return_value = [
                {'level': 'INFO', 'message': 'XSS Oracle: Execution detected in innerHTML', 'timestamp': 123456789}
            ]
            
            test_case_data = {
                'token': 'test_token',
                'payload': '<svg onload=__XSS__("test_token")>',
                'url': 'http://example.com/target',
                'method': 'GET',
                'cookies': {'session': 'abc'}
            }
            
            res = executor.execute_test_case(test_case_data)
            
            # Verify CDP script registration
            mock_driver.execute_cdp_cmd.assert_any_call(
                'Page.addScriptToEvaluateOnNewDocument',
                unittest.mock.ANY
            )
            
            # Verify navigate was called
            mock_driver.get.assert_called_with('http://example.com/target')
            
            # Verify cookies were added
            mock_driver.add_cookie.assert_called_with({'name': 'session', 'value': 'abc'})

            # postMessage sinks must receive the generated payload, not merely
            # the inert oracle token.
            self.assertTrue(any(
                len(call.args) == 2
                and 'msgPayloads' in call.args[0]
                and call.args[1] == test_case_data['payload']
                for call in mock_driver.execute_script.call_args_list
            ))
            
            # Verify execution result mapping
            self.assertTrue(res['oracle_hit'])
            self.assertIn('XSS Oracle: Execution detected', res['oracle_message'])

    @patch('browser_workers.executor.get_random_waf_bypass_headers')
    def test_prepare_browser_headers_preserves_auth_and_filters_transport_headers(self, mock_bypass):
        mock_bypass.return_value = {
            'Authorization': 'bypass-value',
            'X-Forwarded-For': '127.0.0.1',
        }

        headers, user_agent = BrowserExecutor._prepare_browser_headers({
            'headers': {
                'authorization': 'Bearer real-session',
                'User-Agent': 'BugBountyBrowser/1.0',
                'Cookie': 'session=handled-separately',
                'Host': 'attacker.invalid',
                'X-CSRF-Token': 'csrf-value',
            }
        })

        self.assertEqual(headers['authorization'], 'Bearer real-session')
        self.assertEqual(headers['X-CSRF-Token'], 'csrf-value')
        self.assertEqual(headers['X-Forwarded-For'], '127.0.0.1')
        self.assertNotIn('Authorization', headers)
        self.assertNotIn('Cookie', headers)
        self.assertNotIn('Host', headers)
        self.assertEqual(user_agent, 'BugBountyBrowser/1.0')

    def test_non_get_navigation_preserves_method_body_and_response_context(self):
        page = MagicMock()
        route = MagicMock()
        route.request.is_navigation_request.return_value = True
        route.request.headers = {'accept': 'text/html', 'content-length': '999'}

        BrowserExecutor._navigate_with_method(
            page=page,
            url='https://example.com/profile',
            method='POST',
            headers={'Authorization': 'Bearer token'},
            json_data={'display_name': '<svg/onload=x>'},
        )

        intercept = page.route.call_args.args[1]
        intercept(route)
        route.continue_.assert_called_once_with(
            method='POST',
            headers={
                'accept': 'text/html',
                'Authorization': 'Bearer token',
                'Content-Type': 'application/json',
            },
            post_data='{"display_name": "<svg/onload=x>"}',
        )
        page.goto.assert_called_once_with('https://example.com/profile')
        page.unroute.assert_called_once_with('**/*', intercept)

    def test_top_level_navigation_guard_enforces_program_and_temporary_auth_scope(self):
        case = {
            'url': 'https://app.example.test/public/search',
            'target_base_url': 'https://app.example.test',
            'target_scope_tags': {
                'in_scope': ['https://app.example.test/public/*'],
                'out_of_scope': ['https://app.example.test/public/admin/*'],
            },
            'auth_spec': {
                'allowed_auth_origins': ['https://login.example.test'],
            },
        }

        self.assertTrue(BrowserExecutor._navigation_url_allowed(
            case, 'https://app.example.test/public/profile'
        ))
        self.assertFalse(BrowserExecutor._navigation_url_allowed(
            case, 'https://app.example.test/public/admin/users'
        ))
        self.assertFalse(BrowserExecutor._navigation_url_allowed(
            case, 'https://login.example.test/start'
        ))
        self.assertTrue(BrowserExecutor._navigation_url_allowed(
            case, 'https://login.example.test/start', allow_auth_origin=True
        ))
        self.assertFalse(BrowserExecutor._navigation_url_allowed(
            case, 'https://attacker.invalid/'
        ))

    @patch('psutil.wait_procs', return_value=([], []))
    @patch('psutil.Process')
    def test_uc_cleanup_terminates_only_matching_profile_tree(self, process_factory, wait_procs):
        root = MagicMock()
        child = MagicMock()
        root.cmdline.return_value = [
            'chrome.exe',
            '--user-data-dir=C:\\Temp\\xssboss-owned-profile',
        ]
        root.children.return_value = [child]
        process_factory.return_value = root
        driver = MagicMock()
        driver.browser_pid = 4242
        driver.user_data_dir = 'C:\\Temp\\xssboss-owned-profile'

        BrowserExecutor._terminate_owned_uc_tree(driver)

        child.terminate.assert_called_once()
        root.terminate.assert_called_once()
        wait_procs.assert_called_once()

    @patch('psutil.Process')
    def test_uc_cleanup_refuses_mismatched_profile(self, process_factory):
        root = MagicMock()
        root.cmdline.return_value = ['chrome.exe', '--user-data-dir=C:\\Users\\normal-profile']
        process_factory.return_value = root
        driver = MagicMock()
        driver.browser_pid = 4242
        driver.user_data_dir = 'C:\\Temp\\xssboss-owned-profile'

        BrowserExecutor._terminate_owned_uc_tree(driver)

        root.terminate.assert_not_called()

    def test_uc_cleanup_detaches_only_matching_finalizer(self):
        from weakref import finalize

        Driver = type('Driver', (), {})
        driver = Driver()
        other = Driver()
        matching = finalize(driver, lambda value: None, driver)
        unrelated = finalize(other, lambda value: None, other)

        BrowserExecutor._detach_uc_finalizer(driver)

        self.assertFalse(matching.alive)
        self.assertTrue(unrelated.alive)
        unrelated.detach()

    def test_uc_trusted_click_only_activates_token_javascript_links(self):
        matching = MagicMock()
        matching.get_attribute.return_value = "javascript:__XSS__('expected-token')"
        unrelated = MagicMock()
        unrelated.get_attribute.return_value = "javascript:applicationAction()"
        driver = MagicMock()
        driver.find_elements.return_value = [matching, unrelated]

        BrowserExecutor._click_token_javascript_links_uc(driver, "expected-token")

        matching.click.assert_called_once_with()
        unrelated.click.assert_not_called()

    @patch('undetected_chromedriver.Chrome')
    def test_query_param_strips_empty_dummy_parameters_in_uc(self, mock_uc):
        with patch.object(settings, 'USE_UNDETECTED_CHROME', True):
            executor = BrowserExecutor(oracle_url="http://localhost:8001/api/v1/oracle")
            mock_driver = MagicMock()
            mock_uc.return_value = mock_driver
            mock_driver.get_log.return_value = []

            test_case_data = {
                'token': 'test_token',
                'url': 'https://www.semrush.com/?q=&search=&redirect=&id=&next=&query=&debug=&callback=',
                'method': 'GET',
                'param_name': 'q',
                'params': {'q': '<svg/onload=__XSS__(\'test_token\')>'},
            }

            executor.execute_test_case(test_case_data)

            # Ensure driver navigated to clean single-param URL without empty dummy param soup
            mock_driver.get.assert_called_once()
            called_url = mock_driver.get.call_args[0][0]
            self.assertIn("q=%3Csvg%2Fonload%3D__XSS__%28%27test_token%27%29%3E", called_url)
            self.assertNotIn("search=", called_url)
            self.assertNotIn("redirect=", called_url)
            self.assertNotIn("debug=", called_url)

    @patch('requests.head')
    @patch('requests.get')
    def test_preflight_check_https_fallback_and_reachability(self, mock_get, mock_head):
        from backend_api.utils.stealth import preflight_check
        import requests

        def side_effect(url, **kwargs):
            if url.startswith("http://"):
                raise requests.exceptions.ConnectionError("Failed to connect to http port 80")
            resp = MagicMock()
            resp.status_code = 200
            resp.url = url
            resp.headers = {}
            return resp

        mock_head.side_effect = side_effect
        mock_get.side_effect = side_effect

        res = preflight_check("http://all-inclusive.marriott.com")
        self.assertTrue(res["reachable"])
        self.assertEqual(res["effective_url"], "https://all-inclusive.marriott.com")
        self.assertIsNone(res["error"])
