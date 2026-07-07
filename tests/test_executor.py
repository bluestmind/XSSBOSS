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
            mock_uc.return_value = mock_driver
            
            # Start
            executor.start()
            
            # Verify undetected_chromedriver was called
            mock_uc.assert_called_once()
            self.assertIsNotNone(executor.uc_driver)
            self.assertEqual(executor.uc_driver, mock_driver)
            
            # Stop
            executor.stop()
            mock_driver.quit.assert_called_once()
            self.assertIsNone(executor.uc_driver)

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
