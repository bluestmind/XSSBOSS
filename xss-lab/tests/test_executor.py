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
            mock_driver.execute_cdp_cmd.assert_called_with(
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
