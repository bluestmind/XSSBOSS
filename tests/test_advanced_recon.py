import unittest
from unittest.mock import MagicMock, patch
import json

from backend_api.models.target import Target
from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from recon_engine.advanced_recon import AdvancedRecon

class MockResponse:
    def __init__(self, content, status_code=200):
        self.content = content
        self.status_code = status_code
        
    def read(self):
        return self.content

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

class TestAdvancedRecon(unittest.TestCase):
    
    @patch("urllib.request.urlopen")
    def test_fetch_archive_urls(self, mock_urlopen):
        mock_data = [
            ["original"],
            ["http://example.com/page1"],
            ["http://example.com/page2?debug=true"]
        ]
        mock_response = MockResponse(json.dumps(mock_data).encode("utf-8"))
        mock_urlopen.return_value = mock_response
        
        db = MagicMock()
        target = Target(id=1, base_url="http://example.com")
        db.query().filter().first.return_value = target
        
        recon = AdvancedRecon(db, 1)
        urls = recon.fetch_archive_urls("http://example.com")
        
        self.assertEqual(len(urls), 2)
        self.assertEqual(urls[0], "http://example.com/page1")
        self.assertEqual(urls[1], "http://example.com/page2?debug=true")

    @patch("urllib.request.urlopen")
    def test_discover_and_parse_js(self, mock_urlopen):
        js_content = b"""
        const api1 = "/api/v1/user";
        let api2 = '/api/v2/config?admin=1';
        let val = getParameterByName("jsquery");
        let id = searchParams.get("testparam");
        let arg = queryParams['myparam'];
        """
        mock_urlopen.return_value = MockResponse(js_content)
        
        db = MagicMock()
        target = Target(id=1, base_url="http://example.com")
        db.query().filter().first.return_value = target
        
        mock_ep = Endpoint(id=10, target_id=1, method="GET", url_pattern="http://example.com/assets/main.js")
        mock_html_ep = Endpoint(id=11, target_id=1, method="GET", url_pattern="http://example.com/")
        db.query().filter().all.return_value = [mock_ep, mock_html_ep]
        
        # Mock database queries inside Param check
        db.query().filter().first.return_value = None
        
        recon = AdvancedRecon(db, 1)
        js_links = recon.discover_and_parse_js("http://example.com")
        
        self.assertEqual(len(js_links), 2)
        self.assertTrue(any("/api/v1/user" in link for link in js_links))
        self.assertTrue(any("/api/v2/config" in link for link in js_links))
        
        # Verify db.add was called to save the mined parameters
        self.assertTrue(db.add.called)

if __name__ == "__main__":
    unittest.main()
