import unittest
from unittest.mock import MagicMock, patch
import json

from backend_api.models.target import Target
from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param


class MockResponse:
    def __init__(self, content: bytes, status: int = 200, headers: dict = None):
        self.content = content
        self.status = status
        self.status_code = status
        self.headers = headers or {"Content-Type": "application/json"}
        
    def read(self):
        return self.content

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class TestUltimateRecon(unittest.TestCase):

    def setUp(self):
        from recon_engine.advanced_recon import AdvancedRecon
        self.AdvancedRecon = AdvancedRecon

    def test_noise_filter(self):
        """Verify static media files are filtered out while APIs and dynamic endpoints remain."""
        db = MagicMock()
        target = Target(id=1, base_url="https://example.com")
        db.query().filter().first.return_value = target
        recon = self.AdvancedRecon(db, 1)

        # Static assets without query params -> filtered
        self.assertFalse(recon._is_relevant_url("https://example.com/image.png"))
        self.assertFalse(recon._is_relevant_url("https://example.com/styles.css"))
        self.assertFalse(recon._is_relevant_url("https://example.com/font.woff2"))
        self.assertFalse(recon._is_relevant_url("https://example.com/video.mp4"))

        # Dynamic endpoints or scripts -> preserved
        self.assertTrue(recon._is_relevant_url("https://example.com/api/v1/user"))
        self.assertTrue(recon._is_relevant_url("https://example.com/cart/checkout"))
        self.assertTrue(recon._is_relevant_url("https://example.com/runtime.js"))
        self.assertTrue(recon._is_relevant_url("https://example.com/image.png?url=http://evil.com"))

    @patch("urllib.request.urlopen")
    def test_multi_source_passive_osint(self, mock_urlopen):
        """Verify Wayback, AlienVault OTX, and URLScan sources are parsed concurrently."""
        def urlopen_side_effect(req, timeout=None):
            url = req.full_url if hasattr(req, 'full_url') else str(req)
            if "web.archive.org" in url:
                data = [["original"], ["https://example.com/archive-endpoint"]]
                return MockResponse(json.dumps(data).encode("utf-8"))
            elif "alienvault.com" in url:
                data = {"url_list": [{"url": "https://example.com/otx-endpoint?id=1"}]}
                return MockResponse(json.dumps(data).encode("utf-8"))
            elif "urlscan.io" in url:
                data = {"results": [{"page": {"url": "https://example.com/urlscan-endpoint"}}]}
                return MockResponse(json.dumps(data).encode("utf-8"))
            return MockResponse(b"{}", status=404)

        mock_urlopen.side_effect = urlopen_side_effect

        db = MagicMock()
        target = Target(id=1, base_url="https://example.com")
        db.query().filter().first.return_value = target
        recon = self.AdvancedRecon(db, 1)

        urls = recon.fetch_passive_urls("https://example.com")
        self.assertIn("https://example.com/archive-endpoint", urls)
        self.assertIn("https://example.com/otx-endpoint?id=1", urls)
        self.assertIn("https://example.com/urlscan-endpoint", urls)

    def test_robots_and_sitemaps_harvesting(self):
        """Verify robots.txt and sitemap.xml endpoints are harvested."""
        def fetch_side_effect(url, **_kwargs):
            if "robots.txt" in url:
                return "User-agent: *\nDisallow: /private-admin\nAllow: /checkout-portal\nSitemap: https://example.com/sitemap.xml\n"
            elif "sitemap.xml" in url:
                return '<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://example.com/sitemap-route-1</loc></url></urlset>'
            return ""

        db = MagicMock()
        target = Target(id=1, base_url="https://example.com")
        db.query().filter().first.return_value = target
        recon = self.AdvancedRecon(db, 1)
        recon._fetch_active_text = MagicMock(side_effect=fetch_side_effect)

        urls = recon.fetch_robots_and_sitemaps("https://example.com")
        self.assertIn("https://example.com/private-admin", urls)
        self.assertIn("https://example.com/checkout-portal", urls)
        self.assertIn("https://example.com/sitemap-route-1", urls)

    def test_openapi_spec_probe(self):
        """Verify OpenAPI/Swagger specifications are parsed for endpoints."""
        def fetch_side_effect(url, **_kwargs):
            if "openapi.json" in url:
                spec = {
                    "openapi": "3.0.0",
                    "paths": {
                        "/api/v1/auth/callback": {"get": {}},
                        "/api/v1/checkout/redirect": {"post": {}}
                    }
                }
                return json.dumps(spec)
            return ""

        db = MagicMock()
        target = Target(id=1, base_url="https://example.com")
        db.query().filter().first.return_value = target
        recon = self.AdvancedRecon(db, 1)
        recon._fetch_active_text = MagicMock(side_effect=fetch_side_effect)

        urls = recon.probe_api_specs("https://example.com")
        self.assertIn("https://example.com/api/v1/auth/callback", urls)
        self.assertIn("https://example.com/api/v1/checkout/redirect", urls)


if __name__ == "__main__":
    unittest.main()
