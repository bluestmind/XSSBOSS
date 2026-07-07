import pytest
from unittest.mock import patch, MagicMock
from backend_api.utils.filter_profiler import FilterProfiler
from backend_api.utils.scope_guard import is_url_in_scope
from backend_api.models.target import Target

class TestCoupangImprovements:
    """Test suite for edge defense bypasses and Coupang Taiwan scope handling."""

    def test_coupang_scope_wildcards(self):
        """Verify that all Coupang Taiwan subdomains match the configured scope."""
        target = Target(
            name="Coupang Taiwan",
            base_url="https://www.tw.coupang.com",
            scope_tags={
                "allowed_hosts": [
                    "www.tw.coupang.com",
                    "marketplace.tw.coupangcorp.com",
                    "helpcenter-tw.coupangcorp.com",
                    "tw.coupangcorp.com",
                    "tw.coupangls.com"
                ]
            }
        )

        assert is_url_in_scope(target, "https://www.tw.coupang.com/article/returns-policy")
        assert is_url_in_scope(target, "https://marketplace.tw.coupangcorp.com/tw/s/")
        assert is_url_in_scope(target, "https://helpcenter-tw.coupangcorp.com/hc/zh-tw/search?query=test")
        assert is_url_in_scope(target, "https://tw.coupangcorp.com/?s=test")
        assert is_url_in_scope(target, "https://tw.coupangls.com/")
        assert not is_url_in_scope(target, "https://evil.com/phish")
        assert not is_url_in_scope(target, "https://coupang.kr")

    def test_filter_profiler_browser_fallback_on_403(self):
        """Verify FilterProfiler activates headless browser fallback on HTTP 403."""
        mock_httpx_resp = MagicMock()
        mock_httpx_resp.status_code = 403
        mock_httpx_resp.text = "<html>Access Denied</html>"
        mock_httpx_resp.headers = {"server": "AkamaiGHost"}

        with patch("httpx.request", return_value=mock_httpx_resp):
            with patch("selenium.webdriver.Chrome") as mock_chrome_cls:
                mock_driver = MagicMock()
                mock_driver.title = "Search Results - Coupang"
                mock_driver.page_source = "<html><body>Search Results for \"xss'xss\"</body></html>"
                mock_chrome_cls.return_value = mock_driver

                res = FilterProfiler.send_probe(
                    method="GET",
                    url="https://tw.coupangcorp.com/?s=",
                    param_name="s",
                    param_value="xss'xss",
                    param_location="query",
                    headers={},
                    cookies={},
                    base_body=None,
                    base_json=None,
                    timeout=5
                )

                assert res["status_code"] == 200
                assert res["reflected"] is True
                assert mock_chrome_cls.called

    def test_filter_profiler_handles_normal_200(self):
        """Verify FilterProfiler processes direct 200 responses without spawning browser."""
        mock_httpx_resp = MagicMock()
        mock_httpx_resp.status_code = 200
        mock_httpx_resp.text = "<html><body>xss'xss</body></html>"
        mock_httpx_resp.headers = {"content-type": "text/html"}

        with patch("httpx.request", return_value=mock_httpx_resp):
            with patch("selenium.webdriver.Chrome") as mock_chrome_cls:
                res = FilterProfiler.send_probe(
                    method="GET",
                    url="https://example.com/?q=",
                    param_name="q",
                    param_value="xss'xss",
                    param_location="query",
                    headers={},
                    cookies={},
                    base_body=None,
                    base_json=None,
                    timeout=5
                )

                assert res["status_code"] == 200
                assert res["reflected"] is True
                assert not mock_chrome_cls.called
