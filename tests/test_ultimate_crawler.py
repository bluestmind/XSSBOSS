import pytest
from urllib.parse import urlparse
from unittest.mock import MagicMock, patch

from recon_engine.crawler import Crawler, STEALTH_TELEMETRY_SCRIPT


def test_telemetry_script_integrity():
    """Verify stealth telemetry script contains all necessary modern hooks."""
    assert "_xssboss_api_traffic" in STEALTH_TELEMETRY_SCRIPT
    assert "_xssboss_dom_telemetry" in STEALTH_TELEMETRY_SCRIPT
    assert "_spa_routes" in STEALTH_TELEMETRY_SCRIPT
    assert "window.fetch" in STEALTH_TELEMETRY_SCRIPT
    assert "XMLHttpRequest.prototype.open" in STEALTH_TELEMETRY_SCRIPT
    assert "Element.prototype, 'innerHTML'" in STEALTH_TELEMETRY_SCRIPT
    assert "document.write" in STEALTH_TELEMETRY_SCRIPT
    assert "HTMLAnchorElement.prototype, 'href'" in STEALTH_TELEMETRY_SCRIPT
    assert "history.pushState" in STEALTH_TELEMETRY_SCRIPT


def test_crawler_destructive_url_blacklist():
    """Verify destructive endpoints like logout or delete are rejected."""
    crawler = Crawler("https://example.com")
    
    assert crawler._is_safe_url("https://example.com/api/v1/user") is True
    assert crawler._is_safe_url("https://example.com/cart/checkout") is True
    assert crawler._is_safe_url("https://example.com/api/logout") is False
    assert crawler._is_safe_url("https://example.com/auth/sign-out") is False
    assert crawler._is_safe_url("https://example.com/account/delete") is False
    assert crawler._is_safe_url("https://example.com/user/cancel-subscription") is False


def test_crawler_external_domain_isolation():
    """Verify crawler does not leak onto external out-of-scope origins."""
    crawler = Crawler("https://marketplace.porsche.com", follow_external=False)
    
    assert crawler._is_safe_url("https://marketplace.porsche.com/api/cart") is True
    assert crawler._is_safe_url("https://google-analytics.com/collect") is False
    assert crawler._is_safe_url("https://evil.com/leak") is False


def test_harvest_background_api_traffic():
    """Verify background fetch/XHR traffic is ingested with JSON and query parameters."""
    crawler = Crawler("https://marketplace.porsche.com")
    crawler.driver = MagicMock()
    
    # Mock intercepted fetch call from SPA
    crawler.driver.execute_script.return_value = [
        {
            "type": "fetch",
            "method": "POST",
            "url": "https://marketplace.porsche.com/api/checkout/cart/redirect?listingId=052R4E&originUrl=https://evil.com",
            "headers": {"Content-Type": "application/json"},
            "body": '{"action": "redirect", "token": "abc"}'
        }
    ]
    
    crawler._harvest_background_api_traffic()
    
    assert len(crawler.requests) == 1
    req = crawler.requests[0]
    assert req["method"] == "POST"
    assert "originUrl" in req["query"]
    assert req["json"] == {"action": "redirect", "token": "abc"}


def test_extract_framework_routes():
    """Verify Next.js and Nuxt.js client routes are introspected."""
    crawler = Crawler("https://marketplace.porsche.com")
    crawler.driver = MagicMock()
    crawler.driver.current_url = "https://marketplace.porsche.com/home"
    
    crawler.driver.execute_script.return_value = [
        "/de/de_DE/cart/checkout",
        "/vehicle/detail?id=123"
    ]
    
    routes = crawler._extract_framework_routes()
    assert "https://marketplace.porsche.com/de/de_DE/cart/checkout" in routes
    assert "https://marketplace.porsche.com/vehicle/detail?id=123" in routes


def test_crawler_groups_content_instances_but_preserves_feature_routes():
    assert Crawler._route_template("https://example.com/blog/first-post") == "/blog/:item"
    assert Crawler._route_template("https://example.com/blog/second-post") == "/blog/:item"
    assert Crawler._route_template("https://example.com/jobs/search?q=security") == "/jobs/search?q="
    assert Crawler._route_template("https://example.com/callback?next=/home") == "/callback?next="


def test_crawler_canonical_key_deduplicates_values_not_parameter_surfaces():
    first = Crawler._canonical_crawl_key("https://example.com/search?q=one&page=1")
    second = Crawler._canonical_crawl_key("https://example.com/search?page=9&q=two")
    distinct = Crawler._canonical_crawl_key("https://example.com/search?redirect=/home")
    assert first == second
    assert first != distinct


def test_query_and_security_feature_routes_receive_higher_priority():
    content_score, _ = Crawler._url_priority("https://example.com/blog/a-post", 1)
    search_score, reasons = Crawler._url_priority("https://example.com/search?q=test", 1)
    assert search_score > content_score
    assert "query_parameters" in reasons
    assert any(reason.startswith("feature_route:") for reason in reasons)
    research_score, research_reasons = Crawler._url_priority(
        "https://example.com/product-design-research", 1
    )
    assert research_score == content_score
    assert not any(reason.startswith("feature_route:") for reason in research_reasons)
    job_score, job_reasons = Crawler._url_priority(
        "https://example.com/jobs/staff-search-engineer", 2
    )
    assert job_score < search_score
    assert not any(reason.startswith("feature_route:search") for reason in job_reasons)
