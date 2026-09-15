from __future__ import annotations

from xsscollector.parsers import parse_css, parse_html, parse_javascript, parse_openapi, parse_robots, parse_sitemap


def test_html_collects_routes_forms_and_technology() -> None:
    result = parse_html("""
      <html><head><title> Inventory </title><script>fetch('/api/v1/items?limit=10')</script></head>
      <body><a href='/users/42'>User</a><form method='post' action='/search'>
      <input name='query'><input name='csrf_token'></form></body></html>
    """, "https://example.com/")
    assert result.title == "Inventory"
    assert "https://example.com/users/42" in result.urls
    assert ("POST", "https://example.com/search", "html-form") in result.endpoint_hints
    assert any(item[0] == "csrf_token" for values in result.endpoint_parameters.values() for item in values)
    assert "https://example.com/api/v1/items?limit=10" in result.urls


def test_openapi_is_inventory_only() -> None:
    result = parse_openapi({"openapi": "3.1.0", "paths": {"/users/{id}": {"get": {"parameters": [{"name": "id", "in": "path"}]}, "delete": {}}}}, "https://api.example.com/openapi.json")
    assert ("GET", "https://api.example.com/users/{id}", "openapi") in result.endpoint_hints
    assert ("DELETE", "https://api.example.com/users/{id}", "openapi") in result.endpoint_hints
    assert ("id", "path", "unknown") in result.endpoint_parameters["GET https://api.example.com/users/{id}"]


def test_robots_and_sitemap() -> None:
    maps, denied = parse_robots("User-agent: *\nDisallow: /private\nSitemap: https://example.com/map.xml")
    assert denied == {"/private"}
    assert maps == {"https://example.com/map.xml"}
    assert parse_sitemap("<urlset><url><loc>https://example.com/a</loc></url></urlset>") == {"https://example.com/a"}


def test_html_and_css_collect_broad_asset_surface() -> None:
    result = parse_html("""
      <link rel='stylesheet' href='/assets/app.css'>
      <style>@import '/theme.css'; .hero { background:url('/hero.png') }</style>
      <img src='/small.png' srcset='/medium.png 2x, /large.png 3x'>
      <video poster='/poster.jpg'><source src='/movie.webm'></video>
      <button onclick="location.assign('/next')">Next</button>
      <meta http-equiv='refresh' content='0; url=/login'>
    """, "https://example.com/page/")
    assert "https://example.com/assets/app.css" in result.asset_urls
    assert "https://example.com/theme.css" in result.asset_urls
    assert "https://example.com/large.png" in result.asset_urls
    assert "https://example.com/movie.webm" in result.asset_urls
    assert "https://example.com/login" in result.urls
    assert result.inline_scripts == ["location.assign('/next')"]

    css = parse_css("@import url('./base.css'); a{background:url(../img/a.svg)} /*# sourceMappingURL=app.css.map */", "https://example.com/css/app.css")
    assert css.asset_urls == {
        "https://example.com/css/base.css",
        "https://example.com/img/a.svg",
        "https://example.com/css/app.css.map",
    }
