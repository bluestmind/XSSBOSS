"""Passive parsers for HTML, CSS, JavaScript, XML sitemaps, robots, and OpenAPI."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit

from .models import ParsedDocument

URL_RE = re.compile(r"(?:(?:https?:)?//[^\s'\"<>]+|/(?:api|graphql|rest|v\d|assets|static)/[A-Za-z0-9_./?&=%{}:-]*)")
FETCH_RE = re.compile(r"(?:fetch|axios\.(?:get|post|put|patch|delete)|\.open)\s*\(\s*['\"]([^'\"]+)", re.I)
ROUTE_RE = re.compile(r"(?:path|url|endpoint|route)\s*:\s*['\"]([^'\"]+)['\"]", re.I)
CSS_URL_RE = re.compile(r"url\(\s*(['\"]?)(.*?)\1\s*\)", re.I | re.S)
CSS_IMPORT_RE = re.compile(r"@import\s+(?!url\()['\"]([^'\"]+)['\"]", re.I)
SOURCE_MAP_RE = re.compile(r"[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)", re.I)

ASSET_ATTRIBUTES = {
    "script": ("src",), "link": ("href",), "img": ("src",), "source": ("src",),
    "video": ("src", "poster"), "audio": ("src",), "track": ("src",),
    "embed": ("src",), "object": ("data",), "input": ("src",),
}


def _web_url(base_url: str, candidate: str) -> str | None:
    value = candidate.strip().strip("'\"")
    if not value or value.startswith(("#", "data:", "blob:", "javascript:", "mailto:", "tel:", "about:")):
        return None
    url = urljoin(base_url, value)
    return url if urlsplit(url).scheme.lower() in {"http", "https"} and urlsplit(url).netloc else None


def _record_url(result: ParsedDocument, base_url: str, candidate: str, key: str, asset: bool = False) -> str | None:
    url = _web_url(base_url, candidate)
    if not url:
        return None
    result.urls.add(url)
    if asset:
        result.asset_urls.add(url)
    result.observations.append(("asset-reference" if asset else "document-reference", key, url, 1.0))
    return url


class _HTMLInventoryParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.result = ParsedDocument()
        self._title = False
        self._title_parts: list[str] = []
        self._current_form: dict[str, Any] | None = None
        self._inline_script = False
        self._script_parts: list[str] = []
        self._inline_style = False
        self._style_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag == "base" and values.get("href"):
            base = _web_url(self.base_url, values["href"])
            if base:
                self.base_url = base
        for attribute in ASSET_ATTRIBUTES.get(tag, ()):
            if values.get(attribute):
                _record_url(self.result, self.base_url, values[attribute], f"{tag}.{attribute}", asset=True)
        if tag in {"a", "area"} and values.get("href"):
            _record_url(self.result, self.base_url, values["href"], f"{tag}.href")
        if tag == "iframe" and values.get("src"):
            _record_url(self.result, self.base_url, values["src"], "iframe.src")
        if values.get("data-url"):
            _record_url(self.result, self.base_url, values["data-url"], f"{tag}.data-url")
        for attribute in ("srcset", "imagesrcset"):
            for candidate in self._srcset(values.get(attribute, "")):
                _record_url(self.result, self.base_url, candidate, f"{tag}.{attribute}", asset=True)
        if values.get("style"):
            parse_css(values["style"], self.base_url, self.result, source=f"{tag}.style")
        for name, value in values.items():
            if name.startswith("on") and value.strip():
                self.result.inline_scripts.append(value)
                parse_javascript(value, self.base_url, self.result)
        if tag == "title":
            self._title = True
        elif tag == "form":
            action = urljoin(self.base_url, values.get("action") or self.base_url)
            method = (values.get("method") or "GET").upper()
            self._current_form = {"url": action, "method": method}
            self.result.endpoint_hints.append((method, action, "html-form"))
            if method == "GET":
                self.result.urls.add(action)
        elif self._current_form is not None and tag in {"input", "textarea", "select", "button"}:
            if values.get("name"):
                key = f"{self._current_form['method']} {self._current_form['url']}"
                self.result.endpoint_parameters.setdefault(key, []).append(
                    (values["name"], "body" if self._current_form["method"] != "GET" else "query", values.get("type"))
                )
        elif tag == "script" and not values.get("src"):
            self._inline_script = True
            self._script_parts = []
        elif tag == "style":
            self._inline_style = True
            self._style_parts = []
        elif tag == "meta":
            name = values.get("name") or values.get("property") or values.get("http-equiv")
            if name and values.get("content"):
                self.result.observations.append(("html-meta", name.lower(), values["content"][:1000], 1.0))
            if values.get("http-equiv", "").lower() == "refresh":
                match = re.search(r"(?:^|;)\s*url\s*=\s*(.+)$", values.get("content", ""), re.I)
                if match:
                    _record_url(self.result, self.base_url, match.group(1), "meta.refresh")

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._title = False
            self.result.title = " ".join("".join(self._title_parts).split())[:500]
        elif tag == "form":
            self._current_form = None
        elif tag == "script" and self._inline_script:
            script = "".join(self._script_parts)
            self.result.inline_scripts.append(script)
            parse_javascript(script, self.base_url, self.result)
            self._inline_script = False
        elif tag == "style" and self._inline_style:
            parse_css("".join(self._style_parts), self.base_url, self.result, source="style-block")
            self._inline_style = False

    def handle_data(self, data: str) -> None:
        if self._title:
            self._title_parts.append(data)
        if self._inline_script:
            self._script_parts.append(data)
        if self._inline_style:
            self._style_parts.append(data)

    @staticmethod
    def _srcset(value: str) -> list[str]:
        if not value or value.lstrip().lower().startswith("data:"):
            return []
        return [part.strip().split()[0] for part in value.split(",") if part.strip()]


def parse_html(text: str, base_url: str) -> ParsedDocument:
    parser = _HTMLInventoryParser(base_url)
    parser.feed(text)
    return parser.result


def parse_css(text: str, base_url: str, result: ParsedDocument | None = None, source: str = "css") -> ParsedDocument:
    """Inventory CSS imports, resources, and source maps without rendering the stylesheet."""
    result = result or ParsedDocument()
    candidates = [match[1] for match in CSS_URL_RE.findall(text)]
    candidates.extend(CSS_IMPORT_RE.findall(text))
    candidates.extend(SOURCE_MAP_RE.findall(text))
    for candidate in dict.fromkeys(candidates):
        _record_url(result, base_url, candidate, source, asset=True)
    return result


def parse_javascript(text: str, base_url: str, result: ParsedDocument | None = None) -> ParsedDocument:
    result = result or ParsedDocument()
    candidates = set(URL_RE.findall(text)) | set(FETCH_RE.findall(text)) | set(ROUTE_RE.findall(text))
    for candidate in candidates:
        clean = candidate.rstrip("),;]}")
        url = _web_url(base_url, clean)
        if url:
            result.urls.add(url)
            result.endpoint_hints.append(("GET", url, "javascript-static"))
    for name in re.findall(r"[?&]([A-Za-z_][\w.-]{0,100})=", text):
        result.parameters.append((name, "query", None))
    if "__NEXT_DATA__" in text or "/_next/" in text:
        result.technologies.add("Next.js")
    if "webpackChunk" in text:
        result.technologies.add("Webpack")
    if "__NUXT__" in text:
        result.technologies.add("Nuxt")
    return result


def parse_sitemap(text: str) -> set[str]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return set()
    return {element.text.strip() for element in root.iter() if element.tag.rsplit("}", 1)[-1] == "loc" and element.text}


def parse_robots(text: str) -> tuple[set[str], set[str]]:
    sitemaps: set[str] = set()
    disallowed: set[str] = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        if key.lower() == "sitemap" and value:
            sitemaps.add(value)
        elif key.lower() == "disallow" and value:
            disallowed.add(value)
    return sitemaps, disallowed


def parse_openapi(data: dict[str, Any], base_url: str) -> ParsedDocument:
    result = ParsedDocument()
    if not ("openapi" in data or "swagger" in data) or not isinstance(data.get("paths"), dict):
        return result
    result.observations.append(("api-spec", "version", data.get("openapi") or data.get("swagger"), 1.0))
    for path, path_item in data["paths"].items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                continue
            url = urljoin(base_url, path)
            result.endpoint_hints.append((method.upper(), url, "openapi"))
            operation = operation if isinstance(operation, dict) else {}
            params = list(path_item.get("parameters", [])) + list(operation.get("parameters", []))
            for parameter in params:
                if isinstance(parameter, dict) and parameter.get("name"):
                    schema = parameter.get("schema", {}) if isinstance(parameter.get("schema"), dict) else {}
                    result.endpoint_parameters.setdefault(f"{method.upper()} {url}", []).append(
                        (str(parameter["name"]), str(parameter.get("in", "unknown")), str(schema.get("type", "unknown")))
                    )
    return result


def parse_document(body: bytes, content_type: str, url: str) -> ParsedDocument:
    text = body.decode("utf-8", errors="replace")
    lowered = content_type.lower()
    if "html" in lowered or text.lstrip().lower().startswith(("<!doctype html", "<html")):
        return parse_html(text, url)
    if "javascript" in lowered or url.split("?", 1)[0].lower().endswith((".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")):
        return parse_javascript(text, url)
    if "text/css" in lowered or url.split("?", 1)[0].lower().endswith(".css"):
        return parse_css(text, url)
    if "xml" in lowered or url.lower().endswith((".xml", ".xml.gz")):
        result = ParsedDocument(urls=parse_sitemap(text))
        return result
    if "json" in lowered or url.lower().endswith(".json"):
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return ParsedDocument()
        return parse_openapi(data, url) if isinstance(data, dict) else ParsedDocument()
    return ParsedDocument()


def infer_technologies(headers: dict[str, str], body: bytes) -> set[str]:
    tech: set[str] = set()
    lower_headers = {key.lower(): value for key, value in headers.items()}
    server = lower_headers.get("server")
    powered = lower_headers.get("x-powered-by")
    if server:
        tech.add(f"Server:{server[:100]}")
    if powered:
        tech.add(f"PoweredBy:{powered[:100]}")
    sample = body[:500_000].decode("utf-8", errors="ignore")
    signals = {
        "React": ("data-reactroot", "__REACT_DEVTOOLS_GLOBAL_HOOK__"),
        "Next.js": ("__NEXT_DATA__", "/_next/static/"),
        "Vue": ("data-v-", "__VUE__"),
        "Angular": ("ng-version", "_ngcontent-"),
        "Nuxt": ("__NUXT__", "/_nuxt/"),
        "WordPress": ("wp-content/", "wp-includes/"),
    }
    for name, needles in signals.items():
        if any(needle in sample for needle in needles):
            tech.add(name)
    return tech
