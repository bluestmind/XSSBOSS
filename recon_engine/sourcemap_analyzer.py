"""
Source Map (.map) Reconstruction & Deep Code Surface Analyzer for XSS Boss.

Unpacks remote and local JavaScript source maps to reconstruct original TypeScript, JSX,
and Vue components, harvesting hidden API routes, parameters, developer comments, and DOM sinks.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

try:
    import httpx
except ImportError:
    httpx = None

from backend_api.utils.logger import logger


@dataclass
class SourceMapFinding:
    """Findings extracted from reconstructed source maps."""
    original_file_path: str
    discovered_endpoints: List[str] = field(default_factory=list)
    discovered_parameters: List[str] = field(default_factory=list)
    dom_sinks: List[Dict[str, Any]] = field(default_factory=list)
    developer_comments: List[str] = field(default_factory=list)
    secrets_or_flags: List[str] = field(default_factory=list)


class SourceMapAnalyzer:
    """Unpacks source maps and performs deep static analysis on unminified source code."""

    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout

    def analyze_script_for_sourcemap(self, script_url: str, script_content: Optional[str] = None) -> List[SourceMapFinding]:
        """Attempt to locate, download, and analyze the source map for a given script URL."""
        findings: List[SourceMapFinding] = []
        map_url = None

        # 1. Check for //# sourceMappingURL= directive
        if script_content:
            match = re.search(r'//[#@]\s*sourceMappingURL=([^\s]+)', script_content)
            if match:
                raw_map = match.group(1).strip()
                map_url = urllib.parse.urljoin(script_url, raw_map)

        # 2. Fallback to direct .map URL suffix
        if not map_url:
            map_url = f"{script_url}.map"

        # 3. Fetch and parse source map
        map_json_str = self._fetch_text(map_url)
        if not map_json_str:
            return findings

        try:
            map_data = json.loads(map_json_str)
            if isinstance(map_data, dict) and "sources" in map_data:
                logger.info(f"Successfully reconstructed source map: {map_url}")
                findings = self.parse_sourcemap_data(map_data)
        except Exception:
            pass

        return findings

    def parse_sourcemap_data(self, map_data: Dict[str, Any]) -> List[SourceMapFinding]:
        """Parse raw source map JSON object into structured findings."""
        findings = []
        sources = map_data.get("sources", [])
        sources_content = map_data.get("sourcesContent", [])

        for i, src_path in enumerate(sources):
            content = sources_content[i] if i < len(sources_content) and sources_content[i] else ""
            if not content:
                continue

            finding = SourceMapFinding(original_file_path=src_path)

            # 1. Extract API endpoints
            endpoint_matches = re.finditer(r'[\'"`](/(?:api|n-api|admin|v\d+|auth|user|checkout|cart|gateway)/[a-zA-Z0-9_/.-]+)[\'"`]', content)
            endpoints = list(dict.fromkeys([m.group(1) for m in endpoint_matches]))
            finding.discovered_endpoints = endpoints

            # 2. Extract parameters (React props, URLSearchParams, query destructs)
            param_matches = re.finditer(r'(?:searchParams\.get|params\.get|\.get|req\.query\[|router\.query\.)\(?[\'"`]?([a-zA-Z0-9_]+)[\'"`]?', content)
            params = list(dict.fromkeys([m.group(1) for m in param_matches]))
            finding.discovered_parameters = params

            # 3. Extract DOM sinks in original code
            sink_matches = re.finditer(r'(dangerouslySetInnerHTML|innerHTML|outerHTML|eval|document\.write|location\.href)\s*[:=]\s*([^;\n]+)', content)
            for sm in sink_matches:
                finding.dom_sinks.append({
                    "sink": sm.group(1),
                    "code_snippet": sm.group(0)[:120].strip()
                })

            # 4. Extract developer comments & security notes
            comment_matches = re.finditer(r'//\s*(?:TODO|FIXME|NOTE|HACK|DEV|DEBUG|SECURITY)[^\n]+', content, re.IGNORECASE)
            comments = [m.group(0).strip() for m in comment_matches][:10]
            finding.developer_comments = comments

            # 5. Extract debug flags / secrets
            flags_matches = re.finditer(r'(?:DEBUG|ENABLE_TESTING|DEV_MODE|IS_ADMIN|STAGING)\s*[:=]\s*(?:true|1)', content)
            finding.secrets_or_flags = [m.group(0).strip() for m in flags_matches]

            if (finding.discovered_endpoints or finding.discovered_parameters or
                    finding.dom_sinks or finding.developer_comments):
                findings.append(finding)

        return findings

    def _fetch_text(self, url: str) -> Optional[str]:
        """Safely fetch HTTP text."""
        if not httpx or not url:
            return None
        try:
            resp = httpx.get(
                url,
                timeout=self.timeout,
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 200:
                return resp.text
        except Exception:
            pass
        return None
