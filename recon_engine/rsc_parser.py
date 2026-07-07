"""React Server Component (RSC) & Flight Data Parser for Next.js App Router.

Extracts serialized server-rendered props, parameters, server action endpoints,
and embedded state from Next.js window.__next_f streaming streams.
"""

import json
import re
from typing import Dict, Any, List, Optional, Set
from backend_api.utils.logger import logger


class RSCParser:
    """Parse Next.js React Server Component flight data streams."""

    @staticmethod
    def extract_rsc_chunks_from_html(html_content: str) -> List[str]:
        """Extract all raw serialized flight chunk strings from HTML."""
        chunks = []
        # Pattern 1: self.__next_f.push([1, "..."])
        matches = re.finditer(r'(?:self|window)\.__next_f\.push\(\[\s*\d+\s*,\s*(".*?")\s*\]\)', html_content)
        for m in matches:
            try:
                raw_json_str = m.group(1)
                chunk_text = json.loads(raw_json_str)
                chunks.append(chunk_text)
            except Exception:
                pass

        # Pattern 2: inline script tags containing flight strings
        inline_matches = re.finditer(r'<script[^>]*>(?:self|window)\.__next_f\.push\((.*?)\)</script>', html_content)
        for m in inline_matches:
            raw = m.group(1).strip()
            if raw.startswith("[") and raw.endswith("]"):
                try:
                    parsed_arr = json.loads(raw)
                    if len(parsed_arr) >= 2 and isinstance(parsed_arr[1], str):
                        chunks.append(parsed_arr[1])
                except Exception:
                    pass

        return chunks

    @staticmethod
    def parse_rsc_stream(rsc_stream: str) -> Dict[str, Any]:
        """Parse raw flight stream data and extract structured parameters and routes."""
        results = {
            "serialized_parameters": {},
            "server_actions": set(),
            "internal_routes": set(),
            "component_tree": []
        }

        # 1. Extract serialized __PAGE__ query parameters
        # Example: __PAGE__?{\"pageName\":\"val\",\"title\":\"val\"}
        page_param_matches = re.finditer(r'__PAGE__\?(\{.*?\})', rsc_stream)
        for m in page_param_matches:
            try:
                raw_json = m.group(1).replace(r'\"', '"').replace(r'\u0026', '&')
                params_obj = json.loads(raw_json)
                if isinstance(params_obj, dict):
                    results["serialized_parameters"].update(params_obj)
            except Exception:
                pass

        # 2. Extract server action IDs (Next.js server actions)
        action_matches = re.finditer(r'[\'\"]([a-f0-9]{40,64})[\'\"]', rsc_stream)
        for m in action_matches:
            results["server_actions"].add(m.group(1))

        # 3. Extract internal API and route references
        route_matches = re.finditer(r'[\'\"](/(?:api|n-api|article|product|item|gw|cart|checkout)/[a-zA-Z0-9_/-]+)[\'\"]', rsc_stream)
        for m in route_matches:
            results["internal_routes"].add(m.group(1))

        results["server_actions"] = sorted(results["server_actions"])
        results["internal_routes"] = sorted(results["internal_routes"])
        return results

    @staticmethod
    def analyze_driver_rsc(driver) -> Dict[str, Any]:
        """Extract and parse window.__next_f directly from a live browser session."""
        extract_code = """
            try {
                if (window.__next_f && Array.isArray(window.__next_f)) {
                    return window.__next_f.map(item => Array.isArray(item) ? item[1] : '').join('\\n');
                }
            } catch(e) {}
            return '';
        """
        try:
            flight_stream = driver.execute_script(extract_code)
            if flight_stream:
                return RSCParser.parse_rsc_stream(flight_stream)
        except Exception as e:
            logger.warning(f"Failed to extract window.__next_f from browser: {e}")

        # Fallback to HTML parsing
        html = driver.page_source
        chunks = RSCParser.extract_rsc_chunks_from_html(html)
        combined_stream = "\n".join(chunks)
        return RSCParser.parse_rsc_stream(combined_stream)
