"""Native Client-Side Bundle & SPA Analyzer for XSS Boss.

Extracts, downloads, and analyzes Webpack, Next.js, Vite, and Rollup
chunks in real-time to discover hidden API attack surfaces, DOM sinks,
React/Vue state hooks, postMessage listeners, and client-side vulnerabilities.
"""

import hashlib
import re
import urllib.parse
from typing import Dict, Any, List, Optional, Set
from backend_api.utils.logger import logger
from recon_engine.sourcemap_analyzer import SourceMapAnalyzer


class BundleAnalyzer:
    """Analyze modern SPA client-side bundles for vulnerabilities and hidden endpoints."""

    PATTERNS = {
        "dom_sources": r"\b(?:location\.(?:hash|search|href|pathname)|document\.(?:URL|documentURI|referrer)|window\.name|(?:localStorage|sessionStorage)\.getItem\s*\(|(?:event|e)\.data\b)",
        "dom_sinks": r"\b(dangerouslySetInnerHTML|innerHTML|outerHTML|document\.write(?:ln)?|setHTMLUnsafe|parseHTMLUnsafe)\s*[:=]\s*\{?([^,;\}]+)",
        "navigation_sinks": r"\b(window\.location|location\.href|location\.assign|location\.replace)\s*=\s*([^;,\n]+)",
        "eval_sinks": r"\b(eval|Function|setTimeout|setInterval)\s*\(\s*([^,\)]+)",
        "postmessage_listeners": r"\b(?:addEventListener\([\'\"]message[\'\"]|\.onmessage\s*=)",
        "postmessage_schemas": r"\b(?:event|e)\.data\.(?:action|type|url|target|payload|data|config|route)\b",
        "internal_api_endpoints": r"[\'\"](/(?:n-api|api|gw|member|cart|checkout|v\d+|graphql|query)/[a-zA-Z0-9_/.-]+)[\'\"]",
        "react_hooks_params": r"(?:useSearchParams|useParams|useRouter|useLocation|useQuery)\s*\(\s*\)",
        "param_accessors": r"(?:searchParams\.get|params\.get|query\.get|router\.query\.)\(?[\'\"`]?([a-zA-Z0-9_]+)[\'\"`]?",
        "storage_keys": r"(?:localStorage|sessionStorage)\.(?:getItem|setItem)\s*\(\s*[\'\"`]?([a-zA-Z0-9_.-]+)[\'\"`]?",
        "sensitive_tokens": r"(?:api[_-]?key|secret|auth[_-]?token|bearer|access[_-]?token)\s*[:=]\s*[\'\"]([a-zA-Z0-9_\-\.]{16,})[\'\"]",
        "prototype_pollution": r"\b(__proto__|prototype|constructor)\s*\[",
        "sanitizers": r"\b(?:DOMPurify\.sanitize|sanitizeHTML|escapeHTML|trustedTypes\.createPolicy)\s*\(",
        "websocket_urls": r"[\'\"`](?:wss?://)[a-zA-Z0-9_/.:-]+[\'\"`]|new\s+WebSocket\s*\(\s*[\'\"`][^\'\"`]+[\'\"`]",
    }

    @staticmethod
    def extract_script_urls(html_content: str, base_url: str) -> List[str]:
        """Extract all JavaScript script bundle URLs from an HTML document."""
        script_srcs = re.findall(r'<script[^>]+src=[\"\']([^\"\']+)[\"\']', html_content, re.IGNORECASE)
        resolved_urls = []
        for src in script_srcs:
            src = src.strip()
            if not src:
                continue
            full_url = urllib.parse.urljoin(base_url, src)
            resolved_urls.append(full_url)
        return list(dict.fromkeys(resolved_urls))

    @staticmethod
    def analyze_script_content(script_url: str, content: str, analyze_sourcemaps: bool = True) -> Dict[str, Any]:
        """Analyze a single JavaScript script's text content for security findings."""
        file_name = script_url.split("/")[-1].split("?")[0]
        results = {
            "url": script_url,
            "file_name": file_name,
            "size_bytes": len(content),
            "dom_sources": [],
            "dom_sinks": [],
            "navigation_sinks": [],
            "eval_sinks": [],
            "postmessage_listeners": [],
            "postmessage_schemas": [],
            "internal_api_endpoints": [],
            "discovered_parameters": [],
            "storage_keys": [],
            "sensitive_tokens": [],
            "prototype_pollution": [],
            "sanitizers": [],
            "websocket_urls": [],
            "sourcemap_findings": [],
        }

        for cat, pattern in BundleAnalyzer.PATTERNS.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for m in matches:
                start = max(0, m.start() - 60)
                end = min(len(content), m.end() + 60)
                snippet = content[start:end].replace("\n", " ").strip()

                if cat == "sensitive_tokens":
                    secret = m.group(1)
                    results[cat].append({
                        "kind": m.group(0).split(":", 1)[0].split("=", 1)[0].strip(),
                        "fingerprint": hashlib.sha256(secret.encode("utf-8")).hexdigest(),
                        "length": len(secret),
                        "offset": m.start(),
                    })
                elif cat in ["param_accessors", "storage_keys"]:
                    key_name = m.group(1)
                    target_list = results["discovered_parameters"] if cat == "param_accessors" else results["storage_keys"]
                    if key_name not in target_list:
                        target_list.append(key_name)
                else:
                    results[cat].append({
                        "match": m.group(0),
                        "snippet": snippet,
                        "offset": m.start()
                    })

        # Source-to-Sink Taint Flow Linking & AST Taint Graph Analysis
        results["source_sink_flows"] = BundleAnalyzer.detect_source_to_sink_flows(content)
        for flow in results["source_sink_flows"]:
            param = flow.get("param_name")
            if param and param not in results["discovered_parameters"]:
                results["discovered_parameters"].append(param)

        try:
            from recon_engine.taint_graph import ASTTaintGraph
            ranked_params = ASTTaintGraph.rank_parameters_by_reachability(content)
            results["taint_graph_ranked"] = ranked_params
            for param, p_data in ranked_params.items():
                if param and param not in results["discovered_parameters"]:
                    results["discovered_parameters"].append(param)
        except Exception:
            pass

        # Deduplicate internal API endpoints
        unique_apis = list(dict.fromkeys([item["match"].strip("'\"`") for item in results["internal_api_endpoints"]]))
        results["internal_api_endpoints"] = unique_apis

        # Optional Source Map Analysis
        if analyze_sourcemaps:
            sm_analyzer = SourceMapAnalyzer()
            sm_findings = sm_analyzer.analyze_script_for_sourcemap(script_url, content)
            if sm_findings:
                results["sourcemap_findings"] = sm_findings
                for smf in sm_findings:
                    results["internal_api_endpoints"].extend(smf.discovered_endpoints)
                    results["discovered_parameters"].extend(smf.discovered_parameters)

        results["internal_api_endpoints"] = sorted(list(set(results["internal_api_endpoints"])))
        results["discovered_parameters"] = sorted(list(set(results["discovered_parameters"])))
        return results

    @staticmethod
    def detect_source_to_sink_flows(content: str, window_chars: int = 800) -> List[Dict[str, Any]]:
        """Identify lexical source-to-sink dataflows within local code windows."""
        flows: List[Dict[str, Any]] = []
        
        # Regex patterns for sources with captured variable or parameter names
        source_patterns = [
            (r'(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:new\s+URLSearchParams\([^)]*\)\.get|searchParams\.get|params\.get|router\.query\.)\(?[\'\"`]?([a-zA-Z0-9_]+)[\'\"`]?', "url_param"),
            (r'(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:location\.(?:hash|search|pathname)|document\.location\.(?:hash|search))', "location_property"),
            (r'(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:localStorage|sessionStorage)\.getItem\s*\(\s*[\'\"`]?([a-zA-Z0-9_.-]+)[\'\"`]?', "storage_item"),
            (r'(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:e|event)\.data(?:\.([a-zA-Z0-9_]+))?', "postmessage_payload")
        ]

        # Regex patterns for sinks
        sink_patterns = [
            (r'\b(?:innerHTML|outerHTML|setHTMLUnsafe|parseHTMLUnsafe|dangerouslySetInnerHTML)\b', "dom_xss"),
            (r'\b(?:document\.write|document\.writeln)\b', "dom_xss"),
            (r'\b(?:eval|Function|setTimeout|setInterval)\b', "eval_injection"),
            (r'\b(?:window\.location|location\.href|location\.assign|location\.replace)\s*=', "navigation_xss")
        ]

        for src_regex, src_kind in source_patterns:
            for src_match in re.finditer(src_regex, content):
                var_name = src_match.group(1)
                param_name = src_match.group(2) if src_match.lastindex and src_match.lastindex >= 2 else var_name
                src_pos = src_match.start()

                # Look in forward code window for sink references to this variable
                search_window = content[src_pos: src_pos + window_chars]
                
                for sink_regex, sink_kind in sink_patterns:
                    sink_match = re.search(sink_regex, search_window)
                    if sink_match and var_name in search_window[sink_match.start():]:
                        snippet = search_window[:min(len(search_window), 250)].replace("\n", " ").strip()
                        flows.append({
                            "source_type": src_kind,
                            "var_name": var_name,
                            "param_name": param_name,
                            "sink_type": sink_match.group(0),
                            "sink_kind": sink_kind,
                            "confidence": "high",
                            "snippet": snippet
                        })
                        break

        return flows

    @staticmethod
    def analyze_page_bundles(driver, base_url: str, max_bundles: int = 25) -> Dict[str, Any]:
        """Download and analyze bundles directly using an active browser driver."""
        logger.info(f"Analyzing client bundles on {base_url}...")
        html = driver.page_source
        script_urls = BundleAnalyzer.extract_script_urls(html, base_url)
        logger.info(f"Discovered {len(script_urls)} client script bundle(s) on {base_url}")

        combined_results = {
            "base_url": base_url,
            "total_bundles_scanned": 0,
            "discovered_endpoints": set(),
            "discovered_parameters": set(),
            "dom_sources": [],
            "dom_sinks": [],
            "navigation_sinks": [],
            "eval_sinks": [],
            "postmessage_listeners": [],
            "postmessage_schemas": [],
            "sensitive_tokens": [],
            "prototype_pollution": [],
            "sanitizers": [],
            "websocket_urls": [],
        }

        for url in script_urls[:max_bundles]:
            try:
                fetch_code = f"""
                    var callback = arguments[arguments.length - 1];
                    fetch('{url}')
                        .then(r => r.text())
                        .then(text => callback({{success: true, content: text}}))
                        .catch(err => callback({{success: false, error: String(err)}}));
                """
                res = driver.execute_async_script(fetch_code)
                if res and res.get("success"):
                    content = res.get("content", "")
                    analysis = BundleAnalyzer.analyze_script_content(url, content)
                    combined_results["total_bundles_scanned"] += 1
                    combined_results["discovered_endpoints"].update(analysis["internal_api_endpoints"])
                    combined_results["discovered_parameters"].update(analysis["discovered_parameters"])
                    combined_results["dom_sources"].extend(analysis["dom_sources"])
                    combined_results["dom_sinks"].extend(analysis["dom_sinks"])
                    combined_results["navigation_sinks"].extend(analysis["navigation_sinks"])
                    combined_results["eval_sinks"].extend(analysis["eval_sinks"])
                    combined_results["postmessage_listeners"].extend(analysis["postmessage_listeners"])
                    combined_results["postmessage_schemas"].extend(analysis["postmessage_schemas"])
                    combined_results["sensitive_tokens"].extend(analysis["sensitive_tokens"])
                    combined_results["prototype_pollution"].extend(analysis["prototype_pollution"])
                    combined_results["sanitizers"].extend(analysis["sanitizers"])
                    combined_results["websocket_urls"].extend(analysis["websocket_urls"])
            except Exception as e:
                logger.warning(f"Failed to analyze bundle {url}: {e}")

        combined_results["discovered_endpoints"] = sorted(combined_results["discovered_endpoints"])
        combined_results["discovered_parameters"] = sorted(combined_results["discovered_parameters"])
        logger.info(
            f"Bundle analysis complete: {combined_results['total_bundles_scanned']} bundles scanned, "
            f"{len(combined_results['discovered_endpoints'])} API endpoints discovered, "
            f"{len(combined_results['discovered_parameters'])} parameters mined, "
            f"{len(combined_results['dom_sinks'])} DOM sinks detected."
        )
        return combined_results
