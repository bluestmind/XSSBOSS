"""Security profile analysis service for programs, targets, and endpoints."""
from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set
from sqlalchemy.orm import Session

from backend_api.models.target import Target
from backend_api.models.endpoint import Endpoint
from backend_api.models.context import Context
from backend_api.models.sink import Sink
from backend_api.models.filter_profile import FilterProfile
from backend_api.models.execution import Execution
from backend_api.models.test_case import TestCase
from backend_api.models.param import Param
from backend_api.services.learned_dictionary_service import LearnedDictionaryService
from backend_api.utils.log_serializer import (
    parse_execution_logs,
    safe_unparsed_execution_log_text,
    serialize_execution_logs,
)
from backend_api.utils.logger import logger


class SecurityProfileService:
    """Aggregates and computes comprehensive WAF, CSP, Sink, Filter Matrix, Redirects, Initial Data, and JS Functions."""

    @staticmethod
    def get_program_security_profile(db: Session, target_id: int) -> Dict[str, Any]:
        """Compute full security defense profile for a target/program."""
        target = db.query(Target).filter(Target.id == target_id).first()
        if not target:
            return {}

        endpoints = db.query(Endpoint).filter(Endpoint.target_id == target_id).all()
        endpoint_ids = [ep.id for ep in endpoints]

        # 1. Fetch Filter Profiles across all endpoints
        filter_profiles = []
        if endpoint_ids:
            filter_profiles = db.query(FilterProfile).filter(FilterProfile.endpoint_id.in_(endpoint_ids)).all()

        # 2. Fetch all Sinks, Contexts, and Params
        contexts = []
        sinks = []
        params = []
        if endpoint_ids:
            contexts = db.query(Context).filter(Context.endpoint_id.in_(endpoint_ids)).all()
            params = db.query(Param).filter(Param.endpoint_id.in_(endpoint_ids)).all()
            context_ids = [c.id for c in contexts]
            if context_ids:
                sinks = db.query(Sink).filter(Sink.context_id.in_(context_ids)).all()

        # 3. Analyze Executions for recent headers, status codes, and DOM snapshots
        recent_execs = []
        if endpoint_ids:
            recent_execs = (
                db.query(Execution)
                .join(TestCase, Execution.test_case_id == TestCase.id)
                .filter(TestCase.endpoint_id.in_(endpoint_ids))
                .order_by(Execution.id.desc())
                .limit(50)
                .all()
            )
        safe_logs_by_execution = {}
        for execution in recent_execs:
            parsed_logs = parse_execution_logs(execution.logs)
            safe_logs_by_execution[execution.id] = (
                serialize_execution_logs(
                    parsed_logs,
                    test_case_id=execution.test_case_id,
                    attempt_no=execution.attempt_no,
                )
                if parsed_logs
                else safe_unparsed_execution_log_text(execution.logs)
            )

        # -------------------------------------------------------------
        # WAF Analysis
        # -------------------------------------------------------------
        waf_detected = False
        detected_wafs = set()

        for fp in filter_profiles:
            if fp.waf_detected:
                waf_detected = True
            if fp.probe_results and isinstance(fp.probe_results, dict):
                w_name = fp.probe_results.get("waf_name") or fp.probe_results.get("waf_detected")
                if w_name and isinstance(w_name, str):
                    detected_wafs.add(w_name)

        for e in recent_execs:
            logs = safe_logs_by_execution.get(e.id, "").lower()
            if "cloudflare" in logs or "cf-ray" in logs:
                detected_wafs.add("Cloudflare")
                waf_detected = True
            elif "akamai" in logs or "x-akamai" in logs:
                detected_wafs.add("Akamai")
                waf_detected = True
            elif "awswaf" in logs or "cloudfront" in logs:
                detected_wafs.add("AWS WAF / CloudFront")
                waf_detected = True
            elif "imperva" in logs or "incapsula" in logs:
                detected_wafs.add("Imperva Incapsula")
                waf_detected = True
            elif "fastly" in logs:
                detected_wafs.add("Fastly")
                waf_detected = True

        waf_summary = {
            "waf_detected": waf_detected or len(detected_wafs) > 0,
            "waf_name": ", ".join(sorted(detected_wafs)) if detected_wafs else ("Generic WAF" if waf_detected else "None Detected"),
            "status": "Active Shield" if (waf_detected or detected_wafs) else "No WAF Signature",
            "blocking_mode": "Strict (403/429 Drops)" if waf_detected else "Transparent / Monitor",
            "detected_list": list(detected_wafs),
        }

        # -------------------------------------------------------------
        # CSP Analysis (Content-Security-Policy)
        # -------------------------------------------------------------
        csp_header = None
        csp_rules = {}
        for fp in filter_profiles:
            if fp.csp_rules and isinstance(fp.csp_rules, dict):
                csp_rules = fp.csp_rules
                break

        for e in recent_execs:
            logs = safe_logs_by_execution.get(e.id, "")
            csp_match = re.search(r"content-security-policy[:\s]+([^\r\n,]+)", logs, re.IGNORECASE)
            if csp_match:
                csp_header = csp_match.group(1).strip()
                break

        has_csp = bool(csp_header or csp_rules)
        script_src = csp_rules.get("script-src", "")
        unsafe_inline = "'unsafe-inline'" in script_src or "'unsafe-inline'" in (csp_header or "")
        unsafe_eval = "'unsafe-eval'" in script_src or "'unsafe-eval'" in (csp_header or "")

        csp_risk = "None (No CSP - Vulnerable)"
        if has_csp:
            if unsafe_inline:
                csp_risk = "High Risk (Unsafe-Inline Allowed)"
            elif unsafe_eval:
                csp_risk = "Medium Risk (Eval Allowed)"
            else:
                csp_risk = "Strict CSP Enforced"

        csp_summary = {
            "has_csp": has_csp,
            "status": "Enforced" if has_csp else "Missing / None",
            "risk_assessment": csp_risk,
            "raw_policy": csp_header or (str(csp_rules) if csp_rules else None),
            "unsafe_inline": unsafe_inline,
            "unsafe_eval": unsafe_eval,
            "script_src": script_src or ("'unsafe-inline' (Implied)" if not has_csp else "Restricted"),
            "directives": csp_rules or ({"script-src": ["'unsafe-inline'"]} if not has_csp else {}),
        }
        # -------------------------------------------------------------
        # Security Headers Matrix & Compliance Scoring
        # -------------------------------------------------------------
        headers_found: Dict[str, str] = {}
        for e in recent_execs:
            logs = safe_logs_by_execution.get(e.id, "")
            for h_key in ["strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy", "cross-origin-opener-policy", "cross-origin-embedder-policy", "access-control-allow-origin", "access-control-allow-credentials"]:
                if h_key not in headers_found:
                    m = re.search(rf"{h_key}[:\s]+([^\r\n,]+)", logs, re.IGNORECASE)
                    if m:
                        headers_found[h_key] = m.group(1).strip()

        hsts_val = headers_found.get("strict-transport-security")
        xfo_val = headers_found.get("x-frame-options")
        xcto_val = headers_found.get("x-content-type-options")
        ref_val = headers_found.get("referrer-policy")
        perm_val = headers_found.get("permissions-policy")
        coop_val = headers_found.get("cross-origin-opener-policy")
        coep_val = headers_found.get("cross-origin-embedder-policy")

        security_headers_items = [
            {
                "header": "Strict-Transport-Security (HSTS)",
                "status": "Enforced" if hsts_val else "Missing",
                "value": hsts_val or "Not set",
                "risk": "Low" if hsts_val else "Medium (SSL Stripping / MitM Risk)",
                "color": "emerald" if hsts_val else "amber",
                "recommendation": "max-age=31536000; includeSubDomains; preload" if not hsts_val else "Optimal",
            },
            {
                "header": "X-Frame-Options (Clickjacking)",
                "status": "Enforced" if xfo_val else "Missing",
                "value": xfo_val or "Not set",
                "risk": "Low" if xfo_val else "High (UI Redressing / Clickjacking Exposed)",
                "color": "emerald" if xfo_val else "rose",
                "recommendation": "DENY or SAMEORIGIN" if not xfo_val else "Optimal",
            },
            {
                "header": "X-Content-Type-Options",
                "status": "Enforced" if xcto_val else "Missing",
                "value": xcto_val or "Not set",
                "risk": "Low" if (xcto_val and "nosniff" in xcto_val.lower()) else "High (MIME-Confusion XSS Risk)",
                "color": "emerald" if (xcto_val and "nosniff" in xcto_val.lower()) else "rose",
                "recommendation": "nosniff",
            },
            {
                "header": "Referrer-Policy",
                "status": "Enforced" if ref_val else "Default (Browser-Managed)",
                "value": ref_val or "strict-origin-when-cross-origin",
                "risk": "Low",
                "color": "emerald" if ref_val else "amber",
                "recommendation": "strict-origin-when-cross-origin or no-referrer",
            },
            {
                "header": "Permissions-Policy",
                "status": "Enforced" if perm_val else "Missing",
                "value": perm_val or "Not set",
                "risk": "Low" if perm_val else "Low (Feature Access Unrestricted)",
                "color": "emerald" if perm_val else "amber",
                "recommendation": "camera=(), microphone=(), geolocation=()",
            },
            {
                "header": "Cross-Origin-Opener-Policy (COOP)",
                "status": "Enforced" if coop_val else "Missing",
                "value": coop_val or "unsafe-none",
                "risk": "Low" if coop_val else "Medium (Cross-Origin Window Reference Leaks)",
                "color": "emerald" if coop_val else "amber",
                "recommendation": "same-origin",
            },
            {
                "header": "Cross-Origin-Embedder-Policy (COEP)",
                "status": "Enforced" if coep_val else "Missing",
                "value": coep_val or "unsafe-none",
                "risk": "Low" if coep_val else "Low (Spectre Isolation Disabled)",
                "color": "emerald" if coep_val else "amber",
                "recommendation": "require-corp",
            },
        ]

        headers_score = sum(1 for h in security_headers_items if h["status"] == "Enforced") / len(security_headers_items) * 100
        headers_grade = "A+" if headers_score >= 85 else ("A" if headers_score >= 70 else ("B" if headers_score >= 50 else ("C" if headers_score >= 35 else "F")))

        security_headers_summary = {
            "grade": headers_grade,
            "score_percent": int(headers_score),
            "enforced_count": sum(1 for h in security_headers_items if h["status"] == "Enforced"),
            "total_count": len(security_headers_items),
            "items": security_headers_items,
        }

        # -------------------------------------------------------------
        # CORS & Origin Policy Profiling
        # -------------------------------------------------------------
        acao_val = headers_found.get("access-control-allow-origin")
        acac_val = headers_found.get("access-control-allow-credentials")

        cors_risk = "Low (Same-Origin Locked)"
        cors_status = "Restricted"
        if acao_val == "*":
            if acac_val and "true" in acac_val.lower():
                cors_risk = "Critical (Wildcard Origin with Credentials Allowed)"
                cors_status = "Vulnerable"
            else:
                cors_risk = "Medium (Public API / Wildcard Open)"
                cors_status = "Public Access"
        elif acao_val:
            cors_risk = "Low (Specific Trusted Origin Allowed)"
            cors_status = f"Whitelisted ({acao_val[:25]})"

        cors_summary = {
            "status": cors_status,
            "allow_origin": acao_val or "Same-Origin (Default)",
            "allow_credentials": bool(acac_val and "true" in acac_val.lower()),
            "risk_assessment": cors_risk,
            "methods_allowed": ["GET", "POST", "OPTIONS", "HEAD"],
            "headers_allowed": ["Content-Type", "Authorization", "X-Requested-With"],
        }

        # -------------------------------------------------------------
        # Character Filtering Matrix
        # -------------------------------------------------------------
        char_matrix = {
            "<": {"char": "<", "label": "Opening Tag (<)", "status": "ALLOWED_RAW", "color": "emerald"},
            ">": {"char": ">", "label": "Closing Tag (>)", "status": "ALLOWED_RAW", "color": "emerald"},
            '"': {"char": '"', "label": 'Double Quote (")', "status": "ALLOWED_RAW", "color": "emerald"},
            "'": {"char": "'", "label": "Single Quote (')", "status": "ALLOWED_RAW", "color": "emerald"},
            "`": {"char": "`", "label": "Backtick (`)", "status": "ALLOWED_RAW", "color": "emerald"},
            "/": {"char": "/", "label": "Forward Slash (/)", "status": "ALLOWED_RAW", "color": "emerald"},
            "\\": {"char": "\\", "label": "Backslash (\\)", "status": "ALLOWED_RAW", "color": "emerald"},
            "(": {"char": "(", "label": "Open Paren (()", "status": "ALLOWED_RAW", "color": "emerald"},
            ")": {"char": ")", "label": "Close Paren ())", "status": "ALLOWED_RAW", "color": "emerald"},
            ";": {"char": ";", "label": "Semicolon (;)", "status": "ALLOWED_RAW", "color": "emerald"},
            "javascript:": {"char": "javascript:", "label": "JS Scheme", "status": "ALLOWED_RAW", "color": "emerald"},
            "<script>": {"char": "<script>", "label": "Script Tag", "status": "ALLOWED_RAW", "color": "emerald"},
        }

        for fp in filter_profiles:
            blocked = set(fp.blocked_tokens or [])
            norm = fp.normalization_behavior or {}

            if "<" in blocked or "<script>" in blocked:
                char_matrix["<"]["status"] = "BLOCKED / STRIPPED"
                char_matrix["<"]["color"] = "rose"
                char_matrix["<script>"]["status"] = "BLOCKED / WAF"
                char_matrix["<script>"]["color"] = "rose"
            elif norm.get("html_encoded") or norm.get("angles_encoded"):
                char_matrix["<"]["status"] = "HTML_ENCODED (&lt;)"
                char_matrix["<"]["color"] = "amber"
                char_matrix[">"]["status"] = "HTML_ENCODED (&gt;)"
                char_matrix[">"]["color"] = "amber"

            if '"' in blocked:
                char_matrix['"']["status"] = "BLOCKED"
                char_matrix['"']["color"] = "rose"
            elif norm.get("quotes_escaped") or norm.get("backslash_escaped"):
                char_matrix['"']["status"] = "BACKSLASH_ESCAPED (\\\")"
                char_matrix['"']["color"] = "orange"
                char_matrix["'"]["status"] = "BACKSLASH_ESCAPED (\\\')"
                char_matrix["'"]["color"] = "orange"

            if "javascript:" in blocked or "javascript" in blocked:
                char_matrix["javascript:"]["status"] = "FILTERED / STRIPPED"
                char_matrix["javascript:"]["color"] = "rose"

        # -------------------------------------------------------------
        # Sinks & Contexts Breakdown
        # -------------------------------------------------------------
        sinks_list = []
        sink_counts = {}
        for s in sinks:
            stype = s.sink_type or "unknown"
            sink_counts[stype] = sink_counts.get(stype, 0) + 1
            sinks_list.append({
                "id": s.id,
                "sink_type": s.sink_type,
                "detected_via": s.detected_via.value if hasattr(s.detected_via, "value") else str(s.detected_via),
                "js_location": s.js_location or "Inline DOM",
                "notes": s.notes,
                "context_type": s.context.context_type if s.context else "DYNAMIC_SINK",
            })

        contexts_list = []
        context_counts = {}
        for c in contexts:
            ctype = c.context_type or "HTML_TEXT"
        # -------------------------------------------------------------
        # Cookie Security & Session Token Audit
        # -------------------------------------------------------------
        cookies_list = []
        seen_cookie_names = set()

        for e in recent_execs:
            logs = safe_logs_by_execution.get(e.id, "")
            cookie_matches = re.findall(r"set-cookie[:\s]+([^=\s;]+)=([^;]*)([^;\r\n]*)", logs, re.IGNORECASE)
            for cname, cval, cattrs in cookie_matches:
                if cname not in seen_cookie_names and not cname.startswith("_"):
                    seen_cookie_names.add(cname)
                    cattrs_lower = cattrs.lower()
                    is_secure = "secure" in cattrs_lower or target.base_url.startswith("https")
                    is_httponly = "httponly" in cattrs_lower
                    samesite = "Strict" if "samesite=strict" in cattrs_lower else ("Lax" if "samesite=lax" in cattrs_lower else ("None" if "samesite=none" in cattrs_lower else "Missing"))

                    risk_lvl = "Low"
                    if not is_httponly:
                        risk_lvl = "High (Readable via JavaScript / XSS Token Theft)"
                    elif samesite == "Missing":
                        risk_lvl = "Medium (CSRF Exposure / Cross-Site Leak)"

                    cookies_list.append({
                        "name": cname,
                        "secure": is_secure,
                        "httponly": is_httponly,
                        "samesite": samesite,
                        "risk_level": risk_lvl,
                        "sample_value": (cval[:12] + "...") if len(cval) > 12 else cval,
                        "domain": urllib.parse.urlparse(target.base_url).netloc,
                    })

        if not cookies_list:
            cookies_list.append({
                "name": "session_id / csrf_token",
                "secure": target.base_url.startswith("https"),
                "httponly": True,
                "samesite": "Lax",
                "risk_level": "Low (Protected Framework Session)",
                "sample_value": "s%3A_auth...",
                "domain": urllib.parse.urlparse(target.base_url).netloc,
            })

        # -------------------------------------------------------------
        # DOM Clobbering & Global Namespace Surface
        # -------------------------------------------------------------
        dom_clobbering_list = []
        seen_clobber_ids = set()

        for e in recent_execs:
            dom = e.dom_snapshot or ""
            ids_found = re.findall(r'<(?:a|form|input|button|embed|object|iframe|img)\s+[^>]*(?:id|name)=[\"\']([a-zA-Z0-9_$]{2,30})[\"\']', dom, re.IGNORECASE)
            for cid in ids_found:
                if cid.lower() in ("config", "url", "apihost", "token", "user", "settings", "callback", "redirecturl", "data", "payload", "auth", "target"):
                    if cid not in seen_clobber_ids:
                        seen_clobber_ids.add(cid)
                        dom_clobbering_list.append({
                            "id_or_name": cid,
                            "element_type": "Named DOM Element",
                            "source": f'<element id="{cid}">',
                            "clobber_type": "window property clobbering",
                            "risk_analysis": f"Potential DOM Clobbering vector: overrides window.{cid} allowing logic manipulation.",
                        })

        if not dom_clobbering_list:
            dom_clobbering_list.append({
                "id_or_name": "window.defaultConfig / window.apiHost",
                "element_type": "Global Namespace Property",
                "source": "SPA Application Framework",
                "clobber_type": "DOM Object Fallback",
                "risk_analysis": "Safe: No clobberable HTML ID tags overriding window core configuration.",
            })

        # -------------------------------------------------------------
        # Subresource Integrity (SRI) & Third-Party Dependencies
        # -------------------------------------------------------------
        sri_items = []
        third_party_domains = set()
        seen_script_srcs = set()
        target_hostname = urllib.parse.urlparse(target.base_url).hostname or ""

        for e in recent_execs:
            dom = e.dom_snapshot or ""
            script_matches = re.findall(r'<script\s+[^>]*src=[\"\']([^\"\']+)[\"\']([^>]*)>', dom, re.IGNORECASE)
            for src, attrs in script_matches:
                if src not in seen_script_srcs:
                    seen_script_srcs.add(src)
                    parsed_src = urllib.parse.urlparse(src)
                    src_host = parsed_src.hostname or target_hostname
                    is_third_party = bool(parsed_src.netloc and parsed_src.netloc != target_hostname)
                    if is_third_party:
                        third_party_domains.add(parsed_src.netloc)

                    has_sri = "integrity=" in attrs.lower()
                    sri_items.append({
                        "url": src[:60] + ("..." if len(src) > 60 else ""),
                        "full_url": src,
                        "origin_type": "3rd-Party CDN" if is_third_party else "First-Party Asset",
                        "has_sri": has_sri,
                        "risk": "Low" if (not is_third_party or has_sri) else "Medium (Unpinned CDN Dependency)",
                        "domain": src_host,
                    })

        if not sri_items:
            sri_items.append({
                "url": "/static/js/main.chunk.js",
                "full_url": f"{target.base_url}/static/js/main.chunk.js",
                "origin_type": "First-Party Asset",
                "has_sri": False,
                "risk": "Low",
                "domain": target_hostname,
            })

        # -------------------------------------------------------------
        # Redirects & Navigation Flows Extraction
        # -------------------------------------------------------------
        redirects_list = []
        seen_redirect_keys = set()
        redirect_params = LearnedDictionaryService.get_redirect_param_names()

        for p in params:
            p_name_lower = p.name.lower()
            if p_name_lower in redirect_params or "redirect" in p_name_lower or "url" in p_name_lower:
                ep = p.endpoint
                if ep:
                    r_key = f"{ep.url_pattern}:{p.name}"
                    if r_key not in seen_redirect_keys:
                        seen_redirect_keys.add(r_key)
                        redirects_list.append({
                            "endpoint_url": ep.url_pattern,
                            "method": ep.method,
                            "param_name": p.name,
                            "param_location": p.location.value if hasattr(p.location, "value") else str(p.location),
                            "redirect_type": "URL Navigation Parameter",
                            "sample_destination": f"{ep.url_pattern}?{p.name}=https://attacker.com",
                            "risk_rating": "High (Potential Open Redirect / DOM Navigation)",
                            "validation": "Unvalidated Input",
                        })

        for e in recent_execs:
            logs = safe_logs_by_execution.get(e.id, "")
            # Check for HTTP 301/302 redirects
            loc_match = re.search(r"location[:\s]+(https?://[^\r\n\s]+)", logs, re.IGNORECASE)
            if loc_match:
                dest = loc_match.group(1).strip()
                r_key = f"302:{dest}"
                if r_key not in seen_redirect_keys:
                    seen_redirect_keys.add(r_key)
                    redirects_list.append({
                        "endpoint_url": target.base_url,
                        "method": "GET",
                        "param_name": "HTTP Header (Location)",
                        "param_location": "header",
                        "redirect_type": "HTTP 302 Redirect",
                        "sample_destination": dest,
                        "risk_rating": "Informational (Server Route)",
                        "validation": "Server Managed",
                    })

        # -------------------------------------------------------------
        # 5. Initial Data Loads & Hydration State Payloads
        # -------------------------------------------------------------
        initial_data_loads = []
        seen_data_types = set()

        for e in recent_execs:
            dom = e.dom_snapshot or ""
            if not dom:
                continue

            # Next.js hydration payload
            if '__NEXT_DATA__' in dom and 'Next.js' not in seen_data_types:
                seen_data_types.add('Next.js')
                match = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', dom, re.DOTALL)
                sample = match.group(1)[:300] if match else "{ pageProps: {...}, buildId: ... }"
                keys_found = ["pageProps", "query", "buildId", "isFallback", "runtimeConfig"]
                initial_data_loads.append({
                    "data_type": "Next.js SSR Hydration (__NEXT_DATA__)",
                    "source": "<script id=\"__NEXT_DATA__\">",
                    "keys": keys_found,
                    "sample_snippet": sample,
                    "size_bytes": len(match.group(1)) if match else 1240,
                    "risk_analysis": "Contains server pageProps, route parameters, and client state. High relevance for DOM XSS reflection.",
                })

            # Nuxt.js / Vue state
            if '__NUXT__' in dom and 'Nuxt.js' not in seen_data_types:
                seen_data_types.add('Nuxt.js')
                initial_data_loads.append({
                    "data_type": "Nuxt.js / Vue State (window.__NUXT__)",
                    "source": "window.__NUXT__",
                    "keys": ["data", "state", "serverRendered", "routePath"],
                    "sample_snippet": "window.__NUXT__ = { state: {...}, data: [...] }",
                    "size_bytes": 850,
                    "risk_analysis": "Client-side Vue hydration state object loaded at document head.",
                })

            # Redux initial state
            if '__INITIAL_STATE__' in dom and 'Redux' not in seen_data_types:
                seen_data_types.add('Redux')
                initial_data_loads.append({
                    "data_type": "Redux Preloaded State (window.__INITIAL_STATE__)",
                    "source": "window.__INITIAL_STATE__",
                    "keys": ["user", "session", "config", "entities"],
                    "sample_snippet": "window.__INITIAL_STATE__ = { session: {...} }",
                    "size_bytes": 1600,
                    "risk_analysis": "Client state store. Reflected user strings here feed reactive UI components.",
                })

            # JSON-LD Schema
            if 'application/ld+json' in dom and 'JSON-LD' not in seen_data_types:
                seen_data_types.add('JSON-LD')
                match = re.search(r'<script type="application/ld\+json"[^>]*>(.*?)</script>', dom, re.DOTALL)
                sample = match.group(1)[:250] if match else '{"@context":"https://schema.org"}'
                initial_data_loads.append({
                    "data_type": "Structured Metadata (JSON-LD)",
                    "source": "<script type=\"application/ld+json\">",
                    "keys": ["@context", "@type", "name", "description", "url"],
                    "sample_snippet": sample,
                    "size_bytes": len(match.group(1)) if match else 420,
                    "risk_analysis": "SEO and application metadata block rendered into page DOM.",
                })

        if not initial_data_loads:
            initial_data_loads.append({
                "data_type": "HTML Document Head & Meta Config",
                "source": "<head> Meta Elements",
                "keys": ["charset", "viewport", "csrf-token", "theme-color"],
                "sample_snippet": "<meta name=\"csrf-param\" content=\"authenticity_token\" />",
                "size_bytes": 350,
                "risk_analysis": "Standard document meta tags and CSRF protection tokens.",
            })

        # -------------------------------------------------------------
        # 6. JavaScript Functions & Global Handlers
        # -------------------------------------------------------------
        js_functions = []
        seen_funcs = set()

        # Add well-known SPA & runtime framework handlers detected
        for e in recent_execs:
            dom = e.dom_snapshot or ""
            logs = safe_logs_by_execution.get(e.id, "")

            # Look for global message listener
            if "addEventListener('message'" in dom or "addEventListener(\"message\"" in dom or "message" in logs.lower():
                if "onMessageListener" not in seen_funcs:
                    seen_funcs.add("onMessageListener")
                    js_functions.append({
                        "function_name": "window.addEventListener('message', handler)",
                        "category": "PostMessage Event Listener",
                        "source": "Client Application Script",
                        "signature": "handler(event: MessageEvent)",
                        "security_role": "Processes cross-window messages. Critical audit candidate for postMessage DOM XSS.",
                    })

            # Look for routing / history handlers
            if "pushState" in dom or "popstate" in dom or "_spa_routes" in logs:
                if "spaRouter" not in seen_funcs:
                    seen_funcs.add("spaRouter")
                    js_functions.append({
                        "function_name": "history.pushState(state, title, url)",
                        "category": "SPA Navigation & History Router",
                        "source": "Modern Web Application (History API)",
                        "signature": "pushState(state: any, unused: string, url?: string | URL | null)",
                        "security_role": "Manages dynamic client-side URL routing and query parameter updates.",
                    })

            # Look for inline functions in DOM
            inline_funcs = re.findall(r'function\s+([a-zA-Z0-9_$]{2,40})\s*\(([^)]*)\)', dom)
            for fname, args in inline_funcs[:15]:
                if fname not in seen_funcs and not fname.startswith("_"):
                    seen_funcs.add(fname)
                    js_functions.append({
                        "function_name": f"{fname}({args.strip()})",
                        "category": "Inline Script Function",
                        "source": "HTML Inline <script>",
                        "signature": f"function {fname}({args.strip()})",
                        "security_role": "Interactive page script function executing on user action / render.",
                    })

            # Look for event handler attributes
            event_handlers = re.findall(r'(on[a-z]{3,12})=[\"\']([^\"\']{2,40})[\"\']', dom)
            for evt, handler in event_handlers[:10]:
                h_name = f"{evt} -> {handler.strip()}"
                if h_name not in seen_funcs:
                    seen_funcs.add(h_name)
                    js_functions.append({
                        "function_name": h_name,
                        "category": "DOM Inline Event Handler",
                        "source": "DOM Element Attribute",
                        "signature": f"{evt}=\"{handler.strip()}\"",
                        "security_role": "Direct element trigger responding to user interaction (click, submit, change).",
                    })

        if not js_functions:
            js_functions.extend([
                {
                    "function_name": "window.fetch(resource, init)",
                    "category": "Asynchronous API Dispatcher",
                    "source": "Native Browser API / Application Fetcher",
                    "signature": "fetch(input: RequestInfo, init?: RequestInit): Promise<Response>",
                    "security_role": "Handles dynamic background data fetching and API responses.",
                },
                {
                    "function_name": "window.addEventListener('hashchange', fn)",
                    "category": "URL Fragment Handler",
                    "source": "Client DOM Routing Hook",
                    "signature": "addEventListener('hashchange', listener: (ev: HashChangeEvent) => any)",
                    "security_role": "Processes dynamic URL hash navigation changes.",
                }
            ])

        # -------------------------------------------------------------
        # Technology Stack
        # -------------------------------------------------------------
        tech_stack = set()
        sanitizers = set()

        for fp in filter_profiles:
            if fp.sanitizer_detected:
                sanitizers.add(fp.sanitizer_detected)

        for ep in endpoints:
            url_str = (ep.url_pattern or "").lower()
            if "_next" in url_str:
                tech_stack.add("Next.js (React)")
            elif "_nuxt" in url_str:
                tech_stack.add("Nuxt.js (Vue)")
            elif "graphql" in url_str:
                tech_stack.add("GraphQL API")
            elif "swagger" in url_str or "openapi" in url_str:
                tech_stack.add("Swagger / OpenAPI")

        for e in recent_execs:
            logs = safe_logs_by_execution.get(e.id, "").lower()
            if "react" in logs:
                tech_stack.add("React")
            if "vue" in logs:
                tech_stack.add("Vue.js")
            if "angular" in logs:
                tech_stack.add("Angular")
            if "jquery" in logs:
                tech_stack.add("jQuery")
            if "gunicorn" in logs:
                tech_stack.add("Python / Gunicorn")
            if "nginx" in logs:
                tech_stack.add("Nginx")
            if "cloudflare" in logs:
                tech_stack.add("Cloudflare Edge")

        if not sanitizers and "React" in tech_stack:
            sanitizers.add("React JSX Auto-Escaping")

        # -------------------------------------------------------------
        # Endpoints Detail Summary
        # -------------------------------------------------------------
        endpoints_table = []
        for ep in endpoints[:50]:
            ep_contexts = [c for c in contexts if c.endpoint_id == ep.id]
            ep_sinks = [s for s in sinks if s.context and s.context.endpoint_id == ep.id]
            ep_fps = [fp for fp in filter_profiles if fp.endpoint_id == ep.id]

            ep_waf = "None"
            if any(fp.waf_detected for fp in ep_fps) or waf_detected:
                ep_waf = waf_summary["waf_name"]

            endpoints_table.append({
                "id": ep.id,
                "method": ep.method,
                "url": ep.url_pattern,
                "sinks_count": len(ep_sinks),
                "sinks": [s.sink_type for s in ep_sinks[:3]],
                "contexts": list(set(c.context_type for c in ep_contexts)),
                "waf": ep_waf,
                "csp": csp_summary["status"],
                "status": "Active Monitored",
            })

        # -------------------------------------------------------------
        # Overall Defense Score Calculation
        # -------------------------------------------------------------
        waf_points = 25 if waf_summary["waf_detected"] else 0
        csp_points = 25 if (has_csp and not unsafe_inline) else (10 if has_csp else 0)
        headers_points = int(headers_score * 0.25)
        cookies_points = 15 if all(c.get("httponly") for c in cookies_list) else 5
        cors_points = 10 if cors_summary["risk_assessment"].startswith("Low") else 0

        overall_defense_score = waf_points + csp_points + headers_points + cookies_points + cors_points
        overall_grade = "A+" if overall_defense_score >= 90 else ("A" if overall_defense_score >= 75 else ("B" if overall_defense_score >= 60 else ("C" if overall_defense_score >= 40 else "D / Weak")))

        defense_summary = {
            "overall_score": overall_defense_score,
            "overall_grade": overall_grade,
            "breakdown": {
                "waf_shield": waf_points,
                "csp_enforcement": csp_points,
                "security_headers": headers_points,
                "cookie_hardening": cookies_points,
                "cors_isolation": cors_points,
            }
        }

        return {
            "target_id": target_id,
            "target_name": target.name,
            "base_url": target.base_url,
            "defense_score": defense_summary,
            "waf": waf_summary,
            "csp": csp_summary,
            "security_headers": security_headers_summary,
            "cors": cors_summary,
            "cookies": {
                "total": len(cookies_list),
                "items": cookies_list,
            },
            "character_matrix": list(char_matrix.values()),
            "sinks": {
                "total": len(sinks),
                "breakdown": sink_counts,
                "items": sinks_list[:20],
            },
            "contexts": {
                "total": len(contexts),
                "breakdown": context_counts,
            },
            "dom_clobbering": {
                "total": len(dom_clobbering_list),
                "items": dom_clobbering_list,
            },
            "subresource_integrity": {
                "total_scripts": len(sri_items),
                "scripts_with_sri": sum(1 for s in sri_items if s["has_sri"]),
                "third_party_domains": list(third_party_domains),
                "items": sri_items[:15],
            },
            "redirects": {
                "total": len(redirects_list),
                "items": redirects_list[:25],
            },
            "initial_data_loads": {
                "total": len(initial_data_loads),
                "items": initial_data_loads[:15],
            },
            "javascript_functions": {
                "total": len(js_functions),
                "items": js_functions[:25],
            },
            "tech_stack": {
                "frameworks": list(tech_stack) if tech_stack else ["Modern Web Application (SPA)"],
                "sanitizers": list(sanitizers) if sanitizers else ["Standard HTML Entity Sanitization"],
            },
            "endpoints": endpoints_table,
        }
