"""Pipe scan — fast, browser-less HTTP triage (dalfox `cat urls | dalfox pipe` parity).

For each URL it fetches the response and runs the *cheap* deterministic checks — vulnerable-library
scan + data-flow taint for reachable DOM sinks — flagging candidates worth the expensive browser
pipeline. This is the request-efficient front door: triage many URLs by HTTP alone, then hand only
the candidates to the full oracle-backed flow.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, List, Optional


class PipeScanService:
    @staticmethod
    def scan_url(url: str, fetch_fn: Optional[Callable[[str], str]] = None) -> Dict[str, Any]:
        if not (url.startswith("http://") or url.startswith("https://")):
            return {"url": url, "error": "not an absolute http(s) URL"}
        if fetch_fn is None:
            def fetch_fn(u: str) -> str:
                import httpx
                from backend_api.config import settings
                from backend_api.utils.rate_limiter import rate_limited_call

                return rate_limited_call(
                    u,
                    lambda: httpx.get(
                        u,
                        timeout=10,
                        follow_redirects=False,
                        verify=not settings.ALLOW_INSECURE_TLS,
                    ),
                ).text

        try:
            content = fetch_fn(url) or ""
        except Exception as e:
            return {"url": url, "error": str(e)}

        from analysis_engine.vulnerable_library_scanner import VulnerableLibraryScanner
        from analysis_engine.smart_taint_analyzer import SmartTaintAnalyzer, Reachability

        libs = [f.to_dict() for f in VulnerableLibraryScanner.scan(content)]
        dom = [f.to_dict() for f in SmartTaintAnalyzer.analyze(content)
               if f.reachability is Reachability.REACHABLE]
        return {
            "url": url,
            "vulnerable_libraries": libs,
            "dom_sinks": dom,
            "candidate": bool(libs or dom),
            "reason": ("vulnerable-lib" if libs else "") + ("+dom-sink" if dom else "") or "clean-http",
        }

    @classmethod
    def scan_urls(cls, urls: Iterable[str], fetch_fn: Optional[Callable[[str], str]] = None,
                  candidates_only: bool = False) -> List[Dict[str, Any]]:
        out = []
        for u in urls:
            u = u.strip()
            if not u:
                continue
            r = cls.scan_url(u, fetch_fn)
            if candidates_only and not r.get("candidate"):
                continue
            out.append(r)
        return out
