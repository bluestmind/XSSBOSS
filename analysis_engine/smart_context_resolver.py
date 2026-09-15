"""Smart context resolver — turn proven sink reachability into the RIGHT test, not a blind guess.

When a parameter doesn't reflect in the server HTML, the old flow fell back to fuzzing it as
generic ``HTML_TEXT`` — a dumb-bot guess that fires HTML payloads at a parameter that actually
reaches ``eval`` (JS context) or ``location.href`` (URL context). This resolver reads the smart
taint analysis of the page's JavaScript and maps each proven sink to the *correct* injection
context (and a priority boost), so the fuzzer tests the parameter the way it can actually execute.

Maps the analyzer's sink kinds to the real ``ContextType`` enum the generator/grammars use.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from analysis_engine.smart_taint_analyzer import Reachability, SmartTaintAnalyzer


# smart-taint sink kind -> the ContextType value the fuzzer's grammars key on.
_SINK_TO_CONTEXT: Dict[str, str] = {
    "innerHTML": "HTML_TEXT",
    "insertAdjacentHTML": "HTML_TEXT",
    "document_write": "HTML_TEXT",
    "jquery_html": "HTML_TEXT",
    "jquery_selector": "HTML_TEXT",
    "range_fragment": "HTML_TEXT",
    "srcdoc": "SRC_DOC_ATTR",
    "eval": "JS_STRING_LITERAL",
    "function_ctor": "JS_STRING_LITERAL",
    "timer_string": "JS_STRING_LITERAL",
    "navigation": "URL_QUERY",
    "iframe_src": "URL_QUERY",
    "set_href_attr": "URL_QUERY",
}


class SmartContextResolver:
    """Resolves proven source→sink flows into concrete injection contexts + priority."""

    @staticmethod
    def context_for_sink(sink_kind: str) -> Optional[str]:
        return _SINK_TO_CONTEXT.get(sink_kind)

    @classmethod
    def resolve(cls, js_code: str) -> Dict[str, List[Dict[str, object]]]:
        """param name -> list of {context, reachability, confidence, sink_kind, severity}, best-first."""
        out: Dict[str, List[Dict[str, object]]] = {}
        for f in SmartTaintAnalyzer.analyze(js_code or ""):
            ctx = cls.context_for_sink(f.sink_kind)
            if not ctx:
                continue
            out.setdefault(f.source_param, []).append({
                "context": ctx,
                "reachability": f.reachability.value,
                "confidence": f.confidence,
                "sink_kind": f.sink_kind,
                "severity": f.severity,
            })
        for param in out:
            out[param].sort(key=lambda d: (d["reachability"] != "reachable", -float(d["confidence"])))
        return out

    @classmethod
    def contexts_for_param(cls, js_code: str, param_name: str, reachable_only: bool = True) -> List[str]:
        """Distinct contexts to test a parameter in, derived from its proven sinks."""
        entries = cls.resolve(js_code).get(param_name, [])
        seen: List[str] = []
        for e in entries:
            if reachable_only and e["reachability"] != "reachable":
                continue
            if e["context"] not in seen:
                seen.append(str(e["context"]))
        return seen

    @staticmethod
    def priority_boost(reachability: str, confidence: float) -> int:
        """Boost proven-reachable params so a smart hunter spends budget on them first."""
        if reachability == "reachable":
            return int(40 + 40 * float(confidence))   # 40..80
        if reachability == "sanitized":
            return 3                                    # keep, but low priority
        return 0

    @classmethod
    def best_boost_for_param(cls, js_code: str, param_name: str) -> int:
        entries = cls.resolve(js_code).get(param_name, [])
        return max((cls.priority_boost(str(e["reachability"]), float(e["confidence"])) for e in entries), default=0)
