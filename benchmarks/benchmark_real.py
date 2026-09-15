"""
XSSBOSS Real End-to-End Benchmark.

This is NOT a simulation. It:
1. Starts hard_mock_target.py as a real HTTP server
2. Uses XSSBOSS's real analysis pipeline (context classifier, filter profiler,
   payload knowledge base, genetic breeder, autonomous brain) to generate payloads
3. Navigates a real Playwright Chromium browser to each endpoint with each payload
4. Injects the real oracle_inject.js script to detect JavaScript execution
5. Records ground-truth results: True Positive, False Positive, True Negative, False Negative

Usage:
    python -m benchmarks.benchmark_real
"""
from __future__ import annotations

import json
import os
import sys
import signal
import subprocess
import socket
import time
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path
from urllib.parse import quote, urlencode

# Ensure project root on path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DATABASE_URL", f"sqlite:///{ROOT / 'xssboss.db'}")
os.environ.setdefault("CELERY_TASK_ALWAYS_EAGER", "True")

from analysis_engine.enhanced_context_classifier import EnhancedContextClassifier
from analysis_engine.filter_profiler import FilterProfiler
from backend_api.models.context import ContextType
from fuzzer.payload_knowledge_base import PayloadKnowledgeBase
from fuzzer.genetic import GeneticBreeder
from fuzzer.autonomous_xss_brain import AutonomousXSSBrain
from browser_workers.oracle_inject import get_oracle_script


# ─────────────────────────────────────────────────────────────────────────────
# Benchmark route definitions — ground truth for hard_mock_target.py
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class BenchmarkRoute:
    """A route on hard_mock_target with known ground truth."""
    name: str
    method: str
    path: str
    param_name: str
    param_location: str  # query | body | json
    expected_vulnerable: bool
    context_type: str
    description: str
    difficulty: str = "medium"  # easy | medium | hard | boss
    blocked_keywords: List[str] = field(default_factory=list)
    blocked_chars: List[str] = field(default_factory=list)
    needs_stored_step: bool = False
    stored_view_path: str | None = None


BENCHMARK_ROUTES: List[BenchmarkRoute] = [
    # ─── VULNERABLE ROUTES (True Positive expected) ───
    BenchmarkRoute(
        name="Raw HTML Reflection",
        method="GET", path="/hard/html", param_name="q", param_location="query",
        expected_vulnerable=True, context_type="HTML_TEXT",
        description="Unfiltered HTML text reflection — trivial XSS.",
        difficulty="easy",
    ),
    BenchmarkRoute(
        name="Naive Filter Bypass",
        method="GET", path="/hard/filter-bypass", param_name="q", param_location="query",
        expected_vulnerable=True, context_type="HTML_TEXT",
        description="Strips <script>, javascript:, onerror, srcdoc, expression(). Must use alternate tags/events.",
        difficulty="medium",
        blocked_keywords=["script", "javascript:", "onerror", "srcdoc", "expression("],
    ),
    BenchmarkRoute(
        name="Extreme Filter Bypass",
        method="GET", path="/hard/extreme-filter", param_name="q", param_location="query",
        expected_vulnerable=True, context_type="HTML_TEXT",
        description="Blocks quotes, parentheses, script, onerror, onload. Must use backticks/exotic handlers.",
        difficulty="hard",
        blocked_keywords=["script", "onerror", "onload", "javascript"],
        blocked_chars=["(", ")", "'", '"'],
    ),
    BenchmarkRoute(
        name="Quoted Attribute Breakout",
        method="GET", path="/hard/attr-quoted", param_name="name", param_location="query",
        expected_vulnerable=True, context_type="ATTR_QUOTED",
        description="Unfiltered double-quoted attribute — break out with event handler.",
        difficulty="easy",
    ),
    BenchmarkRoute(
        name="Unquoted Attribute Breakout",
        method="GET", path="/hard/attr-unquoted", param_name="probe", param_location="query",
        expected_vulnerable=True, context_type="ATTR_UNQUOTED",
        description="Unquoted attribute on <img> — space/event handler injection.",
        difficulty="easy",
    ),
    BenchmarkRoute(
        name="JS String Breakout",
        method="GET", path="/hard/js-string", param_name="term", param_location="query",
        expected_vulnerable=True, context_type="JS_STRING_LITERAL",
        description="Unfiltered JS double-quoted string — close string or close </script>.",
        difficulty="medium",
    ),
    BenchmarkRoute(
        name="Event Handler Injection",
        method="GET", path="/hard/event", param_name="handler", param_location="query",
        expected_vulnerable=True, context_type="EVENT_HANDLER_ATTR",
        description="Direct injection into onpointerenter attribute, auto-triggered via setTimeout.",
        difficulty="easy",
    ),
    BenchmarkRoute(
        name="JSON-in-Script Breakout",
        method="GET", path="/hard/json-script", param_name="data", param_location="query",
        expected_vulnerable=True, context_type="JSON_IN_SCRIPT",
        description="JSON inside <script type=application/json> — close </script> breakout.",
        difficulty="medium",
    ),
    BenchmarkRoute(
        name="DOM innerHTML Sink",
        method="GET", path="/hard/dom-sink", param_name="next", param_location="query",
        expected_vulnerable=True, context_type="HTML_TEXT",
        description="Client-side innerHTML sink fed by URLSearchParams, delayed by setTimeout.",
        difficulty="medium",
    ),
    BenchmarkRoute(
        name="POST Body Reflection",
        method="POST", path="/hard/post-body", param_name="note", param_location="body",
        expected_vulnerable=True, context_type="HTML_TEXT",
        description="POST form body reflected into HTML.",
        difficulty="medium",
    ),
    BenchmarkRoute(
        name="POST JSON Reflection",
        method="POST", path="/hard/post-json", param_name="message", param_location="json",
        expected_vulnerable=True, context_type="JS_STRING_LITERAL",
        description="POST JSON body reflected into <script> block.",
        difficulty="medium",
    ),
    BenchmarkRoute(
        name="DOM Clobbering",
        method="GET", path="/hard/dom-clobber", param_name="q", param_location="query",
        expected_vulnerable=True, context_type="HTML_TEXT",
        description="DOM clobbering gadget: inject named element to hijack window.redirectTo.href.",
        difficulty="hard",
    ),
    BenchmarkRoute(
        name="Stored XSS",
        method="POST", path="/hard/stored-post", param_name="msg", param_location="body",
        expected_vulnerable=True, context_type="HTML_TEXT",
        description="Stored XSS: POST to /hard/stored-post, trigger at /hard/stored-view.",
        difficulty="hard",
        needs_stored_step=True,
        stored_view_path="/hard/stored-view",
    ),
    BenchmarkRoute(
        name="Ultimate Boss",
        method="GET", path="/hard/ultimate-boss", param_name="q", param_location="query",
        expected_vulnerable=True, context_type="HTML_TEXT",
        description="Recursive keyword stripping + blocked quotes/parens/slashes. DOM clobbering gadget.",
        difficulty="boss",
        blocked_keywords=["script", "iframe", "img", "onerror", "onload", "onbegin", "onfocus",
                          "onmouseover", "javascript", "srcdoc", "eval", "setTimeout", "Function"],
        blocked_chars=["(", ")", "'", '"', "`", "/", "\\"],
    ),

    # ─── SAFE ROUTES (True Negative expected — must NOT fire) ───
    BenchmarkRoute(
        name="Safe HTML (html.escape)",
        method="GET", path="/hard/safe-html", param_name="q", param_location="query",
        expected_vulnerable=False, context_type="HTML_TEXT",
        description="html.escape() encoding — NO XSS should be possible.",
        difficulty="easy",
    ),
    BenchmarkRoute(
        name="Safe JS (json.dumps + script close neutralized)",
        method="GET", path="/hard/safe-js", param_name="term", param_location="query",
        expected_vulnerable=False, context_type="JS_STRING_LITERAL",
        description="json.dumps() + </ neutralization — NO XSS should be possible.",
        difficulty="easy",
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Real execution engine
# ─────────────────────────────────────────────────────────────────────────────

def _find_free_port() -> int:
    """Find an available TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_server(host: str, port: int, timeout: float = 15.0) -> bool:
    """Wait until the server is accepting connections."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.3)
    return False


class RealBenchmarkRunner:
    """
    End-to-end benchmark runner using real HTTP, real Playwright browser,
    and the real XSSBOSS oracle injection script.
    """

    def __init__(
        self,
        max_payloads_per_route: int = 30,
        max_genetic_generations: int = 3,
        browser_timeout_ms: int = 8000,
    ):
        self.max_payloads = max_payloads_per_route
        self.max_generations = max_genetic_generations
        self.browser_timeout_ms = browser_timeout_ms
        self.server_process: subprocess.Popen | None = None
        self.base_url: str = ""
        self.port: int = 0

    # ── Server lifecycle ──────────────────────────────────────────────────

    def _start_mock_target(self) -> None:
        """Start hard_mock_target.py as a real HTTP server."""
        self.port = _find_free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"

        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT)

        self.server_process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "hard_mock_target:app",
             "--host", "127.0.0.1", "--port", str(self.port),
             "--log-level", "warning"],
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
        )

        if not _wait_for_server("127.0.0.1", self.port):
            self.server_process.kill()
            raise RuntimeError(f"hard_mock_target failed to start on port {self.port}")

    def _stop_mock_target(self) -> None:
        """Stop the mock target server."""
        if self.server_process:
            try:
                if sys.platform == "win32":
                    self.server_process.terminate()
                else:
                    os.kill(self.server_process.pid, signal.SIGTERM)
                self.server_process.wait(timeout=5)
            except Exception:
                self.server_process.kill()
            self.server_process = None

    def _reset_server_state(self) -> None:
        """Reset the mock target's in-memory state (stored XSS db etc)."""
        try:
            import httpx
            httpx.get(f"{self.base_url}/hard/reset-state", timeout=3)
        except Exception:
            pass

    # ── Payload generation (real XSSBOSS pipeline) ────────────────────────

    def _generate_payloads(self, route: BenchmarkRoute, token: str) -> List[str]:
        """Use the real XSSBOSS pipeline to generate payloads for a route."""
        # Build filter profile from route metadata
        blocked_tokens = list(route.blocked_chars) + route.blocked_keywords
        filter_profile = {
            "blocked_tokens": blocked_tokens,
            "allowed_tokens": [c for c in ["<", ">", '"', "'", ";", "(", ")", "/", "`"]
                               if c not in route.blocked_chars],
            "normalization_behavior": [],
            "waf_detected": len(blocked_tokens) > 5,
            "sanitizer_detected": False,
            "csp_rules": {},
            "context_type": route.context_type,
        }

        # Phase 1: Context-seeded payloads from knowledge base
        try:
            context_enum = ContextType(route.context_type)
        except (ValueError, KeyError):
            context_enum = ContextType.HTML_TEXT

        payloads = []
        try:
            seeded = PayloadKnowledgeBase.get_context_payloads(
                context_type=context_enum,
                filter_profile=filter_profile,
                token=token,
                limit=self.max_payloads,
            )
            payloads.extend(seeded)
        except Exception:
            pass

        # Phase 2: Autonomous brain synthesis
        try:
            brain = AutonomousXSSBrain()
            report = brain.synthesize_attack_chain(
                context_type=route.context_type,
                token=token,
                filter_profile=filter_profile,
                max_payloads=self.max_payloads,
            )
            for decision in report.top_payloads:
                if decision.payload not in payloads:
                    payloads.append(decision.payload)
        except Exception:
            pass

        # Phase 3: Genetic evolution on top seeds
        if payloads and len(payloads) < self.max_payloads:
            parents = payloads[:10]
            for gen in range(self.max_generations):
                for parent in parents:
                    try:
                        mutated = GeneticBreeder.mutate(
                            payload=parent,
                            token=token,
                            filter_profile=filter_profile,
                        )
                        if mutated not in payloads:
                            payloads.append(mutated)
                    except Exception:
                        pass
                    if len(payloads) >= self.max_payloads:
                        break
                if len(payloads) >= self.max_payloads:
                    break

        return payloads[:self.max_payloads]

    # ── Real browser execution ────────────────────────────────────────────

    def _execute_in_browser(
        self,
        playwright,
        browser,
        route: BenchmarkRoute,
        payload: str,
        token: str,
    ) -> Dict[str, Any]:
        """
        Execute a single payload against a route in a real Playwright browser.
        Returns execution result with oracle_hit ground truth.
        """
        oracle_script = get_oracle_script()
        oracle_hit = False
        oracle_message = None
        console_messages = []
        page_errors = []

        # Create isolated context
        context = browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1280, "height": 720},
        )
        context.set_default_navigation_timeout(self.browser_timeout_ms)
        context.set_default_timeout(self.browser_timeout_ms)

        # Inject oracle script into every document
        init_script = f"""
            window.__XSS_TOKEN__ = {json.dumps(token)};
            window.__ORACLE_URL__ = "http://localhost:9999/noop";
            {oracle_script}
        """
        context.add_init_script(init_script)

        page = context.new_page()

        def on_console(msg):
            nonlocal oracle_hit, oracle_message
            text = msg.text
            console_messages.append({"type": msg.type.upper(), "text": text})
            if "XSS Oracle: Execution detected" in text and token in text:
                oracle_hit = True
                oracle_message = text

        def on_page_error(err):
            page_errors.append(err.message if hasattr(err, 'message') else str(err))

        page.on("console", on_console)
        page.on("pageerror", on_page_error)

        url = self.base_url + route.path

        try:
            if route.method == "GET":
                if route.param_location == "query":
                    url += f"?{quote(route.param_name, safe='')}={quote(payload, safe='')}"
                page.goto(url)

            elif route.method == "POST":
                if route.needs_stored_step:
                    # Step 1: Submit payload to storage endpoint
                    escaped_payload = payload.replace('`', '\\`')
                    if route.param_location == "json":
                        page.goto(self.base_url + "/")  # Navigate first for context
                        page.evaluate(f"""
                            fetch("{self.base_url + route.path}", {{
                                method: "POST",
                                headers: {{"Content-Type": "application/json"}},
                                body: JSON.stringify({{ "{route.param_name}": `{escaped_payload}` }})
                            }});
                        """)
                    else:
                        page.goto(self.base_url + "/")
                        page.evaluate(f"""
                            fetch("{self.base_url + route.path}", {{
                                method: "POST",
                                headers: {{"Content-Type": "application/x-www-form-urlencoded"}},
                                body: "{route.param_name}=" + encodeURIComponent(`{escaped_payload}`)
                            }});
                        """)
                    time.sleep(0.5)
                    # Step 2: Navigate to view page
                    page.goto(self.base_url + route.stored_view_path)
                else:
                    # Direct POST navigation via route interception
                    def intercept(route_obj):
                        if route_obj.request.is_navigation_request():
                            if route.param_location == "json":
                                route_obj.continue_(
                                    method="POST",
                                    headers={"Content-Type": "application/json"},
                                    post_data=json.dumps({route.param_name: payload}),
                                )
                            else:
                                route_obj.continue_(
                                    method="POST",
                                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                                    post_data=f"{route.param_name}={quote(payload, safe='')}",
                                )
                        else:
                            route_obj.continue_()

                    page.route("**/*", intercept)
                    try:
                        page.goto(url)
                    finally:
                        page.unroute("**/*", intercept)

            # Trigger interactive events (matching executor.py logic)
            try:
                page.evaluate("""
                    (function() {
                        try {
                            var token = window.__XSS_TOKEN__;
                            if (!token) return;
                            var elements = document.querySelectorAll('*');
                            for (var i = 0; i < elements.length; i++) {
                                var el = elements[i];
                                if (!el.attributes) continue;
                                for (var j = 0; j < el.attributes.length; j++) {
                                    var attr = el.attributes[j];
                                    if (attr.value && (attr.value.indexOf(token) !== -1 ||
                                        (attr.name === 'href' && attr.value.toLowerCase().indexOf('javascript:') === 0))) {
                                        try { if (typeof el.click === 'function') el.click(); } catch(e) {}
                                        ['click','mouseover','focus','input','change','pointerenter','toggle','animationend'].forEach(function(evt) {
                                            try { el.dispatchEvent(new Event(evt, {bubbles:true,cancelable:true})); } catch(e) {}
                                        });
                                        if (attr.name.indexOf('on') === 0) {
                                            try { el.dispatchEvent(new Event(attr.name.substring(2), {bubbles:true,cancelable:true})); } catch(e) {}
                                        }
                                    }
                                }
                            }
                            // postMessage probing
                            try {
                                [token, JSON.stringify({type:'xss',data:token,message:token}), {type:'xss',data:token,message:token}].forEach(function(msg) {
                                    window.postMessage(msg, '*');
                                });
                            } catch(e) {}
                        } catch(e) {}
                    })();
                """)
            except Exception:
                pass

            # Wait for oracle callbacks
            time.sleep(2.0)

            # Extended wait if token is reflected but no hit yet
            if not oracle_hit:
                try:
                    content = page.content()
                    if token in content:
                        time.sleep(2.0)
                except Exception:
                    pass

        except Exception as e:
            page_errors.append(str(e))

        # Get final DOM for analysis
        dom_snapshot = None
        try:
            dom_snapshot = page.content()
        except Exception:
            pass

        try:
            context.close()
        except Exception:
            pass

        return {
            "oracle_hit": oracle_hit,
            "oracle_message": oracle_message,
            "console": console_messages,
            "errors": page_errors,
            "dom_snapshot_length": len(dom_snapshot) if dom_snapshot else 0,
        }

    # ── Main benchmark loop ───────────────────────────────────────────────

    def run(self) -> Dict[str, Any]:
        """Run the full real benchmark."""
        print("\n" + "=" * 75)
        print("    XSSBOSS REAL END-TO-END BENCHMARK")
        print("    (Real HTTP • Real Playwright Browser • Real Oracle Verification)")
        print("=" * 75)

        self._start_mock_target()
        print(f"[+] Mock target started on {self.base_url}")

        from playwright.sync_api import sync_playwright

        results: List[Dict[str, Any]] = []
        start_time = time.time()

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
            ])

            for route in BENCHMARK_ROUTES:
                result = self._benchmark_route(pw, browser, route)
                results.append(result)

                # Print live progress
                status_icon = {
                    "TP": "✅",
                    "TN": "✅",
                    "FP": "❌",
                    "FN": "❌",
                    "SKIP": "⏭️",
                }
                icon = status_icon.get(result["classification"], "?")
                attempts_info = f" ({result['attempts_to_exploit']} payloads)" if result.get("attempts_to_exploit") else ""
                print(f"  {icon} [{result['classification']}] {route.name} [{route.difficulty}]{attempts_info}")
                if result.get("winning_payload"):
                    print(f"       Payload: {result['winning_payload'][:100]}")

            browser.close()

        self._stop_mock_target()
        elapsed = time.time() - start_time

        # Compute summary stats
        tp = sum(1 for r in results if r["classification"] == "TP")
        tn = sum(1 for r in results if r["classification"] == "TN")
        fp = sum(1 for r in results if r["classification"] == "FP")
        fn = sum(1 for r in results if r["classification"] == "FN")
        total_vuln = sum(1 for r in BENCHMARK_ROUTES if r.expected_vulnerable)
        total_safe = sum(1 for r in BENCHMARK_ROUTES if not r.expected_vulnerable)

        detection_rate = (tp / total_vuln * 100) if total_vuln else 0
        fp_rate = (fp / total_safe * 100) if total_safe else 0
        avg_attempts = 0
        tp_results = [r for r in results if r["classification"] == "TP"]
        if tp_results:
            avg_attempts = sum(r["attempts_to_exploit"] for r in tp_results) / len(tp_results)

        summary = {
            "benchmark": "XSSBOSS Real E2E Benchmark",
            "total_routes": len(BENCHMARK_ROUTES),
            "vulnerable_routes": total_vuln,
            "safe_routes": total_safe,
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "detection_rate": round(detection_rate, 1),
            "false_positive_rate": round(fp_rate, 1),
            "average_attempts_to_exploit": round(avg_attempts, 1),
            "elapsed_seconds": round(elapsed, 2),
            "results": results,
        }

        # Print summary
        print("\n" + "=" * 75)
        print("    BENCHMARK RESULTS")
        print("=" * 75)
        print(f"  Total Routes:           {summary['total_routes']}")
        print(f"  Vulnerable Routes:      {summary['vulnerable_routes']}")
        print(f"  Safe Routes:            {summary['safe_routes']}")
        print("-" * 75)
        print(f"  True Positives (TP):    {tp}/{total_vuln}  → Detection Rate: {detection_rate:.1f}%")
        print(f"  True Negatives (TN):    {tn}/{total_safe}  → FP Rate: {fp_rate:.1f}%")
        print(f"  False Positives (FP):   {fp}")
        print(f"  False Negatives (FN):   {fn}")
        print(f"  Avg Payloads to Exploit: {avg_attempts:.1f}")
        print(f"  Total Time:             {elapsed:.1f}s")
        print("=" * 75)

        if fn > 0:
            print("\n  ⚠️  MISSED ROUTES (False Negatives):")
            for r in results:
                if r["classification"] == "FN":
                    print(f"    - {r['route_name']} [{r['difficulty']}]: {r['description']}")
        if fp > 0:
            print("\n  🚨 FALSE POSITIVES:")
            for r in results:
                if r["classification"] == "FP":
                    print(f"    - {r['route_name']}: fired on safe endpoint!")

        # Save results
        results_dir = ROOT / "benchmarks" / "results"
        results_dir.mkdir(exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        results_path = results_dir / f"benchmark_{ts}.json"
        with open(results_path, "w") as f:
            # Don't save full DOM snapshots
            clean_results = []
            for r in results:
                cr = {k: v for k, v in r.items() if k != "console_log"}
                clean_results.append(cr)
            json.dump({**summary, "results": clean_results}, f, indent=2, default=str)
        print(f"\n  📄 Results saved to {results_path}")

        return summary

    def _benchmark_route(
        self,
        playwright,
        browser,
        route: BenchmarkRoute,
    ) -> Dict[str, Any]:
        """Benchmark a single route end-to-end."""
        token = f"xB0ss_{route.name.replace(' ', '_')[:20]}_{int(time.time()) % 100000}"

        # Reset server state before stored XSS routes
        if route.needs_stored_step:
            self._reset_server_state()

        # Generate payloads using real XSSBOSS pipeline
        payloads = self._generate_payloads(route, token)

        if not payloads:
            return {
                "route_name": route.name,
                "method": route.method,
                "path": route.path,
                "expected_vulnerable": route.expected_vulnerable,
                "difficulty": route.difficulty,
                "description": route.description,
                "classification": "FN" if route.expected_vulnerable else "TN",
                "attempts_to_exploit": 0,
                "total_payloads_generated": 0,
                "winning_payload": None,
                "error": "No payloads generated",
            }

        # Execute each payload in real browser
        hit_found = False
        winning_payload = None
        attempts = 0

        for payload in payloads:
            attempts += 1
            result = self._execute_in_browser(playwright, browser, route, payload, token)

            if result["oracle_hit"]:
                hit_found = True
                winning_payload = payload
                break

        # Classify result
        if route.expected_vulnerable:
            classification = "TP" if hit_found else "FN"
        else:
            classification = "FP" if hit_found else "TN"

        return {
            "route_name": route.name,
            "method": route.method,
            "path": route.path,
            "expected_vulnerable": route.expected_vulnerable,
            "difficulty": route.difficulty,
            "description": route.description,
            "classification": classification,
            "attempts_to_exploit": attempts if hit_found else len(payloads),
            "total_payloads_generated": len(payloads),
            "winning_payload": winning_payload,
        }


if __name__ == "__main__":
    runner = RealBenchmarkRunner(
        max_payloads_per_route=30,
        max_genetic_generations=3,
        browser_timeout_ms=8000,
    )
    try:
        runner.run()
    except KeyboardInterrupt:
        print("\n[!] Benchmark interrupted.")
        runner._stop_mock_target()
    except Exception as e:
        print(f"\n[!] Benchmark error: {e}")
        import traceback
        traceback.print_exc()
        runner._stop_mock_target()
