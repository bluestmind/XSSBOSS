"""
XSSBOSS Benchmark Performance Profiler.

Measures real throughput and latency of core pipeline components:
- Payload generation rate (payloads/sec)
- Context classification throughput
- Genetic mutation throughput
- Knowledge base query latency
- Autonomous brain synthesis time
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DATABASE_URL", f"sqlite:///{ROOT / 'xssboss.db'}")
os.environ.setdefault("CELERY_TASK_ALWAYS_EAGER", "True")

from analysis_engine.enhanced_context_classifier import EnhancedContextClassifier
from backend_api.models.context import ContextType
from fuzzer.payload_knowledge_base import PayloadKnowledgeBase
from fuzzer.genetic import GeneticBreeder
from fuzzer.mutation_engine import MutationEngine
from fuzzer.autonomous_xss_brain import AutonomousXSSBrain


TOKEN = "PERF_BENCH_TOKEN"

# Representative HTML documents for classification benchmarking
SAMPLE_HTMLS = [
    '<div>Search: xB0ss_PERF_MARKER_1 results</div>',
    '<input value="xB0ss_PERF_MARKER_1" type="text">',
    '<!-- comment: xB0ss_PERF_MARKER_1 -->',
    '<script>var x = "xB0ss_PERF_MARKER_1";</script>',
    '<style>body { font: "xB0ss_PERF_MARKER_1"; }</style>',
    '<svg><text>xB0ss_PERF_MARKER_1</text></svg>',
    '<a href="/search?q=xB0ss_PERF_MARKER_1">link</a>',
    '<div onclick="xB0ss_PERF_MARKER_1">click</div>',
    '<title>xB0ss_PERF_MARKER_1</title>',
    '<math><mtext>xB0ss_PERF_MARKER_1</mtext></math>',
]
MARKER = "xB0ss_PERF_MARKER_1"

CONTEXTS_TO_BENCH = [
    ContextType.HTML_TEXT,
    ContextType.ATTR_QUOTED,
    ContextType.JS_STRING_LITERAL,
    ContextType.HTML_COMMENT,
    ContextType.CSS_STYLE_BLOCK,
    ContextType.EVENT_HANDLER_ATTR,
]


def _bench(name: str, func, iterations: int = 100) -> Dict[str, Any]:
    """Run a function N times and report throughput."""
    start = time.perf_counter()
    for _ in range(iterations):
        func()
    elapsed = time.perf_counter() - start
    per_sec = iterations / elapsed if elapsed > 0 else 0
    return {
        "name": name,
        "iterations": iterations,
        "elapsed_seconds": round(elapsed, 4),
        "ops_per_second": round(per_sec, 1),
    }


class PerformanceBenchmark:
    """Benchmark throughput and latency of core pipeline components."""

    def run(self) -> Dict[str, Any]:
        start_time = time.time()
        results: List[Dict[str, Any]] = []

        filter_profile = {
            "blocked_tokens": ["script", "alert", "(", ")"],
            "allowed_tokens": ["<", ">", '"', "'", ";", "/", "`"],
            "normalization_behavior": [],
            "waf_detected": False,
            "sanitizer_detected": False,
            "csp_rules": {},
            "context_type": "HTML_TEXT",
        }

        # 1. Context Classification throughput
        results.append(_bench(
            "Context Classification",
            lambda: EnhancedContextClassifier.classify_all_reflections(SAMPLE_HTMLS[0], MARKER),
            iterations=200,
        ))

        # 2. Knowledge Base query throughput
        results.append(_bench(
            "Knowledge Base Query (HTML_TEXT)",
            lambda: PayloadKnowledgeBase.get_context_payloads(
                context_type=ContextType.HTML_TEXT,
                filter_profile=filter_profile,
                token=TOKEN,
                limit=25,
            ),
            iterations=100,
        ))

        # 3. Knowledge Base across all bench contexts
        for ctx in CONTEXTS_TO_BENCH:
            fp = {**filter_profile, "context_type": ctx.value}
            results.append(_bench(
                f"KB Query ({ctx.value})",
                lambda c=ctx, f=fp: PayloadKnowledgeBase.get_context_payloads(
                    context_type=c, filter_profile=f, token=TOKEN, limit=25,
                ),
                iterations=50,
            ))

        # 4. Genetic Mutation throughput
        seed_payload = '<img src=x onerror=alert(1)>'
        results.append(_bench(
            "Genetic Mutation",
            lambda: GeneticBreeder.mutate(
                payload=seed_payload,
                token=TOKEN,
                filter_profile=filter_profile,
            ),
            iterations=200,
        ))

        # 5. MutationEngine operations
        me = MutationEngine
        results.append(_bench(
            "MutationEngine.apply_mixed_case",
            lambda: me.apply_mixed_case(seed_payload),
            iterations=500,
        ))
        results.append(_bench(
            "MutationEngine.apply_url_encoding",
            lambda: me.apply_url_encoding(seed_payload),
            iterations=500,
        ))
        results.append(_bench(
            "MutationEngine.apply_html_entities",
            lambda: me.apply_html_entities(seed_payload),
            iterations=500,
        ))

        # 6. Autonomous Brain synthesis
        brain = AutonomousXSSBrain()
        results.append(_bench(
            "Autonomous Brain Synthesis",
            lambda: brain.synthesize_attack_chain(
                context_type="HTML_TEXT",
                token=TOKEN,
                filter_profile=filter_profile,
                max_payloads=30,
            ),
            iterations=20,
        ))

        # 7. Full classification across all sample documents
        results.append(_bench(
            "Classify All 10 Samples",
            lambda: [EnhancedContextClassifier.classify_all_reflections(h, MARKER) for h in SAMPLE_HTMLS],
            iterations=50,
        ))

        elapsed = time.time() - start_time

        return {
            "benchmark": "Performance Profiler",
            "elapsed_seconds": round(elapsed, 2),
            "passed": True,  # Performance benchmarks don't gate CI
            "metrics": results,
        }


if __name__ == "__main__":
    benchmark = PerformanceBenchmark()
    summary = benchmark.run()

    print("\n" + "=" * 75)
    print("     XSSBOSS PERFORMANCE BENCHMARK")
    print("=" * 75)
    print(f"  {'Component':<40} {'Ops/sec':>10} {'Iterations':>12} {'Time':>8}")
    print("  " + "-" * 70)
    for m in summary["metrics"]:
        print(f"  {m['name']:<40} {m['ops_per_second']:>10.1f} {m['iterations']:>12} {m['elapsed_seconds']:>7.3f}s")
    print("=" * 75)
