"""
XSSBOSS Benchmark Suite — CI Quality Gate Tests.

These tests enforce minimum quality thresholds. If any fail, CI should block the merge.
Uses pytest markers for selective execution:
    - pytest -m "benchmark" — all benchmarks
    - pytest -m "benchmark_fast" — component-level only (no browser)
    - pytest -m "benchmark_real" — real E2E (requires Playwright + available port)
"""
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DATABASE_URL", f"sqlite:///{ROOT / 'xssboss.db'}")
os.environ.setdefault("CELERY_TASK_ALWAYS_EAGER", "True")

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Component-level quality gates (fast, no browser)
# ─────────────────────────────────────────────────────────────────────────────

class TestContextClassifierGate(unittest.TestCase):
    """Enforce context classifier accuracy ≥ 85%."""

    def test_context_classifier_accuracy(self):
        from benchmarks.benchmark_context_classifier import ContextClassifierBenchmark
        result = ContextClassifierBenchmark().run()
        self.assertGreaterEqual(
            result["accuracy"], 85.0,
            f"Context classifier accuracy {result['accuracy']}% is below 85% gate. "
            f"Misclassified: {result['correct']}/{result['total_samples']}"
        )


class TestFalsePositiveGate(unittest.TestCase):
    """Enforce zero false positives on safe endpoints."""

    def test_zero_false_positives(self):
        from benchmarks.benchmark_false_positive import FalsePositiveBenchmark
        result = FalsePositiveBenchmark().run()
        self.assertEqual(
            result["false_positives"], 0,
            f"False positive rate is {result['fp_rate']}% — expected 0%. "
            f"FP endpoints: {[r['endpoint'] for r in result['details'] if r['false_positive']]}"
        )


class TestFuzzerEfficacyGate(unittest.TestCase):
    """Enforce fuzzer bypass rate ≥ 80% on canonical challenges."""

    def test_xssboss_beats_naive_fuzzer(self):
        from benchmarks.benchmark_fuzzer_efficacy import XSSBossBenchmarkRunner
        result = XSSBossBenchmarkRunner(max_attempts=60).run_full_benchmark()
        self.assertGreaterEqual(
            result["xssboss_success_rate"], 80.0,
            f"XSSBoss success rate {result['xssboss_success_rate']}% is below 80% gate."
        )
        self.assertLess(
            result["xssboss_avg_attempts"], result["naive_avg_attempts"],
            "XSSBoss should solve challenges in fewer attempts than the naive fuzzer."
        )


class TestPerformanceGate(unittest.TestCase):
    """Enforce minimum throughput on key components."""

    def test_context_classification_throughput(self):
        from benchmarks.benchmark_performance import PerformanceBenchmark
        result = PerformanceBenchmark().run()
        classification_metric = next(
            (m for m in result["metrics"] if m["name"] == "Context Classification"), None
        )
        self.assertIsNotNone(classification_metric, "Context Classification metric not found")
        self.assertGreater(
            classification_metric["ops_per_second"], 50,
            f"Context classification at {classification_metric['ops_per_second']} ops/sec "
            f"is below 50 ops/sec minimum."
        )

    def test_knowledge_base_query_throughput(self):
        from benchmarks.benchmark_performance import PerformanceBenchmark
        result = PerformanceBenchmark().run()
        kb_metric = next(
            (m for m in result["metrics"] if m["name"] == "Knowledge Base Query (HTML_TEXT)"), None
        )
        self.assertIsNotNone(kb_metric, "Knowledge Base Query metric not found")
        self.assertGreater(
            kb_metric["ops_per_second"], 20,
            f"KB query at {kb_metric['ops_per_second']} ops/sec is below 20 ops/sec minimum."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Real E2E quality gate (requires Playwright)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.skipif(
    os.environ.get("SKIP_REAL_BENCHMARK") == "1",
    reason="SKIP_REAL_BENCHMARK=1 set — skipping real E2E benchmark"
)
class TestRealBenchmarkGate(unittest.TestCase):
    """Enforce real E2E detection rate and false-positive discipline."""

    @classmethod
    def setUpClass(cls):
        """Run the full real benchmark once and cache results."""
        from benchmarks.benchmark_real import RealBenchmarkRunner
        runner = RealBenchmarkRunner(
            max_payloads_per_route=30,
            max_genetic_generations=3,
            browser_timeout_ms=8000,
        )
        try:
            cls._results = runner.run()
        except Exception as e:
            cls._results = {"error": str(e), "detection_rate": 0, "false_positive_rate": 100}
            runner._stop_mock_target()

    def test_detection_rate_above_60_percent(self):
        """XSSBOSS must detect ≥ 60% of known-vulnerable routes."""
        self.assertGreaterEqual(
            self._results["detection_rate"], 60.0,
            f"Detection rate {self._results['detection_rate']}% is below 60% gate."
        )

    def test_zero_false_positives_on_safe_routes(self):
        """XSSBOSS must NOT report XSS on properly-escaped safe routes."""
        self.assertEqual(
            self._results["false_positive_rate"], 0.0,
            f"False positive rate is {self._results['false_positive_rate']}% — expected 0%."
        )

    def test_easy_routes_all_detected(self):
        """All 'easy' difficulty routes must be detected."""
        easy_results = [r for r in self._results.get("results", [])
                        if r["difficulty"] == "easy" and r["expected_vulnerable"]]
        missed = [r["route_name"] for r in easy_results if r["classification"] != "TP"]
        self.assertEqual(
            len(missed), 0,
            f"Easy routes missed: {missed}"
        )


if __name__ == "__main__":
    unittest.main()
