"""
XSSBOSS Benchmark Suite — Master Orchestrator.

Runs all benchmark modules and produces:
- Console summary table
- JSON results (saved to benchmarks/results/)
- Markdown report (saved to benchmarks/results/)
- Pass/fail exit code for CI

Usage:
    python -m benchmarks.benchmark_suite              # Full suite (real E2E + component)
    python -m benchmarks.benchmark_suite --real-only   # Real E2E only
    python -m benchmarks.benchmark_suite --fast        # Component benchmarks only (no browser)
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def run_real_benchmark() -> Dict[str, Any]:
    """Run the real end-to-end benchmark with Playwright."""
    print("\n" + "━" * 75)
    print("  🔬 PHASE 1: Real End-to-End Benchmark (Playwright + Live Server)")
    print("━" * 75)
    from benchmarks.benchmark_real import RealBenchmarkRunner
    runner = RealBenchmarkRunner(
        max_payloads_per_route=30,
        max_genetic_generations=3,
        browser_timeout_ms=8000,
    )
    try:
        return runner.run()
    except Exception as e:
        print(f"  ❌ Real benchmark failed: {e}")
        import traceback
        traceback.print_exc()
        runner._stop_mock_target()
        return {"benchmark": "Real E2E", "error": str(e), "passed": False}


def run_context_classifier_benchmark() -> Dict[str, Any]:
    """Run the context classifier accuracy benchmark."""
    print("\n" + "━" * 75)
    print("  🔬 PHASE 2: Context Classifier Accuracy Benchmark")
    print("━" * 75)
    try:
        from benchmarks.benchmark_context_classifier import ContextClassifierBenchmark
        benchmark = ContextClassifierBenchmark()
        return benchmark.run()
    except Exception as e:
        print(f"  ❌ Context classifier benchmark failed: {e}")
        return {"benchmark": "Context Classifier", "error": str(e), "passed": False}


def run_false_positive_benchmark() -> Dict[str, Any]:
    """Run the false-positive discipline benchmark."""
    print("\n" + "━" * 75)
    print("  🔬 PHASE 3: False-Positive Discipline Benchmark")
    print("━" * 75)
    try:
        from benchmarks.benchmark_false_positive import FalsePositiveBenchmark
        benchmark = FalsePositiveBenchmark()
        return benchmark.run()
    except Exception as e:
        print(f"  ❌ False-positive benchmark failed: {e}")
        return {"benchmark": "False Positive", "error": str(e), "passed": False}


def run_fuzzer_efficacy_benchmark() -> Dict[str, Any]:
    """Run the existing fuzzer efficacy benchmark."""
    print("\n" + "━" * 75)
    print("  🔬 PHASE 4: Fuzzer Efficacy Benchmark (Component-Level)")
    print("━" * 75)
    try:
        from benchmarks.benchmark_fuzzer_efficacy import XSSBossBenchmarkRunner
        runner = XSSBossBenchmarkRunner(max_attempts=60)
        summary = runner.run_full_benchmark()
        summary["benchmark"] = "Fuzzer Efficacy"
        summary["passed"] = summary["xssboss_success_rate"] >= 80.0
        return summary
    except Exception as e:
        print(f"  ❌ Fuzzer efficacy benchmark failed: {e}")
        return {"benchmark": "Fuzzer Efficacy", "error": str(e), "passed": False}


def generate_markdown_report(all_results: List[Dict[str, Any]], elapsed: float) -> str:
    """Generate a Markdown report from all benchmark results."""
    lines = [
        "# XSSBOSS Benchmark Report",
        "",
        f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Total Runtime:** {elapsed:.1f}s",
        "",
        "## Summary",
        "",
        "| Benchmark | Status | Key Metric |",
        "|---|---|---|",
    ]

    for r in all_results:
        name = r.get("benchmark", "Unknown")
        passed = r.get("passed", False)
        status = "✅ PASS" if passed else "❌ FAIL"

        if "detection_rate" in r:
            metric = f"Detection: {r['detection_rate']}% | FP: {r['false_positive_rate']}%"
        elif "accuracy" in r:
            metric = f"Accuracy: {r['accuracy']}%"
        elif "fp_rate" in r:
            metric = f"FP Rate: {r['fp_rate']}%"
        elif "xssboss_success_rate" in r:
            metric = f"Bypass Rate: {r['xssboss_success_rate']}%"
        elif "error" in r:
            metric = f"Error: {r['error']}"
        else:
            metric = "—"

        lines.append(f"| {name} | {status} | {metric} |")

    # Real E2E details
    for r in all_results:
        if r.get("benchmark") == "XSSBOSS Real E2E Benchmark" and "results" in r:
            lines.extend([
                "",
                "## Real End-to-End Results",
                "",
                "| Route | Difficulty | Expected | Result | Payloads | Winning Payload |",
                "|---|---|---|---|---|---|",
            ])
            for detail in r["results"]:
                vuln = "Vulnerable" if detail["expected_vulnerable"] else "Safe"
                cls = detail["classification"]
                icon = {"TP": "✅", "TN": "✅", "FP": "❌", "FN": "❌"}.get(cls, "?")
                payload = (detail.get("winning_payload") or "—")[:60]
                lines.append(
                    f"| {detail['route_name']} | {detail['difficulty']} | {vuln} | {icon} {cls} | "
                    f"{detail['attempts_to_exploit']}/{detail['total_payloads_generated']} | `{payload}` |"
                )

    lines.append("")
    return "\n".join(lines)


def main():
    # Windows terminals and redirected files commonly default to cp1252, while
    # this report deliberately uses Unicode status symbols.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="XSSBOSS Benchmark Suite")
    parser.add_argument("--real-only", action="store_true", help="Run only the real E2E benchmark")
    parser.add_argument("--fast", action="store_true", help="Run only component-level benchmarks (no browser)")
    args = parser.parse_args()

    print("\n" + "█" * 75)
    print("█" + " " * 73 + "█")
    print("█" + "    XSSBOSS BENCHMARK SUITE".center(73) + "█")
    print("█" + " " * 73 + "█")
    print("█" * 75)

    start_time = time.time()
    all_results: List[Dict[str, Any]] = []

    if args.real_only:
        all_results.append(run_real_benchmark())
    elif args.fast:
        all_results.append(run_context_classifier_benchmark())
        all_results.append(run_false_positive_benchmark())
        all_results.append(run_fuzzer_efficacy_benchmark())
    else:
        # Full suite
        all_results.append(run_real_benchmark())
        all_results.append(run_context_classifier_benchmark())
        all_results.append(run_false_positive_benchmark())
        all_results.append(run_fuzzer_efficacy_benchmark())

    elapsed = time.time() - start_time

    # Overall pass/fail
    all_passed = all(r.get("passed", False) for r in all_results)

    print("\n" + "█" * 75)
    print("█" + " " * 73 + "█")
    print("█" + "    OVERALL RESULT".center(73) + "█")
    overall = "✅ ALL BENCHMARKS PASSED" if all_passed else "❌ SOME BENCHMARKS FAILED"
    print("█" + f"    {overall}".center(73) + "█")
    print("█" + f"    Total time: {elapsed:.1f}s".center(73) + "█")
    print("█" + " " * 73 + "█")
    print("█" * 75)

    # Save results
    results_dir = ROOT / "benchmarks" / "results"
    results_dir.mkdir(exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")

    # JSON
    json_path = results_dir / f"suite_{ts}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "elapsed_seconds": elapsed,
            "all_passed": all_passed,
            "benchmarks": all_results,
        }, f, indent=2, default=str)
    print(f"\n  📄 JSON results: {json_path}")

    # Markdown
    md_path = results_dir / f"report_{ts}.md"
    md_content = generate_markdown_report(all_results, elapsed)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)
    print(f"  📄 Markdown report: {md_path}")

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
