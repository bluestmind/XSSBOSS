"""Unit tests validating XSSBoss Fuzzer Efficacy Benchmark."""
import unittest
from benchmarks.benchmark_fuzzer_efficacy import XSSBossBenchmarkRunner, BENCHMARK_CHALLENGES


class TestFuzzerBenchmark(unittest.TestCase):

    def setUp(self):
        self.runner = XSSBossBenchmarkRunner(max_attempts=60)

    def test_xssboss_guided_benchmark_efficacy(self):
        """Verify XSSBoss guided fuzzer achieves high bypass rate across filter/context challenges."""
        summary = self.runner.run_full_benchmark()

        # XSSBoss should achieve at least 80% to 100% success rate on canonical challenges
        self.assertGreaterEqual(summary["xssboss_success_rate"], 80.0)
        self.assertGreaterEqual(summary["xssboss_solved"], 4)

        # XSSBoss should solve challenges with fewer iterations on average than random baseline
        self.assertLess(summary["xssboss_avg_attempts"], summary["naive_avg_attempts"])

    def test_attribute_breakout_challenge(self):
        """Verify attribute breakout with angle brackets blocked is solved efficiently."""
        challenge = BENCHMARK_CHALLENGES[0]
        res = self.runner.run_xssboss_guided_benchmark(challenge)
        self.assertTrue(res["solved"])
        self.assertIsNotNone(res["winning_payload"])
        self.assertNotIn("<", res["winning_payload"])
        self.assertNotIn(">", res["winning_payload"])


if __name__ == "__main__":
    unittest.main()
