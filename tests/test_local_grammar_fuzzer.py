"""Unit tests for Local Coverage-Guided Grammar Fuzzer."""
import unittest
from fuzzer.local_grammar_fuzzer import LocalGrammarFuzzer, LocalFuzzCandidate


class TestLocalGrammarFuzzer(unittest.TestCase):

    def test_fixpoint_search_generates_candidates(self):
        """Fixpoint search produces candidates with parser state coverage and mutation scores."""
        token = "LOCAL_TEST_TOKEN"
        candidates = LocalGrammarFuzzer.run_fixpoint_search(token=token, max_trials=15)

        self.assertGreater(len(candidates), 0)
        top = candidates[0]
        self.assertIsInstance(top, LocalFuzzCandidate)
        self.assertIn(token, top.payload)
        self.assertGreater(len(top.states_covered), 0)

    def test_evolve_grammar_population_respects_blocked_chars(self):
        """Evolved grammar survivors do not contain blocked single characters."""
        token = "EVOLVE_TOKEN"
        blocked = {"<", ">"}
        survivors = LocalGrammarFuzzer.evolve_grammar_population(
            token=token,
            generations=2,
            population_size=10,
            blocked_chars=blocked
        )

        self.assertGreater(len(survivors), 0)
        for s in survivors:
            self.assertNotIn("<", s)
            self.assertNotIn(">", s)


if __name__ == "__main__":
    unittest.main()
