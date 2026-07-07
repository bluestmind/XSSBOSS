"""Unit tests for AutomataLearner."""
import unittest
from analysis_engine.automata_learner import AutomataLearner, SanitizerProfile


class TestAutomataLearner(unittest.TestCase):

    def test_learn_dompurify_mxss_vulnerable_version(self):
        """Minimal-pair differential queries identify DOMPurify <= 2.4.0 mXSS flaw."""
        def mock_dompurify_legacy(input_html: str) -> str:
            # Simulates DOMPurify <= 2.4.0 allowing math/style namespace mutation
            if "<script" in input_html.lower():
                return ""
            if "<math><style>" in input_html:
                return input_html  # Inadvertently preserves mXSS construct
            return input_html

        profile = AutomataLearner.learn_sanitizer(mock_dompurify_legacy)

        self.assertIsInstance(profile, SanitizerProfile)
        self.assertEqual(profile.library_name, "DOMPurify")
        self.assertEqual(profile.version_range, "<= 2.4.0")
        self.assertGreater(len(profile.verified_cve_bypasses), 0)
        self.assertTrue(any("annotation-xml" in b or "style" in b for b in profile.verified_cve_bypasses))

    def test_learn_recursive_strip_incomplete(self):
        """Detects incomplete non-recursive tag stripping sanitizer."""
        def mock_recursive_strip(input_html: str) -> str:
            # Single-pass non-recursive strip
            return input_html.replace("<script>", "")

        profile = AutomataLearner.learn_sanitizer(mock_recursive_strip)

        self.assertIsInstance(profile, SanitizerProfile)
        self.assertEqual(profile.library_name, "sanitize-html")
        self.assertEqual(profile.version_range, "<= 2.7.0")
        self.assertTrue(any("<scr<script>ipt>" in b for b in profile.verified_cve_bypasses))


if __name__ == "__main__":
    unittest.main()
