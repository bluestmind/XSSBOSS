import unittest
from unittest.mock import patch

from backend_api.config import settings
from backend_api.models.experiment import ExperimentStrategy
from fuzzer.generator import PayloadGenerator
from fuzzer.strategy import Strategy, StrategyProfile


class StrategyTests(unittest.TestCase):
    def test_database_and_fuzzer_strategy_enums_stay_in_sync(self):
        self.assertEqual(
            {strategy.value for strategy in ExperimentStrategy},
            {strategy.value for strategy in Strategy},
        )

    def test_smart_adaptive_is_bounded_and_tokenized(self):
        payloads = PayloadGenerator().generate_payloads(
            context_type="HTML_TEXT",
            token="adaptive_token_123",
            strategy=Strategy.SMART_ADAPTIVE,
            max_payloads=12,
        )

        self.assertGreaterEqual(len(payloads), 6)
        self.assertLessEqual(len(payloads), 12)
        self.assertTrue(all("adaptive_token_123" in payload for payload in payloads))

    def test_csp_profile_rejects_script_payload_in_preferred_context(self):
        self.assertFalse(StrategyProfile.should_use_payload(
            Strategy.CSP_AWARE,
            "ATTR_QUOTED",
            "<script>alert(1)</script>",
        ))

    def test_strict_filter_keeps_valid_tagged_template_handler(self):
        token = "STRICT_FILTER_TOKEN"
        profile = {
            "blocked_tokens": ["script", "onerror", "onload", "javascript", "(", ")", "'", '"'],
            "allowed_tokens": ["svg", "animate", "onbegin"],
            "normalization_behavior": [],
            "waf_detected": False,
            "sanitizer_detected": True,
            "probe_results": [
                {"probe_name": "char_`", "payload": "xss`xss", "blocked": False,
                 "escaped": False, "stripped": False, "reflected": True},
            ],
        }

        with patch.object(settings, "LLM_ENABLED", False):
            payloads = PayloadGenerator().generate_payloads(
                context_type="HTML_TEXT",
                token=token,
                strategy=Strategy.UNICODE_HUNT,
                filter_profile=profile,
                max_payloads=8,
            )

        self.assertTrue(any(
            f"onbegin=__XSS__`{token}`" in payload for payload in payloads
        ))


if __name__ == "__main__":
    unittest.main()
