"""Unit tests for Polyglot-First Triage Engine."""
import unittest
from fuzzer.polyglot_triage import PolyglotTriageEngine, TriageResult
from fuzzer.strategy import Strategy, StrategyProfile


class TestPolyglotTriage(unittest.TestCase):

    def test_polyglot_payload_rendering(self):
        """Polyglot payload must render the oracle token and custom callback name."""
        token = "TRIAGE_TOKEN_123"
        payload = PolyglotTriageEngine.get_triage_payload(token=token, callback_name="__ORACLE__", variant=0)

        self.assertIn(token, payload)
        self.assertIn("__ORACLE__", payload)
        # Must contain Somdev universal polyglot indicators (RCDATA closures, SVG, template breakout)
        self.assertIn("</template></noembed></noscript></style></title></textarea></script>", payload)
        self.assertIn("&lt;svg onload=", payload)
        self.assertIn("javascript:", payload)

    def test_all_polyglot_variants_render_properly(self):
        """Verify all registered polyglot triage variants render cleanly with oracle tokens."""
        token = "CANARY_ALL_VARIANTS"
        for i in range(len(PolyglotTriageEngine.TRIAGE_POLYGLOTS)):
            rendered = PolyglotTriageEngine.get_triage_payload(token=token, callback_name="__XSS__", variant=i)
            self.assertIn(token, rendered)
            self.assertIn("__XSS__", rendered)
            self.assertNotIn("{TOKEN}", rendered)
            self.assertNotIn("{CALLBACK}", rendered)

    def test_triage_immediate_execution(self):
        """When oracle executes on Request #1, triage marks vulnerability confirmed and halts further fuzzing."""
        token = "HIT_TOKEN"
        result = PolyglotTriageEngine.evaluate_triage(
            dom_snapshot=f"<svg onload=__XSS__('{token}')>",
            token=token,
            oracle_executed=True
        )

        self.assertTrue(result.executed)
        self.assertTrue(result.reflected)
        self.assertFalse(result.should_continue_fuzzing)
        self.assertEqual(result.recommended_strategy, "confirmed")

    def test_triage_zero_reflection_pruning(self):
        """When token is completely unreflected in DOM, parameter is pruned to preserve 30 req/min budget."""
        token = "MISSING_TOKEN"
        result = PolyglotTriageEngine.evaluate_triage(
            dom_snapshot="<html><body><div>Static generic landing page</div></body></html>",
            token=token,
            oracle_executed=False
        )

        self.assertFalse(result.executed)
        self.assertFalse(result.reflected)
        self.assertFalse(result.should_continue_fuzzing)
        self.assertEqual(result.recommended_strategy, "prune")

    def test_triage_residue_identifies_contexts(self):
        """When token reflects without execution, residue identifies active reflection contexts."""
        token = "RESIDUE_TOKEN"
        html = f'<html><body><input type="text" name="q" value="prefix {token} suffix"><script>var x = "{token}";</script></body></html>'
        
        result = PolyglotTriageEngine.evaluate_triage(
            dom_snapshot=html,
            token=token,
            oracle_executed=False
        )

        self.assertFalse(result.executed)
        self.assertTrue(result.reflected)
        self.assertTrue(result.should_continue_fuzzing)
        self.assertIn("ATTR_QUOTED", result.candidate_contexts)
        self.assertIn("JS_STRING_LITERAL", result.candidate_contexts)

    def test_is_triage_payload_detects_all_variants(self):
        """is_triage_payload recognises every rendered variant, token-independent, and rejects noise."""
        for i in range(len(PolyglotTriageEngine.TRIAGE_POLYGLOTS)):
            rendered = PolyglotTriageEngine.get_triage_payload(token="ABC123", variant=i)
            self.assertTrue(PolyglotTriageEngine.is_triage_payload(rendered), f"variant {i} not detected")
        # Ordinary single-context grammar payloads must not be mistaken for the triage probe.
        self.assertFalse(PolyglotTriageEngine.is_triage_payload("<img src=x onerror=__XSS__('ABC')>"))
        self.assertFalse(PolyglotTriageEngine.is_triage_payload("\"><svg onload=alert(1)>"))
        self.assertFalse(PolyglotTriageEngine.is_triage_payload(""))
        self.assertFalse(PolyglotTriageEngine.is_triage_payload(None))

    def test_residue_detects_event_handler_context(self):
        """Token surviving inside an on* handler attribute is reported as EVENT_HANDLER_ATTR."""
        token = "EVT_TOKEN"
        html = f'<div onmouseover="doThing(\'{token}\')">x</div>'
        result = PolyglotTriageEngine.evaluate_triage(dom_snapshot=html, token=token, oracle_executed=False)
        self.assertTrue(result.reflected)
        self.assertIn("EVENT_HANDLER_ATTR", result.candidate_contexts)

    def test_strategy_profile_polyglot_first(self):
        """Verify Strategy.POLYGLOT_FIRST is properly registered in StrategyProfile."""
        profile = StrategyProfile.get_profile(Strategy.POLYGLOT_FIRST)
        self.assertEqual(profile['name'], 'Polyglot-First Triage')
        self.assertEqual(profile['mutation_strategy'], 'polyglot_first')


if __name__ == "__main__":
    unittest.main()
