"""Unit tests for Fitness Signal Attribution and Execution Log Serialization."""
import unittest
from backend_api.utils.log_serializer import parse_execution_logs, serialize_execution_logs
from backend_api.models.test_case import TestCase
from backend_api.models.execution import Execution, OracleStatus
from fuzzer.genetic import FitnessScorer


class TestFitnessAttribution(unittest.TestCase):

    def test_log_serializer_json_roundtrip(self):
        """Verify structured logs serialize to JSON and parse back cleanly."""
        logs_data = {
            "token": "XSSBOSS_TEST_123",
            "csp_violation": True,
            "blocked_uri": "https://attacker.com/xss?token=XSSBOSS_TEST_123",
            "errors": ["Uncaught SyntaxError: Unexpected token 'XSSBOSS_TEST_123'"],
            "console": ["Debug log"],
            "sink": "innerHTML",
            "tech_stack": {"react": "18.2.0"}
        }

        serialized = serialize_execution_logs(logs_data)
        self.assertIsInstance(serialized, str)
        self.assertIn('"token": "XSSBOSS_TEST_123"', serialized)

        parsed = parse_execution_logs(serialized)
        self.assertEqual(parsed["token"], "XSSBOSS_TEST_123")
        self.assertTrue(parsed["csp_violation"])
        self.assertEqual(parsed["sink"], "innerHTML")
        self.assertEqual(parsed["tech_stack"]["react"], "18.2.0")

    def test_log_serializer_ast_fallback(self):
        """Verify legacy str(dict) format is parsed gracefully for backwards compatibility."""
        legacy_str = "{'token': 'LEGACY_999', 'errors': ['Error: test'], 'csp_violation': False}"
        parsed = parse_execution_logs(legacy_str)
        self.assertEqual(parsed["token"], "LEGACY_999")
        self.assertEqual(parsed["errors"], ["Error: test"])
        self.assertFalse(parsed["csp_violation"])

    def test_csp_noise_immunity_without_token(self):
        """Third-party background CSP violations without payload token should NOT inflate fitness."""
        token = "PROBE_TOKEN_ABC123"
        test_case = TestCase(id=1, token=token, payload=f"<script>{token}</script>")
        unrelated_csp_logs = serialize_execution_logs({
            "sink": "securitypolicyviolation",
            "blocked_uri": "https://analytics.google.com/collect",
            "violated_directive": "font-src",
            "errors": []
        })
        execution = Execution(id=1, oracle_status=OracleStatus.MISSED, logs=unrelated_csp_logs, dom_snapshot="")

        fitness = FitnessScorer.calculate_fitness(test_case, execution)
        self.assertEqual(fitness, 0.0)

    def test_genuine_csp_violation_with_token(self):
        """Payload token present in blocked URI or sample must receive high fitness score (90)."""
        token = "PROBE_TOKEN_ABC123"
        test_case = TestCase(id=1, token=token, payload=f"<script>{token}</script>")
        genuine_csp_logs = serialize_execution_logs({
            "sink": "securitypolicyviolation",
            "blocked_uri": f"https://example.com/api?probe={token}",
            "violated_directive": "script-src",
            "sample": f"<script src=//{token}.evil.com>",
            "errors": []
        })
        execution = Execution(id=1, oracle_status=OracleStatus.MISSED, logs=genuine_csp_logs, dom_snapshot="")

        fitness = FitnessScorer.calculate_fitness(test_case, execution)
        self.assertEqual(fitness, 90.0)

    def test_generic_console_error_noise_immunity(self):
        """Generic application errors without token should NOT inflate score."""
        token = "PROBE_TOKEN_XYZ"
        test_case = TestCase(id=1, token=token, payload=f"'{token}'")
        
        # Base execution with clean DOM reflection
        base_logs = serialize_execution_logs({"errors": [], "console": []})
        exec_base = Execution(id=1, oracle_status=OracleStatus.MISSED, logs=base_logs, dom_snapshot=f"<div>{token}</div>")
        base_fitness = FitnessScorer.calculate_fitness(test_case, exec_base)

        # Execution with generic 3rd-party error
        unrelated_error_logs = serialize_execution_logs({
            "errors": ["TypeError: Cannot read properties of undefined (reading 'map')"],
            "console": ["Google Tag Manager loaded"]
        })
        exec_unrelated = Execution(id=2, oracle_status=OracleStatus.MISSED, logs=unrelated_error_logs, dom_snapshot=f"<div>{token}</div>")
        unrelated_fitness = FitnessScorer.calculate_fitness(test_case, exec_unrelated)

        # Fitness must be identical (no unearned error bonus)
        self.assertEqual(unrelated_fitness, base_fitness)

    def test_syntax_error_with_token_co_occurrence(self):
        """Syntax error caused by breakout containing payload token gets error reward (+30)."""
        token = "PROBE_TOKEN_XYZ"
        test_case = TestCase(id=1, token=token, payload=f"'{token}'")
        
        base_logs = serialize_execution_logs({"errors": [], "console": []})
        exec_base = Execution(id=1, oracle_status=OracleStatus.MISSED, logs=base_logs, dom_snapshot=f"<div>{token}</div>")
        base_fitness = FitnessScorer.calculate_fitness(test_case, exec_base)

        breakout_error_logs = serialize_execution_logs({
            "errors": [f"Uncaught SyntaxError: Invalid or unexpected token '{token}'"],
            "console": []
        })
        exec_breakout = Execution(id=2, oracle_status=OracleStatus.MISSED, logs=breakout_error_logs, dom_snapshot=f"<div>{token}</div>")
        breakout_fitness = FitnessScorer.calculate_fitness(test_case, exec_breakout)

        # Breakout syntax error grants exactly +30
        self.assertEqual(breakout_fitness - base_fitness, 30.0)

    def test_sink_attribution_requires_token(self):
        """Dangerous sink reach requires token co-occurrence."""
        token = "PROBE_TOKEN_SINK"
        test_case = TestCase(id=1, token=token, payload=f"<img src=x onerror=1>{token}")
        
        base_logs = serialize_execution_logs({"errors": [], "console": []})
        exec_base = Execution(id=1, oracle_status=OracleStatus.MISSED, logs=base_logs, dom_snapshot=f"<div>{token}</div>")
        base_fitness = FitnessScorer.calculate_fitness(test_case, exec_base)

        # Unrelated sink read by framework
        unrelated_sink_logs = serialize_execution_logs({
            "sink": "innerHTML",
            "data": "<div>Normal user navigation bar</div>"
        })
        exec_unrelated = Execution(id=2, oracle_status=OracleStatus.MISSED, logs=unrelated_sink_logs, dom_snapshot=f"<div>{token}</div>")
        unrelated_fitness = FitnessScorer.calculate_fitness(test_case, exec_unrelated)
        self.assertEqual(unrelated_fitness, base_fitness)

        # Genuine sink reach containing token
        genuine_sink_logs = serialize_execution_logs({
            "sink": "innerHTML",
            "data": f"<img src=x onerror=1>{token}</div>"
        })
        exec_genuine = Execution(id=3, oracle_status=OracleStatus.MISSED, logs=genuine_sink_logs, dom_snapshot=f"<div>{token}</div>")
        genuine_fitness = FitnessScorer.calculate_fitness(test_case, exec_genuine)
        # Genuine sink grants +50 bonus
        self.assertEqual(genuine_fitness - base_fitness, 50.0)


if __name__ == "__main__":
    unittest.main()
