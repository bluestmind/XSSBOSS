"""Unit tests for Cross-Tenant Bandit Memory and WAF Block Weaponizer."""
import unittest
from fuzzer.bandit import ThompsonSelector, WAFBlockWeaponizer


class TestCrossTenantBandit(unittest.TestCase):

    def setUp(self):
        self.actions = [
            "apply_mixed_case",
            "apply_zero_width",
            "apply_comment_obfuscation",
            "apply_homoglyphs",
            "apply_alternative_whitespace"
        ]

    def test_fingerprint_key_generation(self):
        """Fingerprint keys are privacy-safe and combine WAF, framework, and context."""
        key = ThompsonSelector.make_fingerprint_key(
            waf="Cloudflare",
            framework="Next.js",
            context="ATTR_QUOTED"
        )
        self.assertEqual(key, "waf:cloudflare|fw:next.js|ctx:ATTR_QUOTED")

    def test_cross_tenant_memory_retention(self):
        """Trained weights for a WAF fingerprint are retained across separate bandit instances."""
        selector_a = ThompsonSelector(self.actions)
        fp_key = "waf:cloudflare|ctx:HTML_TEXT"
        
        # Train on tenant A
        for _ in range(5):
            selector_a.update("apply_comment_obfuscation", success=True, context=fp_key)

        # New tenant B creates fresh bandit selector
        selector_b = ThompsonSelector(self.actions)
        # Should initialize from cross-tenant memory with high alpha for comment obfuscation
        selector_b._ensure_context(fp_key)
        self.assertGreater(selector_b.alphas[fp_key]["apply_comment_obfuscation"], 5.0)

    def test_cloudflare_block_weaponization(self):
        """Cloudflare 403 blocks are identified and recommend comment obfuscation."""
        res = WAFBlockWeaponizer.fingerprint_block(
            status_code=403,
            headers={"cf-ray": "848231023a-IAD", "server": "cloudflare"},
            body="<html><body>Attention Required! | Cloudflare</body></html>"
        )
        self.assertIsNotNone(res)
        self.assertEqual(res["waf_detected"], "cloudflare")
        self.assertEqual(res["recommended_evasion"], "apply_comment_obfuscation")
        self.assertEqual(res["bandit_context"], "waf:cloudflare")

    def test_aws_waf_block_weaponization(self):
        """AWS WAF 403 blocks are identified from response headers and bodies."""
        res = WAFBlockWeaponizer.fingerprint_block(
            status_code=403,
            headers={"x-amzn-requestid": "abc-123", "server": "awselb/2.0"},
            body="<html><body>Request blocked by AWS WAF</body></html>"
        )
        self.assertIsNotNone(res)
        self.assertEqual(res["waf_detected"], "aws_waf")
        self.assertEqual(res["recommended_evasion"], "apply_alternative_whitespace")


if __name__ == "__main__":
    unittest.main()
