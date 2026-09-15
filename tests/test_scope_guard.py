import unittest

from backend_api.models.target import Target
from backend_api.utils.scope_guard import (
    allowed_hosts_for_target,
    is_host_allowed,
    is_url_in_scope,
    scope_rule_matches_url,
)


class ScopeGuardTests(unittest.TestCase):
    def test_manual_target_is_exact_host_and_path(self):
        target = Target(base_url="https://app.example.com/account")

        self.assertTrue(is_url_in_scope(target, "https://app.example.com/account"))
        self.assertTrue(is_url_in_scope(target, "https://app.example.com/account/profile"))
        self.assertFalse(is_url_in_scope(target, "https://app.example.com/admin"))
        self.assertFalse(is_url_in_scope(target, "https://dev.app.example.com/account"))
        self.assertFalse(is_url_in_scope(target, "http://app.example.com/account"))

    def test_explicit_scope_does_not_get_widened_by_base_url(self):
        target = Target(
            base_url="https://example.com",
            scope_tags={"in_scope": ["https://example.com/public/*"]},
        )

        self.assertTrue(is_url_in_scope(target, "https://example.com/public/search"))
        self.assertFalse(is_url_in_scope(target, "https://example.com/admin"))

    def test_wildcard_requires_explicit_rule_and_excludes_apex(self):
        target = Target(
            base_url="https://example.com",
            scope_tags={"in_scope": ["*.example.com"]},
        )

        self.assertTrue(is_url_in_scope(target, "https://api.example.com/v1"))
        self.assertFalse(is_url_in_scope(target, "https://example.com/"))
        self.assertFalse(is_url_in_scope(target, "https://example.com.attacker.invalid/"))
        self.assertEqual(allowed_hosts_for_target(target), ["*.example.com"])
        self.assertTrue(is_host_allowed("api.example.com", ["*.example.com"]))
        self.assertFalse(is_host_allowed("example.com", ["*.example.com"]))

    def test_out_of_scope_rule_wins(self):
        target = Target(
            base_url="https://example.com",
            scope_tags={
                "in_scope": ["https://example.com/*"],
                "out_of_scope": ["https://example.com/billing/*"],
            },
        )

        self.assertTrue(is_url_in_scope(target, "https://example.com/profile"))
        self.assertFalse(is_url_in_scope(target, "https://example.com/billing/cards"))

    def test_rejects_normalization_and_userinfo_scope_bypasses(self):
        target = Target(
            base_url="https://example.com/app",
            scope_tags={"in_scope": ["https://example.com/app"]},
        )

        self.assertFalse(is_url_in_scope(target, "https://example.com/app/%2e%2e/admin"))
        self.assertFalse(is_url_in_scope(target, "https://example.com/app/%252e%252e/admin"))
        self.assertFalse(is_url_in_scope(target, "https://example.com/app%2fadmin"))
        self.assertFalse(is_url_in_scope(target, "https://user@example.com/app"))
        self.assertFalse(scope_rule_matches_url("https://user@example.com/app", "https://example.com/app"))

    def test_scheme_port_and_query_constraints_are_exact(self):
        rule = "https://example.com:8443/search?tenant=allowed*"
        self.assertTrue(scope_rule_matches_url(rule, "https://example.com:8443/search?tenant=allowed-1"))
        self.assertFalse(scope_rule_matches_url(rule, "https://example.com/search?tenant=allowed-1"))
        self.assertFalse(scope_rule_matches_url(rule, "http://example.com:8443/search?tenant=allowed-1"))
        self.assertFalse(scope_rule_matches_url(rule, "https://example.com:8443/search?tenant=other"))
        self.assertTrue(scope_rule_matches_url("example.com:8443/app", "https://example.com:8443/app"))
        self.assertFalse(scope_rule_matches_url("example.com:8443/app", "https://example.com:9443/app"))


if __name__ == "__main__":
    unittest.main()
