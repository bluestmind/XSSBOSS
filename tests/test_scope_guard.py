import unittest

from backend_api.models.target import Target
from backend_api.utils.scope_guard import (
    allowed_hosts_for_target,
    is_host_allowed,
    is_url_in_scope,
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


if __name__ == "__main__":
    unittest.main()
