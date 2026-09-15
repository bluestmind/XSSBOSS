from __future__ import annotations

from unittest.mock import patch

import pytest

from xsscollector.scope import ScopeError, ScopePolicy, ScopeRule


def test_exact_scope_does_not_include_subdomains() -> None:
    policy = ScopePolicy(["https://example.com/app/"])
    assert policy.is_allowed("https://example.com/app/users")
    assert not policy.is_allowed("https://api.example.com/app/users")
    assert not policy.is_allowed("https://example.com/application")
    assert not policy.is_allowed("http://example.com/app/users")


def test_wildcard_is_explicit_and_excludes_apex() -> None:
    policy = ScopePolicy(["*.example.com"])
    assert policy.is_allowed("https://api.example.com/")
    assert not policy.is_allowed("https://example.com/")


def test_deny_wins() -> None:
    policy = ScopePolicy(["example.com"], ["example.com/private/*"])
    assert policy.is_allowed("https://example.com/public")
    assert not policy.is_allowed("https://example.com/private/users")


def test_embedded_url_credentials_are_rejected() -> None:
    policy = ScopePolicy(["example.com"])
    assert not policy.is_allowed("https://user:password@example.com/")


def test_private_destinations_are_rejected_by_default() -> None:
    policy = ScopePolicy(["example.test"])
    fake = [(2, 1, 6, "", ("127.0.0.1", 443))]
    with patch("socket.getaddrinfo", return_value=fake):
        with pytest.raises(ScopeError, match="private"):
            policy.validate_destination("https://example.test/")


def test_private_destinations_can_be_explicitly_enabled() -> None:
    policy = ScopePolicy(["example.test"], allow_private_networks=True)
    fake = [(2, 1, 6, "", ("127.0.0.1", 443))]
    with patch("socket.getaddrinfo", return_value=fake):
        assert policy.validate_destination("https://example.test/") == ["127.0.0.1"]
