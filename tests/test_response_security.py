"""Focused tests for passive response security posture observations."""
import pytest

from backend_api.utils.response_security import analyze_response
from browser_workers.executor import BrowserExecutor
from unittest.mock import MagicMock, patch
from backend_api.config import settings


def test_separates_enforced_and_report_only_csp_and_exact_trusted_types():
    result = analyze_response(
        url="https://example.test/account?token=secret#private",
        status_code=200,
        headers={
            "Content-Security-Policy": "default-src 'self'; script-src 'nonce-abc' 'strict-dynamic'",
            "Content-Security-Policy-Report-Only": [
                "require-trusted-types-for 'script'; trusted-types app"
            ],
        },
    )

    assert result["schema_version"] == "response-security-posture/v1"
    assert result["target"]["url"] == "https://example.test/account"
    assert result["observations"]["csp"]["state"] == "enforced_and_report_only"
    assert result["observations"]["trusted_types"]["state"] == "report_only"
    assert result["observations"]["trusted_types"]["exact_script_sink_enforcement"] is False

    enforced = analyze_response(
        url="https://example.test/",
        status_code=200,
        headers={"content-security-policy": "require-trusted-types-for 'script'"},
    )
    assert enforced["observations"]["trusted_types"]["state"] == "enforced"


def test_does_not_accept_substring_or_unquoted_trusted_types_token():
    for policy in (
        "require-trusted-types-for script",
        "require-trusted-types-for 'script-more'",
    ):
        result = analyze_response(
            url="https://example.test/",
            status_code=200,
            headers={"Content-Security-Policy": policy},
        )
        assert result["observations"]["trusted_types"]["state"] == "not_enforced"


def test_validates_key_headers_and_csp_frame_ancestors_covers_framing():
    result = analyze_response(
        url="https://example.test/",
        status_code=200,
        headers={
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff-extra",
            "Referrer-Policy": "future-policy, strict-origin",
            "Permissions-Policy": "camera=(), microphone=()",
            "Cross-Origin-Opener-Policy": "same-origin",
        },
    )
    posture = result["observations"]["headers"]
    assert posture["strict_transport_security"]["state"] == "valid"
    assert posture["strict_transport_security"]["max_age_seconds"] == 31536000
    assert posture["x_content_type_options"]["state"] == "invalid"
    assert posture["x_frame_options"]["state"] == "covered_by_csp"
    assert posture["referrer_policy"]["recognized_policy"] == "strict-origin"
    assert posture["permissions_policy"]["state"] == "syntactically_valid"
    assert posture["cross_origin_opener_policy"]["state"] == "valid"


def test_cookie_output_is_attribute_only_and_never_contains_names_or_values():
    secret_name = "session_identifier"
    secret_value = "top-secret-cookie-value"
    result = analyze_response(
        url="https://example.test/",
        status_code=200,
        headers={"Set-Cookie": f"{secret_name}={secret_value}; Secure; HttpOnly"},
        cookie_metadata=[
            {
                "name": secret_name,
                "value": secret_value,
                "secure": True,
                "httpOnly": True,
                "sameSite": "None",
                "domain": ".example.test",
                "path": "/private",
            }
        ],
    )
    cookie_posture = result["observations"]["cookies"]
    assert cookie_posture["state"] == "observed"
    assert cookie_posture["cookies"][0] == {
        "index": 0,
        "secure": True,
        "http_only": True,
        "same_site": "none",
        "partitioned": None,
        "domain_attribute_present": True,
        "path_scope": "scoped",
        "expiration_declared": False,
        "name_prefix": None,
        "prefix_invariants_valid": None,
    }
    serialized = repr(result)
    assert secret_name not in serialized
    assert secret_value not in serialized


def test_set_cookie_without_metadata_is_explicitly_unknown_and_not_parsed():
    secret = "do-not-return-me"
    result = analyze_response(
        url="https://example.test/",
        status_code=200,
        headers={"Set-Cookie": f"sid={secret}; Secure; HttpOnly; SameSite=Lax"},
    )
    cookies = result["observations"]["cookies"]
    assert cookies["state"] == "metadata_unavailable"
    assert cookies["cookie_count"] is None
    assert cookies["attribute_summary"]["secure"] == "unknown"
    assert secret not in repr(result)


def test_cookie_prefix_invariants_are_checked_without_retaining_names():
    result = analyze_response(
        url="https://example.test/",
        status_code=200,
        headers={},
        cookie_metadata=[
            {
                "name": "__Host-private-session",
                "value": "secret-one",
                "secure": True,
                "httpOnly": True,
                "sameSite": "Lax",
                "path": "/",
                "domain": "",
            },
            {
                "name": "__Host-broken-session",
                "value": "secret-two",
                "secure": True,
                "path": "/",
                "domain": ".example.test",
            },
        ],
    )

    cookies = result["observations"]["cookies"]["cookies"]
    assert cookies[0]["prefix_invariants_valid"] is True
    assert cookies[1]["prefix_invariants_valid"] is False
    assert "private-session" not in repr(result)
    assert "secret-one" not in repr(result)
    assert any(
        item["code"] == "cookie_prefix_invariant_invalid"
        for item in result["evidence"]
    )


def test_cors_syntax_and_wildcard_credentials_conflict_are_observations():
    result = analyze_response(
        url="https://api.example.test/data",
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    cors = result["observations"]["cors"]
    assert cors["state"] == "wildcard_credentials_conflict"
    assert cors["allow_origin"]["kind"] == "wildcard"
    assert any(item["code"] == "cors_wildcard_credentials" for item in result["evidence"])

    invalid = analyze_response(
        url="https://api.example.test/data",
        status_code=200,
        headers={"Access-Control-Allow-Origin": "https://a.test https://b.test"},
    )
    assert invalid["observations"]["cors"]["state"] == "invalid_syntax"


def test_duplicate_allow_origin_field_instances_are_invalid_even_when_identical():
    result = analyze_response(
        url="https://api.example.test/data",
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": [
                "https://client.example",
                "https://client.example",
            ]
        },
    )
    cors = result["observations"]["cors"]
    assert cors["state"] == "invalid_syntax"
    assert cors["allow_origin"] == {
        "state": "invalid",
        "kind": "invalid",
        "field_instance_count": 2,
        "duplicate_field_instances": True,
    }


def test_cors_origin_with_trailing_path_separator_is_invalid_serialization():
    result = analyze_response(
        url="https://api.example.test/data",
        status_code=200,
        headers={"Access-Control-Allow-Origin": "https://client.example/"},
    )

    assert result["observations"]["cors"]["state"] == "invalid_syntax"


@pytest.mark.parametrize(
    (
        "policies",
        "element_state",
        "attribute_state",
        "eval_state",
        "intersection",
    ),
    [
        ([], "unknown", "unknown", "unknown", False),
        (["img-src 'self'"], "allowed", "allowed", "allowed", False),
        (["default-src 'self'"], "blocked", "blocked", "blocked", False),
        (
            ["script-src 'unsafe-inline' 'unsafe-eval'"],
            "allowed",
            "allowed",
            "allowed",
            False,
        ),
        (
            [
                "script-src 'unsafe-eval'; "
                "script-src-elem 'unsafe-inline'; script-src-attr 'none'"
            ],
            "allowed",
            "blocked",
            "allowed",
            False,
        ),
        (
            [
                "default-src 'unsafe-inline' 'unsafe-eval'; "
                "script-src-elem 'none'"
            ],
            "blocked",
            "allowed",
            "allowed",
            False,
        ),
        (
            [
                "script-src 'unsafe-inline' 'unsafe-eval'",
                "default-src 'self'",
            ],
            "blocked",
            "blocked",
            "blocked",
            True,
        ),
    ],
)
def test_effective_csp_script_controls_follow_fallback_and_policy_intersection(
    policies,
    element_state,
    attribute_state,
    eval_state,
    intersection,
):
    headers = {"Content-Security-Policy": policies} if policies else {}
    result = analyze_response(
        url="https://example.test/",
        status_code=200,
        headers=headers,
    )
    controls = result["observations"]["csp"]["effective_script_controls"]
    assert controls["effective_inline_script_element_state"] == element_state
    assert controls["effective_inline_script_attribute_state"] == attribute_state
    assert controls["effective_eval_state"] == eval_state
    assert controls["effective_policy_intersection_applied"] is intersection


@pytest.mark.parametrize(
    "source_expression",
    ["'nonce-randomvalue'", "'sha256-AbCdEf0123456789='"],
)
def test_nonce_or_hash_makes_unsafe_inline_ineffective_in_modern_csp(
    source_expression,
):
    result = analyze_response(
        url="https://example.test/",
        status_code=200,
        headers={
            "Content-Security-Policy": (
                f"script-src 'unsafe-inline' {source_expression}"
            )
        },
    )
    controls = result["observations"]["csp"]["effective_script_controls"]
    assert controls["effective_inline_script_element_state"] == "blocked"
    assert controls["effective_inline_script_attribute_state"] == "blocked"
    assert controls["unsafe_inline_ineffective_due_to_nonce_or_hash"] is True
    assert any(
        item["code"] == "csp_unsafe_inline_ineffective"
        for item in result["evidence"]
    )


def test_combined_csp_field_policy_list_uses_restrictive_intersection():
    result = analyze_response(
        url="https://example.test/",
        status_code=200,
        headers={
            "Content-Security-Policy": (
                "script-src 'unsafe-inline' 'unsafe-eval', default-src 'self'"
            )
        },
    )
    csp = result["observations"]["csp"]
    controls = csp["effective_script_controls"]
    assert csp["enforced"]["policy_count"] == 2
    assert controls["effective_policy_intersection_applied"] is True
    assert controls["effective_inline_script_element_state"] == "blocked"
    assert controls["effective_inline_script_attribute_state"] == "blocked"
    assert controls["effective_eval_state"] == "blocked"


def test_cache_observation_uses_only_explicit_context_and_does_not_claim_exploit():
    result = analyze_response(
        url="https://example.test/profile",
        status_code=200,
        headers={"Cache-Control": "public, s-maxage=300"},
        browser_telemetry={"authenticated": True, "dom": "private content"},
    )
    cache = result["observations"]["cache"]
    assert cache["response_context"] == "explicitly_sensitive"
    assert cache["shared_cache_exposure"] == "possible"
    assert result["assessment"]["exploitability"] == "not_assessed"
    assert "private content" not in repr(result)


def test_unknown_and_not_applicable_states_are_preserved():
    result = analyze_response(
        url="http://example.test/",
        status_code=204,
        headers={},
    )
    observations = result["observations"]
    assert observations["csp"]["state"] == "missing"
    assert observations["trusted_types"]["state"] == "unknown"
    assert observations["headers"]["strict_transport_security"]["state"] == "not_applicable"
    assert observations["cookies"]["state"] == "unknown"
    assert observations["cors"]["state"] == "not_declared"
    assert observations["cache"]["response_context"] == "unknown"
    assert len(result["limitations"]) >= 4


def test_untrusted_header_and_cookie_metadata_are_bounded():
    cookies = [
        {"name": f"cookie-{index}", "value": "secret", "secure": True}
        for index in range(250)
    ]
    headers = {
        **{f"X-Unused-{index}": "x" for index in range(400)},
        "Content-Security-Policy": ["default-src 'self'"] * 100,
    }
    # Put the relevant field first so the global field bound does not intentionally omit it.
    headers = {"Content-Security-Policy": headers.pop("Content-Security-Policy"), **headers}

    result = analyze_response(
        url="https://example.test/",
        status_code=200,
        headers=headers,
        cookie_metadata=cookies,
    )

    assert result["observations"]["csp"]["enforced"]["policy_count"] == 32
    assert result["observations"]["cookies"]["cookie_count"] == 100
    assert result["observations"]["cookies"]["truncated"] is True
    assert "cookie-" not in repr(result)
    assert "secret" not in repr(result)


def test_browser_cookie_capture_discards_identifiers_and_values_immediately():
    metadata = BrowserExecutor._cookie_attribute_metadata([{
        "name": "session-secret-name",
        "value": "session-secret-value",
        "secure": True,
        "httpOnly": True,
        "sameSite": "Lax",
        "domain": ".example.test",
        "path": "/private",
        "expires": 1_900_000_000,
    }])

    assert "session-secret" not in repr(metadata)
    assert metadata[0]["secure"] is True
    assert metadata[0]["path"] == "<scoped>"


def test_browser_response_selector_rejects_iframe_navigation_and_subresources():
    page = MagicMock()
    main_frame = object()
    page.main_frame = main_frame
    response = MagicMock()
    response.request.is_navigation_request.return_value = True
    response.request.frame = object()
    assert BrowserExecutor._is_main_navigation_response(response, page) is False

    response.request.frame = main_frame
    assert BrowserExecutor._is_main_navigation_response(response, page) is True

    response.request.is_navigation_request.return_value = False
    assert BrowserExecutor._is_main_navigation_response(response, page) is False


def test_browser_posture_marks_unavailable_metadata_instead_of_fake_success():
    posture = BrowserExecutor._build_response_posture(
        url="https://example.test/private?token=secret",
        status_code=200,
        headers={"Content-Security-Policy": "default-src 'self'"},
        cookie_metadata=None,
        metadata_observed=False,
        request_has_credentials=True,
        source="uc_metadata_unavailable",
    )

    assert posture["target"]["status_code"] is None
    assert posture["target"]["url"] == "https://example.test/private"
    assert posture["observations"]["csp"]["state"] == "missing"
    assert posture["assessment"]["metadata_observed"] is False


def test_browser_posture_discloses_when_csp_is_removed_for_execution():
    with patch.object(settings, "BYPASS_CSP", True):
        posture = BrowserExecutor._build_response_posture(
            url="https://example.test/",
            status_code=200,
            headers={"Content-Security-Policy": "default-src 'self'"},
            cookie_metadata=[],
            metadata_observed=True,
            request_has_credentials=False,
            source="main_navigation",
        )

    assert posture["assessment"]["browser_policy_modified"] is True
    assert "removed CSP" in posture["limitations"][0]
