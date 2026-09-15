"""Passive response security posture observations.

The analyzer only interprets response metadata supplied by an authorized caller.  It
does not issue requests, replay cookies, or attempt to prove exploitability.  Raw
header values and cookie values are intentionally excluded from the result.
"""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit


SCHEMA_VERSION = "response-security-posture/v1"
MAX_HEADER_FIELDS = 256
MAX_HEADER_VALUES_PER_FIELD = 32
MAX_HEADER_VALUE_CHARS = 16_384
MAX_COOKIE_METADATA_ITEMS = 100

_DIRECTIVE_NAME = re.compile(r"^[a-z][a-z0-9-]*$")
_INTEGER = re.compile(r"^[0-9]+$")
_NONCE_OR_HASH_SOURCE = re.compile(
    r"^'(?:nonce-[^']+|sha(?:256|384|512)-[^']+)'$",
    re.IGNORECASE,
)
_VALID_REFERRER_POLICIES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}
_VALID_COOP = {
    "unsafe-none",
    "same-origin-allow-popups",
    "same-origin",
    "noopener-allow-popups",
}
_VALID_COEP = {"unsafe-none", "require-corp", "credentialless"}
_VALID_CORP = {"same-origin", "same-site", "cross-origin"}


def _safe_url(raw_url: Any) -> str:
    """Return a URL identifier without credentials, query parameters, or fragments."""
    try:
        parsed = urlsplit(str(raw_url or ""))
        if not parsed.scheme or not parsed.hostname:
            return "<invalid-url>"
        hostname = parsed.hostname
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        netloc = hostname
        if parsed.port is not None:
            netloc = f"{netloc}:{parsed.port}"
        return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", "", ""))
    except (TypeError, ValueError):
        return "<invalid-url>"


def _safe_source(source: Any) -> str:
    candidate = str(source or "").strip().lower()
    if re.fullmatch(r"[a-z][a-z0-9_-]{0,39}", candidate):
        return candidate
    return "other"


def _header_map(headers: Any) -> Dict[str, List[str]]:
    """Normalize header names while retaining separate field instances when supplied."""
    normalized: Dict[str, List[str]] = {}
    if not isinstance(headers, Mapping):
        return normalized
    for field_index, (raw_name, raw_value) in enumerate(headers.items()):
        if field_index >= MAX_HEADER_FIELDS:
            break
        name = str(raw_name).strip().lower()[:256]
        if not name:
            continue
        if isinstance(raw_value, Sequence) and not isinstance(
            raw_value, (str, bytes, bytearray)
        ):
            values = []
            for value_index, item in enumerate(raw_value):
                if value_index >= MAX_HEADER_VALUES_PER_FIELD:
                    break
                values.append(str(item)[:MAX_HEADER_VALUE_CHARS])
        elif raw_value is None:
            values = []
        else:
            values = [str(raw_value)[:MAX_HEADER_VALUE_CHARS]]
        normalized.setdefault(name, []).extend(values)
    return normalized


def _first(headers: Dict[str, List[str]], name: str) -> Optional[str]:
    values = headers.get(name, [])
    return values[0].strip() if values else None


def _tokens(value: Optional[str], separator: str = ",") -> List[str]:
    if value is None:
        return []
    return [part.strip().lower() for part in value.split(separator) if part.strip()]


def _resolve_script_source_list(
    directives: Dict[str, List[str]], directive_chain: Tuple[str, ...]
) -> Tuple[Optional[List[str]], Optional[str]]:
    """Resolve one CSP3 fetch directive through its defined fallback chain."""
    for directive in directive_chain:
        if directive in directives:
            return directives[directive], directive
    return None, None


def _contains_nonce_or_hash(sources: Optional[List[str]]) -> bool:
    return bool(
        sources
        and any(_NONCE_OR_HASH_SOURCE.fullmatch(token) for token in sources)
    )


def _inline_state(sources: Optional[List[str]]) -> Tuple[str, bool]:
    """Evaluate a generic inline script without a matching nonce or hash."""
    if sources is None:
        return "allowed", False
    unsafe_inline = "'unsafe-inline'" in sources
    nonce_or_hash = _contains_nonce_or_hash(sources)
    ineffective_unsafe_inline = unsafe_inline and nonce_or_hash
    return (
        "allowed" if unsafe_inline and not nonce_or_hash else "blocked",
        ineffective_unsafe_inline,
    )


def _effective_policy_script_controls(
    directives: Dict[str, List[str]],
) -> Dict[str, Any]:
    """Compute browser-effective script controls for one CSP policy.

    Each enforced CSP policy is applied independently by browsers.  These states
    describe generic inline code without a matching nonce/hash; they do not claim
    that nonce-bearing application scripts are blocked.
    """
    element_sources, element_directive = _resolve_script_source_list(
        directives, ("script-src-elem", "script-src", "default-src")
    )
    attribute_sources, attribute_directive = _resolve_script_source_list(
        directives, ("script-src-attr", "script-src", "default-src")
    )
    eval_sources, eval_directive = _resolve_script_source_list(
        directives, ("script-src", "default-src")
    )
    element_state, element_unsafe_inline_ineffective = _inline_state(element_sources)
    attribute_state, attribute_unsafe_inline_ineffective = _inline_state(
        attribute_sources
    )
    eval_state = (
        "allowed"
        if eval_sources is None or "'unsafe-eval'" in eval_sources
        else "blocked"
    )
    return {
        "effective_inline_script_element_state": element_state,
        "effective_inline_script_attribute_state": attribute_state,
        "effective_eval_state": eval_state,
        "effective_inline_script_element_directive": (
            element_directive or "unrestricted"
        ),
        "effective_inline_script_attribute_directive": (
            attribute_directive or "unrestricted"
        ),
        "effective_eval_directive": eval_directive or "unrestricted",
        "element_unsafe_inline_ineffective_due_to_nonce_or_hash": (
            element_unsafe_inline_ineffective
        ),
        "attribute_unsafe_inline_ineffective_due_to_nonce_or_hash": (
            attribute_unsafe_inline_ineffective
        ),
        "unsafe_inline_ineffective_due_to_nonce_or_hash": (
            element_unsafe_inline_ineffective
            or attribute_unsafe_inline_ineffective
        ),
    }


def _parse_csp_policy(value: str) -> Dict[str, Any]:
    directives: Dict[str, List[str]] = {}
    duplicate_directives: List[str] = []
    malformed_directives = 0
    for segment in value.split(";"):
        pieces = segment.strip().split()
        if not pieces:
            continue
        name = pieces[0].lower()
        if not _DIRECTIVE_NAME.fullmatch(name):
            malformed_directives += 1
            continue
        if name in directives:
            duplicate_directives.append(name)
            continue
        directives[name] = [token.lower() for token in pieces[1:]]

    script_sources = directives.get("script-src")
    fallback_used = False
    if script_sources is None and "default-src" in directives:
        script_sources = directives["default-src"]
        fallback_used = True

    if script_sources is None:
        script_controls = {
            "source_restriction_declared": False,
            "fallback_to_default_src": False,
            "unsafe_inline_declared": None,
            "unsafe_eval_declared": None,
            "nonce_or_hash_declared": None,
            "strict_dynamic_declared": None,
        }
    else:
        script_controls = {
            "source_restriction_declared": True,
            "fallback_to_default_src": fallback_used,
            "unsafe_inline_declared": "'unsafe-inline'" in script_sources,
            "unsafe_eval_declared": "'unsafe-eval'" in script_sources,
            "nonce_or_hash_declared": any(
                token.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
                for token in script_sources
            ),
            "strict_dynamic_declared": "'strict-dynamic'" in script_sources,
        }
    script_controls.update(_effective_policy_script_controls(directives))

    return {
        "directive_names": sorted(directives),
        "duplicate_directives": sorted(set(duplicate_directives)),
        "malformed_directive_count": malformed_directives,
        "script_controls": script_controls,
        "requires_trusted_types_for_script": (
            "'script'" in directives.get("require-trusted-types-for", [])
        ),
        "trusted_types_policy_restriction_declared": "trusted-types" in directives,
        "frame_ancestors_declared": "frame-ancestors" in directives,
    }


def _summarize_policies(values: List[str]) -> Dict[str, Any]:
    policies = [_parse_csp_policy(value) for value in values if value.strip()]
    names = sorted({name for policy in policies for name in policy["directive_names"]})
    controls = [policy["script_controls"] for policy in policies]
    def intersect(field: str) -> str:
        if not controls:
            return "unknown"
        states = [item[field] for item in controls]
        if "blocked" in states:
            return "blocked"
        if all(state == "allowed" for state in states):
            return "allowed"
        return "unknown"

    element_state = intersect("effective_inline_script_element_state")
    attribute_state = intersect("effective_inline_script_attribute_state")
    eval_state = intersect("effective_eval_state")

    return {
        "state": "present" if policies else "missing",
        "policy_count": len(policies),
        "directive_names": names,
        "duplicate_directives": sorted(
            {name for policy in policies for name in policy["duplicate_directives"]}
        ),
        "malformed_directive_count": sum(
            policy["malformed_directive_count"] for policy in policies
        ),
        "script_controls": {
            "source_restriction_declared": (
                any(item["source_restriction_declared"] for item in controls)
                if controls
                else None
            ),
            "unsafe_inline_declared": (
                any(item["unsafe_inline_declared"] is True for item in controls)
                if controls
                else None
            ),
            "unsafe_eval_declared": (
                any(item["unsafe_eval_declared"] is True for item in controls)
                if controls
                else None
            ),
            "nonce_or_hash_declared": (
                any(item["nonce_or_hash_declared"] is True for item in controls)
                if controls
                else None
            ),
            "strict_dynamic_declared": (
                any(item["strict_dynamic_declared"] is True for item in controls)
                if controls
                else None
            ),
            "effective_inline_script_element_state": element_state,
            "effective_inline_script_attribute_state": attribute_state,
            "effective_eval_state": eval_state,
            "effective_policy_intersection_applied": len(controls) > 1,
            "inline_script_element_restricting_policy_count": sum(
                item["effective_inline_script_element_state"] == "blocked"
                for item in controls
            ),
            "inline_script_attribute_restricting_policy_count": sum(
                item["effective_inline_script_attribute_state"] == "blocked"
                for item in controls
            ),
            "eval_restricting_policy_count": sum(
                item["effective_eval_state"] == "blocked" for item in controls
            ),
            "effective_inline_script_element_directives": sorted(
                {
                    item["effective_inline_script_element_directive"]
                    for item in controls
                }
            ),
            "effective_inline_script_attribute_directives": sorted(
                {
                    item["effective_inline_script_attribute_directive"]
                    for item in controls
                }
            ),
            "effective_eval_directives": sorted(
                {item["effective_eval_directive"] for item in controls}
            ),
            "unsafe_inline_ineffective_due_to_nonce_or_hash": (
                any(
                    item["unsafe_inline_ineffective_due_to_nonce_or_hash"]
                    for item in controls
                )
                if controls
                else None
            ),
            "element_unsafe_inline_ineffective_due_to_nonce_or_hash": (
                any(
                    item[
                        "element_unsafe_inline_ineffective_due_to_nonce_or_hash"
                    ]
                    for item in controls
                )
                if controls
                else None
            ),
            "attribute_unsafe_inline_ineffective_due_to_nonce_or_hash": (
                any(
                    item[
                        "attribute_unsafe_inline_ineffective_due_to_nonce_or_hash"
                    ]
                    for item in controls
                )
                if controls
                else None
            ),
        },
        "requires_trusted_types_for_script": any(
            policy["requires_trusted_types_for_script"] for policy in policies
        ),
        "trusted_types_policy_restriction_declared": any(
            policy["trusted_types_policy_restriction_declared"] for policy in policies
        ),
        "frame_ancestors_declared": any(
            policy["frame_ancestors_declared"] for policy in policies
        ),
    }


def _csp_policy_field_values(
    headers: Dict[str, List[str]], name: str
) -> List[str]:
    """Expand the CSP serialized-policy-list form used for combined fields."""
    return [
        policy.strip()
        for field_value in headers.get(name, [])
        for policy in field_value.split(",")
        if policy.strip()
    ]


def _analyze_csp(headers: Dict[str, List[str]]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    enforced = _summarize_policies(
        _csp_policy_field_values(headers, "content-security-policy")
    )
    report_only = _summarize_policies(
        _csp_policy_field_values(headers, "content-security-policy-report-only")
    )
    if enforced["state"] == "present" and report_only["state"] == "present":
        state = "enforced_and_report_only"
    elif enforced["state"] == "present":
        state = "enforced"
    elif report_only["state"] == "present":
        state = "report_only"
    else:
        state = "missing"

    if enforced["requires_trusted_types_for_script"]:
        tt_state = "enforced"
    elif report_only["requires_trusted_types_for_script"]:
        tt_state = "report_only"
    elif enforced["state"] == "present" or report_only["state"] == "present":
        tt_state = "not_enforced"
    else:
        tt_state = "unknown"

    trusted_types = {
        "state": tt_state,
        "exact_script_sink_enforcement": tt_state == "enforced",
        "enforced_policy_restriction_declared": enforced[
            "trusted_types_policy_restriction_declared"
        ],
        "report_only_policy_restriction_declared": report_only[
            "trusted_types_policy_restriction_declared"
        ],
    }
    effective = {
        key: enforced["script_controls"][key]
        for key in (
            "effective_inline_script_element_state",
            "effective_inline_script_attribute_state",
            "effective_eval_state",
            "effective_policy_intersection_applied",
            "inline_script_element_restricting_policy_count",
            "inline_script_attribute_restricting_policy_count",
            "eval_restricting_policy_count",
            "unsafe_inline_ineffective_due_to_nonce_or_hash",
        )
    }
    return {
        "state": state,
        "enforced": enforced,
        "report_only": report_only,
        "effective_script_controls": effective,
    }, trusted_types


def _parse_hsts(value: Optional[str], is_https: bool) -> Dict[str, Any]:
    if not is_https:
        return {
            "state": "not_applicable",
            "present": value is not None,
            "reason": "HSTS is only learned from secure transport.",
        }
    if value is None:
        return {"state": "missing", "present": False}
    parts = [part.strip() for part in value.split(";") if part.strip()]
    max_ages: List[int] = []
    include_subdomains = False
    preload = False
    malformed = False
    for part in parts:
        key, separator, raw_argument = part.partition("=")
        key = key.strip().lower()
        if key == "max-age":
            argument = raw_argument.strip().strip('"') if separator else ""
            if _INTEGER.fullmatch(argument):
                max_ages.append(int(argument))
            else:
                malformed = True
        elif key == "includesubdomains" and not separator:
            include_subdomains = True
        elif key == "preload" and not separator:
            preload = True
    valid = len(max_ages) == 1 and not malformed
    return {
        "state": "valid" if valid else "invalid",
        "present": True,
        "max_age_seconds": max_ages[0] if len(max_ages) == 1 else None,
        "include_subdomains": include_subdomains,
        "preload_declared": preload,
    }


def _exact_header(
    value: Optional[str], valid_values: set[str], *, missing_state: str = "missing"
) -> Dict[str, Any]:
    if value is None:
        return {"state": missing_state, "present": False}
    normalized = value.strip().lower()
    return {
        "state": "valid" if normalized in valid_values else "invalid",
        "present": True,
        "recognized_value": normalized if normalized in valid_values else None,
    }


def _analyze_headers(
    headers: Dict[str, List[str]], *, is_https: bool, frame_ancestors: bool
) -> Dict[str, Dict[str, Any]]:
    xfo = _exact_header(_first(headers, "x-frame-options"), {"deny", "sameorigin"})
    if xfo["state"] == "missing" and frame_ancestors:
        xfo = {
            "state": "covered_by_csp",
            "present": False,
            "csp_frame_ancestors_declared": True,
        }

    referrer_value = _first(headers, "referrer-policy")
    referrer_tokens = _tokens(referrer_value)
    recognized_referrer = [
        token for token in referrer_tokens if token in _VALID_REFERRER_POLICIES
    ]
    if referrer_value is None:
        referrer = {"state": "missing", "present": False}
    else:
        referrer = {
            "state": "valid" if recognized_referrer else "invalid",
            "present": True,
            "recognized_policy": recognized_referrer[-1] if recognized_referrer else None,
            "unrecognized_token_count": len(referrer_tokens) - len(recognized_referrer),
        }

    permissions = _first(headers, "permissions-policy")
    if permissions is None:
        permissions_result = {"state": "missing", "present": False}
    else:
        entries = [item.strip() for item in permissions.split(",") if item.strip()]
        syntactic = bool(entries) and all(
            re.match(r"^[a-zA-Z][a-zA-Z0-9-]*\s*=\s*\([^)]*\)$", item)
            for item in entries
        )
        permissions_result = {
            "state": "syntactically_valid" if syntactic else "unverified_syntax",
            "present": True,
            "declared_feature_count": len(entries),
        }

    return {
        "strict_transport_security": _parse_hsts(
            _first(headers, "strict-transport-security"), is_https
        ),
        "x_content_type_options": _exact_header(
            _first(headers, "x-content-type-options"), {"nosniff"}
        ),
        "x_frame_options": xfo,
        "referrer_policy": referrer,
        "permissions_policy": permissions_result,
        "cross_origin_opener_policy": _exact_header(
            _first(headers, "cross-origin-opener-policy"), _VALID_COOP
        ),
        "cross_origin_embedder_policy": _exact_header(
            _first(headers, "cross-origin-embedder-policy"), _VALID_COEP
        ),
        "cross_origin_resource_policy": _exact_header(
            _first(headers, "cross-origin-resource-policy"), _VALID_CORP
        ),
    }


def _origin_kind(value: str) -> str:
    candidate = value.strip()
    if candidate == "*":
        return "wildcard"
    if candidate.lower() == "null":
        return "null"
    if "," in candidate or " " in candidate:
        return "invalid"
    try:
        parsed = urlsplit(candidate)
        valid = (
            parsed.scheme.lower() in {"http", "https"}
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and parsed.path == ""
            and not parsed.query
            and not parsed.fragment
        )
        if valid:
            _ = parsed.port
            return "serialized_origin"
    except ValueError:
        pass
    return "invalid"


def _analyze_cors(headers: Dict[str, List[str]]) -> Dict[str, Any]:
    allow_origin_fields = headers.get("access-control-allow-origin", [])
    allow_origin = (
        allow_origin_fields[0].strip() if len(allow_origin_fields) == 1 else None
    )
    credentials = _first(headers, "access-control-allow-credentials")
    vary_tokens = {
        token.strip().lower()
        for value in headers.get("vary", [])
        for token in value.split(",")
        if token.strip()
    }
    if not allow_origin_fields:
        return {
            "state": "not_declared",
            "allow_origin": {
                "state": "missing",
                "kind": None,
                "field_instance_count": 0,
            },
            "allow_credentials": {
                "state": "missing" if credentials is None else "orphaned"
            },
            "vary_origin_declared": "origin" in vary_tokens,
        }

    duplicate_allow_origin = len(allow_origin_fields) != 1
    kind = "invalid" if duplicate_allow_origin else _origin_kind(allow_origin or "")
    if credentials is None:
        credential_state = "not_enabled"
    elif credentials.strip().lower() == "true":
        credential_state = "enabled"
    else:
        credential_state = "invalid"

    if kind == "invalid" or credential_state == "invalid":
        state = "invalid_syntax"
    elif kind == "wildcard" and credential_state == "enabled":
        state = "wildcard_credentials_conflict"
    elif kind == "null":
        state = "null_origin_allowed"
    else:
        state = "declared"
    return {
        "state": state,
        "allow_origin": {
            "state": "valid" if kind != "invalid" else "invalid",
            "kind": kind,
            "field_instance_count": len(allow_origin_fields),
            "duplicate_field_instances": duplicate_allow_origin,
        },
        "allow_credentials": {"state": credential_state},
        "vary_origin_declared": "origin" in vary_tokens,
        "dynamic_origin_behavior": "unknown",
    }


def _cookie_items(cookie_metadata: Any) -> Optional[List[Mapping[str, Any]]]:
    if cookie_metadata is None:
        return None
    if isinstance(cookie_metadata, Mapping):
        nested = cookie_metadata.get("cookies")
        if isinstance(nested, Sequence) and not isinstance(nested, (str, bytes, bytearray)):
            return [
                item for item in nested[: MAX_COOKIE_METADATA_ITEMS + 1]
                if isinstance(item, Mapping)
            ]
        attribute_keys = {
            "secure",
            "httponly",
            "http_only",
            "samesite",
            "same_site",
            "partitioned",
            "path",
            "domain",
            "expires",
            "max_age",
            "name_prefix",
        }
        if attribute_keys.intersection(str(key).lower() for key in cookie_metadata):
            return [cookie_metadata]
        result = []
        for value in cookie_metadata.values():
            if isinstance(value, Mapping):
                result.append(value)
                if len(result) > MAX_COOKIE_METADATA_ITEMS:
                    break
        return result
    if isinstance(cookie_metadata, Sequence) and not isinstance(
        cookie_metadata, (str, bytes, bytearray)
    ):
        return [
            item for item in cookie_metadata[: MAX_COOKIE_METADATA_ITEMS + 1]
            if isinstance(item, Mapping)
        ]
    return []


def _bool_attribute(item: Mapping[str, Any], *names: str) -> Optional[bool]:
    lowered = {str(key).lower(): value for key, value in item.items()}
    for name in names:
        if name in lowered:
            value = lowered[name]
            if isinstance(value, bool):
                return value
            if isinstance(value, (int, float)) and value in {0, 1}:
                return bool(value)
            if isinstance(value, str) and value.strip().lower() in {"true", "false"}:
                return value.strip().lower() == "true"
            return None
    return None


def _cookie_attribute(item: Mapping[str, Any], *names: str) -> Any:
    lowered = {str(key).lower(): value for key, value in item.items()}
    for name in names:
        if name in lowered:
            return lowered[name]
    return None


def _analyze_cookies(
    headers: Dict[str, List[str]], cookie_metadata: Any
) -> Dict[str, Any]:
    items = _cookie_items(cookie_metadata)
    set_cookie_observed = bool(headers.get("set-cookie"))
    if items is None:
        return {
            "state": "metadata_unavailable" if set_cookie_observed else "unknown",
            "set_cookie_header_observed": set_cookie_observed,
            "cookie_count": None,
            "cookies": [],
            "attribute_summary": {
                "secure": "unknown",
                "http_only": "unknown",
                "same_site": "unknown",
            },
        }

    observations: List[Dict[str, Any]] = []
    for index, item in enumerate(items[:MAX_COOKIE_METADATA_ITEMS]):
        secure = _bool_attribute(item, "secure")
        http_only = _bool_attribute(item, "httponly", "http_only")
        partitioned = _bool_attribute(item, "partitioned")
        raw_same_site = _cookie_attribute(item, "samesite", "same_site")
        same_site = (
            str(raw_same_site).strip().lower()
            if raw_same_site is not None
            else None
        )
        if same_site not in {"strict", "lax", "none"}:
            same_site = "unknown" if raw_same_site is not None else None
        domain = _cookie_attribute(item, "domain")
        path = _cookie_attribute(item, "path")
        raw_name = _cookie_attribute(item, "name")
        supplied_prefix = _cookie_attribute(item, "name_prefix")
        if supplied_prefix in {"__Host-", "__Secure-"}:
            name_prefix = supplied_prefix
        elif isinstance(raw_name, str) and raw_name.startswith("__Host-"):
            name_prefix = "__Host-"
        elif isinstance(raw_name, str) and raw_name.startswith("__Secure-"):
            name_prefix = "__Secure-"
        else:
            name_prefix = None
        domain_present = bool(domain)
        path_scope = "root" if path == "/" else "scoped" if path else "unknown"
        if name_prefix == "__Host-":
            prefix_invariants_valid = (
                secure is True and not domain_present and path_scope == "root"
            )
        elif name_prefix == "__Secure-":
            prefix_invariants_valid = secure is True
        else:
            prefix_invariants_valid = None
        observations.append(
            {
                "index": index,
                "secure": secure,
                "http_only": http_only,
                "same_site": same_site,
                "partitioned": partitioned,
                "domain_attribute_present": domain_present,
                "path_scope": path_scope,
                "expiration_declared": (
                    _cookie_attribute(item, "expires", "max_age") is not None
                ),
                "name_prefix": name_prefix,
                "prefix_invariants_valid": prefix_invariants_valid,
            }
        )

    def aggregate(key: str) -> str:
        values = [entry[key] for entry in observations]
        if not values:
            return "not_observed"
        if all(value is True for value in values):
            return "all"
        if any(value is False for value in values):
            return "one_or_more_missing"
        return "unknown"

    same_site_values = [entry["same_site"] for entry in observations]
    if not same_site_values:
        same_site_summary = "not_observed"
    elif all(value in {"strict", "lax"} for value in same_site_values):
        same_site_summary = "all_restrictive"
    elif any(value is None or value == "unknown" for value in same_site_values):
        same_site_summary = "one_or_more_unknown_or_missing"
    else:
        same_site_summary = "none_present"

    return {
        "state": "observed" if observations else "none_observed",
        "set_cookie_header_observed": set_cookie_observed,
        "cookie_count": len(observations),
        "truncated": len(items) > MAX_COOKIE_METADATA_ITEMS,
        "cookies": observations,
        "attribute_summary": {
            "secure": aggregate("secure"),
            "http_only": aggregate("http_only"),
            "same_site": same_site_summary,
        },
    }


def _parse_cache_control(value: Optional[str]) -> Dict[str, Optional[str]]:
    directives: Dict[str, Optional[str]] = {}
    if value is None:
        return directives
    for part in value.split(","):
        name, separator, argument = part.strip().partition("=")
        name = name.strip().lower()
        if name:
            directives[name] = argument.strip().strip('"') if separator else None
    return directives


def _telemetry_flag(browser_telemetry: Any, *keys: str) -> Optional[bool]:
    if not isinstance(browser_telemetry, Mapping):
        return None
    lowered = {str(key).lower(): value for key, value in browser_telemetry.items()}
    for key in keys:
        value = lowered.get(key)
        if isinstance(value, bool):
            return value
    return None


def _analyze_cache(
    headers: Dict[str, List[str]],
    *,
    cookie_state: Dict[str, Any],
    browser_telemetry: Any,
) -> Dict[str, Any]:
    directives = _parse_cache_control(_first(headers, "cache-control"))
    pragma = {token for token in _tokens(_first(headers, "pragma"))}
    explicit_sensitive = _telemetry_flag(
        browser_telemetry,
        "authenticated",
        "request_has_credentials",
        "sensitive_response",
    )
    if explicit_sensitive is None and cookie_state["set_cookie_header_observed"]:
        context = "possibly_stateful"
    elif explicit_sensitive:
        context = "explicitly_sensitive"
    elif explicit_sensitive is False:
        context = "explicitly_non_sensitive"
    else:
        context = "unknown"

    max_age = directives.get("max-age")
    shared_max_age = directives.get("s-maxage")
    return {
        "state": "declared" if directives else "not_declared",
        "no_store": "no-store" in directives,
        "private": "private" in directives,
        "public": "public" in directives,
        "no_cache": "no-cache" in directives or "no-cache" in pragma,
        "immutable": "immutable" in directives,
        "max_age_seconds": int(max_age) if max_age and _INTEGER.fullmatch(max_age) else None,
        "shared_max_age_seconds": (
            int(shared_max_age)
            if shared_max_age and _INTEGER.fullmatch(shared_max_age)
            else None
        ),
        "malformed_age_directive": bool(
            (max_age is not None and not _INTEGER.fullmatch(max_age))
            or (shared_max_age is not None and not _INTEGER.fullmatch(shared_max_age))
        ),
        "response_context": context,
        "shared_cache_exposure": (
            "possible"
            if context in {"possibly_stateful", "explicitly_sensitive"}
            and ("public" in directives or "s-maxage" in directives)
            and "private" not in directives
            and "no-store" not in directives
            else "not_observed"
        ),
    }


def _build_evidence_and_recommendations(
    csp: Dict[str, Any],
    trusted_types: Dict[str, Any],
    headers: Dict[str, Dict[str, Any]],
    cookies: Dict[str, Any],
    cors: Dict[str, Any],
    cache: Dict[str, Any],
) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    evidence: List[Dict[str, str]] = []
    recommendations: List[Dict[str, str]] = []

    def observe(code: str, level: str, summary: str) -> None:
        evidence.append({"code": code, "level": level, "summary": summary})

    def recommend(code: str, priority: str, summary: str) -> None:
        recommendations.append({"code": code, "priority": priority, "summary": summary})

    if csp["state"] == "missing":
        observe("csp_missing", "attention", "No CSP policy was observed.")
        recommend("deploy_enforced_csp", "high", "Deploy an enforced CSP and tune it in report-only mode first.")
    elif csp["state"] == "report_only":
        observe("csp_report_only", "informational", "CSP was observed only in report-only mode.")
        recommend("promote_csp", "high", "Promote the validated report-only policy to enforcement.")
    else:
        observe("csp_enforced", "positive", "At least one enforced CSP policy was observed.")

    script_controls = csp["enforced"]["script_controls"]
    effective_controls = csp["effective_script_controls"]
    inline_allowed = any(
        effective_controls[field] == "allowed"
        for field in (
            "effective_inline_script_element_state",
            "effective_inline_script_attribute_state",
        )
    )
    if inline_allowed:
        observe(
            "csp_inline_effectively_allowed",
            "attention",
            "The enforced CSP intersection allows at least one generic inline script context.",
        )
        recommend(
            "restrict_inline_script",
            "high",
            "Restrict both script elements and script attributes with CSP3 fallbacks accounted for.",
        )
    elif script_controls["unsafe_inline_ineffective_due_to_nonce_or_hash"] is True:
        observe(
            "csp_unsafe_inline_ineffective",
            "informational",
            "Declared unsafe-inline is ineffective because the applicable source list also declares a nonce or hash.",
        )
    if effective_controls["effective_eval_state"] == "allowed":
        observe(
            "csp_eval_effectively_allowed",
            "attention",
            "The enforced CSP intersection allows string compilation such as eval.",
        )
        recommend(
            "restrict_eval",
            "medium",
            "Restrict string compilation through script-src or its default-src fallback.",
        )

    if trusted_types["state"] == "enforced":
        observe("trusted_types_enforced", "positive", "Trusted Types script sink enforcement was observed.")
    elif trusted_types["state"] == "report_only":
        observe("trusted_types_report_only", "informational", "Trusted Types script sink enforcement is report-only.")
        recommend("enforce_trusted_types", "medium", "Promote require-trusted-types-for 'script' after policy telemetry is clean.")

    for name in ("strict_transport_security", "x_content_type_options", "x_frame_options"):
        state = headers[name]["state"]
        if state == "invalid":
            observe(f"{name}_invalid", "attention", f"{name.replace('_', ' ')} has an unrecognized or invalid value.")
            recommend(f"fix_{name}", "medium", f"Correct the {name.replace('_', ' ')} header syntax.")
        elif state == "missing":
            observe(f"{name}_missing", "attention", f"{name.replace('_', ' ')} was not observed.")

    if cookies["attribute_summary"]["secure"] == "one_or_more_missing":
        observe("cookie_secure_missing", "attention", "One or more observed cookies lack the Secure attribute.")
        recommend("secure_cookies", "high", "Set Secure on cookies carried over HTTPS.")
    if cookies["attribute_summary"]["http_only"] == "one_or_more_missing":
        observe("cookie_httponly_missing", "attention", "One or more observed cookies lack HttpOnly.")
        recommend("httponly_cookies", "medium", "Set HttpOnly on cookies that do not require script access.")
    for cookie in cookies["cookies"]:
        if cookie["same_site"] == "none" and cookie["secure"] is not True:
            observe("samesite_none_without_secure", "attention", "An observed SameSite=None cookie is not confirmed Secure.")
            recommend("pair_samesite_none_secure", "high", "Pair SameSite=None with Secure.")
            break
    if any(cookie.get("prefix_invariants_valid") is False for cookie in cookies["cookies"]):
        observe(
            "cookie_prefix_invariant_invalid",
            "attention",
            "An observed prefixed cookie does not satisfy its Secure, Domain, or Path invariant.",
        )
        recommend(
            "fix_cookie_prefix_invariant",
            "high",
            "Make __Host- cookies Secure, host-only, and Path=/; make __Secure- cookies Secure.",
        )

    if cors["state"] == "invalid_syntax":
        observe("cors_invalid", "attention", "CORS response fields contain invalid syntax.")
        recommend("fix_cors_syntax", "high", "Emit one valid serialized origin or a standards-compliant wildcard policy.")
    elif cors["state"] == "wildcard_credentials_conflict":
        observe("cors_wildcard_credentials", "attention", "Wildcard origin and credentials were declared together.")
        recommend("fix_cors_credentials", "high", "Use a validated explicit origin for credentialed CORS responses.")
    elif cors["state"] == "null_origin_allowed":
        observe("cors_null_origin", "attention", "The special null origin is allowed.")
        recommend("review_null_origin", "medium", "Allow null only when the application explicitly requires it.")

    if cache["shared_cache_exposure"] == "possible":
        observe("shared_cache_sensitive_context", "attention", "Shared caching is declared for a response that may be stateful or sensitive.")
        recommend("review_shared_cache", "high", "Verify cache-key separation or mark personalized responses private/no-store.")

    return evidence, recommendations


def analyze_response(
    *,
    url: str,
    status_code: int | None,
    headers: Mapping[str, Any],
    cookie_metadata: Any = None,
    browser_telemetry: Any = None,
    source: str = "main_navigation",
) -> Dict[str, Any]:
    """Analyze supplied response metadata and return versioned posture observations.

    The result is an inventory of observable controls, not a vulnerability finding or
    an exploitability verdict.  Cookie names/values and raw response header values
    are never returned.
    """
    normalized_headers = _header_map(headers)
    safe_target = _safe_url(url)
    try:
        normalized_status = int(status_code)
    except (TypeError, ValueError):
        normalized_status = None

    csp, trusted_types = _analyze_csp(normalized_headers)
    parsed_target = urlsplit(safe_target) if safe_target != "<invalid-url>" else None
    is_https = bool(parsed_target and parsed_target.scheme == "https")
    header_posture = _analyze_headers(
        normalized_headers,
        is_https=is_https,
        frame_ancestors=csp["enforced"]["frame_ancestors_declared"],
    )
    cookies = _analyze_cookies(normalized_headers, cookie_metadata)
    cors = _analyze_cors(normalized_headers)
    cache = _analyze_cache(
        normalized_headers,
        cookie_state=cookies,
        browser_telemetry=browser_telemetry,
    )
    evidence, recommendations = _build_evidence_and_recommendations(
        csp, trusted_types, header_posture, cookies, cors, cache
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "passive_response_security_posture",
        "target": {
            "url": safe_target,
            "status_code": normalized_status,
            "source": _safe_source(source),
        },
        "assessment": {
            "mode": "passive_observation",
            "exploitability": "not_assessed",
        },
        "observations": {
            "csp": csp,
            "trusted_types": trusted_types,
            "headers": header_posture,
            "cookies": cookies,
            "cors": cors,
            "cache": cache,
        },
        "evidence": evidence,
        "recommendations": recommendations,
        "limitations": [
            "A single response cannot establish site-wide policy consistency.",
            "Report-only CSP and browser telemetry do not prove enforcement.",
            "Effective inline CSP states describe generic code without a matching application nonce or hash.",
            "CORS origin reflection requires controlled multi-origin requests to verify.",
            "Cookie posture is unknown unless attribute metadata is supplied; raw Set-Cookie values are not parsed.",
            "Cache behavior depends on intermediaries and cache keys that are not visible in response headers alone.",
        ],
    }
