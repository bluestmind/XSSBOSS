"""Execute a tightly bounded inert A/A/B series for one URL lineage candidate.

The runner is intentionally narrow.  It can only repeat an already-authorized
GET navigation, can only replace one query or fragment value with alphanumeric
stimuli, and stops after three isolated browser runs.  It never writes request
bodies, headers, cookies, paths, custom workflows, or stored-view endpoints.
The fixed A, A, B order is order-confounded prioritization evidence even when it
is repeatable.  It never confirms XSS; only the execution oracle can do that.
"""
from __future__ import annotations

import copy
import hashlib
import re
import secrets
from typing import Any, Callable, Mapping
from urllib.parse import parse_qsl, quote, unquote, urlsplit

from analysis_engine.runtime_lineage_probe import RuntimeLineageProbeCoordinator
from backend_api.utils.runtime_lineage_evidence import (
    classify_runtime_lineage,
    seal_runtime_lineage_probe_evidence,
)
from backend_api.config import settings


MAX_PROBE_RUNS = 3
_FINGERPRINT = re.compile(r"^[0-9a-fA-F]{64}$")
_URL_SOURCE_CATEGORIES = frozenset({
    "document_uri",
    "document_url",
    "location_hash",
    "location_href",
    "location_search",
    "navigation_state",
    "url",
    "url_fragment",
    "url_param",
    "url_param_index",
    "url_query",
})
_QUERY_SOURCE_CATEGORIES = _URL_SOURCE_CATEGORIES - {"location_hash", "url_fragment"}
_FRAGMENT_SOURCE_CATEGORIES = _URL_SOURCE_CATEGORIES - {
    "location_search",
    "url_param",
    "url_param_index",
    "url_query",
}
_SINK_PRIORITY = {
    "eval": 100,
    "function_ctor": 100,
    "timer_string": 95,
    "script_text": 90,
    "script_src": 85,
    "srcdoc": 80,
    "document_write": 75,
    "range_fragment": 70,
    "insertadjacenthtml": 65,
    "outerhtml": 65,
    "innerhtml": 60,
    "jquery_html": 60,
    "setattribute": 45,
    "attribute": 40,
    "navigation": 30,
    "location": 30,
}
_STATE_CHANGING_TERMS = (
    "activate",
    "approve",
    "cancel",
    "checkout",
    "deactivate",
    "delete",
    "destroy",
    "disable",
    "logout",
    "purchase",
    "remove",
    "reset",
    "revoke",
    "signout",
    "terminate",
    "transfer",
    "unsubscribe",
    "withdraw",
)
_METHOD_OVERRIDE_HEADERS = frozenset({
    "x-http-method",
    "x-http-method-override",
    "x-method-override",
})
_METHOD_OVERRIDE_PARAMS = frozenset({
    "_method",
    "http_method",
    "method_override",
    "x-http-method-override",
})


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def runtime_lineage_capture_supports_probes(mode: Any) -> bool:
    """A/A/B needs lineage retained on misses for every arm."""
    return isinstance(mode, str) and mode.strip().lower() in {
        "all", "true", "1", "yes", "on",
    }


def _valid_fingerprint(value: Any) -> bool:
    return isinstance(value, str) and _FINGERPRINT.fullmatch(value) is not None


def _eligible_candidate(primary_result: Mapping[str, Any], location: str) -> dict[str, Any] | None:
    logs = primary_result.get("logs")
    if not isinstance(logs, Mapping):
        return None
    lineage = logs.get("runtime_lineage")
    if not isinstance(lineage, Mapping):
        return None
    flows = lineage.get("causal_flows")
    if not isinstance(flows, list):
        return None

    allowed_sources = (
        _QUERY_SOURCE_CATEGORIES
        if location == "query"
        else _FRAGMENT_SOURCE_CATEGORIES
    )
    candidates: list[dict[str, Any]] = []
    for item in flows[:8]:
        if not isinstance(item, Mapping):
            continue
        candidate_id = item.get("candidate_id")
        sink_fingerprint = item.get("sink_fingerprint")
        source_category = item.get("source_category")
        sink_category = item.get("sink_category")
        if (
            item.get("classification") != "causal_only"
            or not _valid_fingerprint(candidate_id)
            or not _valid_fingerprint(sink_fingerprint)
            or not isinstance(source_category, str)
            or source_category not in allowed_sources
            or not isinstance(sink_category, str)
        ):
            continue
        candidates.append({
            "candidate_id": candidate_id.lower(),
            "sink_fingerprint": sink_fingerprint.lower(),
            "sink_category": sink_category,
            "priority": _SINK_PRIORITY.get(sink_category, 0),
        })
    if not candidates:
        return None
    candidates.sort(
        key=lambda item: (-item["priority"], item["candidate_id"])
    )
    return candidates[0]


def _is_safe_url_probe(
    test_case_data: Mapping[str, Any],
    primary_result: Mapping[str, Any],
    *,
    param_name: str,
    param_location: str,
) -> bool:
    location = str(param_location or "").lower()
    if location not in {"query", "fragment", "hash"}:
        return False
    if not isinstance(param_name, str) or not param_name or len(param_name) > 255:
        return False
    if str(test_case_data.get("method") or "GET").upper() != "GET":
        return False
    if test_case_data.get("steps") or test_case_data.get("stored_view_url"):
        return False
    if test_case_data.get("body") is not None or test_case_data.get("json") is not None:
        return False
    # Dynamic auth performs its own health/login navigations and can mutate the
    # account between arms. Static cookies/headers remain unchanged and are
    # pinned in the execution envelope.
    if test_case_data.get("auth_spec"):
        return False
    if test_case_data.get("fake_message_origin") is not None:
        return False
    if getattr(settings, "BYPASS_CSP", False):
        return False
    if primary_result.get("oracle_hit") is not False:
        return False
    if primary_result.get("execution_error") or primary_result.get("human_intervention"):
        return False
    url = test_case_data.get("url")
    if not isinstance(url, str) or not url:
        return False
    try:
        parsed = urlsplit(url)
        # Accessing ``port`` validates malformed and out-of-range ports now,
        # before a reservation or browser context can be created.
        _ = parsed.port
    except (TypeError, ValueError):
        return False
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return False
    decoded_path = unquote(parsed.path).lower()
    lowered_name = param_name.lower()
    if any(term in decoded_path or term in lowered_name for term in _STATE_CHANGING_TERMS):
        return False

    headers = test_case_data.get("headers") or {}
    if not isinstance(headers, Mapping) or any(
        type(name) is not str or name.strip().lower() in _METHOD_OVERRIDE_HEADERS
        for name in headers
    ):
        return False

    params = test_case_data.get("params") or {}
    if not isinstance(params, Mapping) or len(params) > 128:
        return False
    for key, value in params.items():
        if type(key) is not str or not key or len(key) > 255:
            return False
        if key.strip().lower() in _METHOD_OVERRIDE_PARAMS:
            return False
        if type(value) not in {str, int, float, bool}:
            return False
        if type(value) is str and len(value) > 8192:
            return False

    try:
        url_query = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=128)
    except (TypeError, ValueError):
        return False
    if any(not key or len(key) > 255 or len(value) > 8192 for key, value in url_query):
        return False
    if location == "query":
        if param_name not in params and all(key != param_name for key, _ in url_query):
            return False
        retained_fragment = unquote(parsed.fragment).lower()
        if any(term in retained_fragment for term in _STATE_CHANGING_TERMS):
            return False
    elif not parsed.fragment:
        return False

    # Only the active parameter/fragment is replaced. Refuse to replay a URL
    # when another retained query component advertises a state-changing action.
    retained_query_parts = [
        text.lower()
        for key, value in url_query
        if key != param_name
        for text in (unquote(key), unquote(value))
    ]
    retained_query_parts.extend(
        text.lower()
        for key, value in params.items()
        if key != param_name
        for text in (key, value)
        if type(text) is str
    )
    if any(
        term in component
        for component in retained_query_parts
        for term in _STATE_CHANGING_TERMS
    ):
        return False
    status_code = primary_result.get("status_code")
    if (
        isinstance(status_code, bool)
        or not isinstance(status_code, int)
        or status_code < 200
        or status_code >= 400
    ):
        return False
    return _same_origin(url, primary_result.get("final_url"))


def _same_origin(expected_url: str, observed_url: Any) -> bool:
    if not isinstance(observed_url, str):
        return False
    try:
        expected = urlsplit(expected_url)
        observed = urlsplit(observed_url)
        expected_port = expected.port or (
            443 if expected.scheme.lower() == "https" else 80
        )
        observed_port = observed.port or (
            443 if observed.scheme.lower() == "https" else 80
        )
    except (TypeError, ValueError):
        return False
    return (
        expected.scheme.lower(),
        (expected.hostname or "").lower(),
        expected_port,
        expected.path or "/",
    ) == (
        observed.scheme.lower(),
        (observed.hostname or "").lower(),
        observed_port,
        observed.path or "/",
    )


def can_run_safe_url_probe_series(
    executor: Any,
    test_case_data: Mapping[str, Any],
    primary_result: Mapping[str, Any],
    *,
    param_name: str,
    param_location: str,
) -> bool:
    """Return whether a case may reserve its one bounded A/A/B series.

    This preflight is deliberately pure: it only inspects the executor and the
    already-materialized primary result.  The runner repeats these checks after
    the durable reservation so a later call cannot bypass the same boundary.
    """
    if not isinstance(test_case_data, Mapping) or not isinstance(
        primary_result, Mapping
    ):
        return False
    location = str(param_location or "").lower()
    if (
        getattr(settings, "USE_UNDETECTED_CHROME", False)
        or getattr(executor, "uc_driver", None) is not None
    ):
        return False
    if not _is_safe_url_probe(
        test_case_data,
        primary_result,
        param_name=param_name,
        param_location=location,
    ):
        return False
    candidate = _eligible_candidate(
        primary_result,
        "query" if location == "query" else "fragment",
    )
    if candidate is None:
        return False
    return callable(
        getattr(executor, "create_runtime_lineage_envelope", None)
    )


def _probe_case(
    test_case_data: Mapping[str, Any],
    *,
    param_name: str,
    param_location: str,
    step: Mapping[str, Any],
    execution_envelope: Mapping[str, Any],
) -> dict[str, Any]:
    probe = step["runtime_lineage_probe"]
    stimulus = probe["stimulus"]
    data = copy.deepcopy(dict(test_case_data))
    data["payload"] = stimulus
    data["param_name"] = param_name
    canonical_location = "query" if param_location.lower() == "query" else "fragment"
    data["runtime_lineage_probe"] = {
        **dict(probe),
        "parameter_name": param_name,
        "parameter_location": canonical_location,
    }
    data["runtime_lineage_observations"] = [
        dict(item) for item in step["runtime_lineage_observations"]
    ]
    data["suppress_artifacts"] = True
    data["_runtime_lineage_execution_envelope"] = copy.deepcopy(
        dict(execution_envelope)
    )
    # The lineage hooks match values against the injected token, so the token
    # must be the exact inert stimulus. It remains deliberately unregistered and
    # therefore cannot consume the primary test case's authoritative token.
    data["token"] = stimulus

    location = param_location.lower()
    if location == "query":
        params = dict(data.get("params") or {})
        params[param_name] = stimulus
        data["params"] = params
    else:
        data["url"] = f"{str(data['url']).split('#', 1)[0]}#{quote(stimulus, safe='')}"
    return data


def run_safe_url_probe_series(
    executor: Any,
    test_case_data: Mapping[str, Any],
    primary_result: Mapping[str, Any],
    *,
    param_name: str,
    param_location: str,
    attempt_no: int = 1,
    before_request: Callable[[str], Any] | None = None,
    after_request: Callable[[Mapping[str, Any]], Any] | None = None,
) -> dict[str, Any] | None:
    """Return an order-confounded priority signal after three controlled runs.

    ``None`` means the case was ineligible, a run failed, a structural candidate
    changed, or the A/A/B result did not establish value influence.  The primary
    execution remains authoritative in every such case.  A returned report does
    not establish script execution or XSS; only the execution oracle does.
    """
    location = str(param_location or "").lower()
    # Repeat the worker's pure preflight here as a defense-in-depth boundary for
    # direct callers and for state that changes after the durable reservation.
    if not can_run_safe_url_probe_series(
        executor,
        test_case_data,
        primary_result,
        param_name=param_name,
        param_location=location,
    ):
        return None
    candidate = _eligible_candidate(
        primary_result,
        "query" if location == "query" else "fragment",
    )
    if candidate is None:
        return None

    envelope_factory = getattr(executor, "create_runtime_lineage_envelope", None)
    if not callable(envelope_factory):
        return None
    execution_envelope = envelope_factory(dict(test_case_data))
    if not isinstance(execution_envelope, Mapping):
        return None

    stable_key = _fingerprint(
        "|".join((
            str(test_case_data.get("test_case_id") or "unknown"),
            param_name,
            location,
            candidate["candidate_id"],
        ))
    )
    # Do not derive target-visible stimuli from an oracle token or other stored
    # identifier. One random marker is retained only for this in-memory series.
    marker = "RLP" + secrets.token_hex(8)
    coordinator = RuntimeLineageProbeCoordinator()
    step = coordinator.begin(
        stable_key,
        candidate["candidate_id"],
        candidate["sink_fingerprint"],
        marker,
    )
    final_report: Mapping[str, Any] | None = None

    for _ in range(MAX_PROBE_RUNS):
        probe_data = _probe_case(
            test_case_data,
            param_name=param_name,
            param_location=location,
            step=step,
            execution_envelope=execution_envelope,
        )
        if before_request is not None:
            before_request(str(probe_data["url"]))
        result = executor.execute_test_case(probe_data, None)
        if not isinstance(result, Mapping):
            return None
        if after_request is not None:
            after_request(result)
        if (
            result.get("oracle_hit") is not False
            or result.get("execution_error")
            or result.get("human_intervention")
            or result.get("runtime_lineage_probe_request_blocked", False) is not False
            or not _same_origin(str(probe_data["url"]), result.get("final_url"))
        ):
            return None
        status_code = result.get("status_code")
        if (
            isinstance(status_code, bool)
            or not isinstance(status_code, int)
            or status_code < 200
            or status_code >= 400
        ):
            return None
        logs = result.get("logs")
        report = logs.get("runtime_lineage") if isinstance(logs, Mapping) else None
        if not isinstance(report, Mapping):
            return None
        next_step = coordinator.accept_report(
            stable_key,
            candidate["candidate_id"],
            report,
        )
        if next_step.get("status") not in {"probe", "complete"}:
            return None
        step = next_step
        final_report = report

    if step.get("status") != "complete" or step.get("classification") != "value_influence":
        return None
    sealed = seal_runtime_lineage_probe_evidence(
        final_report,
        test_case_id=test_case_data.get("test_case_id"),
        attempt_no=attempt_no,
        series_id=step.get("series_id"),
        accepted_observations=step.get("runtime_lineage_observations"),
    )
    if classify_runtime_lineage(
        sealed,
        test_case_id=test_case_data.get("test_case_id"),
        attempt_no=attempt_no,
    ) != "value_influence":
        return None
    return sealed


__all__ = [
    "MAX_PROBE_RUNS",
    "can_run_safe_url_probe_series",
    "runtime_lineage_capture_supports_probes",
    "run_safe_url_probe_series",
]
