"""Safe URL probe execution is opt-in, bounded, and value-free."""
from __future__ import annotations

import copy

import pytest

from browser_workers.executor import BrowserExecutor
from browser_workers.runtime_lineage_probe_runner import (
    can_run_safe_url_probe_series,
    run_safe_url_probe_series,
    runtime_lineage_capture_supports_probes,
)


@pytest.fixture(autouse=True)
def _playwright_probe_mode(monkeypatch):
    monkeypatch.setattr(
        "browser_workers.runtime_lineage_probe_runner.settings.USE_UNDETECTED_CHROME",
        False,
    )


def _fp(character: str) -> str:
    return character * 64


def _ledger(
    observation_fingerprint: str | None = None,
    source_category: str = "location_search",
) -> dict:
    sink = {
        "kind": "sink",
        "event_id": "sink-1",
        "context_id": "ctx-1",
        "sink_category": "innerhtml",
        "sink_fingerprint": _fp("b"),
        "ts_ms": 2,
    }
    if observation_fingerprint is not None:
        sink["observation_fingerprint"] = observation_fingerprint
    return {
        "events": [
            {
                "kind": "source",
                "event_id": "source-1",
                "context_id": "ctx-1",
                "source_category": source_category,
                "source_fingerprint": _fp("a"),
                "ts_ms": 1,
            },
            sink,
        ],
    }


def _primary(data: dict, source_category: str = "location_search") -> dict:
    report = BrowserExecutor._build_runtime_lineage_report(
        [_ledger(source_category=source_category)], data
    )
    return {
        "oracle_hit": False,
        "execution_error": None,
        "human_intervention": None,
        "status_code": 200,
        "final_url": data["url"],
        "logs": {"runtime_lineage": report},
    }


class _Executor:
    def __init__(
        self,
        fingerprints=(_fp("c"), _fp("c"), _fp("d")),
        source_category="location_search",
    ):
        self.fingerprints = fingerprints
        self.source_category = source_category
        self.calls: list[dict] = []
        self.envelope_calls = 0

    def create_runtime_lineage_envelope(self, data):
        self.envelope_calls += 1
        return {
            "version": 1,
            "headers": {"User-Agent-Pin": "stable"},
            "user_agent": "Stable Browser",
            "proxy": None,
        }

    def execute_test_case(self, data, screenshot_dir):
        assert screenshot_dir is None
        self.calls.append(copy.deepcopy(data))
        fingerprint = self.fingerprints[len(self.calls) - 1]
        report = BrowserExecutor._build_runtime_lineage_report(
            [_ledger(fingerprint, self.source_category)], data
        )
        return {
            "oracle_hit": False,
            "execution_error": None,
            "human_intervention": None,
            "status_code": 200,
            "final_url": data["url"],
            "logs": {"runtime_lineage": report},
        }


def _case(**overrides) -> dict:
    return {
        "test_case_id": 12,
        "method": "GET",
        "url": "https://authorized.invalid/search?lang=en",
        "params": {"q": "original", "lang": "en"},
        "body": None,
        "json": None,
        "headers": {"Authorization": "Bearer internal"},
        "cookies": {"session": "private"},
        "payload": "original",
        "token": "primary-oracle-token",
        "steps": None,
        "stored_view_url": None,
        **overrides,
    }


@pytest.mark.parametrize("mode", ["all", "true", "1", "yes", "on", " ALL "])
def test_only_all_capture_modes_support_aab(mode):
    assert runtime_lineage_capture_supports_probes(mode) is True


@pytest.mark.parametrize("mode", ["hits", "off", "false", "0", "", None, True])
def test_hit_only_or_disabled_capture_cannot_support_aab(mode):
    assert runtime_lineage_capture_supports_probes(mode) is False


def test_preflight_is_pure_and_accepts_an_eligible_primary_result():
    case = _case()
    executor = _Executor()

    assert can_run_safe_url_probe_series(
        executor,
        case,
        _primary(case),
        param_name="q",
        param_location="query",
    ) is True
    assert executor.calls == []
    assert executor.envelope_calls == 0


@pytest.mark.parametrize(
    "mutation",
    [
        lambda primary: primary["logs"]["runtime_lineage"]["causal_flows"][0].update(
            source_category=[]
        ),
        lambda primary: primary["logs"]["runtime_lineage"].update(causal_flows={}),
        lambda primary: primary.update(status_code=429),
        lambda primary: primary.update(final_url="https://other.invalid/search"),
    ],
)
def test_preflight_rejects_malformed_or_unsafe_primary_evidence_without_side_effects(
    mutation,
):
    case = _case()
    primary = _primary(case)
    mutation(primary)
    executor = _Executor()

    assert can_run_safe_url_probe_series(
        executor,
        case,
        primary,
        param_name="q",
        param_location="query",
    ) is False
    assert executor.calls == []
    assert executor.envelope_calls == 0


def test_preflight_requires_playwright_and_an_envelope_factory(monkeypatch):
    case = _case()
    primary = _primary(case)
    executor = _Executor()
    executor.uc_driver = object()
    assert can_run_safe_url_probe_series(
        executor,
        case,
        primary,
        param_name="q",
        param_location="query",
    ) is False

    executor.uc_driver = None
    monkeypatch.setattr(
        "browser_workers.runtime_lineage_probe_runner.settings.USE_UNDETECTED_CHROME",
        True,
    )
    assert can_run_safe_url_probe_series(
        executor,
        case,
        primary,
        param_name="q",
        param_location="query",
    ) is False
    monkeypatch.setattr(
        "browser_workers.runtime_lineage_probe_runner.settings.USE_UNDETECTED_CHROME",
        False,
    )
    executor.create_runtime_lineage_envelope = None
    assert can_run_safe_url_probe_series(
        executor,
        case,
        primary,
        param_name="q",
        param_location="query",
    ) is False


def test_query_series_runs_exact_a_a_b_and_returns_validated_value_influence():
    case = _case()
    original = copy.deepcopy(case)
    executor = _Executor()
    rate_limited_urls: list[str] = []
    reported_results: list[dict] = []

    report = run_safe_url_probe_series(
        executor,
        case,
        _primary(case),
        param_name="q",
        param_location="query",
        before_request=rate_limited_urls.append,
        after_request=reported_results.append,
    )

    assert report is not None
    assert report["value_free"] is True
    assert report["probe_runs"] == 3
    assert report["summary"]["value_influence"] == 1
    assert len(executor.calls) == 3
    assert executor.envelope_calls == 1
    assert len(rate_limited_urls) == 3
    assert len(reported_results) == 3
    stimuli = [item["payload"] for item in executor.calls]
    assert stimuli[0] == stimuli[1]
    assert stimuli[2] != stimuli[0]
    assert all(value.isalnum() for value in stimuli)
    primary_candidate = _primary(case)["logs"]["runtime_lineage"]["causal_flows"][0][
        "candidate_id"
    ]
    assert all(primary_candidate[:8] not in value for value in stimuli)
    assert [item["runtime_lineage_probe"]["arm"] for item in executor.calls] == [
        "A", "A", "B"
    ]
    assert all(item["params"]["q"] == item["payload"] for item in executor.calls)
    assert all(item["suppress_artifacts"] is True for item in executor.calls)
    assert all(
        item["_runtime_lineage_execution_envelope"]
        == executor.calls[0]["_runtime_lineage_execution_envelope"]
        for item in executor.calls
    )
    assert all(
        item["runtime_lineage_probe"]["parameter_location"] == "query"
        and item["runtime_lineage_probe"]["parameter_name"] == "q"
        for item in executor.calls
    )
    assert all(item["token"] == item["payload"] for item in executor.calls)
    assert all(case["token"] not in item["token"] for item in executor.calls)
    assert case == original


def test_fragment_series_only_replaces_fragment_and_keeps_query_untouched():
    case = _case(
        url="https://authorized.invalid/app?lang=en#original",
        params={"lang": "en"},
    )
    executor = _Executor()

    report = run_safe_url_probe_series(
        executor,
        case,
        _primary(case),
        param_name="fragment",
        param_location="hash",
    )

    # The primary synthetic source is query-only, so a hash series is rejected
    # before an extra request. This guards cross-source attribution.
    assert report is None
    assert executor.calls == []


def test_fragment_series_runs_when_the_candidate_originates_from_the_hash():
    case = _case(
        url="https://authorized.invalid/app?lang=en#original",
        params={"lang": "en"},
    )
    executor = _Executor(source_category="location_hash")

    report = run_safe_url_probe_series(
        executor,
        case,
        _primary(case, source_category="location_hash"),
        param_name="fragment",
        param_location="fragment",
    )

    assert report is not None
    assert report["summary"]["value_influence"] == 1
    assert len(executor.calls) == 3
    assert all(item["params"] == {"lang": "en"} for item in executor.calls)
    assert all(item["url"].startswith("https://authorized.invalid/app?lang=en#RLP") for item in executor.calls)
    assert executor.calls[0]["url"] == executor.calls[1]["url"]
    assert executor.calls[2]["url"] != executor.calls[0]["url"]


@pytest.mark.parametrize(
    "case_overrides,param_location,primary_overrides",
    [
        ({"method": "POST"}, "query", {}),
        ({"body": {"q": "original"}}, "query", {}),
        ({"json": {"q": "original"}}, "query", {}),
        ({"steps": [{"action": "click"}]}, "query", {}),
        ({"stored_view_url": "https://authorized.invalid/view"}, "query", {}),
        ({"auth_spec": {"health_check_url": "/session"}}, "query", {}),
        ({"fake_message_origin": "https://other.invalid"}, "query", {}),
        ({"headers": {"X-HTTP-Method-Override": "DELETE"}}, "query", {}),
        ({"params": {"q": "original", "_method": "POST"}}, "query", {}),
        ({"params": {"lang": "en"}}, "query", {}),
        ({"params": {"q": "original", "action": "delete"}}, "query", {}),
        ({"url": "https://authorized.invalid/search?lang=en#/delete"}, "query", {}),
        ({"url": "https://authorized.invalid/account/delete"}, "query", {}),
        ({}, "query", {"status_code": 403}),
        ({}, "query", {"status_code": 429}),
        ({}, "query", {"status_code": 500}),
        ({}, "query", {"final_url": "https://other.invalid/search"}),
        ({}, "query", {"final_url": "https://authorized.invalid/delete"}),
        ({"url": "file:///tmp/local.html"}, "query", {}),
        ({"url": "javascript:alert(1)"}, "query", {}),
        ({}, "header", {}),
        ({}, "query", {"oracle_hit": True}),
        ({}, "query", {"execution_error": {"type": "Timeout"}}),
        ({}, "query", {"human_intervention": {"kind": "mfa"}}),
    ],
)
def test_stateful_or_uncertain_cases_never_issue_probe_requests(
    case_overrides, param_location, primary_overrides
):
    case = _case(**case_overrides)
    primary = _primary(case)
    primary.update(primary_overrides)
    executor = _Executor()

    report = run_safe_url_probe_series(
        executor,
        case,
        primary,
        param_name="q",
        param_location=param_location,
    )

    assert report is None
    assert executor.calls == []


def test_unstable_a_and_unchanged_b_do_not_upgrade_or_run_beyond_budget():
    case = _case()
    for fingerprints in (
        (_fp("c"), _fp("e"), _fp("d")),
        (_fp("c"), _fp("c"), _fp("c")),
    ):
        executor = _Executor(fingerprints)
        report = run_safe_url_probe_series(
            executor,
            case,
            _primary(case),
            param_name="q",
            param_location="query",
        )
        assert report is None
        assert len(executor.calls) == 3


def test_missing_expected_observation_stops_after_first_probe():
    case = _case()

    class MissingObservationExecutor(_Executor):
        def execute_test_case(self, data, screenshot_dir):
            self.calls.append(copy.deepcopy(data))
            report = BrowserExecutor._build_runtime_lineage_report([_ledger()], data)
            return {"oracle_hit": False, "logs": {"runtime_lineage": report}}

    executor = MissingObservationExecutor()
    report = run_safe_url_probe_series(
        executor,
        case,
        _primary(case),
        param_name="q",
        param_location="query",
    )

    assert report is None
    assert len(executor.calls) == 1


@pytest.mark.parametrize(
    "unsafe_result",
    [
        {"status_code": 403},
        {"status_code": 429},
        {"runtime_lineage_probe_request_blocked": True},
        {"final_url": "https://other.invalid/search?q=redirected"},
        {"final_url": "https://authorized.invalid:not-a-port/search"},
    ],
)
def test_unsafe_probe_response_stops_series_after_first_request(unsafe_result):
    case = _case()

    class UnsafeResponseExecutor(_Executor):
        def execute_test_case(self, data, screenshot_dir):
            result = super().execute_test_case(data, screenshot_dir)
            result.update(unsafe_result)
            return result

    executor = UnsafeResponseExecutor()
    requested_urls: list[str] = []
    reported_results: list[dict] = []

    report = run_safe_url_probe_series(
        executor,
        case,
        _primary(case),
        param_name="q",
        param_location="query",
        before_request=requested_urls.append,
        after_request=reported_results.append,
    )

    assert report is None
    assert len(executor.calls) == 1
    assert len(requested_urls) == 1
    assert len(reported_results) == 1
    assert reported_results[0].get("status_code") == unsafe_result.get(
        "status_code", 200
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://authorized.invalid:not-a-port/search?lang=en",
        "https://authorized.invalid:70000/search?lang=en",
    ],
)
def test_invalid_request_url_port_fails_closed_before_probe(url):
    case = _case(url=url)
    executor = _Executor()

    assert run_safe_url_probe_series(
        executor,
        case,
        _primary(case),
        param_name="q",
        param_location="query",
    ) is None
    assert executor.calls == []
    assert executor.envelope_calls == 0


def test_fragment_probe_requires_an_existing_fragment_to_replace():
    case = _case(url="https://authorized.invalid/app?lang=en", params={"lang": "en"})
    executor = _Executor(source_category="location_hash")

    assert run_safe_url_probe_series(
        executor,
        case,
        _primary(case, source_category="location_hash"),
        param_name="fragment",
        param_location="fragment",
    ) is None
    assert executor.calls == []


def test_expired_or_missing_series_never_attempts_to_build_another_arm(monkeypatch):
    case = _case()
    executor = _Executor()

    def missing_report(self, probe_key, candidate_id, report):
        return {"status": "missing"}

    monkeypatch.setattr(
        "analysis_engine.runtime_lineage_probe.RuntimeLineageProbeCoordinator.accept_report",
        missing_report,
    )
    assert run_safe_url_probe_series(
        executor,
        case,
        _primary(case),
        param_name="q",
        param_location="query",
    ) is None
    assert len(executor.calls) == 1


def test_probe_failure_is_never_promoted():
    case = _case()

    class FailingExecutor(_Executor):
        def execute_test_case(self, data, screenshot_dir):
            self.calls.append(copy.deepcopy(data))
            return {"oracle_hit": False, "execution_error": {"type": "Timeout"}}

    executor = FailingExecutor()
    assert run_safe_url_probe_series(
        executor,
        case,
        _primary(case),
        param_name="q",
        param_location="query",
    ) is None
    assert len(executor.calls) == 1


@pytest.mark.parametrize("oracle_hit", [None, 1, "true"])
def test_primary_requires_an_explicit_boolean_oracle_miss(oracle_hit):
    case = _case()
    primary = _primary(case)
    primary["oracle_hit"] = oracle_hit
    executor = _Executor()

    assert run_safe_url_probe_series(
        executor,
        case,
        primary,
        param_name="q",
        param_location="query",
    ) is None
    assert executor.calls == []


@pytest.mark.parametrize("oracle_hit", [None, 1, "true"])
def test_each_probe_requires_an_explicit_boolean_oracle_miss(oracle_hit):
    case = _case()

    class AmbiguousOracleExecutor(_Executor):
        def execute_test_case(self, data, screenshot_dir):
            result = super().execute_test_case(data, screenshot_dir)
            result["oracle_hit"] = oracle_hit
            return result

    executor = AmbiguousOracleExecutor()
    assert run_safe_url_probe_series(
        executor,
        case,
        _primary(case),
        param_name="q",
        param_location="query",
    ) is None
    assert len(executor.calls) == 1


def test_persistent_uc_profile_is_ineligible_without_isolated_contexts():
    case = _case()
    executor = _Executor()
    executor.uc_driver = object()

    assert run_safe_url_probe_series(
        executor,
        case,
        _primary(case),
        param_name="q",
        param_location="query",
    ) is None
    assert executor.calls == []
