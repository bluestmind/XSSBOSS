import json

from browser_workers.executor import BrowserExecutor
from browser_workers.oracle_inject import get_oracle_script


def _fingerprint(character: str) -> str:
    return character * 64


def _ledger(observation_fingerprint: str = None) -> dict:
    sink = {
        "kind": "sink",
        "event_id": "sink-2",
        "sink_id": "sink-2",
        "context_id": "ctx-1",
        "ts_ms": 2,
        "relation": "direct",
        "sink_category": "innerhtml",
        "sink_fingerprint": _fingerprint("b"),
        # These hostile fields must never survive the reducer.
        "value": "secret-value",
        "filename": "https://target.invalid/private?token=secret",
        "stack": "raw private stack",
    }
    if observation_fingerprint:
        sink["observation_fingerprint"] = observation_fingerprint
    return {
        "schema_version": "runtime-causal-lineage-events/v1",
        "value_free": True,
        "events": [
            {
                "kind": "source",
                "event_id": "src-1",
                "source_id": "src-1",
                "context_id": "ctx-1",
                "ts_ms": 1,
                "relation": "direct",
                "source_category": "location_hash",
                "source_fingerprint": _fingerprint("a"),
                "value": "secret-source",
                "url": "https://target.invalid/#secret",
            },
            sink,
        ],
    }


def test_executor_reduces_page_ledger_without_raw_values_or_locations():
    report = BrowserExecutor._build_runtime_lineage_report([_ledger()], {})

    assert report["schema_version"] == "runtime-causal-lineage/v1"
    assert report["value_free"] is True
    assert report["summary"]["causal_only"] == 1
    serialized = json.dumps(report)
    assert "secret" not in serialized
    assert "target.invalid" not in serialized
    assert "raw private stack" not in serialized


def test_executor_collects_lineage_from_playwright_frames_and_uc():
    class Frame:
        def evaluate(self, _script):
            return _ledger()

    class Page:
        frames = [Frame(), Frame()]

    class Driver:
        def execute_script(self, _script):
            return _ledger()

    playwright_report = BrowserExecutor._collect_runtime_lineage_playwright(Page(), {})
    uc_report = BrowserExecutor._collect_runtime_lineage_uc(Driver(), {})

    assert playwright_report["collection"]["frames_observed"] == 2
    assert uc_report["collection"]["frames_observed"] == 1
    assert playwright_report["summary"]["causal_only"] >= 1
    assert uc_report["summary"]["causal_only"] == 1


def test_executor_accepts_bounded_serialized_lineage_and_ignores_bad_frames():
    class Frame:
        def __init__(self, payload):
            self.payload = payload

        def evaluate(self, _script):
            return self.payload

    class Page:
        frames = [
            Frame("{"),
            Frame("x" * 1_000_001),
            Frame(json.dumps(_ledger())),
        ]

    class Driver:
        def execute_script(self, _script):
            return json.dumps(_ledger())

    playwright_report = BrowserExecutor._collect_runtime_lineage_playwright(Page(), {})
    uc_report = BrowserExecutor._collect_runtime_lineage_uc(Driver(), {})

    assert playwright_report["collection"]["frames_observed"] == 1
    assert playwright_report["summary"]["causal_only"] == 1
    assert uc_report["summary"]["causal_only"] == 1


def test_invalid_controlled_envelope_fails_before_browser_start(monkeypatch):
    executor = BrowserExecutor()
    started = []
    monkeypatch.setattr(executor, "start", lambda: started.append(True))
    monkeypatch.setattr(
        "browser_workers.executor.settings.USE_UNDETECTED_CHROME", False
    )
    result = executor.execute_test_case(
        {
            "runtime_lineage_probe": {"inert": True},
            "_runtime_lineage_execution_envelope": {
                "version": 1,
                "headers": {str(index): "x" for index in range(65)},
                "user_agent": "Pinned",
                "proxy": None,
            },
        },
        None,
    )

    assert started == []
    assert result["runtime_lineage_probe_request_blocked"] is True
    assert result["execution_error"]["type"] == "RuntimeLineageProbeRejected"


def test_executor_namespaces_independent_frame_contexts():
    source_only = _ledger()
    source_only["events"] = source_only["events"][:1]
    sink_only = _ledger()
    sink_only["events"] = sink_only["events"][1:]

    report = BrowserExecutor._build_runtime_lineage_report(
        [source_only, sink_only], {}
    )

    assert report["summary"]["candidates"] == 0


def test_executor_stops_reading_page_events_at_the_analysis_boundary():
    class HostileEvents(list):
        inspected = 0

        def __iter__(self):
            for item in super().__iter__():
                self.inspected += 1
                yield item

    events = HostileEvents([_ledger()["events"][0]] * 1000)
    report = BrowserExecutor._build_runtime_lineage_report([{"events": events}], {})

    assert report is not None
    assert events.inspected == 257


def test_executor_upgrades_only_explicit_inert_stable_aab_observations():
    observations = []
    arms = [
        ("run-a1", "A", "InertAlpha1", _fingerprint("c")),
        ("run-a2", "A", "InertAlpha1", _fingerprint("c")),
        ("run-b1", "B", "InertBravo1", _fingerprint("d")),
    ]
    report = None
    for run_id, arm, stimulus, result_fingerprint in arms:
        report = BrowserExecutor._build_runtime_lineage_report(
            [_ledger(result_fingerprint)],
            {
                "payload": stimulus,
                "param_name": "q",
                "params": {"q": stimulus},
                "runtime_lineage_observations": observations,
                "runtime_lineage_probe": {
                    "run_id": run_id,
                    "arm": arm,
                    "inert": True,
                    "stimulus": stimulus,
                    "parameter_name": "q",
                    "parameter_location": "query",
                },
            },
        )
        observations = report.get("probe_observations", [])

    assert report["summary"]["value_influence"] == 1
    assert report["summary"]["causal_only"] == 0
    assert report["value_influences"][0]["classification"] == "value_influence"
    assert report["value_influences"][0]["aab"] == {
        "pattern": "A/A/B",
        "runs": 3,
        "stable_a": True,
        "b_changed": True,
        "inert": True,
    }


def test_executor_binds_probe_observation_to_exact_safe_payload_and_hash():
    valid_probe = {
        "run_id": "run-a1",
        "arm": "A",
        "inert": True,
        "stimulus": "SafeMarkerA123",
        "parameter_name": "q",
        "parameter_location": "query",
    }
    cases = [
        {
            "payload": "different",
            "param_name": "q",
            "params": {"q": "different"},
            "runtime_lineage_probe": valid_probe,
        },
        {
            "payload": "<not-inert>",
            "param_name": "q",
            "params": {"q": "<not-inert>"},
            "runtime_lineage_probe": {
                **valid_probe,
                "stimulus": "<not-inert>",
            },
        },
        {
            "payload": "SafeMarkerA123",
            "param_name": "q",
            "params": {"q": "SafeMarkerA123"},
            "runtime_lineage_probe": {
                **valid_probe,
                "stimulus_fingerprint": _fingerprint("f"),
            },
        },
    ]

    for test_case_data in cases:
        report = BrowserExecutor._build_runtime_lineage_report(
            [_ledger(_fingerprint("c"))], test_case_data
        )
        assert "probe_observations" not in report
        assert report["summary"]["value_influence"] == 0


def test_executor_requires_query_stimulus_to_match_the_materialized_parameter():
    stimulus = "SafeMarkerA123"
    base = {
        "payload": stimulus,
        "param_name": "q",
        "runtime_lineage_probe": {
            "run_id": "run-a1",
            "arm": "A",
            "inert": True,
            "stimulus": stimulus,
            "parameter_name": "q",
            "parameter_location": "query",
        },
    }

    positive = BrowserExecutor._build_runtime_lineage_report(
        [_ledger(_fingerprint("c"))],
        {**base, "params": {"q": stimulus}},
    )
    mismatched = BrowserExecutor._build_runtime_lineage_report(
        [_ledger(_fingerprint("c"))],
        {**base, "params": {"q": "DifferentMarkerB456"}},
    )

    assert len(positive.get("probe_observations", [])) == 1
    assert "probe_observations" not in mismatched
    assert mismatched["summary"]["value_influence"] == 0


def test_executor_requires_fragment_stimulus_to_match_the_decoded_url_fragment():
    stimulus = "SafeMarkerA123"
    base = {
        "payload": stimulus,
        "param_name": "fragment",
        "params": {},
        "runtime_lineage_probe": {
            "run_id": "run-a1",
            "arm": "A",
            "inert": True,
            "stimulus": stimulus,
            "parameter_name": "fragment",
            "parameter_location": "fragment",
        },
    }

    positive = BrowserExecutor._build_runtime_lineage_report(
        [_ledger(_fingerprint("c"))],
        {**base, "url": "https://target.invalid/app#SafeMarkerA%31%32%33"},
    )
    mismatched = BrowserExecutor._build_runtime_lineage_report(
        [_ledger(_fingerprint("c"))],
        {**base, "url": "https://target.invalid/app#DifferentMarkerB456"},
    )

    assert len(positive.get("probe_observations", [])) == 1
    assert "probe_observations" not in mismatched
    assert mismatched["summary"]["value_influence"] == 0


def test_executor_requires_an_explicit_safe_string_probe_run_id():
    stimulus = "SafeMarkerA123"
    for probe in (
        {"arm": "A", "inert": True, "stimulus": stimulus},
        {"run_id": 123, "arm": "A", "inert": True, "stimulus": stimulus},
    ):
        report = BrowserExecutor._build_runtime_lineage_report(
            [_ledger(_fingerprint("c"))],
            {
                "test_case_id": 123,
                "payload": stimulus,
                "param_name": "q",
                "params": {"q": stimulus},
                "runtime_lineage_probe": probe,
            },
        )

        assert "probe_observations" not in report
        assert report["summary"]["value_influence"] == 0


def test_executor_ignores_malformed_prior_observation_container():
    report = BrowserExecutor._build_runtime_lineage_report(
        [_ledger(_fingerprint("c"))],
        {"runtime_lineage_observations": {"forged": "mapping"}},
    )

    assert report["summary"]["causal_only"] == 1
    assert report["summary"]["value_influence"] == 0
    assert "probe_observations" not in report


def test_controlled_lineage_probes_disable_active_browser_interactions():
    ordinary = {"payload": "marker"}
    controlled = {
        "runtime_lineage_probe": {"inert": True},
        "_runtime_lineage_execution_envelope": {"version": 1},
    }

    assert BrowserExecutor._active_browser_interactions_allowed(ordinary) is True
    assert BrowserExecutor._active_browser_interactions_allowed(controlled) is False
    assert BrowserExecutor._active_browser_interactions_allowed({
        "runtime_lineage_probe": None,
    }) is False


def test_controlled_probe_request_policy_blocks_mutations_and_redirects():
    allowed = BrowserExecutor._controlled_probe_request_allowed
    expected = "https://authorized.invalid/search?q=marker"

    assert allowed(
        expected,
        "https://authorized.invalid/search?q=other",
        "GET",
        resource_type="document",
        is_navigation=True,
        belongs_to_primary_page=True,
        is_main_frame=True,
    ) is True
    assert allowed(
        expected,
        "https://authorized.invalid/api/telemetry",
        "POST",
        resource_type="fetch",
        is_navigation=False,
        belongs_to_primary_page=True,
        is_main_frame=False,
    ) is False
    assert allowed(
        expected,
        "https://other.invalid/search",
        "GET",
        resource_type="document",
        is_navigation=True,
        belongs_to_primary_page=True,
        is_main_frame=True,
    ) is False
    assert allowed(
        expected,
        "https://authorized.invalid/delete",
        "GET",
        resource_type="document",
        is_navigation=True,
        belongs_to_primary_page=True,
        is_main_frame=True,
    ) is False
    assert allowed(
        expected,
        "https://authorized.invalid/search",
        "GET",
        resource_type="document",
        is_navigation=True,
        belongs_to_primary_page=False,
        is_main_frame=True,
    ) is False
    assert allowed(
        expected,
        "https://authorized.invalid/api/data",
        "GET",
        resource_type="fetch",
        is_navigation=False,
        belongs_to_primary_page=True,
        is_main_frame=False,
    ) is False
    assert allowed(
        expected,
        "https://authorized.invalid/static/app.js",
        "GET",
        resource_type="script",
        is_navigation=False,
        belongs_to_primary_page=True,
        is_main_frame=False,
    ) is True


def test_oracle_lineage_is_non_mutating_and_bounded():
    source = get_oracle_script()

    assert "__taint_" not in source
    assert "val = val + marker" not in source
    assert "const val = descriptor.get.call(this);" in source
    assert "return Reflect.get(target, prop, target);" in source
    assert "if (!fakeOrigin) return event;" in source
    assert "enumerable: descriptor.enumerable" in source
    assert "__XSS_CAUSAL_LINEAGE__" in source
    assert "__XSS_CAUSAL_LINEAGE_JSON__" in source
    assert "const causalJsonStringify = JSON.stringify;" in source
    assert "function causalSuppressToJSON(value)" in source
    assert "causalObjectDefineProperty(value, 'toJSON'" in source
    assert "CAUSAL_MAX_EVENTS = 256" in source
    assert "CAUSAL_MAX_DEPTH = 8" in source
    assert "CAUSAL_TTL_MS = 5000" in source
    assert "const causalSha256Constants = [" in source
    assert "function causalObservationMaterial(value)" in source
    assert "observation_fingerprint: causalFingerprint(causalObservationMaterial(value))" in source
    assert "String(value || '')" not in source[source.index("function recordCausalSink"):]
    assert "0x01000193" not in source
    assert "const lineageProbe = window.__XSS_LINEAGE_PROBE__ === true;" in source
    assert "if (lineageProbe) return;" in source
    assert "causalState.events.map" not in source
    assert "Object.assign({}, event)" not in source
    assert "causalAppend(causalState.events, event);" in source
    assert "Promise.prototype.then =" in source
    assert "window.queueMicrotask =" in source
    assert "window.requestAnimationFrame =" in source
    assert "const causalStringMatch = String.prototype.match;" in source
    assert "causalStringMatch," in source
    assert "[/^(.*):(\\d+):(\\d+)\\)?\\s*$/]" in source
    assert "causalSanitizeLocation(filename)" in source
    assert "recordCausalSource(ambientSource, errorStack, 'ambient_match');" in source
    assert "//# sourceURL=xssboss_oracle_inject.js" in source
