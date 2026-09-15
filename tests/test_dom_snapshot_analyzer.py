"""Chrome DOMSnapshot marker analysis exports structure without page content."""
from __future__ import annotations

from analysis_engine.dom_snapshot_analyzer import (
    DOMSnapshotAnalyzer,
    DOMSnapshotDifferentialCollector,
)
from browser_workers.oracle_inject import get_oracle_script


def _snapshot(marker: str, *, include_new: bool = True) -> dict:
    strings: list[str] = []

    def intern(value: str) -> int:
        if value not in strings:
            strings.append(value)
        return strings.index(value)

    names = ["HTML", "BODY", "DIV", "#text", "#document-fragment", "A", "BUTTON"]
    parents = [-1, 0, 1, 2, 2, 4, 1]
    node_values = [intern("") for _ in names]
    node_values[3] = intern(f"rendered {marker}")
    attributes = [[] for _ in names]
    attributes[2] = [intern("class"), intern("preview")]
    attributes[5] = [intern("href"), intern("/safe")]
    attributes[6] = [intern("onclick"), intern("applicationAction()")]
    if include_new:
        attributes[5][1] = intern(f"/next?value={marker}")
        attributes[6][1] = intern(f"applicationAction('{marker}')")

    return {
        "strings": strings,
        "documents": [{
            "documentURL": intern("https://target.test/account?private=value"),
            "nodes": {
                "parentIndex": parents,
                "nodeType": [1, 1, 1, 3, 11, 1, 1],
                "nodeName": [intern(value) for value in names],
                "nodeValue": node_values,
                "attributes": attributes,
                "shadowRootType": {
                    "index": [4],
                    "value": [intern("closed")],
                },
            },
        }],
    }


def test_snapshot_classifies_text_url_event_and_closed_shadow_contexts():
    marker = "marker-123"
    report = DOMSnapshotAnalyzer.analyze(
        _snapshot(marker), marker, phase="interaction"
    )

    assert report["available"] is True
    assert {site["context"] for site in report["sites"]} == {
        "text", "url_attribute", "event_attribute",
    }
    url_site = next(site for site in report["sites"] if site["context"] == "url_attribute")
    assert url_site["attribute_name"] == "href"
    assert url_site["shadow_root_type"] == "closed"
    assert len(url_site["frame_origin_fingerprint"]) == 64
    assert len(url_site["structural_path_fingerprint"]) == 64
    assert marker not in str(report)
    assert "private=value" not in str(report)


def test_sparse_rare_input_values_are_supported_without_text_export():
    marker = "input-canary"
    snapshot = _snapshot("different-marker", include_new=False)
    strings = snapshot["strings"]
    strings.append(f"account name {marker}")
    value_index = len(strings) - 1
    snapshot["documents"][0]["nodes"]["inputValue"] = {
        "index": [2],
        "value": [value_index],
    }

    report = DOMSnapshotAnalyzer.analyze(snapshot, marker, phase="bootstrap")

    assert len(report["sites"]) == 1
    assert report["sites"][0]["context"] == "form_value"
    assert marker not in str(report)
    assert "account name" not in str(report)


def test_differential_suppresses_marker_sites_already_present_at_baseline():
    marker = "stable-marker"
    baseline = _snapshot(marker, include_new=False)
    after = _snapshot(marker, include_new=True)
    responses = iter([baseline, after])

    def send(method: str, params: dict):
        assert method == "DOMSnapshot.captureSnapshot"
        assert params["computedStyles"] == []
        return next(responses)

    collector = DOMSnapshotDifferentialCollector(send, marker)
    assert collector.capture("bootstrap") is True
    assert collector.capture("interaction") is True
    assert collector.capture("third") is False
    report = collector.report()

    assert report["differential_available"] is True
    assert report["summary"]["baseline_marker_sites"] == 1
    assert report["summary"]["after_marker_sites"] == 3
    assert report["summary"]["new_marker_sites"] == 2
    assert {site["context"] for site in report["sites"]} == {
        "url_attribute", "event_attribute",
    }
    assert marker not in str(report)


def test_single_capture_reports_materialization_with_explicit_limit():
    marker = "one-shot-marker"
    collector = DOMSnapshotDifferentialCollector(
        lambda _method, _params: _snapshot(marker, include_new=False),
        marker,
    )
    collector.capture("early_exit")
    report = collector.report()

    assert report["available"] is True
    assert report["differential_available"] is False
    assert report["summary"]["materialized_sites"] == 1


def test_document_node_and_match_budgets_are_explicit(monkeypatch):
    marker = "budget-marker"
    snapshot = _snapshot(marker)
    snapshot["documents"] = snapshot["documents"] * 3
    monkeypatch.setattr(DOMSnapshotAnalyzer, "MAX_DOCUMENTS", 1)
    monkeypatch.setattr(DOMSnapshotAnalyzer, "MAX_NODES", 6)
    monkeypatch.setattr(DOMSnapshotAnalyzer, "MAX_MATCHES", 1)

    report = DOMSnapshotAnalyzer.analyze(snapshot, marker, phase="interaction")

    assert len(report["sites"]) == 1
    assert set(report["budget_exhausted"]) == {"documents", "matches", "nodes"}


def test_invalid_snapshot_is_unavailable_instead_of_raising():
    report = DOMSnapshotAnalyzer.analyze(
        {"strings": "invalid", "documents": None}, "marker", phase="bootstrap"
    )

    assert report["available"] is False
    assert report["sites"] == []


def test_oracle_keeps_closed_shadow_root_semantics_native():
    oracle_source = get_oracle_script()

    assert "Element.prototype.attachShadow =" not in oracle_source
    assert "mode: 'open'" not in oracle_source
