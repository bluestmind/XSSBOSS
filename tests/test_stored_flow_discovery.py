"""Autonomous stored-flow discovery: edge mapping, request-efficiency, and safety."""
import re

from backend_api.services.stored_flow_discovery import (
    DiscoveredEdge,
    SourceCandidate,
    StoredFlowDiscovery,
)


class FakeApp:
    """Models an app where submitting to a source endpoint stores content that renders elsewhere."""

    def __init__(self, wiring, submit_fails=()):
        self.wiring = wiring          # source_endpoint_id -> [render_endpoint_ids]
        self.submit_fails = set(submit_fails)
        self.store = {}               # render_endpoint_id -> [stored values]
        self.submit_calls = 0
        self.render_calls = 0

    def submit(self, endpoint_id, param_id, value):
        self.submit_calls += 1
        if endpoint_id in self.submit_fails:
            return False
        for r in self.wiring.get(endpoint_id, []):
            self.store.setdefault(r, []).append(value)
        return True

    def render(self, endpoint_id):
        self.render_calls += 1
        stored = self.store.get(endpoint_id, [])
        return "<html><body>" + " ".join(f"<div>{v}</div>" for v in stored) + "</body></html>"


def _discover(app, sources, renders, **kw):
    return StoredFlowDiscovery.discover(sources, renders, app.submit, app.render, **kw)


# ------------------------------------------------------------------- edge mapping

def test_maps_each_source_to_its_render_and_not_others():
    app = FakeApp({1: [100], 2: [200]})
    sources = [SourceCandidate(1, 10, "comment"), SourceCandidate(2, 20, "name")]
    edges = _discover(app, sources, [100, 200, 300])

    by_src = {e.source_endpoint_id: e for e in edges}
    assert by_src[1].render_endpoint_ids == [100]
    assert by_src[2].render_endpoint_ids == [200]
    # No cross-contamination.
    assert 200 not in by_src[1].render_endpoint_ids
    assert 100 not in by_src[2].render_endpoint_ids


def test_multi_render_edge_found():
    app = FakeApp({1: [100, 101]})  # e.g. list view + detail view
    edges = _discover(app, [SourceCandidate(1, 10)], [100, 101, 102])
    assert sorted(edges[0].render_endpoint_ids) == [100, 101]
    assert edges[0].snippets  # captured surrounding context


def test_source_with_no_render_is_recorded_but_not_confirmed():
    app = FakeApp({1: []})  # planted but surfaces nowhere
    edges = _discover(app, [SourceCandidate(1, 10)], [100, 200])
    assert edges[0].render_endpoint_ids == []
    assert StoredFlowDiscovery.confirmed_edges(edges) == []


def test_failed_submission_is_skipped():
    app = FakeApp({1: [100], 2: [200]}, submit_fails={2})
    edges = _discover(app, [SourceCandidate(1, 10), SourceCandidate(2, 20)], [100, 200])
    assert {e.source_endpoint_id for e in edges} == {1}  # source 2 never planted


# ------------------------------------------------------------- request efficiency

def test_request_cost_is_sources_plus_renders_not_product():
    app = FakeApp({1: [100], 2: [200], 3: [300]})
    sources = [SourceCandidate(i, i * 10) for i in (1, 2, 3)]
    renders = [100, 200, 300, 400]
    _discover(app, sources, renders)
    # Plant-many / observe-once: 3 submits + 4 renders, NOT 3*4.
    assert app.submit_calls == 3
    assert app.render_calls == 4


# -------------------------------------------------------------------- safety

def test_canary_is_inert_no_html_or_js_metacharacters():
    for _ in range(200):
        c = StoredFlowDiscovery.make_canary()
        assert re.fullmatch(r"wfd[a-z0-9]+", c), c
        assert not any(ch in c for ch in "<>\"'`(){}[];=/\\ &")


def test_canaries_are_unique_per_source():
    app = FakeApp({1: [100], 2: [100]})  # both render to the same page
    edges = _discover(app, [SourceCandidate(1, 10), SourceCandidate(2, 20)], [100])
    # Same page, but each source is distinguished by its own unique canary.
    assert edges[0].canary != edges[1].canary
    assert edges[0].render_endpoint_ids == [100]
    assert edges[1].render_endpoint_ids == [100]


# --------------------------------------------------------------------- bounds

def test_max_sources_and_renders_bounds_respected():
    app = FakeApp({1: [100], 2: [200]})
    sources = [SourceCandidate(1, 10), SourceCandidate(2, 20)]
    edges = _discover(app, sources, [100, 200], max_sources=1)
    assert len(edges) == 1
    assert app.submit_calls == 1


def test_edge_serializes():
    app = FakeApp({1: [100]})
    edges = _discover(app, [SourceCandidate(1, 10)], [100])
    d = edges[0].to_dict()
    assert d["source_endpoint_id"] == 1 and d["render_endpoint_ids"] == [100]
    assert d["canary"].startswith("wfd")
