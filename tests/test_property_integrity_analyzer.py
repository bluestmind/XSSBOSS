from __future__ import annotations

import json

from analysis_engine.property_integrity_analyzer import PropertyIntegrityAnalyzer


def _kinds(result):
    return [item.kind for item in result.observations]


def test_extracts_bounded_named_properties_and_form_control_relationships():
    html = """
    <div id="appConfig"></div>
    <form id="checkout" name="checkoutForm">
      <input name="destination" />
      <button id="submitOrder" name="commit">Submit</button>
    </form>
    <input name="detached" form="checkout" />
    """

    result = PropertyIntegrityAnalyzer.analyze(html_content=html)
    definitions = {(item.name, item.tag, item.parent_form) for item in result.named_properties}

    assert ("appConfig", "div", None) in definitions
    assert ("checkout", "form", None) in definitions
    assert ("destination", "input", "checkout") in definitions
    assert ("commit", "button", "checkout") in definitions
    assert ("detached", "input", "checkout") in definitions
    assert not result.chains
    assert "html_named_property" in _kinds(result)


def test_dom_chain_requires_exact_named_property_implicit_read_and_sink():
    result = PropertyIntegrityAnalyzer.analyze(
        html_content='<div id="appConfig"></div>',
        property_reads=[{
            "kind": "named_property_read",
            "base": "window",
            "name": "appConfig",
            "implicit": True,
            "line": 12,
            "sink_kind": "location-write",
            "reaches_sink": True,
        }],
    )

    assert len(result.dom_clobbering_chains) == 1
    chain = result.dom_clobbering_chains[0]
    assert chain.metadata["named_property"] == "appConfig"
    assert chain.metadata["sink_kind"] == "location-write"
    assert chain.metadata["definition_fingerprints"]


def test_dom_chain_accepts_property_reads_nested_in_client_trust_findings():
    result = PropertyIntegrityAnalyzer.analyze(
        html_content='<iframe name="messageRouter"></iframe>',
        client_trust_findings=[{
            "handler_fingerprint": "a" * 64,
            "trust_classification": "missing",
            "property_reads": [{
                "path": ["window", "messageRouter", "url"],
                "line": 22,
                "sink_kind": "window.open",
                "flow": "property_to_sink",
                "trust_classification": "missing",
            }],
        }],
    )

    assert len(result.dom_clobbering_chains) == 1
    assert result.dom_clobbering_chains[0].metadata["trust"] == "missing"


def test_document_forms_control_chain_requires_observed_relationship():
    html = '<form id="checkout"><input name="destination"></form>'
    matching = PropertyIntegrityAnalyzer.analyze(
        html_content=html,
        property_reads=[{
            "path": ["document", "forms", "checkout", "destination"],
            "sink_kind": "location-write",
            "reaches_sink": True,
            "line": 9,
        }],
    )
    missing_control = PropertyIntegrityAnalyzer.analyze(
        html_content='<form id="checkout"><input name="other"></form>',
        property_reads=[{
            "path": ["document", "forms", "checkout", "destination"],
            "sink_kind": "location-write",
            "reaches_sink": True,
        }],
    )

    assert len(matching.dom_clobbering_chains) == 1
    assert matching.dom_clobbering_chains[0].metadata["relationship"] == "document_forms_control"
    assert len(matching.dom_clobbering_chains[0].metadata["definition_fingerprints"]) == 2
    assert not missing_control.dom_clobbering_chains


def test_standalone_or_mitigated_dom_signals_never_become_chains():
    html = '<div id="appConfig"></div><form name="router"></form>'
    result = PropertyIntegrityAnalyzer.analyze(
        html_content=html,
        property_reads=[
            {"base": "window", "name": "missing", "implicit": True,
             "sink_kind": "innerHTML", "reaches_sink": True},
            {"base": "window", "name": "appConfig", "implicit": True,
             "sink_kind": "innerHTML", "reaches_sink": False},
            {"base": "window", "name": "appConfig", "implicit": True,
             "sink_kind": "innerHTML", "reaches_sink": True, "ownership_guard": True},
            {"base": "window", "name": "appConfig", "lookup_method": "getElementById",
             "sink_kind": "innerHTML", "reaches_sink": True},
            {"base": "window", "name": "appConfig", "implicit": True,
             "sink_kind": "textContent", "reaches_sink": True},
        ],
    )

    assert not result.dom_clobbering_chains
    assert _kinds(result).count("js_named_property_read") == 5


def test_raw_javascript_external_object_merge_gadget_chain():
    javascript = """
    function handle(event) {
      const incoming = event.data.settings;
      _.merge(options, incoming);
      output.innerHTML = options.html;
    }
    """

    result = PropertyIntegrityAnalyzer.analyze(javascript_content=javascript)

    assert len(result.prototype_property_injection_chains) == 1
    chain = result.prototype_property_injection_chains[0]
    assert chain.metadata["mutation_operation"] == "deep_merge"
    assert chain.metadata["gadget_property"] == "html"
    assert chain.metadata["sink_kind"].lower() == "innerhtml"


def test_dynamic_property_write_with_complete_key_guard_is_mitigated():
    javascript = """
    function applySettings(event) {
      const incoming = event.data.settings;
      for (const key in incoming) {
        if (key === "__proto__" || key === "prototype" || key === "constructor") continue;
        options[key] = incoming[key];
      }
      output.innerHTML = options.html;
    }
    """

    result = PropertyIntegrityAnalyzer.analyze(javascript_content=javascript)
    mutations = [item for item in result.observations if item.kind == "property_mutation_candidate"]

    assert mutations
    assert mutations[0].metadata["externally_influenced"] is True
    assert mutations[0].metadata["guarded"] is True
    assert not result.prototype_property_injection_chains


def test_standalone_merge_or_gadget_is_only_an_observation():
    merge_only = PropertyIntegrityAnalyzer.analyze(
        javascript_content="function configure() { _.merge(options, defaults); }"
    )
    gadget_only = PropertyIntegrityAnalyzer.analyze(
        javascript_content="function render() { output.innerHTML = options.html; }"
    )
    source_and_merge_without_gadget = PropertyIntegrityAnalyzer.analyze(
        javascript_content="function configure(event) { const data = event.data; _.merge(options, data); }"
    )

    assert "property_mutation_candidate" in _kinds(merge_only)
    assert not merge_only.chains
    assert "sensitive_property_gadget" in _kinds(gadget_only)
    assert not gadget_only.chains
    assert not source_and_merge_without_gadget.chains


def test_structured_property_events_require_full_ordered_chain():
    events = [
        {"kind": "external_object", "symbol": "incoming", "source_kind": "message_data",
         "externally_influenced": True, "scope": "handler", "line": 2},
        {"kind": "deep_merge", "target_symbol": "settings", "source_symbol": "incoming",
         "scope": "handler", "line": 3},
        {"kind": "gadget_read", "object_symbol": "settings", "property": "url",
         "sink_kind": "location-write", "reaches_sink": True, "scope": "handler", "line": 4},
    ]
    result = PropertyIntegrityAnalyzer.analyze(property_events=events)

    assert len(result.prototype_property_injection_chains) == 1
    assert result.prototype_property_injection_chains[0].metadata["source_kind"] == "message_data"

    guarded_events = [dict(item) for item in events]
    guarded_events[1]["forbidden_key_guard"] = True
    guarded = PropertyIntegrityAnalyzer.analyze(property_events=guarded_events)
    assert not guarded.prototype_property_injection_chains


def test_different_scopes_and_reverse_order_do_not_correlate():
    different_scopes = [
        {"kind": "external_object", "symbol": "incoming", "scope": "one"},
        {"kind": "deep_merge", "target_symbol": "settings", "source_symbol": "incoming", "scope": "two"},
        {"kind": "gadget_read", "object_symbol": "settings", "property": "html",
         "sink_kind": "innerHTML", "reaches_sink": True, "scope": "two"},
    ]
    reverse_order = [
        {"kind": "gadget_read", "object_symbol": "settings", "property": "html",
         "sink_kind": "innerHTML", "reaches_sink": True, "scope": "one"},
        {"kind": "external_object", "symbol": "incoming", "scope": "one"},
        {"kind": "deep_merge", "target_symbol": "settings", "source_symbol": "incoming", "scope": "one"},
    ]

    assert not PropertyIntegrityAnalyzer.analyze(property_events=different_scopes).chains
    assert not PropertyIntegrityAnalyzer.analyze(property_events=reverse_order).chains


def test_raw_javascript_source_declared_after_merge_does_not_correlate():
    javascript = """
    function configure(event) {
      _.merge(settings, incoming);
      const incoming = event.data.settings;
      output.innerHTML = settings.html;
    }
    """

    result = PropertyIntegrityAnalyzer.analyze(javascript_content=javascript)

    assert "property_mutation_candidate" in _kinds(result)
    assert not result.prototype_property_injection_chains


def test_later_source_declaration_does_not_retroactively_taint_earlier_alias():
    reverse_alias = PropertyIntegrityAnalyzer.analyze(javascript_content="""
    function configure(event) {
      const earlier = incoming;
      const incoming = event.data.settings;
      _.merge(options, earlier);
      output.innerHTML = options.html;
    }
    """)
    forward_alias = PropertyIntegrityAnalyzer.analyze(javascript_content="""
    function configure(event) {
      const incoming = event.data.settings;
      const alias = incoming;
      _.merge(options, alias);
      output.innerHTML = options.html;
    }
    """)

    assert not reverse_alias.prototype_property_injection_chains
    assert len(forward_alias.prototype_property_injection_chains) == 1


def test_result_contains_metadata_and_fingerprints_but_no_source_content():
    secret_literal = "DO_NOT_RETURN_THIS_LITERAL_92f713"
    result = PropertyIntegrityAnalyzer.analyze(
        html_content='<div id="appConfig" data-private="DO_NOT_RETURN_THIS_LITERAL_92f713"></div>',
        javascript_content=f'''function handle(event) {{
          const incoming = event.data;
          const privateValue = "{secret_literal}";
          Object.assign(options, incoming);
          output.innerHTML = options.html;
        }}''',
        property_reads=[{
            "base": "window", "name": "appConfig", "implicit": True,
            "sink_kind": "innerHTML", "reaches_sink": True,
        }],
    )
    serialized = json.dumps(result.to_dict(), sort_keys=True)

    assert secret_literal not in serialized
    assert "<div" not in serialized
    assert all(len(item.fingerprint) == 64 for item in result.observations)
    assert all(len(item.fingerprint) == 64 for item in result.chains)


def test_named_property_inventory_is_bounded():
    html = "".join(f'<div id="item{index}"></div>' for index in range(20))
    result = PropertyIntegrityAnalyzer.analyze(html_content=html, max_named_properties=5)

    assert len(result.named_properties) == 5
    assert result.limits["named_properties_truncated"] is True
