"""Regression tests for passive browser trust-boundary analysis."""

from analysis_engine.client_trust_analyzer import ClientTrustAnalyzer
from recon_engine.bundle_analyzer import BundleAnalyzer


def _categories(script: str) -> set[str]:
    return {finding.category for finding in ClientTrustAnalyzer.analyze(script)}


def test_unvalidated_message_data_reaching_dom_sink_is_prioritized():
    script = """
    window.addEventListener("message", function(evt) {
        const fragment = evt.data.html;
        document.querySelector("#preview").innerHTML = fragment;
    });
    """
    findings = ClientTrustAnalyzer.analyze(script)
    lead = next(item for item in findings if item.category == "postmessage_unvalidated_sink")

    assert lead.details["guard"] == "none"
    assert lead.details["sink"] == "innerHTML"
    assert lead.confidence >= 0.9
    assert len(lead.code_fingerprint) == 64


def test_exact_origin_early_reject_suppresses_unvalidated_lead():
    script = """
    addEventListener("message", (evt) => {
        if (evt.origin !== "https://portal.example") return;
        const fragment = evt.data.html;
        output.innerHTML = fragment;
    });
    """
    assert "postmessage_unvalidated_sink" not in _categories(script)


def test_named_message_callback_is_resolved_to_its_handler_body():
    script = """
    window.addEventListener("message", renderMessage);
    function renderMessage(messageEvent) {
        const fragment = messageEvent.data.html;
        output.innerHTML = fragment;
    }
    """
    findings = ClientTrustAnalyzer.analyze(script)

    lead = next(item for item in findings if item.category == "postmessage_unvalidated_sink")
    assert lead.details["event_parameter"] == "messageEvent"
    assert lead.details["sink"] == "innerHTML"


def test_origin_guard_after_sink_does_not_protect_earlier_use():
    script = """
    addEventListener("message", (evt) => {
        const fragment = evt.data.html;
        output.innerHTML = fragment;
        if (evt.origin !== "https://portal.example") return;
    });
    """
    assert "postmessage_unvalidated_sink" in _categories(script)


def test_conditional_origin_guard_that_does_not_dominate_sink_is_not_suppression():
    script = """
    addEventListener("message", (evt) => {
        if (debugMode) {
            if (evt.origin !== "https://portal.example") return;
        }
        const fragment = evt.data.html;
        output.innerHTML = fragment;
    });
    """
    assert "postmessage_unvalidated_sink" in _categories(script)


def test_immutable_allowlist_early_reject_is_recognized():
    script = """
    addEventListener("message", (evt) => {
        const TRUSTED = Object.freeze(["https://one.example", "https://two.example"]);
        if (!TRUSTED.includes(evt.origin)) return;
        const fragment = evt.data.html;
        output.innerHTML = fragment;
    });
    """
    assert "postmessage_unvalidated_sink" not in _categories(script)


def test_substring_origin_check_remains_a_weak_unvalidated_lead():
    script = """
    addEventListener("message", (evt) => {
        if (!evt.origin.endsWith("example.com")) return;
        const fragment = evt.data.html;
        output.innerHTML = fragment;
    });
    """
    categories = _categories(script)
    assert "postmessage_unvalidated_sink" in categories
    assert "postmessage_weak_origin_validation" in categories


def test_wildcard_target_and_external_prototype_mutation_are_structured():
    script = """
    child.postMessage({kind: "ready"}, "*");
    Object.setPrototypeOf(runtimeConfig, event.data.options);
    """
    categories = _categories(script)
    assert "postmessage_wildcard_target" in categories
    assert "external_prototype_mutation" in categories


def test_wildcard_target_in_postmessage_options_object_is_detected():
    script = 'child.postMessage({kind: "ready"}, {targetOrigin: "*", transfer: []});'
    assert "postmessage_wildcard_target" in _categories(script)


def test_named_dom_property_flow_ignores_known_browser_property():
    risky = """
    const config = window.applicationConfig;
    panel.innerHTML = config;
    """
    built_in = """
    const current = window.location;
    panel.innerHTML = current;
    """
    assert "dom_named_property_to_sink" in _categories(risky)
    assert "dom_named_property_to_sink" not in _categories(built_in)


def test_named_dom_property_does_not_correlate_across_function_scope():
    script = """
    function readConfig() {
        const config = window.applicationConfig;
    }
    function render() {
        panel.innerHTML = config;
    }
    """
    assert "dom_named_property_to_sink" not in _categories(script)


def test_trusted_types_identity_policy_is_not_treated_as_sanitization():
    identity = """
    trustedTypes.createPolicy("default", {
        createHTML: value => value,
        createScriptURL: value => value
    });
    """
    sanitizing = """
    trustedTypes.createPolicy("default", {
        createHTML: value => DOMPurify.sanitize(value)
    });
    """
    identity_findings = ClientTrustAnalyzer.analyze(identity)
    assert sum(item.category == "trusted_types_identity_policy" for item in identity_findings) == 2
    assert "trusted_types_identity_policy" not in _categories(sanitizing)


def test_trusted_types_method_shorthand_identity_policy_is_detected():
    script = """
    trustedTypes.createPolicy("default", {
        createHTML(value) { return value; }
    });
    """
    assert "trusted_types_identity_policy" in _categories(script)


def test_comments_and_string_decoys_do_not_generate_trust_findings():
    script = r'''
    // child.postMessage(secret, "*");
    const first = 'postMessage(value, "*")';
    const second = "Object.setPrototypeOf(config, event.data)";
    const third = 'trustedTypes.createPolicy("x", {createHTML: v => v})';
    /* addEventListener("message", e => { out.innerHTML = e.data; }); */
    '''
    assert ClientTrustAnalyzer.analyze(script) == []


def test_analysis_input_and_candidate_output_are_bounded(monkeypatch):
    monkeypatch.setattr(ClientTrustAnalyzer, "MAX_SCRIPT_CHARS", 120)
    monkeypatch.setattr(ClientTrustAnalyzer, "MAX_CANDIDATES_PER_ANALYZER", 2)
    script = (
        'a.postMessage("one", "*");'
        'b.postMessage("two", "*");'
        'c.postMessage("three", "*");'
        + ("x" * 200)
        + 'd.postMessage("outside", "*");'
    )

    findings = ClientTrustAnalyzer.analyze(script, max_findings=100)

    assert sum(item.category == "postmessage_wildcard_target" for item in findings) == 2
    assert all(item.offset < 120 for item in findings)


def test_bundle_analyzer_exports_bounded_trust_summary():
    script = """
    addEventListener("message", event => {
        const html = event.data.html;
        result.innerHTML = html;
    });
    target.postMessage("ready", "*");
    """
    result = BundleAnalyzer.analyze_script_content("https://target.test/app.js", script)

    assert result["client_trust_summary"]["postmessage_unvalidated_sink"] == 1
    assert result["client_trust_summary"]["postmessage_wildcard_target"] == 1
    assert all("snippet" not in item for item in result["client_trust_findings"])


def test_bundle_analyzer_correlates_html_named_property_to_sink_chain():
    result = BundleAnalyzer.analyze_script_content(
        "https://target.test/app.js",
        "const config = window.applicationConfig; output.innerHTML = config;",
        analyze_sourcemaps=False,
        html_content='<div id="applicationConfig"></div>',
    )

    assert result["property_integrity_summary"]["dom_clobbering_chain"] == 1
    chain = result["property_integrity_chains"][0]
    assert chain["metadata"]["named_property"] == "applicationConfig"
    assert "<div" not in str(chain)


def test_bundle_analyzer_requires_complete_property_injection_gadget_chain():
    script = """
    function handle(event) {
        const incoming = event.data.settings;
        _.merge(options, incoming);
        output.innerHTML = options.html;
    }
    """
    result = BundleAnalyzer.analyze_script_content(
        "https://target.test/app.js", script, analyze_sourcemaps=False
    )

    assert result["property_integrity_summary"]["prototype_property_injection_chain"] == 1
    assert result["property_integrity_chains"][0]["metadata"]["gadget_property"] == "html"
