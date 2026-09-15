"""Context-aware sanitizer boundaries prevent high-impact false negatives."""
from __future__ import annotations

from analysis_engine.sanitizer_boundary_analyzer import SanitizerBoundaryAnalyzer
from recon_engine.bundle_analyzer import BundleAnalyzer


def _findings(script: str):
    return SanitizerBoundaryAnalyzer.analyze(script)


def _categories(script: str) -> set[str]:
    return {item.category for item in _findings(script)}


def test_plain_dompurify_flow_to_html_sink_is_an_effective_boundary():
    findings = _findings(
        "const raw = location.hash; "
        "const clean = DOMPurify.sanitize(raw); "
        "preview.innerHTML = clean;"
    )

    assert len(findings) == 1
    assert findings[0].category == "effective_sanitizer_boundary"
    assert findings[0].required_context == "HTML"
    assert findings[0].details["compatible_context"] is True


def test_sanitized_constant_plus_raw_source_is_partial_coverage():
    script = (
        'const mixed = DOMPurify.sanitize("<b>safe</b>") + location.hash; '
        "preview.innerHTML = mixed;"
    )

    findings = _findings(script)

    assert {item.category for item in findings} == {"sanitizer_partial_coverage"}
    assert findings[0].source_kind == "location_hash"
    assert "source_outside_transform" in findings[0].reason_codes


def test_html_sanitizer_used_for_navigation_is_a_context_mismatch():
    script = (
        "const raw = location.hash; "
        "const clean = DOMPurify.sanitize(raw); "
        "location.href = clean;"
    )

    finding = _findings(script)[0]

    assert finding.category == "sanitizer_context_mismatch"
    assert finding.required_context == "URL"
    assert finding.protection_state == "ineffective"
    assert "output_context_mismatch" in finding.reason_codes


def test_sanitizer_assignment_after_sink_does_not_retroactively_clear_flow():
    script = (
        "let value = location.hash; "
        "preview.innerHTML = value; "
        "value = DOMPurify.sanitize(value); "
        "second.innerHTML = value;"
    )

    findings = _findings(script)

    assert {item.category for item in findings} == {
        "sanitizer_partial_coverage",
        "effective_sanitizer_boundary",
    }
    first = next(
        item for item in findings if item.category == "sanitizer_partial_coverage"
    )
    second = next(
        item for item in findings if item.category == "effective_sanitizer_boundary"
    )
    assert first.sink_offset < second.transform_offset < second.sink_offset


def test_custom_sanitizer_name_is_unknown_instead_of_trusted():
    script = (
        "const raw = location.hash; "
        "const maybeClean = sanitizeHTML(raw); "
        "preview.innerHTML = maybeClean;"
    )

    finding = _findings(script)[0]

    assert finding.category == "opaque_sanitizer_flow"
    assert finding.transform_kind == "custom_transform"
    assert "unverified_custom_transform" in finding.reason_codes


def test_dynamic_dompurify_configuration_is_unknown():
    script = (
        "const raw = location.hash; "
        "const clean = DOMPurify.sanitize(raw, runtimeConfig); "
        "preview.innerHTML = clean;"
    )

    finding = _findings(script)[0]

    assert finding.category == "opaque_sanitizer_flow"
    assert "dynamic_or_relaxed_configuration" in finding.reason_codes


def test_global_dompurify_hooks_make_boundary_unknown():
    script = (
        'DOMPurify.addHook("uponSanitizeAttribute", runtimeHook); '
        "const clean = DOMPurify.sanitize(location.hash); "
        "preview.innerHTML = clean;"
    )

    finding = _findings(script)[0]

    assert finding.category == "opaque_sanitizer_flow"
    assert "dynamic_or_relaxed_configuration" in finding.reason_codes


def test_retainting_sanitized_output_is_reported_as_invalidated():
    script = (
        "const raw = location.hash; "
        "const clean = DOMPurify.sanitize(raw); "
        "const mixed = clean + document.referrer; "
        "preview.innerHTML = mixed;"
    )

    findings = _findings(script)

    assert "sanitizer_output_invalidated" in {item.category for item in findings}
    assert any("mixed_with_external_value" in item.reason_codes for item in findings)


def test_trusted_types_string_passthrough_requires_a_complete_source_to_sink_chain():
    script = """
    const policy = trustedTypes.createPolicy("default", {
        createHTML: value => String(value)
    });
    const raw = location.hash;
    const typed = policy.createHTML(raw);
    preview.innerHTML = typed;
    """

    finding = _findings(script)[0]

    assert finding.category == "trusted_types_unvalidated_flow"
    assert finding.details["policy_method"] == "createHTML"
    assert finding.confidence >= 0.9


def test_unused_identity_policy_is_inventory_only_and_not_a_risk_flow():
    script = """
    const policy = trustedTypes.createPolicy("default", {
        createHTML: value => value
    });
    preview.textContent = "constant";
    """

    assert _findings(script) == []


def test_separate_rules_object_and_dompurify_backed_policy_are_resolved():
    script = """
    const rules = {
        createHTML: value => DOMPurify.sanitize(value)
    };
    const policy = trustedTypes.createPolicy("default", rules);
    const raw = location.hash;
    const typed = policy.createHTML(raw);
    preview.innerHTML = typed;
    """

    finding = _findings(script)[0]

    assert finding.category == "effective_sanitizer_boundary"
    assert finding.transform_kind == "trusted_types_policy"


def test_comment_and_string_decoys_do_not_create_boundaries():
    script = r'''
    // const clean = DOMPurify.sanitize(location.hash); out.innerHTML = clean;
    const decoy = "sanitizeHTML(location.hash); out.innerHTML = value";
    '''

    assert _findings(script) == []


def test_findings_are_bounded_and_never_contain_source_text(monkeypatch):
    monkeypatch.setattr(SanitizerBoundaryAnalyzer, "MAX_FINDINGS", 2)
    secret = "private-source-literal"
    script = " ".join(
        f"const raw{i} = location.hash; const clean{i} = sanitizeHTML(raw{i}); "
        f"out{i}.innerHTML = clean{i};"
        for i in range(5)
    ) + f' const unrelated = "{secret}";'

    findings = _findings(script)

    assert len(findings) == 2
    assert secret not in str([item.to_dict() for item in findings])
    assert all(len(item.fingerprint) == 64 for item in findings)


def test_assignment_budget_cannot_starve_later_sink_analysis():
    script = " ".join(f"const filler{i} = {i};" for i in range(700))
    script += (
        " const lateRaw = location.hash;"
        " const lateClean = sanitizeHTML(lateRaw);"
        " output.innerHTML = lateClean;"
    )

    findings = _findings(script)

    assert len(findings) == 1
    assert findings[0].category == "opaque_sanitizer_flow"


def test_conditional_sanitizer_retains_the_unprotected_join_path():
    script = (
        "let value = location.hash; "
        "if (enabled) { value = DOMPurify.sanitize(value); } "
        "preview.innerHTML = value;"
    )

    findings = _findings(script)

    assert "effective_sanitizer_boundary" not in _categories(script)
    assert {item.category for item in findings} == {
        "sanitizer_partial_coverage",
        "sanitizer_output_invalidated",
    }
    assert any("alternative_unprotected_path" in item.reason_codes for item in findings)


def test_unbraced_conditional_sanitizer_retains_the_unprotected_path():
    script = (
        "let value = location.hash; "
        "if (enabled) value = DOMPurify.sanitize(value); "
        "preview.innerHTML = value;"
    )

    assert "effective_sanitizer_boundary" not in _categories(script)
    assert "sanitizer_output_invalidated" in _categories(script)


def test_unused_function_sanitizer_does_not_clear_outer_flow():
    script = (
        "let value = location.hash; "
        "function cleanLater() { value = DOMPurify.sanitize(value); } "
        "preview.innerHTML = value;"
    )

    findings = _findings(script)

    assert {item.category for item in findings} == {"sanitizer_partial_coverage"}
    assert findings[0].reason_codes == ("unprotected_sink_path",)


def test_compound_assignment_retaints_sanitized_output():
    script = (
        "let value = DOMPurify.sanitize(location.hash); "
        "value += document.referrer; "
        "preview.innerHTML = value;"
    )

    assert "sanitizer_output_invalidated" in _categories(script)


def test_sanitized_value_plus_safe_literal_stays_effective():
    script = (
        'const value = DOMPurify.sanitize(location.hash) + "safe-suffix"; '
        "preview.innerHTML = value;"
    )

    assert _categories(script) == {"effective_sanitizer_boundary"}


def test_source_looking_string_literal_is_not_taint():
    script = (
        'const raw = "location.hash"; '
        "const value = DOMPurify.sanitize(raw); "
        "preview.innerHTML = value;"
    )

    assert _findings(script) == []


def test_nested_string_wrapper_preserves_html_context_mismatch():
    script = "location.href = String(DOMPurify.sanitize(location.hash));"

    finding = _findings(script)[0]

    assert finding.category == "sanitizer_context_mismatch"
    assert "content_preserving_wrapper" in finding.reason_codes


def test_url_encoding_is_not_treated_as_navigation_validation():
    finding = _findings("location.href = encodeURI(location.hash);")[0]

    assert finding.category == "sanitizer_context_mismatch"
    assert finding.transform_kind == "url_encoding"


def test_trusted_types_requires_exact_strict_sanitizer_return():
    script = """
    const policy = trustedTypes.createPolicy("default", {
        createHTML: value => value || DOMPurify.sanitize(value)
    });
    const typed = policy.createHTML(location.hash);
    preview.innerHTML = typed;
    """

    finding = _findings(script)[0]

    assert finding.category == "trusted_types_unvalidated_flow"
    assert finding.protection_state == "unknown"


def test_event_handler_attribute_uses_script_context():
    script = """
    const policy = trustedTypes.createPolicy("scripts", {
        createScript: value => value
    });
    const typed = policy.createScript(location.hash);
    node.setAttribute("onclick", typed);
    """

    finding = _findings(script)[0]

    assert finding.sink_kind == "set_event_attr"
    assert finding.required_context == "SCRIPT"
    assert finding.category == "trusted_types_unvalidated_flow"


def test_late_risk_is_ranked_ahead_of_effective_boundary_budget(monkeypatch):
    monkeypatch.setattr(SanitizerBoundaryAnalyzer, "MAX_FINDINGS", 1)
    safe = " ".join(
        f"const safe{i}=DOMPurify.sanitize(location.hash); out{i}.innerHTML=safe{i};"
        for i in range(5)
    )
    script = safe + " const bad=DOMPurify.sanitize(location.hash); location.href=bad;"

    findings = _findings(script)

    assert len(findings) == 1
    assert findings[0].category == "sanitizer_context_mismatch"


def test_bundle_exports_boundary_summary_and_restores_risky_parameter_priority():
    script = """
    const alpha = searchParams.get("alpha");
    const zeta = searchParams.get("zeta");
    const clean = DOMPurify.sanitize(zeta);
    location.href = clean;
    """

    result = BundleAnalyzer.analyze_script_content(
        "https://target.test/app.js", script, analyze_sourcemaps=False
    )

    assert result["sanitizer_boundary_summary"]["sanitizer_context_mismatch"] == 1
    assert result["sanitizer_boundary_findings"][0]["source_param"] == "zeta"
    assert result["reachable_params"][0] == "zeta"
    assert result["discovered_parameters"][0] == "zeta"
    assert "location.href = clean" not in str(result["sanitizer_boundary_findings"])
