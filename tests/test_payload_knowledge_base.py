"""Unit tests for PayloadKnowledgeBase and AutonomousXSSBrain."""
import pytest
from fuzzer.payload_knowledge_base import (
    PayloadKnowledgeBase,
    XSSCategory,
    InjectionContext,
    PayloadEntry,
)
from fuzzer.autonomous_xss_brain import AutonomousXSSBrain
from fuzzer.generator import PayloadGenerator
from fuzzer.mutation_engine import MutationEngine
from fuzzer.strategy import Strategy


def test_payload_knowledge_base_entries():
    """Verify knowledge base loads entries across all key vulnerability categories."""
    entries = PayloadKnowledgeBase.get_all_payloads()
    assert len(entries) >= 20

    # Ensure all primary categories exist
    csti = PayloadKnowledgeBase.get_by_category(XSSCategory.CLIENT_TEMPLATE_INJECTION)
    assert len(csti) >= 5

    dom_clobbering = PayloadKnowledgeBase.get_by_category(XSSCategory.DOM_CLOBBERING)
    assert len(dom_clobbering) >= 3

    pp = PayloadKnowledgeBase.get_by_category(XSSCategory.PROTOTYPE_POLLUTION)
    assert len(pp) >= 4

    mxss = PayloadKnowledgeBase.get_by_category(XSSCategory.MUTATION_XSS)
    assert len(mxss) >= 3

    csp = PayloadKnowledgeBase.get_by_category(XSSCategory.CSP_BYPASS)
    assert len(csp) >= 3

    waf = PayloadKnowledgeBase.get_by_category(XSSCategory.WAF_EVASION)
    assert len(waf) >= 3


def test_knowledge_base_filtering():
    """Test multi-criteria filtering in PayloadKnowledgeBase."""
    angular_payloads = PayloadKnowledgeBase.get_by_framework("angularjs")
    assert len(angular_payloads) >= 3
    assert any("constructor" in p.template for p in angular_payloads)

    vue_payloads = PayloadKnowledgeBase.get_by_framework("vue")
    assert len(vue_payloads) >= 2

    # Context query
    html_payloads = PayloadKnowledgeBase.get_by_context(InjectionContext.HTML_TEXT)
    assert len(html_payloads) > 0

    # Render template
    rendered = PayloadKnowledgeBase.render_payload("csti_angularjs_1_6_sandbox_escape", "TEST_CANARY_999")
    assert "TEST_CANARY_999" in rendered
    assert "{{TOKEN}}" not in rendered


def test_autonomous_xss_brain_synthesis():
    """Verify autonomous brain generates tailored attack chains based on constraints."""
    brain = AutonomousXSSBrain(callback_name="__XSS__")

    # 1. Angular context synthesis
    report = brain.synthesize_attack_chain(
        context_type="HTML_TEXT",
        token="CANARY_ANGULAR",
        frameworks=["angularjs"],
        strategy=Strategy.MAX_COVERAGE,
    )
    assert report.total_candidates_synthesized > 0
    assert any("angular" in d.tags or "csti" in d.tags for d in report.top_payloads)

    # 2. Blocked parentheses synthesis
    report_no_parens = brain.synthesize_attack_chain(
        context_type="HTML_TEXT",
        token="CANARY_NO_PARENS",
        filter_profile={"blocked_characters": ["(", ")"]},
        strategy=Strategy.SMART_ADAPTIVE,
    )
    assert report_no_parens.total_candidates_synthesized > 0
    # Top decision should handle blocked parens
    top_payloads_text = " ".join(d.payload for d in report_no_parens.top_payloads)
    assert "throw" in top_payloads_text or "`" in top_payloads_text

    # 3. WAF targeted synthesis
    report_waf = brain.synthesize_attack_chain(
        context_type="HTML_TEXT",
        token="CANARY_WAF",
        filter_profile={"waf_name": "cloudflare"},
        strategy=Strategy.MAX_COVERAGE,
    )
    assert report_waf.identified_waf == "cloudflare"
    assert report_waf.total_candidates_synthesized > 0


def test_payload_generator_integration():
    """Verify PayloadGenerator loads and uses all new grammars and brain integration."""
    gen = PayloadGenerator()
    stats = gen.get_grammar_stats()
    assert "csti_templates" in stats
    assert "dom_clobbering" in stats
    assert "prototype_pollution" in stats
    assert "mxss_advanced" in stats
    assert "csp_bypasses" in stats
    assert "waf_evasion" in stats

    # Generate payloads
    payloads = gen.generate_payloads(
        context_type="CSTI",
        token="CANARY_CSTI_GEN",
        strategy=Strategy.SMART_ADAPTIVE,
    )
    assert len(payloads) > 0
    assert any("CANARY_CSTI_GEN" in p for p in payloads)


def test_modern_mutations():
    """Verify newly added modern mutators in MutationEngine."""
    payload = "<script>__XSS__('TOKEN123')</script>"
    
    # 1. NFKC normalization
    nfkc = MutationEngine.apply_unicode_nfkc_normalization(payload)
    assert len(nfkc) > 0
    assert "\uff1c" in nfkc[0]

    # 2. Parentheseless throw
    throws = MutationEngine.apply_parentheseless_throw(payload)
    assert len(throws) > 0
    assert any("window.onerror=eval;throw" in t for t in throws)

    # 3. ES6 Reflect/Proxy
    reflects = MutationEngine.apply_es6_reflect_proxy_obfuscation(payload)
    assert len(reflects) > 0
    assert any("Reflect.apply" in r or "filter.constructor" in r for r in reflects)

    # 4. WAF-specific
    waf_vars = MutationEngine.apply_waf_specific_evasions(payload, "cloudflare")
    assert len(waf_vars) > 0
