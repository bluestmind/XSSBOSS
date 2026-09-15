"""Bypass decider — formal go/no-go per context from observed filter evidence."""
from analysis_engine.bypass_decider import BypassDecider, Decision

TOKEN = "tkn123"


def test_open_context_yields_the_payload():
    # Open reflection (no filter) is the highest-confidence XSS — hand over the exploit, don't punt.
    v = BypassDecider.decide("HTML_TEXT", None, TOKEN)
    assert v.decision is Decision.FIRE_WITNESS
    assert v.witness and TOKEN in v.witness
    v2 = BypassDecider.decide("HTML_TEXT", {"blocked_tokens": []}, TOKEN)
    assert v2.decision is Decision.FIRE_WITNESS


def test_unmodeled_context_is_normal():
    v = BypassDecider.decide("UNMODELED_CUSTOM", {"blocked_tokens": ["script"]}, TOKEN)
    assert v.decision is Decision.NORMAL


def test_css_style_block_yields_witness():
    v = BypassDecider.decide("CSS_STYLE_BLOCK", {"blocked_tokens": ["script"]}, TOKEN)
    assert v.decision is Decision.FIRE_WITNESS
    assert v.witness and "</style>" in v.witness


def test_sat_returns_fire_witness():
    # Only <script> filtered -> a bypass provably exists.
    v = BypassDecider.decide("HTML_TEXT", {"blocked_tokens": ["script"]}, TOKEN)
    assert v.decision is Decision.FIRE_WITNESS
    assert v.witness and TOKEN in v.witness


def test_unsat_returns_skip_with_proof():
    # Strip '<' entirely -> no HTML tag breakout can exist -> provably unbypassable.
    v = BypassDecider.decide("HTML_TEXT", {"blocked_chars": ["<"]}, TOKEN)
    assert v.decision is Decision.SKIP
    assert v.proof                      # a real unsat core / structural reason
    assert "unbypassable" in v.rationale


def test_context_mapping_js_literal():
    v = BypassDecider.decide("JS_STRING_LITERAL", {"blocked_tokens": ["alert"]}, TOKEN)
    assert v.smt_context == "JS_STRING_DOUBLE"
    assert v.decision in (Decision.FIRE_WITNESS, Decision.NORMAL, Decision.SKIP)
