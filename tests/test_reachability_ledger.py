"""Reachability ledger — never falsely report clean; measure the decided fraction."""
from analysis_engine.reachability_ledger import Certainty, ReachabilityLedger, classify


def test_classify_precedence():
    # Proof beats absence; a hit beats everything.
    assert classify(oracle_hit=True, smt_proven_safe=True, fired=True) is Certainty.CONFIRMED_VULN
    assert classify(oracle_hit=False, smt_proven_safe=True, fired=True) is Certainty.PROVEN_SAFE
    assert classify(oracle_hit=False, smt_proven_safe=False, fired=True) is Certainty.INCONCLUSIVE
    assert classify(oracle_hit=False, smt_proven_safe=False, fired=False) is Certainty.UNREACHED


def test_coverage_decided_fraction():
    L = ReachabilityLedger()
    L.record_signals("q", "HTML_TEXT", oracle_hit=True)                 # decided (vuln)
    L.record_signals("id", "HTML_TEXT", smt_proven_safe=True)          # decided (safe)
    L.record_signals("name", "HTML_TEXT", fired=True)                  # undecided
    L.record_signals("ref", "URL_QUERY")                              # undecided (unreached)
    cov = L.coverage()
    assert cov["total"] == 4
    assert cov["confirmed_vulnerabilities"] == 1
    assert cov["decided_fraction"] == 0.5      # 2 of 4 decided
    assert cov["undecided"] == 2


def test_never_falsely_reports_clean():
    L = ReachabilityLedger()
    L.record_signals("a", "HTML_TEXT", smt_proven_safe=True)
    L.record_signals("b", "JS_STRING_LITERAL", fired=True)   # inconclusive -> not safe
    # There's an undecided input, so we must NOT certify clean.
    assert L.is_trustworthy_clean() is False
    assert L.coverage()["confirmed_vulnerabilities"] == 0     # but also no confirmed bug

    L2 = ReachabilityLedger()
    L2.record_signals("a", "HTML_TEXT", smt_proven_safe=True)
    L2.record_signals("b", "URL_QUERY", smt_proven_safe=True)
    assert L2.is_trustworthy_clean() is True                  # every input provably safe


def test_gaps_rank_highest_value_first():
    L = ReachabilityLedger()
    L.record_signals("low", "ATTR_QUOTED", fired=True, reachable=False)
    L.record_signals("hot", "JS_STRING_LITERAL", fired=True, reachable=True)   # JS + reachable = top
    L.record_signals("mid", "HTML_TEXT", fired=True, reachable=False)
    gaps = L.gaps()
    assert gaps[0]["param"] == "hot"          # highest-value undecided surface surfaces first
    assert all(g["decided"] is False for g in gaps)


def test_confirmed_listing():
    L = ReachabilityLedger()
    L.record_signals("x", "HTML_TEXT", oracle_hit=True, evidence="alert fired")
    assert L.confirmed()[0]["param"] == "x"
