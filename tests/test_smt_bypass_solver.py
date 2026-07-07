"""Tests for the SMT bypass solver: SAT witnesses, UNSAT proofs, adapters, engine agreement."""
import pytest

from analysis_engine.smt_bypass_solver import (
    CALLBACK,
    BypassSolution,
    FilterConstraints,
    NativeBoundedEngine,
    SMTBypassSolver,
    SolveStatus,
    Z3StringEngine,
    _HAS_Z3,
    _recipes_for_context,
    solve_for_profile,
)

TOKEN = "abc123"


# --------------------------------------------------------------------------- SAT

def test_open_context_yields_verified_html_bypass():
    fc = FilterConstraints(blocked_substrings={"script"})  # classic: only <script> filtered
    sol = SMTBypassSolver().solve("HTML_TEXT", fc, TOKEN)
    assert sol.status is SolveStatus.SAT
    assert sol.witness and CALLBACK in sol.witness
    assert TOKEN in sol.witness
    assert sol.verified is True
    # The synthesized payload really survives the modeled filter.
    assert CALLBACK in fc.apply(sol.witness)


def test_blocking_onerror_routes_to_another_handler():
    # Block the obvious handler + tag; solver must pick surviving spellings.
    fc = FilterConstraints(blocked_substrings={"onerror", "img", "script"})
    sol = SMTBypassSolver().solve("HTML_TEXT", fc, TOKEN)
    assert sol.status is SolveStatus.SAT
    low = sol.witness.lower()
    assert "onerror" not in low and "<img" not in low
    assert sol.verified


def test_blocking_parens_forces_tagged_template_callback():
    # If '(' and ')' are stripped, the paren-less backtick call must be chosen.
    fc = FilterConstraints(blocked_chars={"(", ")"}, blocked_substrings={"script"})
    sol = SMTBypassSolver().solve("HTML_TEXT", fc, TOKEN)
    assert sol.status is SolveStatus.SAT
    assert "(" not in sol.witness and ")" not in sol.witness
    assert f"{CALLBACK}`{TOKEN}`" in sol.witness
    assert sol.verified


def test_attribute_double_quote_breakout():
    fc = FilterConstraints(blocked_substrings={"script"})
    sol = SMTBypassSolver().solve("ATTR_QUOTED_DOUBLE", fc, TOKEN)
    assert sol.status is SolveStatus.SAT
    assert sol.witness.startswith('">')
    assert sol.verified


def test_js_string_single_breakout():
    fc = FilterConstraints(blocked_substrings=set())
    sol = SMTBypassSolver().solve("JS_STRING_SINGLE", fc, TOKEN)
    assert sol.status is SolveStatus.SAT
    assert "'" in sol.witness and ";" in sol.witness
    assert sol.verified


def test_event_handler_context_executes_directly():
    fc = FilterConstraints()
    sol = SMTBypassSolver().solve("EVENT_HANDLER_ATTR", fc, TOKEN)
    assert sol.status is SolveStatus.SAT
    assert sol.witness.startswith(CALLBACK)


def test_url_href_javascript_scheme():
    fc = FilterConstraints()
    sol = SMTBypassSolver().solve("URL_HREF", fc, TOKEN)
    assert sol.status is SolveStatus.SAT
    assert sol.witness.startswith("javascript:")


# ------------------------------------------------------------------------- UNSAT

def test_blocking_all_tags_and_handlers_proves_unsat():
    # Remove every structural primitive the HTML recipe can use → provable infeasibility.
    from analysis_engine import smt_bypass_solver as mod
    blocked = set(mod._TAGS) | set(mod._HANDLERS) | {"script", CALLBACK}
    fc = FilterConstraints(blocked_substrings=blocked)
    sol = SMTBypassSolver().solve("HTML_TEXT", fc, TOKEN)
    assert sol.status is SolveStatus.UNSAT
    assert sol.rationale
    if _HAS_Z3:
        assert sol.unsat_core  # a real core naming the conflicting constraints


def test_charset_without_angle_bracket_proves_unsat_for_html():
    # Allowed charset lacks '<' — no HTML tag breakout can exist.
    fc = FilterConstraints(allowed_charset=set("abcdefghijklmnopqrstuvwxyz0123456789_"))
    sol = SMTBypassSolver().solve("HTML_TEXT", fc, TOKEN)
    assert sol.status is SolveStatus.UNSAT


def test_length_limit_too_small_proves_unsat():
    fc = FilterConstraints(max_length=3)  # far too short for any breakout
    sol = SMTBypassSolver().solve("HTML_TEXT", fc, TOKEN)
    assert sol.status is SolveStatus.UNSAT


def test_unmodeled_context_is_unknown():
    sol = SMTBypassSolver().solve("CSS_PROPERTY", FilterConstraints(), TOKEN)
    assert sol.status is SolveStatus.UNKNOWN


# ---------------------------------------------------------------- engine parity

@pytest.mark.skipif(not _HAS_Z3, reason="z3 not installed")
def test_z3_agrees_with_native_when_z3_is_definite():
    """Where Z3 returns a definite verdict, it must match native (the complete decision procedure).

    Z3's Contains-over-Concat reasoning may time out on some blocklists; a timeout is not a
    disagreement — native remains authoritative for SAT.
    """
    cases = [
        FilterConstraints(blocked_substrings={"script"}),
        FilterConstraints(blocked_chars={"(", ")"}, blocked_substrings={"script"}),
        FilterConstraints(allowed_charset=set("abcdefghijklmnopqrstuvwxyz0123456789_")),  # UNSAT for html
    ]
    for fc in cases:
        recipe = _recipes_for_context("HTML_TEXT", TOKEN)[0]
        z_res, _ = Z3StringEngine.solve_recipe(recipe, fc, timeout_ms=3000)
        native = NativeBoundedEngine.solve_recipe(recipe, fc)
        if z_res is None:
            continue  # z3 timed out — no verdict to compare
        z_sat = not (isinstance(z_res, str) and z_res == "UNSAT")
        assert z_sat == (native is not None), f"engine disagreement on {fc}"


def test_native_engine_alone_still_solves():
    # Fully disable Z3 (SAT decision *and* UNSAT certification) → pure native path.
    solver = SMTBypassSolver(prefer_z3=False, certify_unsat=False)
    sol = solver.solve("HTML_TEXT", FilterConstraints(blocked_substrings={"script"}), TOKEN)
    assert sol.status is SolveStatus.SAT
    assert sol.engine == "native"
    assert sol.verified


def test_native_only_unsat_uses_structural_reason():
    from analysis_engine import smt_bypass_solver as mod
    blocked = set(mod._TAGS) | set(mod._HANDLERS) | {"script", CALLBACK}
    solver = SMTBypassSolver(prefer_z3=False, certify_unsat=False)
    sol = solver.solve("HTML_TEXT", FilterConstraints(blocked_substrings=blocked), TOKEN)
    assert sol.status is SolveStatus.UNSAT
    assert sol.unsat_core  # structural reason present even without z3


# -------------------------------------------------------------------- adapters

def test_adapter_from_sanitizer_profile_recursive_strip():
    """A profile whose learned rule shows incomplete recursive stripping stays bypassable."""
    from analysis_engine.automata_learner import AutomataLearner, SanitizerProfile, TransformationRule

    profile = SanitizerProfile(
        library_name="sanitize-html",
        version_range="<= 2.7.0",
        confidence=0.92,
        learned_rules=[TransformationRule(
            name="recursive_tag_stripping_bypass",
            input_pattern="<scr<script>ipt>",
            observed_output="<script>",
            rule_type="strip",
        )],
    )
    fc = FilterConstraints.from_sanitizer_profile(profile)
    assert fc.strips_recursively is False  # learned weakness carried through
    sol = solve_for_profile(profile, "HTML_TEXT", TOKEN)
    assert sol.status is SolveStatus.SAT


def test_adapter_from_learned_dompurify_profile():
    """End-to-end: learn a mutating sanitizer, then solve for a bypass."""
    from analysis_engine.automata_learner import AutomataLearner

    def dompurify_like(x: str) -> str:
        # strips <script> but mutates svg/math namespace content (mXSS)
        out = x.replace("<script>", "").replace("</script>", "")
        return out

    profile = AutomataLearner.learn_sanitizer(dompurify_like)
    sol = solve_for_profile(profile, "SVG_NAMESPACE", TOKEN)
    assert sol.status in (SolveStatus.SAT, SolveStatus.UNSAT)  # a definite verdict, not a crash
    if sol.status is SolveStatus.SAT:
        assert sol.verified


def test_adapter_from_filter_profile_char_map():
    char_map = {
        "<": {"reflected": True, "stripped": False, "escaped": False},
        ">": {"reflected": True, "stripped": False, "escaped": False},
        '"': {"reflected": False, "stripped": False, "escaped": True},  # escaped ⇒ blocked
    }
    fc = FilterConstraints.from_filter_profile(char_map)
    assert '"' in fc.blocked_chars
    assert "<" not in fc.blocked_chars


# ------------------------------------------------------------------- structure

def test_solution_serializes():
    sol = SMTBypassSolver().solve("HTML_TEXT", FilterConstraints(blocked_substrings={"script"}), TOKEN)
    d = sol.to_dict()
    assert d["status"] == "sat"
    assert "witness" in d and "attempted_recipes" in d
