"""Genetic evolutionary fuzzer for adaptive payload generation."""
import random
import re
import ast
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session

from backend_api.models.test_case import TestCase, TestCaseStatus
from backend_api.models.execution import Execution, OracleStatus
from backend_api.models.sink import Sink
from backend_api.utils.tokenizer import Tokenizer
from fuzzer.mutation_engine import MutationEngine

def extract_taint_flow_rules(telemetry: Dict[str, Any]) -> Dict[str, Any]:
    """Parse console warnings for [TaintFlow] telemetry and extract active filter constraints."""
    rules = {
        'blocked_chars': set(),
        'blocked_words': set(),
        'force_lowercase': False,
        'force_uppercase': False,
        'sanitizer_detected': False,
        'sanitizer_version': None,
    }
    
    console_logs = telemetry.get('console', [])
    for entry in console_logs:
        text = entry.get('text', '')
        if '[TaintFlow]' in text:
            # Format examples:
            # [TaintFlow] String.replace called on "..." with args: [searchValue, replaceValue]
            # [TaintFlow] String.split called on "..." with args: [separator]
            if 'String.split' in text:
                import re
                match = re.search(r'args:\s*\[([^\]]+)\]', text)
                if match:
                    arg_content = match.group(1).strip()
                    # If it's a simple character separator
                    if len(arg_content) == 3 and arg_content.startswith('"') and arg_content.endswith('"'):
                        char = arg_content[1]
                        rules['blocked_chars'].add(char)
                    elif len(arg_content) == 3 and arg_content.startswith("'") and arg_content.endswith("'"):
                        char = arg_content[1]
                        rules['blocked_chars'].add(char)
                        
            elif 'String.replace' in text:
                import re
                match = re.search(r'args:\s*\[([^\]]+)\]', text)
                if match:
                    args_split = match.group(1).split(',')
                    if args_split:
                        search_val = args_split[0].strip()
                        # If a word is being replaced/stripped
                        if search_val.startswith('"') and search_val.endswith('"'):
                            word = search_val[1:-1]
                            if word:
                                rules['blocked_words'].add(word)
                        elif search_val.startswith("'") and search_val.endswith("'"):
                            word = search_val[1:-1]
                            if word:
                                rules['blocked_words'].add(word)
                                
            elif 'String.toLowerCase' in text:
                rules['force_lowercase'] = True
            elif 'String.toUpperCase' in text:
                rules['force_uppercase'] = True
            elif 'RegExp.' in text or 'String.match' in text or 'String.search' in text:
                import re
                match = re.search(r'pattern:\s*(.*?)\s*\(flags:\s*([a-z]*)\)', text)
                if match:
                    pattern = match.group(1).strip()
                    # Extract char class blocks e.g. [<>'"]
                    char_classes = re.findall(r'\[([^\]]+)\]', pattern)
                    for cc in char_classes:
                        for char in ["<", ">", "'", '"', "`", "(", ")", "/", "\\"]:
                            if char in cc:
                                rules['blocked_chars'].add(char)
                    # Extract word literals (simple clean-up of regex symbols)
                    clean_pattern = re.sub(r'\\[a-zA-Z]', '', pattern)
                    clean_pattern = re.sub(r'[^a-zA-Z0-9_|]', '', clean_pattern)
                    words = clean_pattern.split('|')
                    for w in words:
                        if w and len(w) > 2:
                            rules['blocked_words'].add(w.lower())
            elif 'DOMPurify version detected' in text:
                rules['sanitizer_detected'] = True
                parts = text.split('detected:')
                if len(parts) > 1:
                    rules['sanitizer_version'] = parts[1].strip()
            elif 'Sanitizer library detected' in text:
                rules['sanitizer_detected'] = True
                
    # Convert sets to lists for JSON serialization compatibility
    rules['blocked_chars'] = list(rules['blocked_chars'])
    rules['blocked_words'] = list(rules['blocked_words'])
    return rules



class FitnessScorer:
    """Evaluates the fitness score of executed test cases."""

    @staticmethod
    def calculate_fitness(test_case: TestCase, execution: Execution) -> float:
        """Calculate fitness score from 0.0 to 100.0.
        
        Score components:
        - 100.0: Vulnerability verified (oracle hit)
        - 50.0: Target token passed into dynamic sink but execution failed (e.g. CSP blocker)
        - 40.0: Token read by DOM Source / postMessage (high taint proximity)
        - 30.0: Code syntax error containing the token (broke out of context but syntactically broken)
        - 10.0 - 20.0: Partial token reflection in DOM
        """
        # 1. Oracle Hit = perfect execution
        if execution.oracle_status == OracleStatus.HIT:
            return 100.0

        score = 0.0
        logs = {}
        if execution.logs:
            try:
                logs = ast.literal_eval(execution.logs)
                if not isinstance(logs, dict):
                    logs = {}
            except Exception:
                try:
                    import json
                    logs = json.loads(execution.logs)
                except Exception:
                    logs = {}

        # 2. Check for dynamic sink hits or source reads (from instrumentation callbacks)
        sink_type = logs.get('sink')
        if sink_type:
            if sink_type == 'securitypolicyviolation':
                score = max(score, 90.0)  # High fitness: reached execution point but blocked by CSP
            elif sink_type.startswith('DOMSourceRead:') or sink_type == 'postMessage.source':
                score += 40.0  # Taint source successfully read
            else:
                score += 50.0  # Hit a dangerous sink (e.g., innerHTML) but did not execute (e.g., CSP or sanitization)
                # If it hit innerHTML but is NOT reflected in DOM, it was likely sanitized by DOMPurify
                if execution.dom_snapshot and test_case.token not in execution.dom_snapshot:
                    score += 25.0  # Additional fitness weight to trigger sanitizer evasion path!

        # 3. Check for syntax errors (breakout indicator)
        errors = logs.get('errors', [])
        for err in errors:
            err_lower = err.lower()
            if test_case.token in err or any(kw in err_lower for kw in ["syntax", "unexpected token", "invalid or unexpected", "referenceerror", "typeerror", "uncaught"]):
                score += 30.0
                break

        # 4. Check for console warning/error reflection
        console = logs.get('console', [])
        for entry in console:
            text = entry.get('text', '') if isinstance(entry, dict) else str(entry)
            if test_case.token in text:
                score += 15.0
                break

        # 5. Measure DOM reflection ratio
        if execution.dom_snapshot:
            # Check how much of our payload or token exists in DOM
            token_count = execution.dom_snapshot.count(test_case.token)
            if token_count > 0:
                score += min(20.0, 10.0 + token_count * 2.0)

        # 6. DOM-Differential (mXSS / Parser mutation tracker)
        if execution.dom_snapshot and test_case.payload:
            # Strip tokens to compare structure
            clean_payload = test_case.payload.replace(test_case.token, "")
            clean_dom = execution.dom_snapshot.replace(test_case.token, "")
            
            # Use advanced DOM token sequence alignment and similarity
            from fuzzer.sequence_alignment import DOMSequenceAligner
            similarity = DOMSequenceAligner.calculate_similarity(clean_payload, clean_dom)
            
            if any(marker in clean_dom.lower() for marker in ["<math", "<svg", "<annotation-xml", "<noscript"]) and not any(marker in clean_payload.lower() for marker in ["<math", "<svg", "<annotation-xml", "<noscript"]):
                score += 30.0  # High bonus for triggering parser-differential!
            elif similarity < 0.95:
                # Structural difference indicating parser modification/sanitization or potential mXSS bypass
                score += (1.0 - similarity) * 40.0

        # 7. Local Theoretical mXSS Parser Round-Trip Check
        if test_case.payload:
            from fuzzer.mxss_simulator import MXSSSimulator
            mxss_sim_score = MXSSSimulator.check_mutation_differential(test_case.payload)
            if mxss_sim_score > 0.0:
                score += mxss_sim_score * 0.1

        return min(95.0, score)  # Cap non-verified runs at 95.0



class GeneticBreeder:
    """Breeds new generations of fuzzing payloads from successful parents."""

    _markov_selector = None
    _token_technique_history = {}

    @classmethod
    def _get_markov_selector(cls):
        if cls._markov_selector is None:
            from fuzzer.markov_chain import MarkovBreederSelector
            states = [
                'apply_mixed_case',
                'apply_zero_width',
                'apply_comment_obfuscation',
                'apply_alternative_whitespace',
                'apply_homoglyphs',
                'apply_alternating_escapes',
                'apply_csp_bypass_cdn',
                'apply_csp_bypass_angular',
                'apply_framework_directives',
                'apply_template_tag_calls',
                'apply_dom_clobbering',
                'apply_prototype_pollution',
                'apply_cache_poisoning_bypass',
                'apply_mxss_nesting',
                'apply_mxss_namespaced',
                'apply_some_taint_theft',
                'apply_webview_ipc_escape',
                'apply_postmessage_window_name_escape',
                'solve_nested_replacement',
                'solve_unicode_normalize'
            ]
            cls._markov_selector = MarkovBreederSelector(states)
        return cls._markov_selector

    @classmethod
    def _execute_markov_mutation(cls, payload: str, state: str) -> str:
        from fuzzer.constraint_solver import TransformationConstraintSolver
        
        if state == 'apply_mixed_case':
            return MutationEngine.apply_mixed_case(payload)
        elif state == 'apply_zero_width':
            return MutationEngine.apply_zero_width(payload, 1)
        elif state == 'apply_comment_obfuscation':
            return MutationEngine.apply_comment_obfuscation(payload)
        elif state == 'apply_alternative_whitespace':
            return MutationEngine.apply_alternative_whitespace(payload)
        elif state == 'apply_homoglyphs':
            return MutationEngine.apply_homoglyphs(payload, 0.4)
        elif state == 'apply_alternating_escapes':
            return MutationEngine.apply_alternating_escapes(payload)
        elif state == 'apply_csp_bypass_cdn':
            return random.choice(MutationEngine.apply_csp_bypass_cdn(payload))
        elif state == 'apply_csp_bypass_angular':
            return random.choice(MutationEngine.apply_csp_bypass_angular(payload))
        elif state == 'apply_framework_directives':
            return random.choice(MutationEngine.apply_framework_directives(payload))
        elif state == 'apply_template_tag_calls':
            return random.choice(MutationEngine.apply_template_tag_calls(payload))
        elif state == 'apply_dom_clobbering':
            return random.choice(MutationEngine.apply_dom_clobbering(payload))
        elif state == 'apply_prototype_pollution':
            return random.choice(MutationEngine.apply_prototype_pollution(payload))
        elif state == 'apply_cache_poisoning_bypass':
            return random.choice(MutationEngine.apply_cache_poisoning_bypass(payload))
        elif state == 'apply_mxss_nesting':
            return random.choice(MutationEngine.apply_mxss_nesting(payload))
        elif state == 'apply_mxss_namespaced':
            return random.choice(MutationEngine.apply_mxss_namespaced(payload))
        elif state == 'apply_some_taint_theft':
            return random.choice(MutationEngine.apply_some_taint_theft(payload))
        elif state == 'apply_webview_ipc_escape':
            return random.choice(MutationEngine.apply_webview_ipc_escape(payload))
        elif state == 'apply_postmessage_window_name_escape':
            return random.choice(MutationEngine.apply_postmessage_window_name_escape(payload))
        elif state == 'solve_nested_replacement':
            return TransformationConstraintSolver.solve_nested_replacement(payload, "script")
        elif state == 'solve_unicode_normalize':
            return TransformationConstraintSolver.solve_sequence(payload, ["unicode_normalize"])
            
        return payload

    @classmethod
    def _execute_q_class_mutation(cls, payload: str, action_class: str) -> str:
        from fuzzer.constraint_solver import TransformationConstraintSolver
        
        groups = {
            'obfuscate_case': [
                lambda p: MutationEngine.apply_mixed_case(p)
            ],
            'obfuscate_whitespace': [
                lambda p: MutationEngine.apply_zero_width(p, 1),
                lambda p: MutationEngine.apply_alternative_whitespace(p)
            ],
            'obfuscate_escapes': [
                lambda p: MutationEngine.apply_comment_obfuscation(p),
                lambda p: MutationEngine.apply_homoglyphs(p, 0.4),
                lambda p: MutationEngine.apply_alternating_escapes(p)
            ],
            'bypass_csp': [
                lambda p: random.choice(MutationEngine.apply_csp_bypass_cdn(p)),
                lambda p: random.choice(MutationEngine.apply_csp_bypass_angular(p)),
                lambda p: random.choice(MutationEngine.apply_template_tag_calls(p)),
                lambda p: random.choice(MutationEngine.apply_framework_directives(p))
            ],
            'bypass_mxss': [
                lambda p: random.choice(MutationEngine.apply_mxss_nesting(p)),
                lambda p: random.choice(MutationEngine.apply_mxss_namespaced(p))
            ],
            'bypass_dom_clobbering': [
                lambda p: random.choice(MutationEngine.apply_dom_clobbering(p))
            ],
            'bypass_prototype_pollution': [
                lambda p: random.choice(MutationEngine.apply_prototype_pollution(p)),
                lambda p: random.choice(MutationEngine.apply_some_taint_theft(p))
            ],
            'solve_constraints': [
                lambda p: TransformationConstraintSolver.solve_nested_replacement(p, "script"),
                lambda p: TransformationConstraintSolver.solve_nested_replacement(p, "onerror"),
                lambda p: TransformationConstraintSolver.solve_sequence(p, ["unicode_normalize"])
            ]
        }
        
        mutators = groups.get(action_class, groups['obfuscate_case'])
        mutator = random.choice(mutators)
        try:
            return mutator(payload)
        except Exception:
            return payload

    @staticmethod
    def crossover(parent_a: str, parent_a_token: str, parent_b: str, parent_b_token: str, new_token: str) -> str:
        """Perform crossover between two parent payloads while keeping token intact."""
        # Clean placeholders to prevent doubling tokens and keep formatting context
        norm_a = Tokenizer.replace_token_with_placeholders(parent_a, parent_a_token)
        norm_b = Tokenizer.replace_token_with_placeholders(parent_b, parent_b_token)

        # Split parents into chunks (tags, attributes, event handlers)
        chunks_a = [c for c in re.split(r'(\s+|<|>|=|"|\')', norm_a) if c]
        chunks_b = [c for c in re.split(r'(\s+|<|>|=|"|\')', norm_b) if c]

        if len(chunks_a) > 2 and len(chunks_b) > 2:
            # Swap halves at random split point
            split_a = random.randint(1, len(chunks_a) - 1)
            split_b = random.randint(1, len(chunks_b) - 1)
            child = "".join(chunks_a[:split_a] + chunks_b[split_b:])
        else:
            # Character midpoint crossover
            mid_a = len(norm_a) // 2
            mid_b = len(norm_b) // 2
            child = norm_a[:mid_a] + norm_b[mid_b:]

        # Ensure token placeholder exists in the child
        if not any(placeholder in child for placeholder in ["{{TOKEN}}", "{{TOKEN_B64}}", "{{TOKEN_CHARCODE}}", "{{TOKEN_WRAPPER_B64}}"]):
            child += "{{TOKEN}}"

        return Tokenizer.replace_placeholders_with_token(child, new_token)


    @staticmethod
    def mutate(payload: str, token: str, filter_profile: Optional[Dict[str, Any]] = None) -> str:
        """Apply adaptive mutations weighted dynamically based on target filter profiling."""
        protected_tokens = [token, "__XSS__"]
        
        # Determine active context challenges
        is_waf_active = False
        is_csp_active = False
        is_sanitizer_active = False
        tech_stack = {}
        taint_rules = {}
        
        if filter_profile:
            tech_stack = filter_profile.get('tech_stack', {}) or {}
            taint_rules = filter_profile.get('taint_flow_rules', {}) or {}
            if filter_profile.get('waf_detected') or 'waf' in str(filter_profile).lower():
                is_waf_active = True
            if filter_profile.get('csp_rules') or filter_profile.get('csp_detected') or 'csp' in str(filter_profile).lower():
                is_csp_active = True
            if filter_profile.get('sanitizer_detected') or 'sanitizer' in str(filter_profile).lower() or taint_rules.get('sanitizer_detected'):
                is_sanitizer_active = True
        
        # Core safe mutations pool
        core_obfuscation = [
            lambda p: MutationEngine.apply_mixed_case(p),
            lambda p: MutationEngine.apply_zero_width(p, 1),
            lambda p: MutationEngine.apply_comment_obfuscation(p),
            lambda p: MutationEngine.apply_alternative_whitespace(p),
            lambda p: MutationEngine.apply_homoglyphs(p, 0.4),
            lambda p: MutationEngine.apply_alternating_escapes(p)
        ]
        
        techniques = []
        
        # Parse runtime string TaintFlow telemetry rules
        # (loaded in filter_profile block above)
        
        # Adjust obfuscations and mutations dynamically based on TaintFlow logs
        if ' ' in taint_rules.get('blocked_chars', []):
            # Enforce alternative whitespace techniques heavily
            core_obfuscation.append(lambda p: MutationEngine.apply_alternative_whitespace(p))
            core_obfuscation.append(lambda p: MutationEngine.apply_zero_width(p, 1))
            
        blocked_words = taint_rules.get('blocked_words', [])
        if any('script' in w for w in blocked_words):
            # Avoid direct script tags, favor namespaced or nested formats
            techniques.append(lambda p: MutationEngine.apply_tag_nesting(p))
            techniques.append(lambda p: random.choice(MutationEngine.apply_mxss_nesting(p)))
            from fuzzer.constraint_solver import TransformationConstraintSolver
            techniques.append(lambda p: TransformationConstraintSolver.solve_nested_replacement(p, "script"))
            
        if any('onerror' in w for w in blocked_words):
            from fuzzer.constraint_solver import TransformationConstraintSolver
            techniques.append(lambda p: TransformationConstraintSolver.solve_nested_replacement(p, "onerror"))

        blocked_chars = taint_rules.get('blocked_chars', [])
        if any(c in blocked_chars for c in ['<', '>', '"', "'"]):
            from fuzzer.constraint_solver import TransformationConstraintSolver
            techniques.append(lambda p: TransformationConstraintSolver.solve_sequence(p, ["unicode_normalize"]))
            
        # Adaptive Router Weighting
        if is_waf_active:
            # WAF present -> heavily prioritize obfuscation and encoding
            techniques.extend(core_obfuscation * 3)  # Duplicate for higher selection probability
            techniques.append(lambda p: random.choice(MutationEngine.apply_webview_ipc_escape(p)))
        else:
            techniques.extend(core_obfuscation)
            
        if is_csp_active:
            # CSP present -> prioritize bypass CDNs, Angular templates, template tag calls
            techniques.append(lambda p: random.choice(MutationEngine.apply_csp_bypass_cdn(p)))
            techniques.append(lambda p: random.choice(MutationEngine.apply_csp_bypass_angular(p)))
            techniques.append(lambda p: random.choice(MutationEngine.apply_framework_directives(p)))
            techniques.append(lambda p: random.choice(MutationEngine.apply_template_tag_calls(p)))
            techniques.append(lambda p: random.choice(MutationEngine.apply_dom_clobbering(p)))
            techniques.append(lambda p: random.choice(MutationEngine.apply_prototype_pollution(p)))
            techniques.append(lambda p: random.choice(MutationEngine.apply_cache_poisoning_bypass(p)))
        
        if is_sanitizer_active:
            # Sanitizer present -> prioritize mXSS parser differential bypasses
            techniques.append(lambda p: random.choice(MutationEngine.apply_mxss_nesting(p)))
            techniques.append(lambda p: random.choice(MutationEngine.apply_mxss_namespaced(p)))
            techniques.append(lambda p: random.choice(MutationEngine.apply_framework_directives(p)))
            techniques.append(lambda p: random.choice(MutationEngine.apply_dom_clobbering(p)))
            techniques.append(lambda p: random.choice(MutationEngine.apply_prototype_pollution(p)))
            techniques.append(lambda p: random.choice(MutationEngine.apply_some_taint_theft(p)))
            
        if not is_csp_active and not is_sanitizer_active and not is_waf_active:
            # General fallback
            techniques.append(lambda p: random.choice(MutationEngine.apply_csp_bypass_cdn(p)))
            techniques.append(lambda p: random.choice(MutationEngine.apply_csp_bypass_angular(p)))
            techniques.append(lambda p: random.choice(MutationEngine.apply_framework_directives(p)))
            techniques.append(lambda p: random.choice(MutationEngine.apply_mxss_nesting(p)))
            techniques.append(lambda p: random.choice(MutationEngine.apply_mxss_namespaced(p)))
            techniques.append(lambda p: random.choice(MutationEngine.apply_dom_clobbering(p)))
            techniques.append(lambda p: random.choice(MutationEngine.apply_prototype_pollution(p)))
            techniques.append(lambda p: random.choice(MutationEngine.apply_webview_ipc_escape(p)))
            techniques.append(lambda p: random.choice(MutationEngine.apply_postmessage_window_name_escape(p)))

        
        # Tag/HTML-dependent mutations based on character profiling
        has_tag_obfuscation = True
        if filter_profile:
            lt_blocked = False
            for probe in filter_profile.get('probe_results', []):
                if probe.get('probe_name') == 'char_lt':
                    if probe.get('blocked') or probe.get('stripped') or probe.get('escaped'):
                        lt_blocked = True
                        break
            if lt_blocked:
                has_tag_obfuscation = False
                
        if has_tag_obfuscation:
            techniques.append(lambda p: MutationEngine.apply_slash_obfuscation(p))
            techniques.append(lambda p: MutationEngine.apply_full_width(p, 0.4))
            techniques.append(lambda p: MutationEngine.apply_tag_nesting(p))
        else:
            techniques.append(lambda p: random.choice(MutationEngine.apply_prototype_pollution(p)))

        # Add tech stack aware gadget resolver to techniques list
        if tech_stack:
            techniques.append(lambda p: random.choice(MutationEngine.apply_gadget_pollution(p, tech_stack)))
        
        # Adjust technique weighting and perform context re-writing based on character profiles
        if filter_profile:
            char_status = {}
            for probe in filter_profile.get('probe_results', []):
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
            
            if char_status:
                lparen_usable = char_status.get('(', {}).get('usable', True)
                rparen_usable = char_status.get(')', {}).get('usable', True)
                sq_usable = char_status.get("'", {}).get('usable', True)
                dq_usable = char_status.get('"', {}).get('usable', True)
                bt_usable = char_status.get('`', {}).get('usable', True)
                slash_usable = char_status.get('/', {}).get('usable', True)
                backslash_usable = char_status.get('\\', {}).get('usable', True)

                # 1. Handle quote restrictions
                if sq_usable and not dq_usable:
                    payload = payload.replace('"', "'")
                elif dq_usable and not sq_usable:
                    payload = payload.replace("'", '"')
                elif not sq_usable and not dq_usable:
                    if bt_usable:
                        # Replace all single/double quotes with backticks
                        payload = payload.replace("'", "`").replace('"', '`')
                    elif lparen_usable:
                        if backslash_usable:
                            # Try hex encoding or octal encoding randomly
                            import random
                            if random.random() < 0.5:
                                payload = MutationEngine.apply_string_hex_escapes(payload)
                            else:
                                payload = MutationEngine.apply_string_octal_escapes(payload)
                        else:
                            # Convert to String.fromCharCode
                            payload = MutationEngine.apply_string_from_char_code(payload)
                    else:
                        # Replace quoted string literals with regex .source literals where possible
                        def string_to_regex_literal(match):
                            content = match.group(1)
                            if content.isalnum():
                                return f"/{content}/.source"
                            return match.group(0)
                        import re
                        payload = re.sub(r'["\']([a-zA-Z0-9_-]+)["\']', string_to_regex_literal, payload)

                # 2. Handle parentheses restrictions
                if not lparen_usable or not rparen_usable:
                    if bt_usable:
                        # Replace call structures: alert('x') -> alert`x`
                        import re
                        payload = re.sub(r'([a-zA-Z0-9_$]+)\(["\'`]?([^"\'`)]*)["\'`]?\)', r'\1`\2`', payload)
                    elif token:
                        import re
                        # If quotes or slashes are allowed, use onerror + throw bypass
                        if sq_usable:
                            throw_stmt = f"onerror=__XSS__;throw'{token}'"
                        elif dq_usable:
                            throw_stmt = f'onerror=__XSS__;throw"{token}"'
                        elif slash_usable:
                            throw_stmt = f"onerror=__XSS__;throw/{token}/"
                        else:
                            throw_stmt = f"onerror=__XSS__;throw {token}"
                        
                        payload = re.sub(rf'__XSS__\(["\'`]?{re.escape(token)}["\'`]?\)', throw_stmt, payload)
            else:
                # Fallback to legacy normalization strings checks
                normalization = filter_profile.get('normalization_behavior', [])
                if 'quotes_escaped' in normalization or 'quotes_stripped' in normalization:
                    if 'backslashes_escaped' not in normalization and 'backslashes_stripped' not in normalization:
                        payload = payload.replace("'", "\\'").replace('"', '\\"')
                    else:
                        payload = payload.replace('"', '`').replace("'", '`')
                if 'brackets_stripped' in normalization:
                    payload = re.sub(r'([a-zA-Z0-9_$]+)\(([^)]*)\)', r'\1`\2`', payload)

        # Resolve target DOM context type (defaults to 'HTML_TEXT')
        context_str = filter_profile.get('context_type', 'HTML_TEXT') if filter_profile else 'HTML_TEXT'
        
        # Calculate policy probabilities from Q-table using Boltzmann Softmax (T=10.0)
        q_opt = GeneticEvolutionEngine._get_q_optimizer()
        q_values = [q_opt.get_q_value(context_str, act) for act in q_opt.actions]
        # Shift values to avoid overflow
        max_q = max(q_values)
        exps = [math.exp((q - max_q) / 10.0) for q in q_values]
        sum_exps = sum(exps)
        p_qtable = [e / sum_exps for e in exps] if sum_exps > 0 else [1.0/len(q_values)]*len(q_values)
        
        # Get global measurement probabilities from Quantum Qubits
        q_gate = GeneticEvolutionEngine._get_quantum_optimizer()
        p_quantum = q_gate.get_probabilities()
        
        # Entangled State-Action selection: P_final(a) = P_qtable(a) * P_quantum(a)
        combined_weights = []
        for idx, act in enumerate(q_opt.actions):
            combined_weights.append(p_qtable[idx] * p_quantum.get(act, 0.5))
            
        sum_weights = sum(combined_weights)
        if sum_weights > 0:
            action_class = random.choices(q_opt.actions, weights=combined_weights, k=1)[0]
        else:
            action_class = q_opt.select_action(context_str)
        
        # Apply the context-optimized mutation class category
        try:
            payload = GeneticBreeder._execute_q_class_mutation(payload, action_class)
        except Exception:
            pass
            
        # Record the context-action history for parent feedback updates
        GeneticEvolutionEngine._context_action_history[payload] = (context_str, action_class)

        # Next-Gen Markov Chain guided mutation sequence selection
        selector = GeneticBreeder._get_markov_selector()
        
        # Sample technique sequence from Markov matrix (length 2)
        chain = selector.select_technique_chain('apply_mixed_case', steps=2)
        
        # Sequentially apply the sampled technique transitions
        for state in chain:
            try:
                # Wrap each mutation function call
                mutator = lambda p: GeneticBreeder._execute_markov_mutation(p, state)
                payload = MutationEngine._apply_to_unprotected(payload, protected_tokens, mutator)
            except Exception:
                pass
                
        # Register the sequence for the newborn child token so we can update the transition matrix during evolve phase
        GeneticBreeder._token_technique_history[token] = chain

        # Repair syntax errors in JavaScript contexts dynamically
        try:
            payload = GeneticBreeder.auto_repair_payload_syntax(payload)
        except Exception:
            pass

        return payload

    @staticmethod
    def repair_js_syntax(js_code: str) -> str:
        """Autocorrect common bracket and string literal mismatches in generated scripts."""
        in_single = False
        in_double = False
        in_backtick = False
        escaped = False
        stack = []
        
        for char in js_code:
            if escaped:
                escaped = False
                continue
            if char == '\\':
                escaped = True
                continue
            
            if char == "'" and not in_double and not in_backtick:
                in_single = not in_single
                continue
            if char == '"' and not in_single and not in_backtick:
                in_double = not in_double
                continue
            if char == '`' and not in_single and not in_double:
                in_backtick = not in_backtick
                continue
                
            if in_single or in_double or in_backtick:
                continue
                
            if char in ['(', '{', '[']:
                stack.append(char)
            elif char in [')', '}', ']']:
                if stack:
                    mapping = {')': '(', '}': '{', ']': '['}
                    if stack[-1] == mapping[char]:
                        stack.pop()

        # Close open quotes
        if in_single:
            js_code += "'"
        elif in_double:
            js_code += '"'
        elif in_backtick:
            js_code += '`'
            
        # Close open brackets in reverse order of opening
        bracket_mapping = {'(': ')', '{': '}', '[': ']'}
        while stack:
            opener = stack.pop()
            js_code += bracket_mapping[opener]
            
        return js_code

    @staticmethod
    def auto_repair_payload_syntax(payload: str) -> str:
        """Parse script sections, inline event handlers, and javascript: URIs to repair syntax errors."""
        import re
        
        # 1. Repair <script>...</script> blocks
        def repair_script_match(match):
            opening = match.group(1)
            content = match.group(2)
            repaired = GeneticBreeder.repair_js_syntax(content)
            return f"{opening}{repaired}</script>"
            
        payload = re.sub(r'(<script[^>]*>)(.*?)(?=</script>)', repair_script_match, payload, flags=re.IGNORECASE | re.DOTALL)
        
        # 2. Repair inline event handlers (e.g. onerror="...")
        def repair_handler_match(match):
            attr_name = match.group(1)
            quote = match.group(2)
            content = match.group(3)
            repaired = GeneticBreeder.repair_js_syntax(content)
            return f"{attr_name}={quote}{repaired}{quote}"
            
        payload = re.sub(r'(\bon[a-z]+)\s*=\s*(["\'])(.*?)\2', repair_handler_match, payload, flags=re.IGNORECASE)
        
        # 3. Repair javascript: URI schemes
        if payload.lower().startswith('javascript:'):
            scheme = payload[:11]
            js_part = payload[11:]
            payload = scheme + GeneticBreeder.repair_js_syntax(js_part)
            
        return payload



class GeneticEvolutionEngine:
    """Orchestrates generations, selections, and population breeding."""

    _bandit_selector = None
    _q_optimizer = None
    _quantum_optimizer = None
    _token_action_history = {}
    _context_action_history = {}

    @classmethod
    def _get_quantum_optimizer(cls):
        if cls._quantum_optimizer is None:
            from fuzzer.quantum_gate import QuantumGateOptimizer
            actions = [
                'obfuscate_case', 'obfuscate_whitespace', 'obfuscate_escapes',
                'bypass_csp', 'bypass_mxss', 'bypass_dom_clobbering', 
                'bypass_prototype_pollution', 'solve_constraints'
            ]
            cls._quantum_optimizer = QuantumGateOptimizer(actions)
        return cls._quantum_optimizer

    @classmethod
    def _get_bandit_selector(cls):
        if cls._bandit_selector is None:
            from fuzzer.bandit import ThompsonSelector
            cls._bandit_selector = ThompsonSelector(['genetic_breed', 'llm_guided'])
        return cls._bandit_selector

    @classmethod
    def _get_q_optimizer(cls):
        if cls._q_optimizer is None:
            from fuzzer.q_learning import QTableOptimizer
            states = [
                'HTML_TEXT', 'ATTR_QUOTED', 'ATTR_UNQUOTED', 
                'JS_STRING_LITERAL', 'JS_IDENTIFIER', 'EVENT_HANDLER_ATTR',
                'CSS_STYLE', 'URL_QUERY'
            ]
            actions = [
                'obfuscate_case', 'obfuscate_whitespace', 'obfuscate_escapes',
                'bypass_csp', 'bypass_mxss', 'bypass_dom_clobbering', 
                'bypass_prototype_pollution', 'solve_constraints'
            ]
            cls._q_optimizer = QTableOptimizer(states, actions)
        return cls._q_optimizer

    def __init__(self, db: Session):
        self.db = db

    def evolve_next_generation(
        self,
        experiment_id: int,
        endpoint_id: int,
        param_id: int,
        context_id: int,
        generation_number: int,
        token: str,
        filter_profile: Optional[Dict[str, Any]] = None,
        population_size: int = 20
    ) -> List[str]:
        """Breed the next generation from the previous generation's results."""
        cls = self.__class__
        # Resolve target DOM context type and store in filter_profile
        from backend_api.models.context import Context
        ctx_obj = self.db.query(Context).filter(Context.id == context_id).first()
        context_str = ctx_obj.context_type if ctx_obj else "HTML_TEXT"
        
        if not filter_profile:
            filter_profile = {}
        filter_profile['context_type'] = context_str

        # 1. Retrieve the previous generation test cases
        prev_cases = (
            self.db.query(TestCase)
            .filter(TestCase.experiment_id == experiment_id)
            .filter(TestCase.endpoint_id == endpoint_id)
            .filter(TestCase.param_id == param_id)
            .filter(TestCase.context_id == context_id)
            .all()
        )

        if not prev_cases:
            return []

        # 2. Score fitness for each previous test case
        scored_population: List[Tuple[TestCase, float]] = []
        for case in prev_cases:
            executions = (
                self.db.query(Execution)
                .filter(Execution.test_case_id == case.id)
                .all()
            )
            max_fitness = 0.0
            for execution in executions:
                fitness = FitnessScorer.calculate_fitness(case, execution)
                if fitness > max_fitness:
                    max_fitness = fitness
            scored_population.append((case, max_fitness))

        # 3. Sort by fitness (highest first)
        scored_population.sort(key=lambda x: x[1], reverse=True)

        # Next-Gen Reinforcement: Update Markov transition weights for successful parents
        selector = GeneticBreeder._get_markov_selector()
        for case, fitness in scored_population:
            if fitness > 15.0:
                sequence = GeneticBreeder._token_technique_history.get(case.token, [])
                if sequence:
                    selector.matrix.update_transitions(sequence, fitness)

        # Next-Gen Reinforcement: Update Multi-Armed Bandit strategy rewards
        bandit = cls._get_bandit_selector()
        for case, fitness in scored_population:
            action = cls._token_action_history.get(case.payload)
            if action:
                # If fitness is >= 40.0, count as bandit success
                success = fitness >= 40.0
                bandit.update(action, success)

        # Next-Gen Reinforcement: Update Q-Learning Table rewards
        q_opt = cls._get_q_optimizer()
        for case, fitness in scored_population:
            history = cls._context_action_history.get(case.payload)
            if history:
                state, action = history
                q_opt.update_q_value(state, action, state, fitness)

        # Next-Gen Reinforcement: Apply Quantum Rotation Gates to update qubit amplitudes
        q_gate = cls._get_quantum_optimizer()
        avg_fitness = sum(fit for _, fit in scored_population) / len(scored_population) if scored_population else 0.0
        for case, fitness in scored_population:
            history = cls._context_action_history.get(case.payload)
            if history:
                _, action = history
                q_gate.apply_rotation_gate(action, fitness, avg_fitness)

        # Automatically detect and flag CSP constraints from runtime telemetry (securitypolicyviolation)
        triggered_csp = False
        for case in prev_cases:
            executions = self.db.query(Execution).filter(Execution.test_case_id == case.id).all()
            for execution in executions:
                if execution.logs and ('securitypolicyviolation' in execution.logs or 'CSP' in execution.logs):
                    triggered_csp = True
                    break
            if triggered_csp:
                break
        if triggered_csp:
            if not filter_profile:
                filter_profile = {}
            filter_profile['csp_detected'] = True

        # If we have a verified XSS (score 100), we don't need to breed further
        if scored_population and scored_population[0][1] >= 100.0:
            return []

        # If the best parent is not fully exploit-verified, trigger LLM assistance to generate novel bypass variations
        best_fitness = scored_population[0][1] if scored_population else 0.0
        llm_payloads = []
        if best_fitness < 100.0:
            try:
                from backend_api.services.llm_service import LLMService
                
                # Fetch telemetry errors and console logs from the best parent's execution
                best_case = scored_population[0][0]
                best_exec = self.db.query(Execution).filter(Execution.test_case_id == best_case.id).order_by(Execution.executed_at.desc()).first()
                
                telemetry = {}
                if best_exec and best_exec.logs:
                    try:
                        import ast
                        telemetry = ast.literal_eval(best_exec.logs)
                        if not isinstance(telemetry, dict):
                            telemetry = {}
                    except:
                        try:
                            import json
                            telemetry = json.loads(best_exec.logs)
                        except:
                            telemetry = {}
                
                if telemetry:
                    if 'sink' in telemetry and 'sinks' not in telemetry:
                        telemetry['sinks'] = [telemetry['sink']]
                    
                    try:
                        taint_rules = extract_taint_flow_rules(telemetry)
                        if taint_rules:
                            if not filter_profile:
                                filter_profile = {}
                            filter_profile['taint_flow_rules'] = taint_rules
                    except Exception:
                        pass
                        
                    # Extract tech stack telemetry
                    tech_stack = telemetry.get('tech_stack', {})
                    if tech_stack:
                        if not filter_profile:
                            filter_profile = {}
                        filter_profile['tech_stack'] = tech_stack
                
                # Convert context type enum to label string
                from backend_api.models.context import Context
                ctx_obj = self.db.query(Context).filter(Context.id == context_id).first()
                context_str = ctx_obj.context_type if ctx_obj else "HTML_TEXT"
                
                # Check local cache first to avoid slow inline network calls
                cache_file = Path("xss-lab/fuzzer/payload_grammar/llm_payload_cache.json")
                cache_key = f"{context_str}_{token}_{filter_profile.get('filter_kind') if filter_profile else 'none'}"
                
                llm_payloads = []
                if cache_file.exists():
                    try:
                        import json
                        with cache_file.open("r", encoding="utf-8") as f:
                            cache = json.load(f)
                            llm_payloads = cache.get(cache_key, [])
                    except Exception:
                        pass
                
                if not llm_payloads:
                    from backend_api.services.llm_service import LLMService
                    llm_payloads = LLMService.generate_evasion_payloads(
                        context_type=context_str,
                        token=token,
                        filter_profile=filter_profile,
                        telemetry_logs=telemetry,
                        allow_fallback=True
                    )
                    
                    # Store generated variants in local cache
                    try:
                        import json
                        cache = {}
                        if cache_file.exists():
                            try:
                                with cache_file.open("r", encoding="utf-8") as f:
                                    cache = json.load(f)
                            except Exception:
                                pass
                        cache[cache_key] = llm_payloads
                        with cache_file.open("w", encoding="utf-8") as f:
                            json.dump(cache, f, indent=4)
                    except Exception:
                        pass
            except Exception as llm_err:
                from backend_api.utils.logger import logger
                logger.warning(f"Failed to generate/retrieve LLM evasion payloads: {llm_err}")


        # 4. Select top 30% as parent pool (at least 2 parents)
        pool_size = max(2, int(len(scored_population) * 0.3))
        parents = [(item[0].payload, item[0].token) for item in scored_population[:pool_size]]

        # 5. Breed new population using crossover, mutation, and LLM suggestions
        next_gen_payloads = []
        
        # Keep the top parent as elitism (updated with the new generation token)
        best_payload, best_token = parents[0]
        elitism_payload = Tokenizer.replace_token(best_payload, best_token, token)
        next_gen_payloads.append(elitism_payload)

        # Add LLM-generated evasion payloads to the next generation
        for p in llm_payloads:
            next_gen_payloads.append(p)

        bandit = GeneticEvolutionEngine._get_bandit_selector()
        while len(next_gen_payloads) < population_size:
            action = bandit.select_action()
            
            if action == 'llm_guided' and llm_payloads:
                # Pick a random LLM suggestion
                child = random.choice(llm_payloads)
                # Ensure the base token is updated
                child = Tokenizer.replace_token(child, token, token)
                GeneticEvolutionEngine._token_action_history[child] = 'llm_guided'
            else:
                # Boltzmann-weighted parent selection
                from fuzzer.boltzmann import BoltzmannSelector
                selected = BoltzmannSelector.select_parents(scored_population, generation_number, k=2)
                p1_case, p2_case = selected[0], selected[1]
                p1_payload, p1_token = p1_case.payload, p1_case.token
                p2_payload, p2_token = p2_case.payload, p2_case.token
                
                # Crossover
                child = GeneticBreeder.crossover(p1_payload, p1_token, p2_payload, p2_token, token)
                
                # Mutation
                child = GeneticBreeder.mutate(child, token, filter_profile)
                GeneticEvolutionEngine._token_action_history[child] = 'genetic_breed'
            
            next_gen_payloads.append(child)

        # Remove duplicates
        next_gen_payloads = list(dict.fromkeys(next_gen_payloads))
        return next_gen_payloads
