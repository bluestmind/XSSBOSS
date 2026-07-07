import re
import unicodedata
from typing import List, Dict, Set, Optional

class TransformationConstraintSolver:
    """Mathematical transformation constraint solver for decoding and bypassing sequential filters."""
    
    _unicode_cache: Dict[str, List[str]] = {}

    @classmethod
    def _init_unicode_cache(cls):
        """Dynamically scans the Unicode plane and maps compatible decomposition characters (NFKD)."""
        if cls._unicode_cache:
            return
        
        # We target common XSS control characters and alphabet for bypasses
        targets = "sakiacoderpt<>'\"()[]/\\;= "
        cls._unicode_cache = {char: [] for char in targets}
        
        # Scan basic multilingual plane (BMP) which covers 99.9% of bypass cases
        for i in range(65536):
            try:
                c = chr(i)
                normalized = unicodedata.normalize('NFKD', c)
                # Check if the normalized character contains or is equal to our target character
                for target in targets:
                    if target in normalized and c != target:
                        cls._unicode_cache[target].append(c)
            except (ValueError, OverflowError):
                continue

    @staticmethod
    def solve_nested_replacement(target_word: str, blocked_word: str) -> str:
        """Solves the recursive replacement constraint where a blocked word is stripped once.
        
        Example: target_word='script', blocked_word='script' -> returns 'scriscriptpt'
        """
        if not blocked_word or blocked_word not in target_word:
            return target_word
        
        # Split target_word around the first occurrence of blocked_word
        idx = target_word.find(blocked_word)
        if idx == -1:
            return target_word
            
        # Nest it: split the blocked word and insert it into itself
        mid = len(blocked_word) // 2
        nested = blocked_word[:mid] + blocked_word + blocked_word[mid:]
        return target_word[:idx] + nested + target_word[idx + len(blocked_word):]

    @staticmethod
    def solve_unicode_normalization_constraint(target_char: str) -> List[str]:
        """Solves the unicode normalization constraint mapping characters back to ASCII equivalents.
        
        Uses a dynamically generated cache based on compatibility decomposition (NFKD).
        """
        TransformationConstraintSolver._init_unicode_cache()
        char_lower = target_char.lower()
        if char_lower in TransformationConstraintSolver._unicode_cache:
            options = TransformationConstraintSolver._unicode_cache[char_lower]
            if options:
                return options
        return [target_char]

    @staticmethod
    def solve_sequence(payload: str, transformations: List[str]) -> str:
        """Solves a constraint sequence back-propagating the payload through transformation steps."""
        resolved = payload
        for trans in reversed(transformations):
            if trans == "strip_script":
                resolved = TransformationConstraintSolver.solve_nested_replacement(resolved, "script")
            elif trans == "strip_onerror":
                resolved = TransformationConstraintSolver.solve_nested_replacement(resolved, "onerror")
            elif trans == "unicode_normalize":
                # Solve char-by-char normalization
                temp = []
                for char in resolved:
                    options = TransformationConstraintSolver.solve_unicode_normalization_constraint(char)
                    # Use a random choice or the first bypass option to increase mutation variance
                    import random
                    temp.append(random.choice(options) if options else char)
                resolved = "".join(temp)
        return resolved
