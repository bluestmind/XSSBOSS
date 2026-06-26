import re
from typing import List, Dict, Set, Optional

class TransformationConstraintSolver:
    """Mathematical transformation constraint solver for decoding and bypassing sequential filters."""
    
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
        
        For example: 's' can be bypassed using Unicode character U+017F (Latin Small Letter Long S) 
        which normalizes to 's' under compatibility decomposition (NFKD).
        """
        mapping = {
            's': ['\u017f', '\u24da'],
            'k': ['\u212a', '\u24de'],
            'i': ['\u24d8', '\u0131'],
            'a': ['\u24d0', '\u1d43'],
            'c': ['\u24d2', '\u1d9c'],
            'o': ['\u24de', '\u1d52'],
            'd': ['\u24d3', '\u1d48'],
            'e': ['\u24d4', '\u1d49'],
            'r': ['\u24e1', '\u02b3'],
            'p': ['\u24df', '\u1d56'],
            't': ['\u24e3', '\u1d57'],
            '<': ['\ufe64', '\uff1c'],
            '>': ['\ufe65', '\uff1e'],
            '"': ['\u201c', '\u201d', '\uff02'],
            "'": ['\u2018', '\u2019', '\uff07'],
        }
        return mapping.get(target_char.lower(), [target_char])

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
                    temp.append(options[0])  # Pick the primary bypass candidate
                resolved = "".join(temp)
        return resolved
