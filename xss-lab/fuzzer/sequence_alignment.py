import re
from typing import List, Tuple

class DOMSequenceAligner:
    """Mathematical sequence alignment and edit distance analysis for DOM trees."""

    @staticmethod
    def tokenize_html(html: str) -> List[str]:
        """Tokenize HTML markup into structural components (tags, attributes, text nodes) for structural similarity analysis."""
        # Simple HTML token regex matching tags, comments, text blocks
        token_pattern = re.compile(r'(<\/?[a-zA-Z0-9:-]+>|[a-zA-Z0-9:-]+="[^"]*"|[a-zA-Z0-9:-]+=\'[^\']*\'|[^<>\s]+)')
        tokens = token_pattern.findall(html)
        # Normalize and filter out empty tokens
        return [t.strip().lower() for t in tokens if t.strip()]

    @staticmethod
    def edit_distance(seq_a: List[str], seq_b: List[str]) -> int:
        """Computes the Levenshtein distance between two tokenized sequences using dynamic programming."""
        m, n = len(seq_a), len(seq_b)
        
        # Optimize memory usage by keeping only the current and previous rows
        prev_row = list(range(n + 1))
        curr_row = [0] * (n + 1)
        
        for i in range(1, m + 1):
            curr_row[0] = i
            for j in range(1, n + 1):
                cost = 0 if seq_a[i - 1] == seq_b[j - 1] else 1
                curr_row[j] = min(
                    curr_row[j - 1] + 1,       # Insertion
                    prev_row[j] + 1,           # Deletion
                    prev_row[j - 1] + cost     # Substitution
                )
            prev_row = list(curr_row)
            
        return prev_row[n] if m > 0 and n > 0 else max(m, n)

    @staticmethod
    def calculate_similarity(html_a: str, html_b: str) -> float:
        """Calculates normalized sequence similarity between 0.0 (totally different) and 1.0 (identical)."""
        tokens_a = DOMSequenceAligner.tokenize_html(html_a)
        tokens_b = DOMSequenceAligner.tokenize_html(html_b)
        
        max_len = max(len(tokens_a), len(tokens_b))
        if max_len == 0:
            return 1.0
            
        dist = DOMSequenceAligner.edit_distance(tokens_a, tokens_b)
        return 1.0 - (dist / max_len)
