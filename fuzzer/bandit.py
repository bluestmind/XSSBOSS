import random
from typing import List, Dict

class ThompsonSelector:
    """Contextual Thompson Sampling (Multi-Armed Bandit) selector to optimize mutation strategy allocation."""

    def __init__(self, actions: List[str]):
        self.actions = actions
        # Store context-specific alphas and betas
        self.alphas: Dict[str, Dict[str, float]] = {}
        self.betas: Dict[str, Dict[str, float]] = {}
        # Ensure a default global context is always available
        self._ensure_context("global")

    def _ensure_context(self, context: str):
        if context not in self.alphas:
            self.alphas[context] = {action: 1.0 for action in self.actions}
            self.betas[context] = {action: 1.0 for action in self.actions}

    def select_action(self, context: str = "global") -> str:
        """Samples from the Beta distribution for each action in the given context and returns the best action."""
        self._ensure_context(context)
        
        best_action = self.actions[0]
        max_sample = -1.0
        
        for action in self.actions:
            # Sample from Beta(alpha, beta) using random.betavariate
            alpha = max(1.0, self.alphas[context][action])
            beta = max(1.0, self.betas[context][action])
            sample = random.betavariate(alpha, beta)
            
            if sample > max_sample:
                max_sample = sample
                best_action = action
                
        return best_action

    def update(self, action: str, success: bool, context: str = "global"):
        """Updates the posterior Beta distribution parameters for the specified context based on success/failure."""
        self._ensure_context(context)
        
        if action not in self.alphas[context]:
            return
            
        if success:
            # Increment success count (alpha)
            self.alphas[context][action] += 1.0
        else:
            # Increment failure count (beta)
            self.betas[context][action] += 1.0

