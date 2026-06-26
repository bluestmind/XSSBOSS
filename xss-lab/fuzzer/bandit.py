import random
from typing import List, Dict

class ThompsonSelector:
    """Thompson Sampling (Multi-Armed Bandit) selector to optimize mutation strategy allocation."""

    def __init__(self, actions: List[str]):
        self.actions = actions
        # Alpha represents successes (starts at 1.0 for uniform prior)
        self.alphas = {action: 1.0 for action in actions}
        # Beta represents failures (starts at 1.0 for uniform prior)
        self.betas = {action: 1.0 for action in actions}

    def select_action(self) -> str:
        """Samples from the Beta distribution for each action and returns the one with the highest sample value."""
        best_action = self.actions[0]
        max_sample = -1.0
        
        for action in self.actions:
            # Sample from Beta(alpha, beta) using random.betavariate
            alpha = max(1.0, self.alphas[action])
            beta = max(1.0, self.betas[action])
            sample = random.betavariate(alpha, beta)
            
            if sample > max_sample:
                max_sample = sample
                best_action = action
                
        return best_action

    def update(self, action: str, success: bool):
        """Updates the posterior Beta distribution parameters based on success or failure feed."""
        if action not in self.alphas:
            return
            
        if success:
            # Increment success count (alpha)
            self.alphas[action] += 1.0
        else:
            # Increment failure count (beta)
            self.betas[action] += 1.0
