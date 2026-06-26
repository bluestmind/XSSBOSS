import random
from typing import List, Dict, Any, Tuple

class MarkovTransitionMatrix:
    """A first-order Markov Chain transition probability matrix with Bayesian updates."""
    
    def __init__(self, states: List[str]):
        self.states = states
        # Initialize counts matrix with Dirichlet prior (smoothing count = 1.0 for uniform initial distribution)
        self.transition_counts = {
            s_from: {s_to: 1.0 for s_to in states}
            for s_from in states
        }
        self.transition_probabilities = {}
        self._normalize_probabilities()
        
    def _normalize_probabilities(self):
        """Recompute transitional probabilities from transition counts."""
        for s_from, transitions in self.transition_counts.items():
            total = sum(transitions.values())
            self.transition_probabilities[s_from] = {
                s_to: count / total for s_to, count in transitions.items()
            }
            
    def update_transitions(self, state_sequence: List[str], reward: float):
        """Applies a reinforcement learning Bayesian reward update to the transition sequence counts."""
        if len(state_sequence) < 2 or reward <= 0:
            return
            
        for i in range(len(state_sequence) - 1):
            s_from = state_sequence[i]
            s_to = state_sequence[i+1]
            if s_from in self.transition_counts and s_to in self.transition_counts[s_from]:
                # Increment the transition count proportional to the fitness reward
                self.transition_counts[s_from][s_to] += reward
                
        self._normalize_probabilities()
        
    def sample_next_state(self, current_state: str) -> str:
        """Samples the next state using the computed transition probabilities for the current state."""
        if current_state not in self.transition_probabilities:
            return random.choice(self.states)
            
        probs = self.transition_probabilities[current_state]
        r = random.random()
        cumulative = 0.0
        for state, prob in probs.items():
            cumulative += prob
            if r <= cumulative:
                return state
        return random.choice(self.states)

class MarkovBreederSelector:
    """Selects mutation sequences using a Markov Chain transition matrix guided by fitness feedback."""
    
    def __init__(self, technique_names: List[str]):
        self.matrix = MarkovTransitionMatrix(technique_names)
        
    def select_technique_chain(self, initial_state: str, steps: int = 2) -> List[str]:
        """Generates a sequential chain of mutation state names of length 'steps'."""
        chain = []
        current = initial_state if initial_state in self.matrix.states else random.choice(self.matrix.states)
        chain.append(current)
        for _ in range(steps - 1):
            current = self.matrix.sample_next_state(current)
            chain.append(current)
        return chain
