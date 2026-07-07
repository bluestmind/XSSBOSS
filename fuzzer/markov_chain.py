import random
from typing import List, Dict, Any, Tuple

class MarkovTransitionMatrix:
    """A second-order Markov Chain transition probability matrix with Katz-style back-off and Bayesian updates."""
    
    def __init__(self, states: List[str]):
        self.states = states
        # Initialize first-order counts (uniform prior = 1.0)
        self.first_order_counts = {
            s_from: {s_to: 1.0 for s_to in states}
            for s_from in states
        }
        # Initialize second-order counts (uniform prior = 0.1 to allow fast adaptation of new transitions)
        self.second_order_counts = {
            (s1, s2): {s3: 0.1 for s3 in states}
            for s1 in states
            for s2 in states
        }
        self.first_order_probs = {}
        self.second_order_probs = {}
        self._normalize_probabilities()
        
    def _normalize_probabilities(self):
        """Recompute transitional probabilities from transition counts."""
        # Normalize first-order
        for s_from, transitions in self.first_order_counts.items():
            total = sum(transitions.values())
            self.first_order_probs[s_from] = {
                s_to: count / total for s_to, count in transitions.items()
            }
        # Normalize second-order
        for (s1, s2), transitions in self.second_order_counts.items():
            total = sum(transitions.values())
            self.second_order_probs[(s1, s2)] = {
                s3: count / total for s3, count in transitions.items()
            }
            
    def update_transitions(self, state_sequence: List[str], reward: float):
        """Applies a reinforcement learning Bayesian reward update to the transition sequence counts."""
        if len(state_sequence) < 2 or reward <= 0:
            return
            
        # Update first-order transitions
        for i in range(len(state_sequence) - 1):
            s_from = state_sequence[i]
            s_to = state_sequence[i+1]
            if s_from in self.first_order_counts and s_to in self.first_order_counts[s_from]:
                self.first_order_counts[s_from][s_to] += reward
                
        # Update second-order transitions
        for i in range(len(state_sequence) - 2):
            s1 = state_sequence[i]
            s2 = state_sequence[i+1]
            s3 = state_sequence[i+2]
            key = (s1, s2)
            if key in self.second_order_counts and s3 in self.second_order_counts[key]:
                self.second_order_counts[key][s3] += reward
                
        self._normalize_probabilities()
        
    def sample_next_state(self, current_state: str, previous_state: str = None) -> str:
        """Samples the next state using second-order probabilities with back-off to first-order."""
        if previous_state and (previous_state, current_state) in self.second_order_probs:
            # Check if second-order state has been updated past the uniform prior
            key = (previous_state, current_state)
            counts = self.second_order_counts[key]
            # If at least one transition is strongly updated (reward contribution >= 1.0)
            if any(cnt > 1.0 for cnt in counts.values()):
                probs = self.second_order_probs[key]
                return self._weighted_choice(probs)
                
        # Back-off to first-order
        if current_state in self.first_order_probs:
            return self._weighted_choice(self.first_order_probs[current_state])
            
        return random.choice(self.states)
        
    def _weighted_choice(self, probs: Dict[str, float]) -> str:
        r = random.random()
        cumulative = 0.0
        for state, prob in probs.items():
            cumulative += prob
            if r <= cumulative:
                return state
        return random.choice(self.states)

class MarkovBreederSelector:
    """Selects mutation sequences using a Second-Order Markov Chain transition matrix guided by fitness feedback."""
    
    def __init__(self, technique_names: List[str]):
        self.matrix = MarkovTransitionMatrix(technique_names)
        
    def select_technique_chain(self, initial_state: str, steps: int = 2) -> List[str]:
        """Generates a sequential chain of mutation state names of length 'steps'."""
        chain = []
        current = initial_state if initial_state in self.matrix.states else random.choice(self.matrix.states)
        chain.append(current)
        
        previous = None
        for _ in range(steps - 1):
            next_state = self.matrix.sample_next_state(current, previous)
            chain.append(next_state)
            previous = current
            current = next_state
        return chain
