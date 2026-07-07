import random
from typing import List, Dict, Tuple

class QTableOptimizer:
    """Q-learning reinforcement learning optimizer to map DOM contexts to optimal mutations."""
    
    def __init__(self, states: List[str], actions: List[str], alpha: float = 0.2, gamma: float = 0.8, epsilon: float = 0.2):
        self.states = states
        self.actions = actions
        self.alpha = alpha      # Learning rate
        self.gamma = gamma      # Discount factor
        self.epsilon = epsilon  # Exploration rate
        
        # Initialize Q-table: Q[state][action] = 0.0
        self.q_table = {
            state: {action: 0.0 for action in actions}
            for state in states
        }
        
    def select_action(self, current_state: str) -> str:
        """Selects an action using the epsilon-greedy policy mapping to the current DOM context state."""
        if current_state not in self.q_table:
            return random.choice(self.actions)
            
        # Epsilon-greedy exploration
        if random.random() < self.epsilon:
            return random.choice(self.actions)
            
        # Exploitation: select action with maximum Q-value
        state_qs = self.q_table[current_state]
        max_q = max(state_qs.values())
        
        # In case of tie, choose randomly among candidates
        best_actions = [act for act, q in state_qs.items() if q == max_q]
        return random.choice(best_actions)
        
    def update_q_value(self, state: str, action: str, next_state: str, reward: float):
        """Applies Bellman's equation to update Q-values based on transition rewards."""
        if state not in self.q_table or action not in self.q_table[state]:
            return
            
        old_q = self.q_table[state][action]
        
        # Max Q-value of the next state
        next_max_q = 0.0
        if next_state in self.q_table:
            next_max_q = max(self.q_table[next_state].values())
            
        # Q-learning temporal difference update
        new_q = old_q + self.alpha * (reward + self.gamma * next_max_q - old_q)
        self.q_table[state][action] = new_q
