import math
import random
from typing import Dict, List

class QuantumGateOptimizer:
    """Quantum-Inspired Qubit Optimizer utilizing Quantum Rotation Gates to adjust state probabilities."""

    def __init__(self, action_classes: List[str]):
        # Represent each action class as a qubit state defined by angle theta in [0, pi/2]
        # Initial angle is pi/4, meaning equal superposition state with 50% probability
        self.thetas: Dict[str, float] = {action: math.pi / 4 for action in action_classes}
        
    def get_probabilities(self) -> Dict[str, float]:
        """Returns the current state measurement probabilities: P(1) = sin(theta)^2."""
        return {action: math.sin(theta) ** 2 for action, theta in self.thetas.items()}
        
    def select_action(self) -> str:
        """Selects an action class based on measured quantum probabilities."""
        probs = self.get_probabilities()
        actions = list(probs.keys())
        weights = list(probs.values())
        
        # Avoid zero weights sum by adding a small epsilon
        sum_w = sum(weights)
        if sum_w == 0:
            return random.choice(actions)
            
        return random.choices(actions, weights=weights, k=1)[0]
        
    def apply_rotation_gate(self, action: str, fitness_reward: float, baseline_fitness: float):
        """Applies a quantum rotation gate U(delta_theta) to update the qubit state.
        
        If fitness > baseline, we rotate towards |1> (theta -> pi/2) to increase probability.
        If fitness <= baseline, we rotate towards |0> (theta -> 0) to decrease probability.
        """
        if action not in self.thetas:
            return
            
        theta = self.thetas[action]
        
        # Step size scale based on normalized fitness delta
        delta_fitness = fitness_reward - baseline_fitness
        scale = min(1.0, max(-1.0, delta_fitness / 100.0))
        
        # Rotate step (max 0.05 radians per update)
        theta_delta = 0.05 * scale
        
        # Apply gate: theta = theta + theta_delta bounded in [0.01, pi/2 - 0.01]
        new_theta = max(0.01, min(math.pi / 2 - 0.01, theta + theta_delta))
        self.thetas[action] = new_theta
