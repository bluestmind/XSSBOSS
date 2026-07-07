import math
import random
from typing import Dict, List, Tuple

class QuantumGateOptimizer:
    """Entangled Quantum-Inspired Genetic Algorithm (EQIGA) utilizing Quantum Rotation Gates and Entanglement propagation."""

    def __init__(self, action_classes: List[str]):
        # Represent each action class as a qubit state defined by angle theta in [0, pi/2]
        # Initial angle is pi/4, meaning equal superposition state with 50% probability
        self.thetas: Dict[str, float] = {action: math.pi / 4 for action in action_classes}
        # Entanglement correlation coefficients between pairs of actions: chi_ij in [-pi/4, pi/4]
        self.entanglement: Dict[Tuple[str, str], float] = {
            (a1, a2): 0.0 for a1 in action_classes for a2 in action_classes if a1 != a2
        }
        self.action_classes = action_classes
        
    def get_probabilities(self, conditional_shifts: Dict[str, float] = None) -> Dict[str, float]:
        """Returns the current state measurement probabilities: P(1) = sin(theta + shift)^2."""
        probs = {}
        for action, theta in self.thetas.items():
            shift = conditional_shifts.get(action, 0.0) if conditional_shifts else 0.0
            effective_theta = max(0.01, min(math.pi / 2 - 0.01, theta + shift))
            probs[action] = math.sin(effective_theta) ** 2
        return probs
        
    def select_action(self) -> str:
        """Selects an action class simulating quantum state measurement collapse across entangled qubits."""
        # 1. Measure/Select the primary action using baseline probabilities
        probs = self.get_probabilities()
        actions = list(probs.keys())
        weights = list(probs.values())
        
        sum_w = sum(weights)
        if sum_w == 0:
            primary_action = random.choice(actions)
        else:
            primary_action = random.choices(actions, weights=weights, k=1)[0]
            
        # 2. Simulate Wavefunction Collapse: The measurement of primary_action shifts
        # the superposition state angles of all entangled qubits according to the correlation coefficients.
        conditional_shifts = {}
        for action in self.action_classes:
            if action != primary_action:
                # Retrieve the entanglement correlation parameter
                key = (primary_action, action)
                if key in self.entanglement:
                    # Positive correlation increases the target angle, negative decreases it
                    conditional_shifts[action] = self.entanglement[key]
                    
        # 3. Sample the final action under the collapsed/shifted probability distribution
        probs_collapsed = self.get_probabilities(conditional_shifts)
        weights_collapsed = [probs_collapsed[a] for a in actions]
        
        sum_wc = sum(weights_collapsed)
        if sum_wc == 0:
            return primary_action
            
        return random.choices(actions, weights=weights_collapsed, k=1)[0]
        
    def apply_rotation_gate(self, action: str, fitness_reward: float, baseline_fitness: float):
        """Applies a quantum rotation gate U(delta_theta) and updates entanglement parameters.
        
        Rotates the target qubit towards |1> (theta -> pi/2) for positive feedback,
        and propagates the rotation to entangled qubits based on correlation coefficients.
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
        
        # Update Entanglement: If we achieved positive feedback (scale > 0),
        # strengthen the entanglement correlation with other actions that were successful.
        if scale > 0.01:
            for other_action in self.action_classes:
                if other_action != action:
                    key = (action, other_action)
                    if key in self.entanglement:
                        # Soft Hebbian learning update for quantum correlation parameter
                        # Bound entanglement shift in [-math.pi / 4, math.pi / 4]
                        current_ent = self.entanglement[key]
                        new_ent = max(-math.pi / 4, min(math.pi / 4, current_ent + 0.02 * scale))
                        self.entanglement[key] = new_ent
                        
                        # Apply partial entangled rotation to the correlated qubit
                        other_theta = self.thetas[other_action]
                        entangled_delta = theta_delta * (new_ent / (math.pi / 4))
                        self.thetas[other_action] = max(
                            0.01, min(math.pi / 2 - 0.01, other_theta + entangled_delta)
                        )

