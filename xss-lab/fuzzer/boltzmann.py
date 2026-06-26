import math
import random
from typing import List, Tuple, Any

class BoltzmannSelector:
    """Softmax Boltzmann selector using thermodynamic temperature annealing for genetic selection."""

    @staticmethod
    def select_parents(population: List[Tuple[Any, float]], generation: int, k: int = 2) -> List[Any]:
        """Selects k parents from the population using the Boltzmann (Softmax) probability distribution.
        
        Args:
            population: List of tuples containing (individual, fitness_score)
            generation: Current generation number (used for temperature decay)
            k: Number of individuals to select
            
        Returns:
            List of selected individuals
        """
        if not population:
            return []
            
        # Annealing schedule: T(g) = T0 * (gamma ^ g)
        t_0 = 100.0
        gamma = 0.90
        temperature = max(1.0, t_0 * (gamma ** generation))
        
        # Extract individuals and fitness values
        individuals = [item[0] for item in population]
        fitnesses = [item[1] for item in population]
        
        # Shift fitnesses to avoid overflow or domain errors with negative/zero scores
        min_fit = min(fitnesses)
        shifted_fitnesses = [f - min_fit for f in fitnesses]
        
        # Compute exponents: e^(f_i / T)
        try:
            exponents = [math.exp(f / temperature) for f in shifted_fitnesses]
        except OverflowError:
            # Fallback to simple rank-based selection if math overflow occurs
            return random.choices(individuals, k=k)
            
        sum_exp = sum(exponents)
        if sum_exp == 0:
            return random.choices(individuals, k=k)
            
        # Normalize to get selection probabilities
        probabilities = [exp / sum_exp for exp in exponents]
        
        # Sample individuals based on calculated probability distribution
        return random.choices(individuals, weights=probabilities, k=k)
