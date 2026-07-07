import math
import random
from typing import List, Tuple, Any

class BoltzmannSelector:
    """Softmax Boltzmann selector using thermodynamic temperature annealing and Sigma Scaling."""

    @staticmethod
    def select_parents(population: List[Tuple[Any, float]], generation: int, k: int = 2) -> List[Any]:
        """Selects k parents using Boltzmann (Softmax) selection over Sigma-scaled fitness values.
        
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
        
        # 1. Compute Mean and Standard Deviation for Sigma Scaling
        n = len(fitnesses)
        mean_fit = sum(fitnesses) / n
        variance = sum((f - mean_fit) ** 2 for f in fitnesses) / n
        std_dev = math.sqrt(variance)
        
        # 2. Apply Sigma Scaling to prevent premature convergence by outliers
        # f'_i = max(0.1, 1.0 + (f_i - mean) / (2 * std_dev))
        if std_dev > 1e-4:
            scaled_fitnesses = [
                max(0.1, 1.0 + (f - mean_fit) / (2.0 * std_dev))
                for f in fitnesses
            ]
        else:
            # Fallback to shifted fitnesses if standard deviation is zero/tiny
            min_fit = min(fitnesses)
            scaled_fitnesses = [f - min_fit for f in fitnesses]
        
        # 3. Compute exponents: e^(f'_i / T)
        try:
            exponents = [math.exp(f / temperature) for f in scaled_fitnesses]
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

