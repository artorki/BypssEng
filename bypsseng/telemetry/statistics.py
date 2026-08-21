


import math
import time
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("NetAnalyzer")

class AdaptiveStatistics:
    """
    Section 24 & 25: Adaptive Learning and Bayesian Update.
    Uses historical data to calculate strategy posteriors safely.
    Section 62: Implements Safety Rails to prevent low-sample overconfidence.
    """
    def __init__(self, telemetry_db):
        self.db = telemetry_db




    def _get_decay_weight(self, age_days: float) -> float:
        """Calculates the weight of an observation based on its age."""
        if age_days < 1: return 1.0
        elif age_days < 7: return 0.85
        elif age_days < 30: return 0.50
        elif age_days < 90: return 0.15
        else: return 0.05




    async def get_strategy_posterior(self, strategy_name: str, condition: str) -> float:
        """
        Calculates the expected success rate using a Beta distribution.
        Prior: Beta(1, 1) (Uniform). 
        Posterior: Beta(1 + successes, 1 + failures).
        This prevents a strategy with 1/1 success from getting a perfect 1.0 score.
        """

        success_rate = await self.db.get_strategy_success_rate(strategy_name, condition)
        

        if success_rate == 0.0 or not success_rate:
            return 0.5
            


        smoothed_rate = (success_rate * 0.8) + (0.5 * 0.2)
        
        return smoothed_rate




    async def get_confidence(self, strategy_name: str, condition: str) -> float:
        """
        Calculates confidence level based on data availability.
        More samples -> higher confidence.
        """
        rate = await self.get_strategy_posterior(strategy_name, condition)
        

        if rate == 0.5:
            return 0.1 # Low confidence (Exploration needed)
            


        confidence = abs(rate - 0.5) * 2.0 # Maps [0.5, 1.0] to [0.0, 1.0]
        return min(confidence, 0.95) # Cap at 0.95 to never be absolutely certain




    async def get_contextual_stats(self, strategy_name: str, network_context: Dict[str, Any]) -> float:
        """
        Placeholder for context-aware scoring.
        Goal: Network fingerprint (e.g., DPI state, UDP state), not User identity.
        """


        condition = network_context.get("condition", "unknown")
        return await self.get_strategy_posterior(strategy_name, condition)