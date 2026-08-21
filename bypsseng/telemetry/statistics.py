import math
import time
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("NetAnalyzer")


class AdaptiveStatistics:
    def __init__(self, telemetry_db):
        self.db = telemetry_db

    def _get_decay_weight(self, age_days: float) -> float:

        if age_days < 1:
            return 1.0
        elif age_days < 7:
            return 0.85
        elif age_days < 30:
            return 0.50
        elif age_days < 90:
            return 0.15
        else:
            return 0.05

    async def get_strategy_posterior(self, strategy_name: str, condition: str) -> float:

        success_rate = await self.db.get_strategy_success_rate(strategy_name, condition)

        if success_rate == 0.0 or not success_rate:
            return 0.5

        smoothed_rate = (success_rate * 0.8) + (0.5 * 0.2)

        return smoothed_rate

    async def get_confidence(self, strategy_name: str, condition: str) -> float:
        rate = await self.get_strategy_posterior(strategy_name, condition)

        if rate == 0.5:
            return 0.1

        confidence = abs(rate - 0.5) * 2.0
        return min(confidence, 0.95)

    async def get_contextual_stats(
        self, strategy_name: str, network_context: Dict[str, Any]
    ) -> float:

        condition = network_context.get("condition", "unknown")
        return await self.get_strategy_posterior(strategy_name, condition)
