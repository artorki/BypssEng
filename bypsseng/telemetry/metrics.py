import logging
from typing import Optional

logger = logging.getLogger("NetAnalyzer")


async def get_strategy_success_rate(
    strategy_name: str, condition: str, db=None
) -> float:
    if not db:
        logger.warning(
            "TelemetryDB instance not provided to metrics.get_strategy_success_rate. Returning 0.0"
        )
        return 0.0

    try:

        return await db.get_strategy_success_rate(strategy_name, condition)
    except Exception as e:
        logger.error(f"Error fetching strategy success rate via metrics: {e}")
        return 0.0
