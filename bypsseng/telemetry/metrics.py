


import logging
from typing import Optional

logger = logging.getLogger("NetAnalyzer")






async def get_strategy_success_rate(strategy_name: str, condition: str, db=None) -> float:
    """
    Facade function to fetch historical strategy success rate.
    
    Section 11: Instead of importing a global `_db_conn`, it accepts the 
    active TelemetryDB instance as an argument. This ensures it always 
    points to the correct, initialized database connection.
    
    Section 25: The actual Time Decay logic is delegated to the 
    TelemetryDB instance to maintain Single Source of Truth.
    
    Args:
        strategy_name: The name of the strategy (e.g., "vless").
        condition: The network condition (e.g., "dpi_aggressive").
        db: The injected TelemetryDB instance.
        
    Returns:
        The success rate as a float (0.0 to 1.0).
    """
    if not db:
        logger.warning("TelemetryDB instance not provided to metrics.get_strategy_success_rate. Returning 0.0")
        return 0.0
        
    try:

        return await db.get_strategy_success_rate(strategy_name, condition)
    except Exception as e:
        logger.error(f"Error fetching strategy success rate via metrics: {e}")
        return 0.0