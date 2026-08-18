# telemetry/metrics.py
from telemetry.storage import _db_conn

async def get_strategy_success_rate(strategy_name, condition):
    if not _db_conn: return 0.0
    try:
        async with _db_conn.execute("SELECT COUNT(*), SUM(success) FROM strategy_history WHERE strategy = ? AND condition = ?", (strategy_name, condition)) as cursor:
            row = await cursor.fetchone()
            total = row[0]
            if total == 0: return 0.0
            return row[1] / total
    except Exception:
        return 0.0