import aiosqlite
import json
import os
import time
import math
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger("NetAnalyzer")


class TelemetryDB:

    def __init__(self, db_path: str = "telemetry.db"):
        self.db_path = db_path
        self.conn: Optional[aiosqlite.Connection] = None

    async def init(self):

        self.conn = await aiosqlite.connect(self.db_path)

        await self.conn.execute("""CREATE TABLE IF NOT EXISTS network_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, data TEXT NOT NULL
        )""")

        await self.conn.execute("""CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, level TEXT, message TEXT
        )""")

        await self.conn.execute("""CREATE TABLE IF NOT EXISTS decision_telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            network_context TEXT,      -- e.g., dpi_aggressive, udp_dropped
            confidence REAL,
            selected_strategy TEXT,
            score REAL,
            result TEXT,               -- success / failed
            failure_reason TEXT,       -- Section 23: failure_reason
            explanation TEXT
        )""")

        await self.conn.execute("""CREATE TABLE IF NOT EXISTS strategy_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            ts REAL NOT NULL,           -- Section 25: Used for Time Decay
            strategy TEXT, 
            condition TEXT, 
            success INTEGER
        )""")

        await self.conn.commit()
        logger.info("Telemetry Database initialized.")

    async def close(self):

        if self.conn:
            await self.conn.close()
            self.conn = None

    async def insert_network_event(self, data: Dict[str, Any]):

        if self.conn:
            await self.conn.execute(
                "INSERT INTO network_events (ts, data) VALUES (?, ?)",
                (time.time(), json.dumps(data)),
            )
            await self.conn.commit()

    async def insert_log(self, level: str, message: str):

        if self.conn:
            await self.conn.execute(
                "INSERT INTO logs (ts, level, message) VALUES (?, ?, ?)",
                (time.time(), level, message),
            )
            await self.conn.commit()

    async def insert_decision_telemetry(
        self,
        diagnosis: str,
        confidence: float,
        selected_strategy: str,
        score: float,
        result: str,
        explanation: Optional[Dict] = None,
    ):

        if self.conn:
            await self.conn.execute(
                "INSERT INTO decision_telemetry (ts, network_context, confidence, selected_strategy, score, result, failure_reason, explanation) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    time.time(),
                    json.dumps(diagnosis),
                    float(confidence),
                    selected_strategy,
                    float(score),
                    result,
                    (
                        explanation.get("reasons", ["Unknown"])[0]
                        if explanation
                        else "Unknown"
                    ),
                    json.dumps(explanation) if explanation else "{}",
                ),
            )
            await self.conn.commit()

    async def record_strategy_outcome(
        self, strategy: str, condition: str, success: bool
    ):

        if self.conn:
            await self.conn.execute(
                "INSERT INTO strategy_history (ts, strategy, condition, success) VALUES (?, ?, ?, ?)",
                (time.time(), strategy, condition, 1 if success else 0),
            )
            await self.conn.commit()

    async def get_strategy_success_rate(
        self, strategy_name: str, condition: str
    ) -> float:

        if not self.conn:
            return 0.0

        try:
            async with self.conn.execute(
                "SELECT ts, success FROM strategy_history WHERE strategy = ? AND condition = ? ORDER BY ts DESC LIMIT 100",
                (strategy_name, condition),
            ) as cursor:
                rows = await cursor.fetchall()

                if not rows:
                    return 0.0

                total_weight = 0.0
                weighted_success = 0.0
                now = time.time()

                for row in rows:
                    ts = row[0]
                    success = row[1]
                    age_days = (now - ts) / (24 * 3600)

                    if age_days < 1:
                        weight = 1.0
                    elif age_days < 7:
                        weight = 0.85
                    elif age_days < 30:
                        weight = 0.50
                    elif age_days < 90:
                        weight = 0.15
                    else:
                        weight = 0.05

                    total_weight += weight
                    if success == 1:
                        weighted_success += weight

            return weighted_success / total_weight if total_weight > 0 else 0.0

        except Exception as e:
            logger.error(f"Error calculating strategy success rate: {e}")
            return 0.0

    async def get_recent_logs(self, limit: int = 100) -> List[Dict[str, Any]]:

        if self.conn:
            async with self.conn.execute(
                "SELECT ts, level, message FROM logs ORDER BY id DESC LIMIT ?", (limit,)
            ) as cursor:
                rows = await cursor.fetchall()
                return [{"ts": row[0], "level": row[1], "msg": row[2]} for row in rows]
        return []

    async def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:

        if self.conn:
            async with self.conn.execute(
                "SELECT ts, data FROM network_events ORDER BY id DESC LIMIT ?", (limit,)
            ) as cursor:
                rows = await cursor.fetchall()
                return [{"ts": row[0], "data": json.loads(row[1])} for row in rows]
        return []

    async def get_decision_history(self, limit: int = 50) -> List[Dict[str, Any]]:

        if self.conn:
            async with self.conn.execute(
                "SELECT ts, network_context, confidence, selected_strategy, score, result, failure_reason, explanation FROM decision_telemetry ORDER BY id DESC LIMIT ?",
                (limit,),
            ) as cursor:
                rows = await cursor.fetchall()
                return [
                    {
                        "ts": row[0],
                        "network_context": json.loads(row[1]),
                        "confidence": row[2],
                        "selected_strategy": row[3],
                        "score": row[4],
                        "result": row[5],
                        "failure_reason": row[6],
                        "explanation": json.loads(row[7]) if row[7] else {},
                    }
                    for row in rows
                ]
        return []

    async def cleanup_old_logs(self):

        if self.conn:
            cutoff_time = time.time() - (7 * 24 * 60 * 60)
            await self.conn.execute("DELETE FROM logs WHERE ts < ?", (cutoff_time,))
            await self.conn.execute(
                "DELETE FROM network_events WHERE ts < ?", (cutoff_time,)
            )
            await self.conn.commit()


db = TelemetryDB()
