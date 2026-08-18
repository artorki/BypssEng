import aiosqlite
import json
import os
import time

CORE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(CORE_DIR, "Data")
DB_PATH = os.path.join(DATA_DIR, "telemetry.db")
_db_conn = None

async def init_db():
    global _db_conn
    os.makedirs(DATA_DIR, exist_ok=True)
    _db_conn = await aiosqlite.connect(DB_PATH)
    await _db_conn.execute('''CREATE TABLE IF NOT EXISTS network_events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, data TEXT NOT NULL)''')
    await _db_conn.execute('''CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, level TEXT, message TEXT)''')
    
    await _db_conn.execute('''CREATE TABLE IF NOT EXISTS decision_telemetry (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        diagnosis TEXT,
        confidence REAL,
        selected_strategy TEXT,
        score REAL,
        result TEXT,
        explanation TEXT
    )''')
    
    await _db_conn.execute('''CREATE TABLE IF NOT EXISTS strategy_history (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, strategy TEXT, condition TEXT, success INTEGER)''')
    await _db_conn.commit()

async def close_db():
    global _db_conn
    if _db_conn: await _db_conn.close(); _db_conn = None

async def insert_network_event(data):
    if _db_conn:
        await _db_conn.execute("INSERT INTO network_events (ts, data) VALUES (?, ?)", (time.time(), json.dumps(data)))
        await _db_conn.commit()

async def insert_log(level, message):
    if _db_conn:
        await _db_conn.execute("INSERT INTO logs (ts, level, message) VALUES (?, ?, ?)", (time.time(), level, message))
        await _db_conn.commit()

async def insert_decision_telemetry(diagnosis, confidence, selected_strategy, score, result, explanation=None):
    if _db_conn:
        await _db_conn.execute(
            "INSERT INTO decision_telemetry (ts, diagnosis, confidence, selected_strategy, score, result, explanation) VALUES (?, ?, ?, ?, ?, ?, ?)", 
            (time.time(), json.dumps(diagnosis), float(confidence), selected_strategy, float(score), result, json.dumps(explanation) if explanation else "{}")
        )
        await _db_conn.commit()

async def record_strategy_outcome(strategy, condition, success):
    if _db_conn:
        await _db_conn.execute("INSERT INTO strategy_history (ts, strategy, condition, success) VALUES (?, ?, ?, ?)", 
                               (time.time(), strategy, condition, 1 if success else 0))
        await _db_conn.commit()

async def get_recent_logs(limit=100):
    if _db_conn:
        async with _db_conn.execute("SELECT ts, level, message FROM logs ORDER BY id DESC LIMIT ?", (limit,)) as cursor:
            rows = await cursor.fetchall()
            return [{"ts": row[0], "level": row[1], "msg": row[2]} for row in rows]
    return []

async def get_history(limit=50):
    if _db_conn:
        async with _db_conn.execute("SELECT ts, data FROM network_events ORDER BY id DESC LIMIT ?", (limit,)) as cursor:
            rows = await cursor.fetchall()
            return [{"ts": row[0], "data": json.loads(row[1])} for row in rows]
    return []

async def get_decision_history(limit=50):
    if _db_conn:
        async with _db_conn.execute("SELECT ts, diagnosis, confidence, selected_strategy, score, result, explanation FROM decision_telemetry ORDER BY id DESC LIMIT ?", (limit,)) as cursor:
            rows = await cursor.fetchall()
            return [{"ts": row[0], "diagnosis": json.loads(row[1]), "confidence": row[2], "selected_strategy": row[3], "score": row[4], "result": row[5], "explanation": json.loads(row[6]) if row[6] else {}} for row in rows]
    return []

async def cleanup_old_logs():
    if _db_conn:
        cutoff_time = time.time() - (7 * 24 * 60 * 60)
        await _db_conn.execute("DELETE FROM logs WHERE ts < ?", (cutoff_time,))
        await _db_conn.execute("DELETE FROM network_events WHERE ts < ?", (cutoff_time,))
        await _db_conn.commit()
