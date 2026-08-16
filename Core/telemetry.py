# BypssEng - artorki

import aiosqlite
import json
import os
import time

CORE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CORE_DIR)
DATA_DIR = os.path.join(ROOT_DIR, "Data")

DB_PATH = os.path.join(DATA_DIR, "telemetry.db")
_db_conn = None

async def init_db():
    global _db_conn
    os.makedirs(DATA_DIR, exist_ok=True)
    _db_conn = await aiosqlite.connect(DB_PATH)
    await _db_conn.execute('''CREATE TABLE IF NOT EXISTS network_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        data TEXT NOT NULL
    )''')
    await _db_conn.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        level TEXT,
        message TEXT
    )''')
    await _db_conn.commit()

async def close_db():
    global _db_conn
    if _db_conn:
        await _db_conn.close()
        _db_conn = None

async def insert_network_event(data):
    if _db_conn:
        await _db_conn.execute("INSERT INTO network_events (ts, data) VALUES (?, ?)", (time.time(), json.dumps(data)))
        await _db_conn.commit()

async def insert_log(level, message):
    if _db_conn:
        await _db_conn.execute("INSERT INTO logs (ts, level, message) VALUES (?, ?, ?)", (time.time(), level, message))
        await _db_conn.commit()

async def get_recent_logs(limit=100):
    if _db_conn:
        async with _db_conn.execute("SELECT ts, level, message FROM logs ORDER BY id DESC LIMIT ?", (limit,)) as cursor:
            rows = await cursor.fetchall()
            return [{"ts": row[0], "level": row[1], "msg": row[2]} for row in rows]
    return []

