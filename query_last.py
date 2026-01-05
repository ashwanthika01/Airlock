#!/usr/bin/env python3
# query_last.py — print last N telemetry rows; auto-initialize table if missing

import sqlite3
import sys
from textwrap import shorten
import os

DB_FILE = "airlock.db"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 10

SCHEMA = """
CREATE TABLE IF NOT EXISTS telemetry (
    msg_id TEXT PRIMARY KEY,
    ts REAL,
    altitude INTEGER,
    speed INTEGER,
    battery INTEGER,
    lat REAL,
    lon REAL,
    raw TEXT NOT NULL,
    inserted_at REAL DEFAULT (strftime('%s','now'))
)
"""

if not os.path.exists(DB_FILE):
    print("[info] database file not found; creating", DB_FILE)

con = sqlite3.connect(DB_FILE)
cur = con.cursor()
# Ensure table exists
cur.execute(SCHEMA)
con.commit()

# Query last N rows (may be empty if no data received yet)
cur.execute("""
    SELECT msg_id, ts, altitude, speed, battery, lat, lon, raw
    FROM telemetry
    ORDER BY inserted_at DESC
    LIMIT ?
""", (N,))
rows = cur.fetchall()
con.close()

if not rows:
    print("[info] No rows found. Start receiver_client.py (and app.py to send) first.")
else:
    for i, r in enumerate(rows, 1):
        msg_id, ts, alt, spd, bat, lat, lon, raw = r
        ts_str = f"{ts:.3f}" if ts is not None else "None"
        print(f"{i:02d}. id={msg_id} ts={ts_str} alt={alt} spd={spd} bat={bat} lat={lat} lon={lon}")
        print("    raw:", shorten(raw or "", width=120, placeholder="…"))
