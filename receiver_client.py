#!/usr/bin/env python3
# receiver_client.py — UDP receiver with anti-replay + SQLite storage

import socket
from cryptography.fernet import Fernet
import json
import time
import os
import sqlite3
from collections import deque

FERNET_KEY = os.environ.get("FERNET_KEY") or b'HyMs5PCyDY5oWoEKZs98gwwU7ZKxSBrqifkQHVCHn-s='
cipher = Fernet(FERNET_KEY)

UDP_BIND = ('localhost', 9998)
TELEMETRY_FILE = "latest_telemetry.json"
LOG_FILE = "telemetry_log.txt"
DB_FILE = "airlock.db"

# Anti-replay config
MAX_SKEW_SECONDS = 60        # reject packets older/newer than this window
SEEN_WINDOW = 2000           # remember last N msg_ids
seen_ids = deque(maxlen=SEEN_WINDOW)

# DB init
def init_db():
    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()
    cur.execute("""
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
    """)
    con.commit()
    return con

def store_row(con, msg_id, ts, telemetry, raw):
    cur = con.cursor()
    altitude = telemetry.get("altitude")
    speed = telemetry.get("speed")
    battery = telemetry.get("battery")
    loc = telemetry.get("location", {})
    lat = loc.get("lat")
    lon = loc.get("lon")
    cur.execute("""
        INSERT OR IGNORE INTO telemetry (msg_id, ts, altitude, speed, battery, lat, lon, raw)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (msg_id, ts, altitude, speed, battery, lat, lon, raw))
    con.commit()

def within_time_window(ts):
    try:
        now = time.time()
        return abs(now - float(ts)) <= MAX_SKEW_SECONDS
    except Exception:
        return False

def pretty_print(t):
    print("\n--- Telemetry Received ---")
    print(f"ID: {t.get('msg_id')}")
    print(f"TS: {t.get('ts')}")
    print(f"Altitude: {t.get('altitude')}")
    print(f"Speed: {t.get('speed')}")
    print(f"Battery: {t.get('battery')}")
    loc = t.get('location', {})
    print(f"Location: {loc.get('lat')}, {loc.get('lon')}")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(UDP_BIND)
print(f"Receiver ready. Waiting for encrypted data on udp://{UDP_BIND[0]}:{UDP_BIND[1]}")

con = init_db()

try:
    while True:
        try:
            data, addr = sock.recvfrom(65536)

            # decrypt
            try:
                decrypted = cipher.decrypt(data).decode()
            except Exception as e:
                print("Failed to decrypt packet from", addr, ":", e)
                continue

            # parse JSON
            try:
                t = json.loads(decrypted)
            except json.JSONDecodeError:
                # still log raw
                ts_log = time.strftime('%Y-%m-%d %H:%M:%S')
                with open(LOG_FILE, "a") as f:
                    f.write(f"{ts_log} - {decrypted}\n")
                print("Telemetry (raw/non-JSON):", decrypted)
                continue

            # anti-replay checks
            msg_id = t.get("msg_id")
            ts = t.get("ts")

            if not msg_id or not ts:
                print("Rejecting packet: missing msg_id/ts")
                continue

            if msg_id in seen_ids:
                print(f"Rejecting replayed msg_id {msg_id}")
                continue

            if not within_time_window(ts):
                print(f"Rejecting stale/future packet (ts={ts})")
                continue

            seen_ids.append(msg_id)

            # pretty print
            pretty_print(t)

            # write latest to JSON
            with open(TELEMETRY_FILE, "w") as f:
                json.dump(t, f)

            # append to logfile with timestamp
            ts_log = time.strftime('%Y-%m-%d %H:%M:%S')
            with open(LOG_FILE, "a") as f:
                f.write(f"{ts_log} - {decrypted}\n")

            # store in DB
            store_row(con, msg_id, ts, t, decrypted)

        except KeyboardInterrupt:
            print("Receiver shutting down.")
            break
        except Exception as e:
            print("Receiver error:", e)
            time.sleep(0.5)
finally:
    try:
        con.close()
    except Exception:
        pass
    sock.close()
