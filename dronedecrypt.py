#!/usr/bin/env python3
# dronedecrypt.py — simple live viewer for latest_telemetry.json

import json
import time
import os

TELEMETRY_FILE = "latest_telemetry.json"
POLL_INTERVAL = 2

def pretty_print(t):
    try:
        alt = t.get("altitude")
        speed = t.get("speed")
        battery = t.get("battery")
        loc = t.get("location", {})
        lat = loc.get("lat")
        lon = loc.get("lon")
        print(f"[Drone Simulator] Altitude: {alt} | Speed: {speed} | Battery: {battery} | Location: {lat}, {lon}")
    except Exception as e:
        print("Error printing telemetry:", e)

if __name__ == "__main__":
    while True:
        if not os.path.exists(TELEMETRY_FILE):
            print("[Drone Simulator] Waiting for telemetry data...")
            time.sleep(POLL_INTERVAL)
            continue
        try:
            with open(TELEMETRY_FILE, "r") as f:
                telemetry = json.load(f)
            if isinstance(telemetry, dict):
                pretty_print(telemetry)
            else:
                print("[Drone Simulator] Unexpected telemetry format:", telemetry)
        except json.JSONDecodeError:
            print("[Drone Simulator] Received invalid telemetry format (JSONDecodeError)...")
        except Exception as e:
            print("[Drone Simulator] Error reading telemetry file:", e)
        time.sleep(POLL_INTERVAL)
