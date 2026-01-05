#!/usr/bin/env python3
# drone_simulator.py — HTTP telemetry sender (structured JSON)

import requests
import time
import random

URL = "http://127.0.0.1:5000/send"

for i in range(10):
    telemetry = {
        "battery": f"{random.randint(60, 100)}%",
        "altitude": f"{random.uniform(100.0, 500.0):.2f} m",
        "latitude": f"{random.uniform(25.0, 26.0):.5f}",
        "longitude": f"{random.uniform(55.0, 56.0):.5f}",
        "signal_strength": f"{random.randint(50, 100)}%"
    }
    print(f"\n[Drone] Sending Data {i+1}: {telemetry}")
    # Send as JSON under 'data' (server also accepts whole body, but this keeps it explicit)
    r = requests.post(URL, json={"data": telemetry})
    r.raise_for_status()
    enc = r.json().get("encrypted", "")
    print(f"[Encrypted] {enc[:60]}...")
    time.sleep(2)
