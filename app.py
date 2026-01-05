#!/usr/bin/env python3
# app.py — UDP sender with anti-replay metadata

import socket
import time
import json
import os
import uuid
from cryptography.fernet import Fernet

FERNET_KEY = os.environ.get("FERNET_KEY") or b'HyMs5PCyDY5oWoEKZs98gwwU7ZKxSBrqifkQHVCHn-s='
cipher = Fernet(FERNET_KEY)

UDP_TARGET = ('localhost', 9998)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def get_telemetry():
    now = int(time.time())
    data = {
        "msg_id": uuid.uuid4().hex,   # unique per message
        "ts": time.time(),            # epoch seconds (float)
        "altitude": 120 + (now % 10),
        "speed": 42 + (now % 5),
        "battery": 87 - (now % 20),
        "location": {"lat": 12.9716, "lon": 77.5946}
    }
    return data

if __name__ == "__main__":
    while True:
        payload = get_telemetry()
        plaintext = json.dumps(payload)
        encrypted = cipher.encrypt(plaintext.encode())
        sock.sendto(encrypted, UDP_TARGET)
        print("Sent encrypted telemetry:", plaintext)
        time.sleep(2)
