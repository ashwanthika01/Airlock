#!/usr/bin/env python3
import requests
import time

SEND = "http://127.0.0.1:5000/send"
RECV = "http://127.0.0.1:5000/receive"

while True:
    try:
        s = requests.post(SEND)
        s.raise_for_status()
        encrypted = s.json().get("encrypted")
        print("\n🔒 Encrypted Data Received:", encrypted)

        r = requests.post(RECV, json={"encrypted": encrypted})
        r.raise_for_status()
        print("Decrypted Data:", r.json().get("decrypted"))

        time.sleep(2)
    except KeyboardInterrupt:
        print("Stopping.")
        break
    except Exception as e:
        print("Error:", e)
        time.sleep(2)
