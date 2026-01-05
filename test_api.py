#!/usr/bin/env python3
import requests

send = requests.post("http://127.0.0.1:5000/send", json={"data": "Drone battery: 92%"})
send.raise_for_status()
encrypted = send.json().get("encrypted")
print("Encrypted:", encrypted)

recv = requests.post("http://127.0.0.1:5000/receive", json={"encrypted": encrypted})
recv.raise_for_status()
decrypted = recv.json().get("decrypted")
print("Decrypted:", decrypted)
