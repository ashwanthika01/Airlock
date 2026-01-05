import socket
from cryptography.fernet import Fernet

# Same key used in app.py
key = b'HyMs5PCyDY5oWoEKZs98gwwU7ZKxSBrqifkQHVCHn-s='
cipher = Fernet(key)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('localhost', 9998))

print("Receiver started... waiting for messages.")

while True:
    data, address = sock.recvfrom(4096)
    decrypted_data = cipher.decrypt(data).decode()
    print("Decrypted:", decrypted_data)

    # ✅ Log to file
    with open("telemetry_log.txt", "a") as f:
        f.write(f"Decrypted: {decrypted_data}\n")
