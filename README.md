# 🚁 Project Airlock – Secure Drone Telemetry System

Project Airlock is a **security-first drone telemetry system** designed to safely receive, validate, store, and monitor drone flight data. It implements an **Airlock architecture**, where all untrusted drone data is isolated, decrypted, verified, and audited before being displayed or stored.

This project demonstrates real-world concepts used in **aerospace, defense, and autonomous systems**, such as encrypted communication, anti-replay protection, secure boundaries, and audit logging.

---

## ✨ Key Features

* 🔐 **Encrypted telemetry transmission** (Fernet / AES-based)
* 🛡️ **Airlock security boundary** between drones and operators
* ♻️ **Anti-replay protection** using unique message IDs
* ⏱️ **Timestamp validation** to reject stale or future packets
* 📡 **Multi-protocol support** (UDP + HTTP)
* 🗄️ **SQLite database logging** for audit and forensics
* 📊 **Live dashboard & monitoring**
* 📁 **Read-only trusted telemetry viewer**
* ▶️ **One-click system startup using batch files**

---

## 🧠 System Architecture (High Level)

```
[ Drone / Simulator ]
        |
   Encrypted UDP / HTTP
        |
┌──────────────────────────┐
│        AIRLOCK           │
│  • Decrypt               │
│  • Validate              │
│  • Anti-Replay           │
│  • Log                   │
│  • Store (DB)            │
└───────────┬──────────────┘
            |
     Trusted Telemetry
            |
   ┌────────┴────────┐
   ▼                 ▼
Live Viewer      Dashboard / DB
(Read-only)      (Analytics)
```

---

## 📂 Project Structure

```
project-airlock/
│
├── app.py                  # UDP-based encrypted drone telemetry sender
├── receiver_client.py      # Secure Airlock receiver (decrypt, validate, store)
├── drone_simulator.py      # HTTP-based drone telemetry simulator
├── flask_server.py         # Airlock server with API, DB, and dashboard
├── dronedecrypt.py         # Read-only live telemetry viewer
│
├── test_api.py             # One-time encryption/decryption API test
├── testdecrypt_api.py      # Continuous encryption/decryption health check
├── view_db.py              # SQLite database inspection tool
│
├── airlock.db              # SQLite telemetry database (auto-created)
├── telemetry_log.txt       # Append-only telemetry log
├── latest_telemetry.json   # Latest verified telemetry snapshot
│
├── run_http_airlock.bat    # Launch HTTP Airlock pipeline
├── run_udp_airlock.bat     # Launch UDP Airlock pipeline
├── run_udp_db_airlock.bat  # UDP pipeline with DB + display
│
└── README.md               # Project documentation
```

---

## ⚙️ Requirements

* Python 3.8+
* Windows (for `.bat` files) or manual execution on Linux/macOS

### Python Dependencies

```bash
pip install cryptography flask requests
```

---

## ▶️ How to Run the Project

### Option 1: UDP Telemetry Pipeline (Recommended Demo)

```bash
run_udp_db_airlock.bat
```

This starts:

* Secure UDP Airlock receiver
* Drone telemetry sender
* Live read-only display

---

### Option 2: HTTP Airlock Pipeline

```bash
run_http_airlock.bat
```

This starts:

* Flask Airlock server
* API test client
* HTTP drone simulator
* Continuous decrypt monitor

---

## 🔐 Security Design Highlights

* **Encryption**: All telemetry is encrypted using Fernet (AES + HMAC)
* **Anti-Replay**: Duplicate message IDs are rejected
* **Freshness Check**: Packets outside the allowed time window are dropped
* **Isolation**: Viewers never access raw network data
* **Auditability**: All verified telemetry is logged and stored

---

## 📊 Dashboard & Monitoring

The Flask server provides:

* Live drone position on a map
* Altitude, speed, and battery charts
* Telemetry history
* CSV export for offline analysis

---

## 🎓 Educational Value

This project demonstrates:

* Secure system design
* Network communication (UDP & HTTP)
* Cryptography in practice
* Backend APIs
* Database logging & analytics
* Real-time monitoring
* Defense-style Airlock architecture

Ideal for:

* Final-year engineering projects
* Cybersecurity demonstrations
* Drone & IoT telemetry systems

---

## 🚀 Future Enhancements

* TLS-based transport security
* Public-key authentication
* MQTT telemetry support
* Role-based access control
* Anomaly detection & alerts
* Cloud deployment

---

## 🧑‍💻 Authors

Developed as part of **Project Airlock – Secure Drone Telemetry System**.

---

## 📜 License

This project is intended for **educational and research purposes**.

---

⭐ *If you find this project useful, consider giving it a star on GitHub!*
