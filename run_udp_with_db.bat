@echo off
set "HERE=%~dp0"

start "AirLock Receiver (DB)" cmd /k cd /d "%HERE%" ^&^& python receiver_client.py
start "AirLock Sender" cmd /k cd /d "%HERE%" ^&^& python app.py
start "AirLock Display" cmd /k cd /d "%HERE%" ^&^& python dronedecrypt.py
