@echo off
set "HERE=%~dp0"

REM Receiver
start "AirLock Receiver" cmd /k cd /d "%HERE%" ^&^& python receiver_client.py

REM Sender
start "AirLock Sender" cmd /k cd /d "%HERE%" ^&^& python app.py

REM Live display
start "AirLock Display" cmd /k cd /d "%HERE%" ^&^& python dronedecrypt.py
