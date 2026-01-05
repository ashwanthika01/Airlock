@echo off
set "HERE=%~dp0"

REM Flask server
start "AirLock Flask" cmd /k cd /d "%HERE%" ^&^& python flask_server.py

REM Basic test
start "AirLock test_api" cmd /k cd /d "%HERE%" ^&^& python test_api.py

REM Drone simulator (HTTP)
start "AirLock drone_sim" cmd /k cd /d "%HERE%" ^&^& python drone_simulator.py

REM Continuous decrypt loop
start "AirLock testdecrypt" cmd /k cd /d "%HERE%" ^&^& python testdecrypt_api.py

