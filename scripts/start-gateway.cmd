@echo off
title SecureOTA gateway (port 5000)
rem Run from the repository root (this file lives in scripts\).
cd /d "%~dp0.."
rem The dashboard and the gateway must share one API key: read it from the dashboard env.
for /f "usebackq tokens=1,* delims==" %%A in ("apps\web\.env.local") do if /i "%%A"=="EDGE_GATEWAY_API_KEY" set "OTA_GATEWAY_API_KEY=%%~B"
if "%OTA_GATEWAY_API_KEY%"=="" echo WARNING: EDGE_GATEWAY_API_KEY is empty in apps\web\.env.local
set "PY=%CD%\.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"
"%PY%" -m pip install -q -r apps\gateway\requirements.txt
cd apps\gateway
echo Starting the SecureOTA gateway on http://localhost:5000 ...
echo Boards on your Wi-Fi reach it at http://^<this PC's LAN IP^>:5000 (ipconfig shows the IPv4 address).
echo If Windows Firewall asks about Python, allow it on Private networks, or boards cannot connect.
echo Keep this window open. Press Ctrl+C to stop.
"%PY%" -m uvicorn edge_gateway:app --host 0.0.0.0 --port 5000
pause
