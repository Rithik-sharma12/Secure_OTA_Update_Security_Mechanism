@echo off
title SecureOTA gateway (port 5000)
cd /d "%~dp0"
rem The dashboard and the gateway must share one API key: read it from the dashboard env.
for /f "usebackq tokens=1,* delims==" %%A in ("CODE\OTA_IDE\.env.local") do if /i "%%A"=="EDGE_GATEWAY_API_KEY" set "OTA_GATEWAY_API_KEY=%%~B"
if "%OTA_GATEWAY_API_KEY%"=="" echo WARNING: EDGE_GATEWAY_API_KEY is empty in CODE\OTA_IDE\.env.local
set "PY=%~dp0.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"
"%PY%" -m pip install -q -r src\implementation\requirements.txt
cd src\implementation
echo Starting the SecureOTA gateway on http://localhost:5000 ...
echo Keep this window open. Press Ctrl+C to stop.
"%PY%" -m uvicorn edge_gateway:app --host 0.0.0.0 --port 5000
pause
