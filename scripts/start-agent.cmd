@echo off
title SecureOTA USB agent (127.0.0.1:17317)
rem Runs the local USB flashing agent the console uses for "Flash over USB".
cd /d "%~dp0.."
set "PY=%CD%\.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"
"%PY%" --version >nul 2>&1
if errorlevel 1 (
  echo Python 3 is required. Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH".
  pause
  exit /b 1
)
echo Starting the USB agent on http://127.0.0.1:17317 . Keep this window open.
echo Close the Arduino Serial Monitor or any other program using the board's COM port before flashing.
"%PY%" apps\agent\secureota_agent.py
pause
