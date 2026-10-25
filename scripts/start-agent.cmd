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
rem Already running? Keep it if it is this code's version; replace it if it is
rem older (an agent started before a code update keeps running the old code).
set "AGENT_STATE="
for /f %%S in ('powershell -NoProfile -Command "try { $r=Invoke-RestMethod -TimeoutSec 3 http://127.0.0.1:17317/health; $f=(Select-String -Path 'apps\agent\secureota_agent.py' -Pattern 'AGENT_VERSION = .(\d+\.\d+\.\d+).').Matches[0].Groups[1].Value; if($r.version -eq $f){ 'current' } else { 'old' } } catch { 'none' }"') do set "AGENT_STATE=%%S"
if /i "%AGENT_STATE%"=="current" (
  echo The USB agent is already running this version on http://127.0.0.1:17317 .
  timeout /t 3 >nul
  rem Plain exit also closes the extra window start-dev.cmd opened for it.
  exit
)
if /i "%AGENT_STATE%"=="old" (
  echo An older USB agent is running; replacing it with the one in this folder...
  for /f "tokens=5" %%P in ('%SystemRoot%\System32\netstat.exe -ano ^| findstr /R /C:"127.0.0.1:17317 .*LISTENING"') do taskkill /PID %%P /T /F >nul 2>&1
  timeout /t 2 /nobreak >nul
)
echo Starting the USB agent on http://127.0.0.1:17317 . Keep this window open.
echo Close the Arduino Serial Monitor or any other program using the board's COM port before flashing.
"%PY%" apps\agent\secureota_agent.py
pause
