@echo off
title SecureOTA dashboard (localhost:3000)
rem Run from the repository root (this file lives in scripts\).
cd /d "%~dp0.."

rem Already running? Do not start a second copy (that fails with EADDRINUSE).
set "PID3000="
for /f "tokens=5" %%P in (%SystemRoot%\System32\netstat.exe -ano ^| findstr /R /C:":3000 .*LISTENING") do set "PID3000=%%P"
if defined PID3000 (
  echo The dashboard is already running on http://localhost:3000 ^(process %PID3000%^).
  echo Code changes appear on their own; just refresh the page.
  choice /C RO /N /T 10 /D O /M "Press R to restart it, or O to open it [opens in 10 s]: "
  if errorlevel 2 (
    start "" http://localhost:3000
    exit /b 0
  )
  echo Stopping process %PID3000% ...
  taskkill /PID %PID3000% /T /F >nul 2>&1
  timeout /t 2 /nobreak >nul
)

echo Starting the SecureOTA dashboard on http://localhost:3000 ...
echo Keep this window open. Press Ctrl+C to stop.
if not exist "node_modules\next\dist\bin\next" (
  echo Installing dependencies first...
  call npm install
) else (
  rem Reinstall when package-lock.json changed since the last install, e.g. after a pull.
  powershell -NoProfile -Command "if((Get-Item package-lock.json).LastWriteTime -gt (Get-Item node_modules\.package-lock.json -ErrorAction SilentlyContinue).LastWriteTime){ exit 1 }" >nul 2>&1
  if errorlevel 1 (
    echo Dependencies changed since the last install; updating them...
    call npm install
  )
)

rem Start the gateway too, unless it is already listening on 5000.
%SystemRoot%\System32\netstat.exe -ano | findstr /R /C:":5000 .*LISTENING" >nul
if errorlevel 1 (
  echo Opening the gateway in a second window...
  start "SecureOTA gateway" cmd /k call "%~dp0start-gateway.cmd"
) else (
  echo The gateway is already running on port 5000.
)
rem Start the USB flashing agent too. start-agent.cmd keeps a running agent of
rem this version and replaces an older one, so a code update reaches it.
echo Opening the USB agent in a third window...
start "SecureOTA USB agent" cmd /k call "%~dp0start-agent.cmd"
call npm run dev
pause
