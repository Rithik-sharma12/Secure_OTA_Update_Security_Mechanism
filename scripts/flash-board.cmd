@echo off
rem Flash the SecureOTA firmware over USB, like the Arduino IDE's Upload button.
rem   scripts\flash-board.cmd                 find the board and flash firmware-full.bin
rem   scripts\flash-board.cmd --port COM5     use this port
rem   scripts\flash-board.cmd --erase         wipe the whole chip first
rem   scripts\flash-board.cmd --list          list serial ports
rem Build the image first with scripts\build-firmware.cmd.
title SecureOTA flash board
cd /d "%~dp0.."

set "PY=%CD%\.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"
"%PY%" --version >nul 2>&1
if errorlevel 1 (
  echo Python 3 is required. Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH".
  pause
  exit /b 1
)

"%PY%" firmware\tools\flash_board.py %*
set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="0" (
  echo Done. Next: dashboard, Devices, "Set up a new board" and tick "already runs SecureOTA firmware".
) else (
  echo Flashing did not finish. Read the messages above.
)
pause
exit /b %RC%
