@echo off
rem Build the SecureOTA ESP32 firmware on Windows.
rem   scripts\build-firmware.cmd            ESP32 DevKit (esp32dev)
rem   scripts\build-firmware.cmd esp32s3    ESP32-S3 (or esp32c3)
rem Output: firmware\dist\<env>\firmware-full.bin (flash at 0x0) and firmware.bin (publish).
title SecureOTA firmware build
rem Run from the repository root (this file lives in scripts\).
cd /d "%~dp0.."

set "PY=%CD%\.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"
"%PY%" --version >nul 2>&1
if errorlevel 1 (
  echo Python 3 is required. Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH".
  pause
  exit /b 1
)

"%PY%" firmware\tools\build_firmware.py %*
set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="0" (
  echo Next: open the console, Devices, "Flash over USB", choose firmware\dist\esp32dev\firmware-full.bin.
) else (
  echo The build failed. Read the messages above.
)
pause
exit /b %RC%
