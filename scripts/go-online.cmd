@echo off
setlocal EnableExtensions EnableDelayedExpansion
title SecureOTA online
rem Run from the repository root (this file lives in scripts\).
cd /d "%~dp0.."

rem ---------------------------------------------------------------------------
rem  SecureOTA on the internet (Windows). Double-click, or run:
rem    go-online.cmd          put it online (rebuilds with your latest code)
rem    go-online.cmd off      take it offline (data and keys are kept)
rem    go-online.cmd status   show what is running and whether it is public
rem
rem  Uses Docker Desktop + the Cloudflare tunnel already set up in this repo
rem  (deploy\cloudflared\config.yml + credentials.json, secrets in .env.docker):
rem    Dashboard  https://ota.nyx-ctf.tech
rem    Gateway    https://gw.nyx-ctf.tech   (ESP32 boards poll this one)
rem  No router ports are opened; cloudflared dials out to Cloudflare.
rem ---------------------------------------------------------------------------

set "COMPOSE=docker compose -f docker-compose.cloud.yml --env-file .env.docker -p secure_ota"
set "UI_URL=https://ota.nyx-ctf.tech"
set "GW_URL=https://gw.nyx-ctf.tech"

set "ACTION=%~1"
if "%ACTION%"=="" set "ACTION=on"
if /i "%ACTION%"=="on" goto :on
if /i "%ACTION%"=="off" goto :off
if /i "%ACTION%"=="status" goto :status
echo Unknown option "%ACTION%". Use: go-online.cmd [on^|off^|status]
goto :end

rem ===========================================================================
:on
if not exist ".env.docker" (
  echo Missing .env.docker - copy .env.example to .env.docker and fill it in first.
  goto :end
)
if not exist "deploy\cloudflared\credentials.json" (
  echo Missing deploy\cloudflared\credentials.json - see docs\guides\CLOUDFLARE_TUNNEL_SETUP.md.
  goto :end
)
call :ensure_docker || goto :end

rem Private keys must never be in git.
git ls-files | findstr /I /R "\.pem$ \.key$" >nul
if not errorlevel 1 (
  echo REFUSING to go online: private key files are tracked in git:
  git ls-files | findstr /I /R "\.pem$ \.key$"
  goto :end
)

rem Docker publishes ports 3000 and 5000. Local dev copies (start-dev.cmd)
rem hold them too, so they have to stop first.
call :free_port 3000 "local dashboard" || goto :end
call :free_port 5000 "local gateway" || goto :end

echo.
echo ==^> Building with your latest code and starting (first build takes a few minutes)...
%COMPOSE% up -d --build --remove-orphans
if errorlevel 1 (
  echo.
  echo Docker could not start the stack. The messages above say why.
  goto :end
)

echo.
echo ==^> Waiting for the tunnel and the services...
set /a tries=0
:wait_loop
set /a tries+=1
set "CODE="
for /f %%C in ('curl -s -m 15 -o NUL -w "%%{http_code}" %GW_URL%/healthz 2^>NUL') do set "CODE=%%C"
if "!CODE!"=="200" goto :online
if !tries! GEQ 36 goto :not_yet
timeout /t 5 /nobreak >nul
goto :wait_loop

:online
set "UICODE="
for /f %%C in ('curl -s -m 30 -o NUL -w "%%{http_code}" %UI_URL%/ 2^>NUL') do set "UICODE=%%C"
echo.
echo ===========================================================
echo   ONLINE
echo   Dashboard : %UI_URL%   (HTTP !UICODE!)
echo   Gateway   : %GW_URL%   (healthy)
echo.
echo   Also on this computer: http://localhost:3000
echo   Take it offline:       go-online.cmd off
echo ===========================================================
start "" %UI_URL%
goto :end

:not_yet
echo.
echo The containers are up but %GW_URL% is not answering yet.
echo Check the tunnel log:  docker logs secure_ota_cloudflared --tail 30
goto :status

rem ===========================================================================
:off
docker info >nul 2>&1
if errorlevel 1 (
  echo Docker is not running - nothing is online.
  goto :end
)
echo ==^> Taking SecureOTA offline (volumes with keys, releases and users are kept)...
%COMPOSE% down --remove-orphans
echo OFFLINE. Run start-dev.cmd to work locally again.
goto :end

rem ===========================================================================
:status
docker info >nul 2>&1
if errorlevel 1 (
  echo Docker is not running - nothing is online.
  goto :end
)
echo ==^> Containers
%COMPOSE% ps --format "table {{.Name}}\t{{.Status}}"
echo.
echo ==^> Public addresses
curl -s -m 20 -o NUL -w "gateway   %GW_URL%/healthz -> HTTP %%{http_code}\n" %GW_URL%/healthz
curl -s -m 30 -o NUL -w "dashboard %UI_URL%/        -> HTTP %%{http_code}\n" %UI_URL%/
goto :end

rem ===========================================================================
:ensure_docker
docker info >nul 2>&1
if not errorlevel 1 exit /b 0
where docker >nul 2>&1
if errorlevel 1 (
  echo Docker is not installed. Install Docker Desktop from https://www.docker.com/products/docker-desktop/
  exit /b 1
)
echo ==^> Starting Docker Desktop...
start "" "%ProgramFiles%\Docker\Docker\Docker Desktop.exe"
for /l %%I in (1,1,60) do (
  timeout /t 5 /nobreak >nul
  docker info >nul 2>&1 && exit /b 0
)
echo Docker did not start within 5 minutes.
exit /b 1

rem :free_port PORT "what"  -> stops a non-Docker process listening on PORT, after asking
:free_port
set "FP_PID="
for /f "tokens=5" %%P in ('%SystemRoot%\System32\netstat.exe -ano ^| findstr /R /C:":%~1 .*LISTENING"') do set "FP_PID=%%P"
if not defined FP_PID exit /b 0
for /f "tokens=1" %%N in ('tasklist /FI "PID eq !FP_PID!" /NH 2^>NUL') do set "FP_NAME=%%N"
echo !FP_NAME! | findstr /I "docker wslrelay com.docker vpnkit" >nul
if not errorlevel 1 exit /b 0
echo Port %~1 is in use by the %~2 (!FP_NAME!, process !FP_PID!).
choice /C YN /M "Stop it so the online version can use the port"
if errorlevel 2 (
  echo Leaving it running. Stop it yourself, then run go-online.cmd again.
  exit /b 1
)
taskkill /PID !FP_PID! /T /F >nul 2>&1
timeout /t 2 /nobreak >nul
exit /b 0

:end
echo.
pause
endlocal
