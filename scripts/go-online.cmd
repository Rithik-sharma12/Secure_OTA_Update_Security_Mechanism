@echo off
setlocal EnableExtensions EnableDelayedExpansion
title SecureOTA online
rem Run from the repository root (this file lives in scripts\).
cd /d "%~dp0.."

rem ---------------------------------------------------------------------------
rem  SecureOTA on the internet (Windows, Docker Desktop + Cloudflare Tunnel).
rem
rem    scripts\go-online.cmd          rebuild from the code in this folder (including
rem                                   uncommitted changes) and restart every container
rem    scripts\go-online.cmd update   git pull first, then the same
rem    scripts\go-online.cmd status   what is running, and is it reachable
rem    scripts\go-online.cmd logs     last lines of every container log
rem    scripts\go-online.cmd off      take it offline (data and keys are kept)
rem
rem    Dashboard  https://ota.nyx-ctf.tech
rem    Gateway    https://gw.nyx-ctf.tech   (ESP32 boards poll this one)
rem
rem  Each step is checked in order: local containers healthy, then the tunnel
rem  registered with Cloudflare, then the public address answering. When a
rem  step fails the script says which one and why, and writes everything to
rem  deploy\last-run.log (no secrets) so the problem can be read later.
rem
rem  Cloudflare error 1033 means "no cloudflared connector is running for this
rem  tunnel": the tunnel container is not up, or cannot reach Cloudflare.
rem ---------------------------------------------------------------------------

set "COMPOSE=docker compose -f docker-compose.cloud.yml --env-file .env.docker -p secure_ota"
set "UI_URL=https://ota.nyx-ctf.tech"
set "GW_URL=https://gw.nyx-ctf.tech"
set "TUNNEL=secure_ota_cloudflared"
set "LOG=deploy\last-run.log"
rem The console shows local firmware builds with their path on this computer.
set "SECUREOTA_REPO_DIR=%CD%"
if not exist "firmware\dist" mkdir "firmware\dist"

set "PULL="
set "ACTION=%~1"
if "%ACTION%"=="" set "ACTION=on"
if /i "%ACTION%"=="on" goto :on
if /i "%ACTION%"=="sync" goto :on
if /i "%ACTION%"=="update" set "PULL=1"
if /i "%ACTION%"=="update" goto :on
if /i "%ACTION%"=="pull" set "PULL=1"
if /i "%ACTION%"=="pull" goto :on
if /i "%ACTION%"=="status" goto :status
if /i "%ACTION%"=="logs" goto :logs
if /i "%ACTION%"=="off" goto :off
echo Unknown option "%ACTION%". Use: go-online.cmd [on^|update^|status^|logs^|off]
goto :end

rem ===========================================================================
:on
echo SecureOTA go-online %DATE% %TIME%> "%LOG%"

echo ==^> 1/8 Checking the configuration
if not exist ".env.docker" (
  call :fail "Missing .env.docker. Copy .env.example to .env.docker and fill it in."
  goto :end
)
if not exist "deploy\cloudflared\config.yml" (
  call :fail "Missing deploy\cloudflared\config.yml (the tunnel's ingress rules)."
  goto :end
)
if not exist "deploy\cloudflared\credentials.json" (
  call :fail "Missing deploy\cloudflared\credentials.json. Download it from the Cloudflare dashboard (Zero Trust, Networks, Tunnels) or run: cloudflared tunnel create, see docs\guides\CLOUDFLARE_TUNNEL_SETUP.md."
  goto :end
)
rem The tunnel id in config.yml must be the one the credentials belong to.
powershell -NoProfile -Command "$c=(Get-Content 'deploy\cloudflared\credentials.json' -Raw | ConvertFrom-Json).TunnelID; $m=Select-String -Path 'deploy\cloudflared\config.yml' -Pattern '^tunnel:\s*(\S+)'; if(-not $m -or $m.Matches[0].Groups[1].Value -ne $c){ exit 1 }" >nul 2>&1
if errorlevel 1 (
  call :fail "deploy\cloudflared\config.yml names a different tunnel than credentials.json. Put the TunnelID from credentials.json on the 'tunnel:' line."
  goto :end
)
git ls-files 2>nul | findstr /I /R "\.pem$ \.key$ credentials\.json$" >nul
if not errorlevel 1 (
  call :fail "Private keys or tunnel credentials are tracked in git. Remove them from git first: git rm --cached FILE"
  goto :end
)
echo     ok

echo ==^> 2/8 Taking the latest code
set "GITREV=unknown"
set "GITBRANCH=?"
set /a DIRTY=0
for /f %%R in ('git rev-parse --short HEAD 2^>NUL') do set "GITREV=%%R"
for /f %%B in ('git rev-parse --abbrev-ref HEAD 2^>NUL') do set "GITBRANCH=%%B"
for /f %%L in ('git status --porcelain --untracked-files=no 2^>NUL ^| find /c /v ""') do set /a DIRTY=%%L
if "%PULL%"=="1" (
  if !DIRTY! GTR 0 (
    call :fail "There are !DIRTY! uncommitted changes here. Commit or stash them before 'go-online.cmd update', or run plain go-online.cmd to deploy them as they are."
    goto :end
  )
  echo     pulling the latest commits from GitHub...
  git pull --ff-only
  if errorlevel 1 (
    call :fail "git pull did not complete (see above). Resolve it, then run go-online.cmd update again."
    goto :end
  )
  for /f %%R in ('git rev-parse --short HEAD 2^>NUL') do set "GITREV=%%R"
)
echo     branch !GITBRANCH!, commit !GITREV!
if !DIRTY! GTR 0 echo     plus !DIRTY! uncommitted change^(s^) in this folder, which are included
>>"%LOG%" echo code: branch !GITBRANCH! commit !GITREV! uncommitted !DIRTY!

echo ==^> 3/8 Checking the firmware images the dashboard flashes
call :check_firmware

echo ==^> 4/8 Starting Docker
call :ensure_docker || goto :end
echo     ok

echo ==^> 5/8 Freeing ports 3000 and 5000
rem start-dev.cmd runs a local dashboard and gateway on the same ports.
call :free_port 3000 "local dashboard" || goto :end
call :free_port 5000 "local gateway" || goto :end
echo     ok

echo ==^> 6/8 Building the images from this code and restarting the containers
echo     (the first build takes several minutes; later ones reuse unchanged layers)
%COMPOSE% build
if errorlevel 1 (
  call :fail "Docker could not build the images. The messages above say why."
  call :collect
  goto :end
)
rem The project was renamed from SentinelOTA: its Docker volumes are now
rem secureota_*. Copy the old ones once so keys, releases and users carry over.
call :migrate_volume sentinel_gateway_keys secureota_gateway_keys || goto :end
call :migrate_volume sentinel_gateway_cache secureota_gateway_cache || goto :end
call :migrate_volume sentinel_ota_ide_db secureota_ide_db || goto :end
rem --force-recreate: every container restarts on the new image and the
rem current .env.docker, even when Docker thinks nothing changed.
%COMPOSE% up -d --force-recreate --remove-orphans
if errorlevel 1 (
  call :fail "Docker could not start the stack. The messages above say why."
  call :collect
  goto :end
)
rem Old image layers left behind by the rebuild; volumes (keys, releases, users) are untouched.
docker image prune -f >nul 2>&1
rem The network from before the rename, if nothing uses it any more.
docker network rm sentinel_network >nul 2>&1

echo ==^> 7/8 Waiting for the dashboard and gateway on this computer
call :wait_http "http://localhost:5000/healthz" 36 "gateway" || (
  call :fail "The gateway container did not become healthy."
  call :collect
  goto :end
)
call :wait_http "http://localhost:3000/api/health/live" 60 "dashboard" || (
  call :fail "The dashboard container did not become healthy."
  call :collect
  goto :end
)
echo     ok

echo ==^> 8/8 Waiting for the Cloudflare tunnel
set /a tries=0
:tunnel_loop
set /a tries+=1
docker logs %TUNNEL% 2>&1 | findstr /C:"Registered tunnel connection" >nul
if not errorlevel 1 goto :tunnel_up
if !tries! GEQ 30 (
  call :explain_tunnel
  call :collect
  goto :end
)
timeout /t 2 /nobreak >nul
goto :tunnel_loop

:tunnel_up
echo     tunnel connected
call :wait_http "%GW_URL%/healthz" 20 "public gateway" || (
  call :fail "The tunnel is connected but %GW_URL% does not answer. In the Cloudflare dashboard, DNS for ota and gw must be proxied CNAME records to the tunnel id followed by .cfargotunnel.com. Fix it with: cloudflared tunnel route dns TUNNEL-ID gw.nyx-ctf.tech"
  call :collect
  goto :end
)
set "UICODE="
for /f %%C in ('curl -s -m 30 -o NUL -w "%%{http_code}" %UI_URL%/login 2^>NUL') do set "UICODE=%%C"
echo.
echo ===========================================================
echo   ONLINE
echo   Dashboard : %UI_URL%   (HTTP !UICODE!)
echo   Gateway   : %GW_URL%   (healthy)
echo   Code      : !GITBRANCH! @ !GITREV!
echo.
echo   Also on this computer: http://localhost:3000
echo   Status / logs:         scripts\go-online.cmd status ^| logs
echo   Take it offline:       scripts\go-online.cmd off
echo ===========================================================
call :check_agent
echo ONLINE dashboard HTTP !UICODE! commit !GITREV!>> "%LOG%"
call :collect quiet
start "" %UI_URL%
goto :end

rem ===========================================================================
:status
docker info >nul 2>&1
if errorlevel 1 (
  echo Docker is not running, so nothing is online.
  goto :end
)
echo ==^> Code in this folder
for /f %%R in ('git rev-parse --short HEAD 2^>NUL') do echo     commit %%R
findstr /B /C:"ONLINE" "%LOG%" 2>NUL
echo.
echo ==^> Containers
%COMPOSE% ps --format "table {{.Name}}\t{{.Status}}"
echo.
echo ==^> Tunnel
docker logs %TUNNEL% 2>&1 | findstr /C:"Registered tunnel connection" >nul && (echo     connected to Cloudflare) || (echo     NOT connected: see scripts\go-online.cmd logs)
echo.
echo ==^> Addresses
curl -s -m 10 -o NUL -w "local gateway     http://localhost:5000/healthz          HTTP %%{http_code}  %%{time_total}s\n" http://localhost:5000/healthz
curl -s -m 10 -o NUL -w "local dashboard   http://localhost:3000/api/health/live  HTTP %%{http_code}  %%{time_total}s\n" http://localhost:3000/api/health/live
curl -s -m 20 -o NUL -w "public gateway    %GW_URL%/healthz       HTTP %%{http_code}  %%{time_total}s\n" %GW_URL%/healthz
curl -s -m 30 -o NUL -w "public dashboard  %UI_URL%/login         HTTP %%{http_code}  %%{time_total}s\n" %UI_URL%/login
goto :end

:logs
call :collect
type "%LOG%"
goto :end

rem ===========================================================================
:off
docker info >nul 2>&1
if errorlevel 1 (
  echo Docker is not running, so nothing is online.
  goto :end
)
echo ==^> Taking SecureOTA offline (volumes with keys, releases and users are kept)...
%COMPOSE% down --remove-orphans
echo OFFLINE. Run scripts\start-dev.cmd to work locally again.
goto :end

rem ===========================================================================
rem :check_firmware -> is firmware\dist older than the firmware code? offer to rebuild it
:check_firmware
powershell -NoProfile -Command "$b='firmware\dist\esp32dev\build-info.json'; if(-not (Test-Path $b)){ exit 2 }; $t=(Get-Item $b).LastWriteTime; $n=Get-ChildItem -Recurse -File -Path firmware\esp32_ota_main,firmware\lib -Include *.ino,*.c,*.cpp,*.h -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $t } | Select-Object -First 1; if($n){ exit 1 }; exit 0" >nul 2>&1
set "FWRC=%ERRORLEVEL%"
if "%FWRC%"=="0" (
  echo     firmware\dist is up to date with the firmware code
  exit /b 0
)
if "%FWRC%"=="2" (echo     no firmware has been built yet) else (echo     the firmware code changed after the last build)
choice /C YN /T 20 /D N /M "    Build it now (a few minutes; N keeps the older image)"
if errorlevel 2 (
  echo     skipped: run scripts\build-firmware.cmd later; the dashboard picks the new image up without a restart
  exit /b 0
)
set "PY=%CD%\.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"
"%PY%" firmware\tools\build_firmware.py
if errorlevel 1 (
  echo     the firmware build failed; going online anyway with the previous image
) else (
  echo     firmware built
)
exit /b 0

rem :migrate_volume OLD NEW -> one-time copy of a renamed Docker volume (the old one is kept)
:migrate_volume
docker volume inspect %~2 >nul 2>&1
if not errorlevel 1 exit /b 0
docker volume inspect %~1 >nul 2>&1
if errorlevel 1 exit /b 0
echo     copying Docker volume %~1 to %~2 ^(one time, after the rename to SecureOTA^)
rem Stop the containers so nothing writes while the copy runs; they are recreated next.
%COMPOSE% stop >nul 2>&1
docker stop secure_ota_gateway secure_ota_ide >nul 2>&1
docker volume create %~2 >nul
docker run --rm -v %~1:/from:ro -v %~2:/to alpine sh -c "cp -a /from/. /to/"
if errorlevel 1 (
  docker volume rm %~2 >nul 2>&1
  call :fail "Could not copy Docker volume %~1 to %~2. The old volume is untouched; run go-online.cmd again."
  exit /b 1
)
exit /b 0

rem :check_agent -> warn when the USB agent running on this PC is older than this code
:check_agent
powershell -NoProfile -Command "try { $r=Invoke-RestMethod -TimeoutSec 3 http://127.0.0.1:17317/health; $m=Select-String -Path 'apps\agent\secureota_agent.py' -Pattern 'AGENT_VERSION = .(\d+\.\d+\.\d+).'; $f=$m.Matches[0].Groups[1].Value; if($r.version -ne $f){ Write-Output ('  USB agent v'+$r.version+' is running but this code has v'+$f+'. Restart it: scripts\start-agent.cmd') } } catch {}"
exit /b 0

rem :wait_http URL TRIES NAME -> waits TRIES x 5 s for HTTP 200
:wait_http
set /a wt=0
:wait_http_loop
set /a wt+=1
set "WCODE="
for /f %%C in ('curl -s -m 10 -o NUL -w "%%{http_code}" %~1 2^>NUL') do set "WCODE=%%C"
if "!WCODE!"=="200" exit /b 0
if !wt! GEQ %~2 (
  echo     %~3 at %~1 answered HTTP !WCODE! after waiting
  exit /b 1
)
timeout /t 5 /nobreak >nul
goto :wait_http_loop

rem :explain_tunnel -> reads the cloudflared log and says what is wrong
:explain_tunnel
docker ps --format "{{.Names}}" | findstr /X "%TUNNEL%" >nul
if errorlevel 1 (
  call :fail "The tunnel container is not running, which is exactly what Cloudflare error 1033 means."
  exit /b 0
)
docker logs %TUNNEL% 2>&1 | findstr /I /C:"Unauthorized" /C:"invalid credentials" /C:"tunnel not found" /C:"Tunnel not found" >nul
if not errorlevel 1 (
  call :fail "Cloudflare rejected the tunnel credentials: the tunnel was deleted or credentials.json is from another tunnel. Download fresh credentials for this tunnel into deploy\cloudflared\credentials.json."
  exit /b 0
)
docker logs %TUNNEL% 2>&1 | findstr /I /C:"failed to dial" /C:"timeout" /C:"no such host" /C:"connection refused" >nul
if not errorlevel 1 (
  call :fail "cloudflared cannot reach Cloudflare from this network (outbound port 7844 blocked, VPN, or no internet). It already uses HTTP/2 over TCP; check the firewall or VPN."
  exit /b 0
)
call :fail "The tunnel did not register within a minute. Its log is below and in %LOG%."
docker logs %TUNNEL% --tail 25 2>&1
exit /b 0

rem :collect [quiet] -> container status and recent logs into %LOG% (no secrets)
:collect
>>"%LOG%" echo.
>>"%LOG%" echo ==== containers
%COMPOSE% ps --format "table {{.Name}}\t{{.Status}}" >> "%LOG%" 2>&1
for %%S in (secure_ota_cloudflared secure_ota_ide secure_ota_gateway) do (
  >>"%LOG%" echo.
  >>"%LOG%" echo ==== %%S
  docker logs %%S --tail 40 >> "%LOG%" 2>&1
)
if /i not "%~1"=="quiet" echo     details written to %LOG%
exit /b 0

rem :fail "message"
:fail
echo.
echo   PROBLEM: %~1
echo.
>>"%LOG%" echo PROBLEM: %~1
exit /b 0

:ensure_docker
docker info >nul 2>&1
if not errorlevel 1 exit /b 0
where docker >nul 2>&1
if errorlevel 1 (
  call :fail "Docker is not installed. Install Docker Desktop from https://www.docker.com/products/docker-desktop/"
  exit /b 1
)
echo     starting Docker Desktop...
start "" "%ProgramFiles%\Docker\Docker\Docker Desktop.exe"
for /l %%I in (1,1,60) do (
  timeout /t 5 /nobreak >nul
  docker info >nul 2>&1 && exit /b 0
)
call :fail "Docker did not start within 5 minutes."
exit /b 1

rem :free_port PORT "what" -> stops a non-Docker process listening on PORT, after asking
:free_port
set "FP_PID="
for /f "tokens=5" %%P in ('%SystemRoot%\System32\netstat.exe -ano ^| findstr /R /C:":%~1 .*LISTENING"') do set "FP_PID=%%P"
if not defined FP_PID exit /b 0
set "FP_NAME="
for /f "tokens=1" %%N in ('tasklist /FI "PID eq !FP_PID!" /NH 2^>NUL') do set "FP_NAME=%%N"
echo !FP_NAME! | findstr /I "docker wslrelay com.docker vpnkit" >nul
if not errorlevel 1 exit /b 0
echo     port %~1 is used by the %~2 (!FP_NAME!, process !FP_PID!)
choice /C YN /M "    Stop it so the online version can use the port"
if errorlevel 2 (
  call :fail "Port %~1 is still in use. Close the start-dev.cmd windows, then run go-online.cmd again."
  exit /b 1
)
taskkill /PID !FP_PID! /T /F >nul 2>&1
timeout /t 2 /nobreak >nul
exit /b 0

:end
echo.
pause
endlocal
