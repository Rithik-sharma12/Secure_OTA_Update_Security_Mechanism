#!/usr/bin/env bash
# SecureOTA control script: public deployment switch + USB/COM firmware flash.
#
#   Stack (Cloudflare Tunnel, CLOUD mode)
#     ./go-online.sh on            deploy publicly and verify
#     ./go-online.sh on --build    same, forcing an image rebuild first
#     ./go-online.sh off           take it offline (stops cloudflared + stack; data kept)
#     ./go-online.sh status        show what is running and whether it is public
#
#   Firmware (PlatformIO, from CODE/frimware_code)
#     ./go-online.sh ports                         list COM ports with a board attached
#     ./go-online.sh build   [-e ENV]              compile only; prints the .bin path
#     ./go-online.sh flash   [-e ENV] [-p COMx]    compile + flash over USB (auto-detects port)
#     ./go-online.sh monitor [-p COMx]             serial monitor at 115200 baud
#     ./go-online.sh agent                         run the local COM agent so the web dashboard
#                                                  can list/flash this computer's COM ports
#     ENV: esp32dev (default) | esp32s3 | esp32c3
#
# Volumes (signing keys, releases, dashboard users) are never removed by this
# script. Never run `docker compose down -v` against project secure_ota.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

COMPOSE_FILE=docker-compose.cloud.yml
ENV_FILE=.env.docker
PROJECT=secure_ota
GW_URL=https://gw.nyx-ctf.tech
UI_URL=https://ota.nyx-ctf.tech

FW_DIR=CODE/frimware_code
FW_CONFIG=$FW_DIR/esp32_ota_main/ota_config.h
# Where `pip install --user platformio` puts pio.exe (resolved lazily in ensure_pio)
PIO_BIN_DIR=

compose() { docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" -p "$PROJECT" "$@"; }
log()     { printf '\n==> %s\n' "$*"; }
usage()   { sed -n '2,17p' "$0"; exit "${1:-0}"; }

# ───────────────────────────── stack ──────────────────────────────────────

ensure_docker() {
  if ! docker info >/dev/null 2>&1; then
    log "Docker not running - starting Docker Desktop"
    powershell -NoProfile -Command 'Start-Process "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe"' \
      || { echo "could not start Docker Desktop" >&2; exit 1; }
    for _ in $(seq 1 60); do
      docker info >/dev/null 2>&1 && break
      sleep 5
    done
    docker info >/dev/null 2>&1 || { echo "Docker daemon did not come up in 5 min" >&2; exit 1; }
  fi
  echo "docker ready"
}

check_no_tracked_keys() {
  log "Checking for tracked key material"
  if tracked=$(git ls-files | grep -iE '\.pem$|\.key$'); then
    echo "REFUSING to deploy - private key files are tracked in git:" >&2
    echo "$tracked" >&2
    exit 1
  fi
  echo "none tracked"
}

show_status() {
  log "Containers"
  compose ps --format 'table {{.Name}}\t{{.Status}}' 2>/dev/null || echo "(none)"

  if docker inspect -f '{{.State.Running}}' secure_ota_gateway 2>/dev/null | grep -q true; then
    log "Effective gateway public URL"
    docker exec secure_ota_gateway python -c "from gateway.config import PUBLIC_BASE_URL; print(PUBLIC_BASE_URL)"
  fi

  local cf
  cf=$(docker inspect -f '{{.State.Health.Status}}' secure_ota_cloudflared 2>/dev/null | tr -d '\n')
  cf=${cf:-absent}
  log "Public exposure"
  if [ "$cf" = healthy ]; then
    echo "cloudflared: healthy - stack is PUBLIC"
    curl -s -m 20 -o /dev/null -w "gateway   $GW_URL/healthz -> HTTP %{http_code} (%{time_total}s)\n" "$GW_URL/healthz" || true
    curl -s -m 30 -o /dev/null -w "dashboard $UI_URL/        -> HTTP %{http_code} (%{time_total}s)\n" "$UI_URL/"      || true
  else
    echo "cloudflared: $cf - stack is NOT public"
  fi
}

cmd_on() {
  [ -f "$ENV_FILE" ] || { echo "missing $ENV_FILE" >&2; exit 1; }
  ensure_docker
  check_no_tracked_keys

  log "Deploying cloud mode"
  local build_flag=()
  [ "${1:-}" = "--build" ] && build_flag=(--build)
  compose up -d --remove-orphans "${build_flag[@]}"

  log "Waiting for cloudflared"
  local status=unknown
  for _ in $(seq 1 24); do
    status=$(docker inspect -f '{{.State.Health.Status}}' secure_ota_cloudflared 2>/dev/null || echo starting)
    [ "$status" = healthy ] && break
    sleep 5
  done
  echo "cloudflared: $status"
  [ "$status" = healthy ] || { docker logs secure_ota_cloudflared --tail 20; exit 1; }

  show_status
  cat <<EOF

ONLINE.
  Dashboard : $UI_URL   (test the web UI on http://localhost:3000 - the tunnel drops large responses)
  Gateway   : $GW_URL
  Offline   : ./go-online.sh off
EOF
}

cmd_off() {
  if ! docker info >/dev/null 2>&1; then
    echo "Docker is not running - nothing is deployed, already offline."
    exit 0
  fi
  log "Taking stack offline (volumes preserved)"
  compose down --remove-orphans
  show_status
  echo
  echo "OFFLINE."
}

cmd_status() {
  if ! docker info >/dev/null 2>&1; then
    echo "Docker is not running - nothing is deployed."
    exit 0
  fi
  show_status
}

# ───────────────────────────── firmware ───────────────────────────────────

ensure_pio() {
  if ! command -v pio >/dev/null 2>&1; then
    PIO_BIN_DIR=$(python -c "import sysconfig;print(sysconfig.get_path('scripts','nt_user'))" 2>/dev/null | tr -d '\r')
    if command -v cygpath >/dev/null 2>&1 && [ -n "$PIO_BIN_DIR" ]; then
      PIO_BIN_DIR=$(cygpath -u "$PIO_BIN_DIR")
    fi
    [ -n "$PIO_BIN_DIR" ] && [ -x "$PIO_BIN_DIR/pio.exe" ] && export PATH="$PIO_BIN_DIR:$PATH"
  fi
  if ! command -v pio >/dev/null 2>&1; then
    log "PlatformIO not found - installing (pip install --user platformio)"
    pip install --user platformio >/dev/null || { echo "pip install platformio failed" >&2; exit 1; }
    export PATH="$PIO_BIN_DIR:$PATH"
  fi
  command -v pio >/dev/null 2>&1 || { echo "pio still not on PATH after install" >&2; exit 1; }
}

ensure_fw_config() {
  if [ ! -f "$FW_CONFIG" ]; then
    cp "$FW_CONFIG.example" "$FW_CONFIG"
    cat >&2 <<EOF
Created $FW_CONFIG from the example.
Fill in Wi-Fi, DEVICE_ID, BACKEND_URL, BACKEND_API_KEY (and OTA_ROOT_CA for cloud
mode) before flashing. See the comments in that file.
EOF
    exit 1
  fi
  if grep -q CHANGE_ME "$FW_CONFIG"; then
    echo "REFUSING to flash - $FW_CONFIG still contains CHANGE_ME placeholders:" >&2
    grep -n CHANGE_ME "$FW_CONFIG" >&2
    exit 1
  fi
  # A cloud-mode build without a pinned root CA talks TLS to anyone.
  if grep -qE '^\s*#define\s+BACKEND_URL\s+"https://' "$FW_CONFIG" \
     && grep -qE 'OTA_ROOT_CA\[\]\s*PROGMEM\s*=\s*"";' "$FW_CONFIG"; then
    echo "WARNING: BACKEND_URL is https:// but OTA_ROOT_CA is empty - server certificate will NOT be verified." >&2
    echo "         python $FW_DIR/tools/fetch_root_ca.py <host> --out $FW_DIR/esp32_ota_main/root_ca.h" >&2
  fi
}

# Parse -e ENV / -p PORT from the remaining args into FW_ENV / FW_PORT.
parse_fw_args() {
  FW_ENV=esp32dev; FW_PORT=
  while [ $# -gt 0 ]; do
    case "$1" in
      -e|--env)  FW_ENV=$2;  shift 2 ;;
      -p|--port) FW_PORT=$2; shift 2 ;;
      *) echo "unknown option: $1" >&2; usage 1 ;;
    esac
  done
}

cmd_ports() {
  ensure_pio
  log "Serial ports"
  pio device list
}

cmd_build() {
  parse_fw_args "$@"
  ensure_pio
  ensure_fw_config
  log "Building firmware (env $FW_ENV)"
  ( cd "$FW_DIR" && pio run -e "$FW_ENV" )
  local out="$FW_DIR/.pio/build/$FW_ENV"
  merge_full_image "$FW_ENV" "$out"
  log "Binaries"
  ls -l "$out/firmware.bin" "$out/firmware-full.bin" 2>/dev/null
  cat <<EOF
firmware.bin       app image  -> publish on the Releases page (target $(grep -oE 'DEVICE_TYPE\s+"[^"]+"' "$FW_CONFIG" | grep -oE '"[^"]+"')),
                                 or web-flash at 0x10000
firmware-full.bin  merged     -> web-flash a blank board at 0x0 (Devices page, "Flash over USB")
EOF
}

# Merge bootloader + partition table + boot_app0 + app into one image at 0x0,
# so the browser flasher can bring up a blank board in a single write.
merge_full_image() {
  local env=$1 out=$2
  local chip=esp32
  case "$env" in esp32s3) chip=esp32s3 ;; esp32c3) chip=esp32c3 ;; esac
  # ESP32 classic puts the 2nd-stage bootloader at 0x1000; S3/C3 at 0x0.
  local boot_off=0x1000
  [ "$chip" != esp32 ] && boot_off=0x0
  local boot_app0
  boot_app0=$(ls -d "$HOME"/.platformio/packages/framework-arduinoespressif32*/tools/partitions/boot_app0.bin 2>/dev/null | head -1)
  local esptool="$HOME/.platformio/packages/tool-esptoolpy/esptool.py"
  if [ ! -f "$boot_app0" ] || [ ! -f "$esptool" ] || [ ! -f "$out/bootloader.bin" ]; then
    echo "skipping firmware-full.bin (bootloader/boot_app0/esptool not found)" >&2
    return 0
  fi
  python "$esptool" --chip "$chip" merge_bin -o "$out/firmware-full.bin" \
    --flash_mode dio --flash_size 4MB \
    "$boot_off" "$out/bootloader.bin" \
    0x8000     "$out/partitions.bin" \
    0xe000     "$boot_app0" \
    0x10000    "$out/firmware.bin" >/dev/null
}

cmd_flash() {
  parse_fw_args "$@"
  ensure_pio
  ensure_fw_config
  local port_flag=()
  if [ -n "$FW_PORT" ]; then
    port_flag=(--upload-port "$FW_PORT")
  else
    log "No -p given - PlatformIO will auto-detect the port"
    pio device list | grep -E '^COM|^/dev' || { echo "no serial device found - plug the board in (or pass -p COMx)" >&2; exit 1; }
  fi
  log "Building + flashing over USB (env $FW_ENV${FW_PORT:+, port $FW_PORT})"
  ( cd "$FW_DIR" && pio run -e "$FW_ENV" --target upload "${port_flag[@]}" )
  cat <<EOF

FLASHED. The device should now join Wi-Fi and heartbeat to BACKEND_URL within ~15 s.
  Watch it:  ./go-online.sh monitor${FW_PORT:+ -p $FW_PORT}
  Check it:  curl -s http://localhost:5000/api/dashboard | python -m json.tool | grep -A3 '"id"'
If it stays in download mode: hold BOOT, tap RESET, release BOOT, rerun.
EOF
}

cmd_agent() {
  python -c "import serial" 2>/dev/null || pip install --user pyserial >/dev/null
  python -c "import esptool" 2>/dev/null || pip install --user esptool >/dev/null
  log "Starting the SecureOTA local agent (Ctrl+C to stop)"
  exec python Secure_OTA_Update_Security_Mechanism/CODE/agent/secureota_agent.py "$@"
}

cmd_monitor() {
  parse_fw_args "$@"
  ensure_pio
  ( cd "$FW_DIR" && pio device monitor -b 115200 ${FW_PORT:+-p "$FW_PORT"} )
}

# ───────────────────────────── dispatch ───────────────────────────────────

case "${1:-}" in
  on)      shift; cmd_on "$@" ;;
  off)     cmd_off ;;
  status)  cmd_status ;;
  ports)   cmd_ports ;;
  build)   shift; cmd_build "$@" ;;
  flash)   shift; cmd_flash "$@" ;;
  monitor) shift; cmd_monitor "$@" ;;
  agent)   shift; cmd_agent "$@" ;;
  -h|--help|"") usage 0 ;;
  *)       echo "unknown command: $1" >&2; usage 1 ;;
esac
