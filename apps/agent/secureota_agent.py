#!/usr/bin/env python3
"""
SecureOTA local agent - gives the web dashboard access to this computer's COM ports.

The dashboard is served from the cloud and cannot see USB devices on the
machine viewing it. This agent runs on that machine, listens on loopback only,
and the dashboard page talks to it directly from the browser:

    GET  /health                       agent identity and version
    GET  /ports                        connected serial ports (COM7, VID/PID, chip)
    POST /flash                        multipart: file, port, address, [baud], [erase]
    GET  /jobs/<id>                    flash job status, progress, log tail
    GET  /monitor?port=COM7&baud=115200  Server-Sent Events stream of serial output
    GET  /device-info?port=COM7        ask SecureOTA firmware (>= 2.5.0) who it is
    POST /provision                    JSON: port, config{ssid, password, backend_url,
                                       device_token, device_id, ...} -> written to
                                       the board's NVS over USB, board reboots

Security: only browser origins in ALLOWED_ORIGINS may call it (the browser
guarantees the Origin header), and an optional shared token can be required
with --token. It binds 127.0.0.1 and never accepts remote connections.

    python secureota_agent.py                 # port 17317 (installs pyserial/esptool on first run)
    python secureota_agent.py --token abc123  # require X-Agent-Token: abc123
"""
from __future__ import annotations

import argparse
import json
from email.parser import BytesParser
from email.policy import HTTP as EMAIL_HTTP_POLICY
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

def _ensure(module: str, package: str) -> None:
    """Install a missing dependency on first run so the user only needs Python."""
    try:
        __import__(module)
    except ImportError:
        print(f"Installing {package} (first run only)...")
        # --user is refused inside a virtual environment (such as the
        # project's .venv), and not needed there.
        in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
        flags = ["--quiet"] if in_venv else ["--user", "--quiet"]
        subprocess.check_call([sys.executable, "-m", "pip", "install", *flags, package])


_ensure("serial", "pyserial")
_ensure("esptool", "esptool")

import serial  # noqa: E402
from serial.tools import list_ports  # noqa: E402

AGENT_VERSION = "1.4.0"
DEFAULT_PORT = 17317
ALLOWED_ORIGINS = {
    "https://ota.nyx-ctf.tech",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
}
# A console served from this same computer, on any port. Remote sites can
# never present these origins: the browser sets the Origin header.
LOCAL_ORIGIN_RE = re.compile(r"^https?://(localhost|127\.0\.0\.1|\[::1\])(:\d{1,5})?$")
for _extra in (os.environ.get("SECUREOTA_AGENT_ORIGINS") or "").split(","):
    if _extra.strip():
        ALLOWED_ORIGINS.add(_extra.strip().rstrip("/"))


def origin_allowed(origin: str | None) -> bool:
    return bool(origin) and (origin in ALLOWED_ORIGINS or bool(LOCAL_ORIGIN_RE.match(origin or "")))
MAX_LOG_LINES = 400
# Manual download mode: esptool tries to sync this many times without resetting
# (about one attempt per second), so the person has time for BOOT + EN.
MANUAL_BOOT_SECONDS = 40
MANUAL_BOOT_ATTEMPTS = 40
PORT_NAME_RE = re.compile(r"^(COM\d+|/dev/[\w.\-/]+)$")
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{1,8}$")

KNOWN_CHIPS = {
    (0x10C4, 0xEA60): "Silicon Labs CP210x",
    (0x1A86, 0x7523): "WCH CH340",
    (0x1A86, 0x55D4): "WCH CH9102",
    (0x1A86, 0x5523): "WCH CH341",
    (0x0403, 0x6001): "FTDI FT232R",
    (0x0403, 0x6015): "FTDI FT231X",
    (0x303A, 0x1001): "Espressif USB-JTAG/serial",
}

# ------------------------------------------------------------------ esptool

def find_esptool() -> list[str] | None:
    """Command prefix that runs esptool, preferring the installed module."""
    try:
        import esptool  # noqa: F401
        return [sys.executable, "-m", "esptool"]
    except ImportError:
        pass
    candidates = [
        Path.home() / ".platformio" / "packages" / "tool-esptoolpy" / "esptool.py",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return [sys.executable, str(candidate)]
    exe = shutil.which("esptool") or shutil.which("esptool.py")
    return [exe] if exe else None


ESPTOOL = find_esptool()

# ------------------------------------------------------------------ ports

def describe_ports() -> list[dict]:
    result = []
    for port in list_ports.comports():
        chip = KNOWN_CHIPS.get((port.vid or 0, port.pid or 0))
        text = f"{port.description or ''} {port.hwid or ''}".lower()
        bluetooth = "bluetooth" in text or "bthenum" in text
        result.append({
            "path": port.device,
            "description": chip or port.description or "USB serial device",
            "manufacturer": port.manufacturer,
            "serialNumber": port.serial_number,
            "vendorId": f"{port.vid:04X}" if port.vid else None,
            "productId": f"{port.pid:04X}" if port.pid else None,
            "hwid": port.hwid,
            # A USB-serial bridge ESP boards use; the dashboard selects it first.
            "recommended": bool(chip) and not bluetooth,
            "bluetooth": bluetooth,
        })
    result.sort(key=lambda p: (not p["recommended"], [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", p["path"])]))
    return result


BUSY_PORT_HINT = (
    "Close the program using it - Arduino IDE Serial Monitor or Plotter, PlatformIO / VS Code serial monitor, "
    "PuTTY, the dashboard Serial Monitor, or a browser tab that opened the port for flashing - then retry."
)


def port_open_error(port: str) -> str | None:
    """None when the port can be opened; otherwise a sentence saying why not."""
    try:
        probe = serial.Serial()
        probe.port, probe.baudrate = port, 115200
        probe.dtr = probe.rts = False  # looking must not reset the board
        probe.open()
        probe.close()
        return None
    except serial.SerialException as exc:
        text = str(exc)
        if "FileNotFoundError" in text or "cannot find" in text.lower() or "No such file" in text:
            return f"{port} is not connected any more. Plug the board in again and pick its port."
        return f"{port} is in use by another program. {BUSY_PORT_HINT}"

# ------------------------------------------------------------------ multipart

def parse_multipart(content_type: str, body: bytes) -> dict[str, str | bytes]:
    """Minimal multipart/form-data parser (the cgi module is gone in 3.13+).

    Text fields come back as str, file fields as bytes.
    """
    message = BytesParser(policy=EMAIL_HTTP_POLICY).parsebytes(
        b"Content-Type: " + content_type.encode() + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
    )
    fields: dict[str, str | bytes] = {}
    if not message.is_multipart():
        return fields
    for part in message.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        payload = part.get_payload(decode=True) or b""
        if part.get_filename():
            fields[name] = payload
        else:
            fields[name] = payload.decode("utf-8", "replace")
    return fields

# ------------------------------------------------------------------ flash jobs

class FlashJob:
    def __init__(self, port: str, address: str, image: Path, baud: int, erase: bool, manual_boot: bool = False):
        self.id = uuid.uuid4().hex[:12]
        self.port, self.address, self.image, self.baud, self.erase = port, address, image, baud, erase
        self.manual_boot = manual_boot
        # While > 0 the board is expected to be put in download mode by hand.
        self.manual_until: float = 0.0
        self.status = "queued"       # queued | running | success | failed
        self.progress = 0
        self.error: str | None = None
        self.log: deque[str] = deque(maxlen=MAX_LOG_LINES)
        self.started = time.time()
        self.finished: float | None = None
        self.chip: str | None = None

    def to_dict(self, since: int = 0) -> dict:
        lines = list(self.log)
        return {
            "id": self.id, "status": self.status, "progress": self.progress,
            "error": self.error, "chip": self.chip, "port": self.port, "address": self.address,
            "log": lines[since:], "logLength": len(lines),
            "elapsed": round((self.finished or time.time()) - self.started, 1),
            "manualBootSeconds": max(0, round(self.manual_until - time.time())) if self.manual_until else 0,
        }

    def _esptool(self, before: str, attempts: int) -> int:
        """Run one esptool write. Returns its exit code; output goes to the job log."""
        cmd = ESPTOOL + [
            "--chip", "auto", "--port", self.port, "--baud", str(self.baud),
            "--before", before, "--after", "hard_reset", "--connect-attempts", str(attempts),
            "write_flash", "-z", "--flash_mode", "keep", "--flash_size", "keep",
        ]
        if self.erase:
            cmd.append("--erase-all")
        cmd += [self.address, str(self.image)]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        assert proc.stdout
        buffer = ""
        while True:
            ch = proc.stdout.read(1)
            if not ch:
                break
            if ch in "\r\n":
                line = buffer.strip()
                buffer = ""
                # Tool chatter that means nothing to the person at the board.
                if not line or line.startswith("WARNING: Deprecated") or line.startswith("Serial port "):
                    continue
                self.log.append(line)
                # esptool 4: "Writing at 0x00010000... (25 %)"
                # esptool 5: "Writing at 0x00010000 [====>    ]  25.3% 49152/209931 bytes..."
                m = re.search(r"\((\d{1,3})\s*%\)", line) or re.search(r"(\d{1,3})(?:\.\d+)?\s*%", line)
                if m and line.lower().startswith(("writing", "wrote")):
                    self.progress = min(100, int(m.group(1)))
                    self.manual_until = 0.0
                # esptool 4: "Chip is ESP32-D0WD-V3 (revision v3.1)"; 5: "Chip type: ESP32-D0WD-V3 ..."
                m = re.search(r"Chip (?:is|type:)\s*(.+)$", line)
                if m:
                    self.chip = m.group(1).strip()
                    self.manual_until = 0.0
            else:
                buffer += ch
        proc.wait()
        return proc.returncode

    def _connected(self) -> bool:
        text = "\n".join(self.log)
        return self.progress > 0 or bool(self.chip) or "Writing at" in text

    def _data_dropped(self) -> bool:
        text = "\n".join(self.log)
        return any(token in text for token in (
            "Serial data stream stopped", "Timed out waiting for packet", "Packet content transfer stopped",
            "checksum error", "Possible serial noise", "MD5 of file does not match",
        ))

    def _connect_failed(self) -> bool:
        text = "\n".join(self.log)
        return any(token in text for token in (
            "Failed to connect", "Wrong boot mode", "No serial data received", "Invalid head of packet",
        ))

    def _diagnosis(self) -> str:
        text = "\n".join(self.log)
        steps = "Press and hold BOOT (IO0), press and release EN (RST), then release BOOT."
        if "waiting for download" in text:
            return ("The board is in download mode but does not answer. Close other serial tools, "
                    "try another USB cable or port, then retry.")
        m = re.search(r"Wrong boot mode detected \((0x[0-9a-fA-F]+)\)", text)
        if m:
            return (f"The board never entered download mode: it reset but started its normal firmware "
                    f"(boot mode {m.group(1)}), so IO0 was not held low. {steps}")
        return ("The board never entered download mode and printed nothing. Check the COM port, that the USB "
                f"cable carries data and that the CP210x / CH340 driver is installed. {steps}")

    def run(self):
        self.status = "running"
        if not ESPTOOL:
            self.status, self.error = "failed", "esptool not found - pip install esptool"
            self.finished = time.time()
            return
        try:
            # Fail fast and plainly when another program holds the port; esptool
            # would otherwise report it as a board that does not answer.
            busy = port_open_error(self.port)
            if busy:
                self.status, self.error = "failed", busy
                self.log.append(f"[agent] {busy}")
                return
            code = 1
            if not self.manual_boot:
                self.log.append("[agent] resetting the board into download mode (automatic)")
                code = self._esptool("default_reset", 8)
            if code != 0 and (self.manual_boot or (self._connect_failed() and self.progress == 0)):
                # Boards without the auto-download circuit, or adapters whose
                # DTR/RTS do not reach EN/IO0: let the person do it by hand.
                window = MANUAL_BOOT_SECONDS
                self.log.append(f"[agent] waiting {window} s for manual download mode: hold BOOT, "
                                "press and release EN (RST), release BOOT")
                self.manual_until = time.time() + window
                code = self._esptool("no_reset", MANUAL_BOOT_ATTEMPTS)
                self.manual_until = 0.0
                if code == 0:
                    self.log.append("[agent] done. If the board does not start, press EN (RST) once.")
            # Connected, then the transfer broke: what the Arduino IDE answers
            # with "try a lower upload speed". Retry once at 115200.
            if code != 0 and self._connected() and self._data_dropped() and self.baud > 115200:
                self.log.append(f"[agent] the transfer broke at {self.baud} baud; retrying at 115200 (slower, more tolerant)")
                self.baud, self.progress = 115200, 0
                code = self._esptool("no_reset" if self.manual_boot else "default_reset", 8)
            if code == 0:
                self.status, self.progress = "success", 100
            else:
                self.status = "failed"
                if self._connect_failed() and self.progress == 0:
                    self.error = self._diagnosis()
                else:
                    tail = [l for l in self.log if "error" in l.lower() or "failed" in l.lower()]
                    self.error = tail[-1] if tail else f"esptool exited with code {code}"
        except Exception as exc:  # noqa: BLE001
            self.status, self.error = "failed", str(exc)
        finally:
            self.manual_until = 0.0
            self.finished = time.time()
            try:
                self.image.unlink()
            except OSError:
                pass


JOBS: dict[str, FlashJob] = {}
JOBS_LOCK = threading.Lock()


def port_busy_with_flash(port: str) -> bool:
    with JOBS_LOCK:
        return any(job.port == port and job.status in {"queued", "running"} for job in JOBS.values())

# ------------------------------------------------------------------ USB provisioning
#
# SecureOTA firmware 2.5.0+ answers a small line protocol on its USB serial
# port (see esp32_ota_main.ino, "USB provisioning protocol"):
#
#   SOTA:INFO                 -> SOTA:INFO {"device_id": ..., "version": ...}
#   SOTA:PROVISION {json}     -> SOTA:OK ... (then reboots) | SOTA:ERR reason
#
# Wi-Fi password and device token travel browser -> 127.0.0.1 -> USB cable
# only; nothing here is exposed beyond this machine.

PROVISION_KEYS = {
    "ssid": 32, "password": 64, "backend_url": 200, "device_token": 128,
    "device_id": 64, "api_key": 128, "hostname": 32,
    # Gateway Ed25519 public key (64 hex) for the stage 5 manifest check.
    "gateway_key": 64,
}
SERIAL_EXCHANGE_SECONDS = 12.0


def open_quietly(port: str, baud: int) -> "serial.Serial":
    """Open with DTR and RTS released.

    On ESP32 dev boards DTR/RTS drive IO0 and EN through the auto-download
    circuit. Releasing both lets the chip run; a plain open on some drivers
    leaves one asserted, which holds the board in reset or boots it into the
    ROM download mode, where it never answers the firmware protocol.
    """
    ser = serial.Serial()
    ser.port = port
    ser.baudrate = baud
    ser.timeout = 0.2
    ser.dtr = False
    ser.rts = False
    ser.open()
    # Some drivers apply the line states only after open; set them again.
    ser.dtr = False
    ser.rts = False
    return ser


def reset_into_firmware(ser: "serial.Serial") -> None:
    """Restart the board into its flashed firmware (esptool's hard reset):
    IO0 released (DTR off), EN pulsed low through RTS for 100 ms."""
    ser.dtr = False
    ser.rts = True
    time.sleep(0.12)
    ser.rts = False


def explain_silence(seen: list[str]) -> str:
    """Why a board did not answer, judged from what it printed."""
    text = "\n".join(seen)
    if "waiting for download" in text or re.search(r"boot:0x(0|2|3|4|5|6|7)\b", text):
        return ("The board is in ROM download mode, not running the firmware. Release BOOT, press EN (RST) once, "
                "and retry.")
    if "Brownout detector was triggered" in text:
        return ("The board keeps resetting because its supply voltage drops (brownout). Use a USB port directly "
                "on the computer, a shorter or thicker cable, or a powered hub.")
    crash = next((line for line in seen if "Guru Meditation" in line or "abort()" in line or "panic" in line.lower()), None)
    if crash:
        return f"The firmware crashes at start-up: {crash[:160]}"
    if "invalid header" in text or "flash read err" in text:
        return ("The board resets but cannot load the app from flash (invalid header). Flash the full image "
                "(firmware-full.bin at 0x0) with \"Erase entire flash\" ticked.")
    if text.count("rst:") >= 3:
        return "The board is boot-looping. Its output is shown below."
    if not seen:
        return ("The board printed nothing, not even the ROM boot message, after being reset over USB. Press EN "
                "(RST) once and retry; if it stays silent, the USB cable or adapter is not passing data from the board.")
    return ("The board runs but did not answer the SecureOTA request. It needs SecureOTA firmware 2.5.0 or "
            "newer; its last output is shown below.")


def serial_exchange(port: str, baud: int, request: str, accept: tuple[str, ...],
                    timeout: float = SERIAL_EXCHANGE_SECONDS, reset: bool = False) -> tuple[str | None, list[str]]:
    """Send `request` (re-sent every ~1.5 s) until a line starting with one of
    `accept` arrives. Returns (matching line or None, recent output lines).

    With reset=True the board is first restarted into its firmware, and its
    boot output is kept, so a failure can say what the board did instead."""
    seen: deque[str] = deque(maxlen=60)
    ser = open_quietly(port, baud)
    try:
        if reset:
            ser.reset_input_buffer()
            reset_into_firmware(ser)
            # Give the bootloader and setup() a moment before the first request.
            next_send = time.time() + 1.2
        else:
            time.sleep(0.3)
            ser.reset_input_buffer()
            next_send = 0.0
        deadline = time.time() + timeout
        pending = b""
        while time.time() < deadline:
            if time.time() >= next_send:
                ser.write((request + "\n").encode("utf-8"))
                ser.flush()
                next_send = time.time() + 1.5
            chunk = ser.read(512)
            if not chunk:
                continue
            pending += chunk
            while b"\n" in pending:
                raw, pending = pending.split(b"\n", 1)
                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue
                seen.append(line)
                if line.startswith(accept):
                    return line, list(seen)
        if pending.strip():
            seen.append(pending.decode("utf-8", "replace").strip())
        return None, list(seen)
    finally:
        ser.close()


def _parse_tagged_json(line: str, tag: str) -> dict:
    try:
        return json.loads(line[len(tag):].strip() or "{}")
    except json.JSONDecodeError:
        return {}

# ------------------------------------------------------------------ HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = f"SecureOTAAgent/{AGENT_VERSION}"
    token: str | None = None

    # -- helpers
    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        # Non-browser callers (curl) send no Origin; they are already local.
        return origin is None or origin_allowed(origin)

    def _cors(self):
        origin = self.headers.get("Origin")
        if origin_allowed(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Agent-Token")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Access-Control-Max-Age", "600")

    def _json(self, status: int, payload: dict):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        if not self._origin_ok():
            self._json(403, {"ok": False, "error": "origin not allowed"})
            return False
        if self.token and self.headers.get("X-Agent-Token") != self.token:
            self._json(401, {"ok": False, "error": "agent token required"})
            return False
        return True

    def log_message(self, fmt, *args):  # quieter console
        if "/jobs/" in (args[0] if args else "") or "/health" in (args[0] if args else ""):
            return
        super().log_message(fmt, *args)

    # -- verbs
    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        if not self._authorized():
            return
        url = urlparse(self.path)
        if url.path == "/health":
            return self._json(200, {"ok": True, "agent": "secureota-agent", "version": AGENT_VERSION,
                                    "platform": sys.platform, "esptool": bool(ESPTOOL), "tokenRequired": bool(self.token),
                                    "features": ["flash", "monitor", "device-info", "provision"]})
        if url.path == "/ports":
            ports = describe_ports()
            return self._json(200, {"ok": True, "supported": True, "ports": ports, "count": len(ports)})
        if url.path.startswith("/jobs/"):
            job_id = url.path.split("/", 2)[2]
            since = int(parse_qs(url.query).get("since", ["0"])[0] or 0)
            with JOBS_LOCK:
                job = JOBS.get(job_id)
            if not job:
                return self._json(404, {"ok": False, "error": "unknown job"})
            return self._json(200, {"ok": True, "job": job.to_dict(since)})
        if url.path == "/monitor":
            return self._monitor(parse_qs(url.query))
        if url.path == "/device-info":
            return self._device_info(parse_qs(url.query))
        self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        if not self._authorized():
            return
        url = urlparse(self.path)
        if url.path == "/provision":
            return self._provision()
        if url.path != "/flash":
            return self._json(404, {"ok": False, "error": "not found"})

        ctype = self.headers.get("Content-Type", "")
        if not ctype.startswith("multipart/form-data"):
            return self._json(400, {"ok": False, "error": "multipart/form-data expected"})
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 32 * 1024 * 1024:
            return self._json(413, {"ok": False, "error": "body missing or larger than 32 MB"})
        form = parse_multipart(ctype, self.rfile.read(length))

        port = form.get("port", "").strip()
        address = form.get("address", "0x10000").strip() or "0x10000"
        baud = int(form.get("baud") or 460800)
        erase = form.get("erase", "false").lower() == "true"
        manual_boot = form.get("before", "default_reset") == "no_reset"
        data = form.get("file")

        if not PORT_NAME_RE.match(port):
            return self._json(400, {"ok": False, "error": f"invalid port '{port}'"})
        if not ADDRESS_RE.match(address):
            return self._json(400, {"ok": False, "error": f"invalid flash address '{address}'"})
        if not isinstance(data, bytes):
            return self._json(400, {"ok": False, "error": "file is required"})
        if not data:
            return self._json(400, {"ok": False, "error": "empty firmware image"})
        if not ESPTOOL:
            return self._json(500, {"ok": False, "error": "esptool not found - pip install esptool"})
        if port_busy_with_flash(port):
            return self._json(409, {"ok": False, "error": f"{port} is already being flashed"})

        tmp = Path(tempfile.gettempdir()) / f"secureota-{uuid.uuid4().hex}.bin"
        tmp.write_bytes(data)
        job = FlashJob(port, address, tmp, baud, erase, manual_boot)
        with JOBS_LOCK:
            JOBS[job.id] = job
        threading.Thread(target=job.run, daemon=True).start()
        self._json(202, {"ok": True, "jobId": job.id, "bytes": len(data)})

    # -- USB provisioning
    def _read_json_body(self) -> dict | None:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 16 * 1024:
            self._json(413, {"ok": False, "error": "JSON body missing or larger than 16 KB"})
            return None
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            self._json(400, {"ok": False, "error": "application/json expected"})
            return None
        try:
            body = json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            self._json(400, {"ok": False, "error": "invalid JSON"})
            return None
        if not isinstance(body, dict):
            self._json(400, {"ok": False, "error": "JSON object expected"})
            return None
        return body

    def _device_info(self, query: dict):
        port = (query.get("port") or [""])[0].strip()
        baud = int((query.get("baud") or ["115200"])[0])
        if not PORT_NAME_RE.match(port):
            return self._json(400, {"ok": False, "error": f"invalid port '{port}'"})
        if port_busy_with_flash(port):
            return self._json(409, {"ok": False, "error": f"{port} is being flashed"})
        try:
            # First ask the board as it is; if it stays quiet, restart it into
            # its firmware (it may be held in reset or in download mode) and ask again.
            line, seen = serial_exchange(port, baud, "SOTA:INFO", ("SOTA:INFO ",), timeout=4.0)
            if not line:
                line, seen = serial_exchange(port, baud, "SOTA:INFO", ("SOTA:INFO ",), timeout=12.0, reset=True)
        except serial.SerialException as exc:
            return self._json(409, {"ok": False, "error": f"cannot open {port} (close any serial monitor first): {exc}"})
        if not line:
            return self._json(504, {"ok": False, "error": explain_silence(seen), "output": seen[-20:]})
        return self._json(200, {"ok": True, "device": _parse_tagged_json(line, "SOTA:INFO")})

    def _provision(self):
        body = self._read_json_body()
        if body is None:
            return
        port = str(body.get("port", "")).strip()
        baud = int(body.get("baud") or 115200)
        config = body.get("config")
        if not PORT_NAME_RE.match(port):
            return self._json(400, {"ok": False, "error": f"invalid port '{port}'"})
        if not isinstance(config, dict) or not config:
            return self._json(400, {"ok": False, "error": "config object is required"})

        clean: dict = {}
        for key, value in config.items():
            if key == "reset_health":
                clean[key] = bool(value)
                continue
            if key not in PROVISION_KEYS:
                return self._json(400, {"ok": False, "error": f"unknown config key '{key}'"})
            if not isinstance(value, str) or len(value) > PROVISION_KEYS[key] or "\n" in value or "\r" in value:
                return self._json(400, {"ok": False, "error": f"'{key}' must be a single-line string of at most {PROVISION_KEYS[key]} characters"})
            clean[key] = value
        if port_busy_with_flash(port):
            return self._json(409, {"ok": False, "error": f"{port} is being flashed"})

        request = "SOTA:PROVISION " + json.dumps(clean, separators=(",", ":"))
        try:
            line, seen = serial_exchange(port, baud, request, ("SOTA:OK", "SOTA:ERR"), timeout=6.0)
            if not line:
                line, seen = serial_exchange(port, baud, request, ("SOTA:OK", "SOTA:ERR"), timeout=12.0, reset=True)
        except serial.SerialException as exc:
            return self._json(409, {"ok": False, "error": f"cannot open {port} (close any serial monitor first): {exc}"})
        if not line:
            return self._json(504, {"ok": False, "error": explain_silence(seen), "output": seen[-20:]})
        if line.startswith("SOTA:ERR"):
            return self._json(422, {"ok": False, "error": line[len("SOTA:ERR"):].strip() or "rejected by the board"})
        # Never echo the secrets back; report which fields were written.
        return self._json(200, {"ok": True, "message": line[len("SOTA:OK"):].strip(), "written": sorted(clean.keys())})

    # -- serial monitor as SSE
    def _monitor(self, query: dict):
        port = (query.get("port") or [""])[0].strip()
        baud = int((query.get("baud") or ["115200"])[0])
        if not PORT_NAME_RE.match(port):
            return self._json(400, {"ok": False, "error": f"invalid port '{port}'"})
        try:
            ser = open_quietly(port, baud)
            ser.timeout = 0.5
            if (query.get("reset") or ["0"])[0] == "1":
                reset_into_firmware(ser)
        except serial.SerialException as exc:
            return self._json(409, {"ok": False, "error": f"cannot open {port}: {exc}"})

        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

        def send(event: str, text: str):
            payload = f"event: {event}\ndata: {json.dumps(text)}\n\n".encode()
            self.wfile.write(payload)
            self.wfile.flush()

        try:
            send("open", f"{port} @ {baud}")
            pending = b""
            last_ping = time.time()
            while True:
                chunk = ser.read(4096)
                if chunk:
                    pending += chunk
                    while b"\n" in pending:
                        line, pending = pending.split(b"\n", 1)
                        send("line", line.decode("utf-8", "replace").rstrip("\r"))
                elif time.time() - last_ping > 10:
                    send("ping", "")
                    last_ping = time.time()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            pass
        finally:
            ser.close()


def main():
    parser = argparse.ArgumentParser(description="SecureOTA local COM agent")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"loopback port (default {DEFAULT_PORT})")
    parser.add_argument("--token", default=os.environ.get("SECUREOTA_AGENT_TOKEN") or None,
                        help="require this X-Agent-Token header on every request")
    parser.add_argument("--allow-origin", action="append", default=[], help="extra browser origin to allow")
    args = parser.parse_args()
    ALLOWED_ORIGINS.update(args.allow_origin)
    Handler.token = args.token

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.daemon_threads = True
    print(f"SecureOTA agent v{AGENT_VERSION} listening on http://127.0.0.1:{args.port}")
    print(f"  esptool : {'found' if ESPTOOL else 'MISSING - pip install esptool'}")
    print(f"  origins : {', '.join(sorted(ALLOWED_ORIGINS))}")
    print(f"  token   : {'required' if args.token else 'not required'}")
    ports = describe_ports()
    print(f"  ports   : {', '.join(p['path'] + ' (' + p['description'] + ')' for p in ports) or 'none connected'}")
    print("Leave this window open while using the dashboard. Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
