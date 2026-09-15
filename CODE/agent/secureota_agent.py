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
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", "--quiet", package])


_ensure("serial", "pyserial")
_ensure("esptool", "esptool")

import serial  # noqa: E402
from serial.tools import list_ports  # noqa: E402

AGENT_VERSION = "1.0.0"
DEFAULT_PORT = 17317
ALLOWED_ORIGINS = {
    "https://ota.nyx-ctf.tech",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
}
MAX_LOG_LINES = 400
PORT_NAME_RE = re.compile(r"^(COM\d+|/dev/[\w.\-/]+)$")
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{1,8}$")

KNOWN_CHIPS = {
    (0x10C4, 0xEA60): "Silicon Labs CP210x",
    (0x1A86, 0x7523): "WCH CH340",
    (0x1A86, 0x55D4): "WCH CH9102",
    (0x0403, 0x6001): "FTDI FT232R",
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
        result.append({
            "path": port.device,
            "description": chip or port.description or "USB serial device",
            "manufacturer": port.manufacturer,
            "serialNumber": port.serial_number,
            "vendorId": f"{port.vid:04X}" if port.vid else None,
            "productId": f"{port.pid:04X}" if port.pid else None,
            "hwid": port.hwid,
        })
    result.sort(key=lambda p: [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", p["path"])])
    return result

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
    def __init__(self, port: str, address: str, image: Path, baud: int, erase: bool):
        self.id = uuid.uuid4().hex[:12]
        self.port, self.address, self.image, self.baud, self.erase = port, address, image, baud, erase
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
        }

    def run(self):
        self.status = "running"
        if not ESPTOOL:
            self.status, self.error = "failed", "esptool not found - pip install esptool"
            self.finished = time.time()
            return
        cmd = ESPTOOL + [
            "--chip", "auto", "--port", self.port, "--baud", str(self.baud),
            "--before", "default_reset", "--after", "hard_reset", "--connect-attempts", "45",
            "write_flash", "-z", "--flash_mode", "keep", "--flash_size", "keep",
        ]
        if self.erase:
            cmd.append("--erase-all")
        cmd += [self.address, str(self.image)]
        try:
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
                    m = re.search(r"\((\d{1,3})\s*%\)", line)
                    if m:
                        self.progress = int(m.group(1))
                    m = re.search(r"Chip is (.+)$", line)
                    if m:
                        self.chip = m.group(1).strip()
                else:
                    buffer += ch
            proc.wait()
            if proc.returncode == 0:
                self.status, self.progress = "success", 100
            else:
                self.status = "failed"
                tail = [l for l in self.log if "error" in l.lower() or "failed" in l.lower()]
                self.error = tail[-1] if tail else f"esptool exited with code {proc.returncode}"
                if "Wrong boot mode" in (self.error or "") or "Failed to connect" in (self.error or ""):
                    self.error = "The board did not enter download mode. Hold its BOOT button while connecting and retry."
        except Exception as exc:  # noqa: BLE001
            self.status, self.error = "failed", str(exc)
        finally:
            self.finished = time.time()
            try:
                self.image.unlink()
            except OSError:
                pass


JOBS: dict[str, FlashJob] = {}
JOBS_LOCK = threading.Lock()

# ------------------------------------------------------------------ HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = f"SecureOTAAgent/{AGENT_VERSION}"
    token: str | None = None

    # -- helpers
    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        # Non-browser callers (curl) send no Origin; they are already local.
        return origin is None or origin in ALLOWED_ORIGINS

    def _cors(self):
        origin = self.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
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
                                    "platform": sys.platform, "esptool": bool(ESPTOOL), "tokenRequired": bool(self.token)})
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
        self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        if not self._authorized():
            return
        url = urlparse(self.path)
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

        tmp = Path(tempfile.gettempdir()) / f"secureota-{uuid.uuid4().hex}.bin"
        tmp.write_bytes(data)
        job = FlashJob(port, address, tmp, baud, erase)
        with JOBS_LOCK:
            JOBS[job.id] = job
        threading.Thread(target=job.run, daemon=True).start()
        self._json(202, {"ok": True, "jobId": job.id, "bytes": len(data)})

    # -- serial monitor as SSE
    def _monitor(self, query: dict):
        port = (query.get("port") or [""])[0].strip()
        baud = int((query.get("baud") or ["115200"])[0])
        if not PORT_NAME_RE.match(port):
            return self._json(400, {"ok": False, "error": f"invalid port '{port}'"})
        try:
            ser = serial.Serial(port, baud, timeout=0.5)
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
