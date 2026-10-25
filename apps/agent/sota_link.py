#!/usr/bin/env python3
"""
SecureOTA UART link host.

Boards without networking (ATmega328P, STM32F103) reach the gateway through
this program, running on any computer or Raspberry Pi wired to the board's
serial port. The board drives the conversation; this host only relays:

    board                                   link host                        gateway
    SOTA:HELLO id=.. t=.. v=.. h=.. q=..    POST /api/heartbeat              (device token)
    SOTA:MANIFEST?                          GET  /releases/latest/manifest
    SOTA:CHUNK <offset> <length>            GET  firmware (once, then cached)
    SOTA:VERIFY v=.. s=.. i=.. n=.. g=..    POST /api/verify/manifest        gateway-assisted stage 5
    SOTA:STATUS <phase> <version>           POST /api/devices/<id>/ota/status

Lines from the board that start with "#" are its log. Full protocol:
firmware/UART_LINK.md.

The host is not trusted with the update: the board hashes every byte it
receives (stage 4) and the gateway's Ed25519 signature covers that digest
(stage 5), so a host that alters the image only gets the update rejected.

Usage:
    python sota_link.py --port COM7 --gateway http://192.168.1.20:5000 --token <device token>
    (or set SOTA_DEVICE_TOKEN; --api-key / SOTA_API_KEY uses the fleet key instead)

Needs pyserial (pip install pyserial); the HTTP side uses only the standard library.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

# (method, url, json body or None) -> (status, body bytes)
HttpFn = Callable[[str, str, Any], 'tuple[int, bytes]']

# Board phases -> gateway OTA phases (apps/gateway/gateway/deployment.py OTA_PHASES)
PHASES = {
    'downloading': 'downloading',
    'installing': 'installing',
    'confirmed': 'succeeded',
    'self_test_failed': 'failed',
    'failed': 'failed',
    'rejected_downgrade': 'failed',
    'rejected_size': 'failed',
    'rejected_package': 'failed',
    'rejected_sha256': 'failed',
    'rejected_signature': 'failed',
}

MAX_CHUNK = 512


def parse_fields(text: str) -> dict[str, str]:
    """'v=1.0.0 s=ab..' -> {'v': '1.0.0', 's': 'ab..'}"""
    fields = {}
    for token in text.split():
        key, sep, value = token.partition('=')
        if sep:
            fields[key] = value
    return fields


class LinkHost:
    def __init__(self, gateway: str, http: HttpFn, log: Callable[[str], None] = print):
        self.gateway = gateway.rstrip('/')
        self.http = http
        self.log = log
        self.device_id = ''
        self.device_type = ''
        self.manifest: dict[str, Any] | None = None
        self.image: bytes | None = None

    # ── one line from the board -> one reply line (or None) ──────────────
    def handle(self, line: str) -> str | None:
        line = line.strip()
        if not line:
            return None
        if line.startswith('#'):
            self.log(f'[board] {line[1:].strip()}')
            return None
        if not line.startswith('SOTA:'):
            self.log(f'[board] {line}')
            return None
        command, _, rest = line[5:].partition(' ')
        try:
            handler = {
                'HELLO': self._hello,
                'MANIFEST?': self._manifest,
                'CHUNK': self._chunk,
                'VERIFY': self._verify,
                'STATUS': self._status,
            }.get(command)
            if handler is None:
                return 'SOTA:ERR unknown command'
            return handler(rest)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            self.log(f'[link] {command} failed: {exc}')
            return 'SOTA:ERR gateway unreachable'

    def _json(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        status, raw = self.http(method, self.gateway + path, body)
        try:
            return status, json.loads(raw.decode('utf-8') or 'null')
        except ValueError:
            return status, None

    def _hello(self, rest: str) -> str:
        f = parse_fields(rest)
        self.device_id = f.get('id', self.device_id)
        self.device_type = f.get('t', self.device_type)
        quarantined = f.get('q') == '1'
        status, _ = self._json('POST', '/api/heartbeat', {
            'device_id': self.device_id,
            'device_type': self.device_type,
            'current_version': f.get('v', '0.0.0'),
            'ash_score': int(f.get('h', '100')),
            'status': 'Quarantined' if quarantined else 'Healthy',
            'location': 'uart-link',
            'logs': [f'[LINK] {self.device_type} {self.device_id} via UART link host'],
        })
        return 'SOTA:ACK' if 200 <= status < 300 else f'SOTA:ERR heartbeat {status}'

    def _manifest(self, _rest: str) -> str:
        if not self.device_id:
            return 'SOTA:ERR send HELLO first'
        query = urllib.parse.urlencode({'device_id': self.device_id, 'device_type': self.device_type})
        status, manifest = self._json('GET', f'/releases/latest/manifest?{query}')
        if status == 404 or (isinstance(manifest, dict) and manifest.get('updateAvailable') is False):
            return 'SOTA:NONE'
        if status != 200 or not isinstance(manifest, dict):
            return f'SOTA:ERR manifest {status}'
        if not manifest.get('manifestSignature'):
            return 'SOTA:ERR manifest is not signed (update the gateway)'
        if self.manifest is None or self.manifest.get('sha256') != manifest.get('sha256'):
            self.image = None  # a different release: fetch its bytes again
        self.manifest = manifest
        image = manifest.get('imageSha256') or '-'
        return (f"SOTA:MANIFEST v={manifest['version']} s={manifest['sha256']} i={image} "
                f"n={int(manifest['size'])} g={manifest['manifestSignature']}")

    def _chunk(self, rest: str) -> str:
        parts = rest.split()
        if len(parts) != 2 or self.manifest is None:
            return 'SOTA:ERR no manifest'
        offset, length = int(parts[0]), min(int(parts[1]), MAX_CHUNK)
        if self.image is None:
            url = self.manifest.get('downloadUrl') or self.manifest.get('url') or ''
            if url.startswith('/'):
                url = self.gateway + url
            status, body = self.http('GET', url, None)
            if status != 200:
                return f'SOTA:ERR download {status}'
            self.image = body
            self.log(f'[link] fetched v{self.manifest.get("version")} ({len(body)} bytes)')
        if offset < 0 or offset >= len(self.image):
            return 'SOTA:ERR offset out of range'
        return f'SOTA:DATA {offset} {self.image[offset:offset + length].hex()}'

    def _verify(self, rest: str) -> str:
        f = parse_fields(rest)
        image = f.get('i')
        status, answer = self._json('POST', '/api/verify/manifest', {
            'version': f.get('v', ''),
            'sha256': f.get('s', ''),
            'imageSha256': None if image in (None, '-') else image,
            'size': int(f.get('n', '0')),
            'signature': f.get('g', ''),
        })
        if status != 200 or not isinstance(answer, dict):
            return f'SOTA:ERR verify {status}'
        valid = answer.get('valid') is True
        self.log(f'[link] gateway-assisted stage 5: {"valid" if valid else "INVALID"}')
        return f'SOTA:VERDICT {1 if valid else 0}'

    def _status(self, rest: str) -> str:
        phase, _, version = rest.partition(' ')
        gateway_phase = PHASES.get(phase)
        if gateway_phase and self.device_id:
            self._json('POST', f'/api/devices/{urllib.parse.quote(self.device_id)}/ota/status', {
                'phase': gateway_phase,
                'version': version.strip(),
                'detail': f'{self.device_type}: {phase.replace("_", " ")}',
            })
        self.log(f'[board] status {phase} {version}')
        return 'SOTA:ACK'


def make_http(token: str | None, api_key: str | None, timeout: float = 15.0) -> HttpFn:
    headers = {'Accept': 'application/json'}
    if token:
        headers['x-device-token'] = token
    elif api_key:
        headers['x-api-key'] = api_key

    def http(method: str, url: str, body: Any) -> tuple[int, bytes]:
        data = None
        request_headers = dict(headers)
        if body is not None:
            data = json.dumps(body).encode('utf-8')
            request_headers['Content-Type'] = 'application/json'
        request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    return http


def main() -> None:
    parser = argparse.ArgumentParser(description='SecureOTA UART link host for ATmega328P / STM32F103 boards.')
    parser.add_argument('--port', required=True, help='serial port of the board, e.g. COM7 or /dev/ttyUSB0')
    parser.add_argument('--baud', type=int, default=115200)
    parser.add_argument('--gateway', required=True, help='gateway base URL, e.g. http://192.168.1.20:5000')
    parser.add_argument('--token', default=os.environ.get('SOTA_DEVICE_TOKEN'), help='device token (or SOTA_DEVICE_TOKEN)')
    parser.add_argument('--api-key', default=os.environ.get('SOTA_API_KEY'), help='fleet API key instead of a device token')
    args = parser.parse_args()

    try:
        import serial  # pyserial
    except ImportError:
        sys.exit('pyserial is required: pip install pyserial')

    host = LinkHost(args.gateway, make_http(args.token, args.api_key))
    port = serial.Serial()
    port.port, port.baudrate, port.timeout = args.port, args.baud, 0.2
    port.dtr = port.rts = False
    port.open()
    print(f'[link] {args.port} <-> {args.gateway}  (Ctrl+C to stop)')
    pending = b''
    try:
        while True:
            pending += port.read(256)
            while b'\n' in pending:
                raw, pending = pending.split(b'\n', 1)
                reply = host.handle(raw.decode('utf-8', 'replace'))
                if reply:
                    port.write(reply.encode('ascii') + b'\n')
            if len(pending) > 4096:  # a board that never sends a newline
                pending = b''
            time.sleep(0.005)
    except KeyboardInterrupt:
        pass
    finally:
        port.close()


if __name__ == '__main__':
    main()
