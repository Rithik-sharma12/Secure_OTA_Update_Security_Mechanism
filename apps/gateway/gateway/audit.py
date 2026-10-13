"""
SentinelOTA Edge Gateway — Audit trail of state-changing requests

Every POST/PUT/PATCH/DELETE that is not a device's own report is recorded
with who made it, from where, what it was and how it ended — including 401s,
which are the interesting rows when someone is guessing keys.

Who: the dashboard calls with the fleet key and names the signed-in operator
in `x-actor` (lib/gateway-proxy.ts). That header is only believed alongside a
valid fleet key; without one the row says so. Device-originated traffic
(heartbeats, status and result reports) is high volume and already visible in
telemetry and the command history, so it is not audited here.

Routes add a human-readable line with `audit_note(request, ...)`; the
middleware writes it after the response status is known.
"""

from __future__ import annotations

import hmac
import re
from typing import Any

from fastapi import FastAPI, Request

from .config import API_KEY
from .history import record_audit

_WRITE_METHODS = {'POST', 'PUT', 'PATCH', 'DELETE'}
_DEVICE_REPORT_PATHS = (
    re.compile(r'^/api/heartbeat$'),
    re.compile(r'^/api/devices/[^/]+/ota/status$'),
    re.compile(r'^/api/devices/[^/]+/commands/[^/]+/result$'),
)
_DEVICE_IN_PATH = re.compile(r'^/api/devices/([^/]+)')
_ACTOR_RE = re.compile(r'[^\w .@:()/-]')


def audit_note(request: Request, action: str, detail: str | None = None, device_id: str | None = None) -> None:
    """Attach a description of what this request did to its audit row."""
    request.state.audit = {'action': action, 'detail': detail, 'device_id': device_id}


def _presented_fleet_key(request: Request) -> str:
    authorization = request.headers.get('authorization', '')
    bearer = authorization.split(' ', 1)[1].strip() if authorization.lower().startswith('bearer ') else ''
    return (request.query_params.get('api_key') or request.headers.get('x-api-key') or bearer or '').strip()


def _actor(request: Request) -> str:
    if request.url.path == '/api/github/webhook':
        return 'github-webhook'
    key = _presented_fleet_key(request)
    key_ok = (not API_KEY) or (bool(key) and hmac.compare_digest(key.encode(), API_KEY.encode()))
    if key_ok:
        named = _ACTOR_RE.sub('', request.headers.get('x-actor', '')).strip()[:96]
        return f'dashboard:{named}' if named else 'fleet-key (unnamed caller)'
    if request.headers.get('x-device-token'):
        return 'device-token'
    return 'unauthenticated'


def install_audit_middleware(app: FastAPI) -> None:
    @app.middleware('http')
    async def _audit(request: Request, call_next: Any):
        if request.method not in _WRITE_METHODS or any(p.match(request.url.path) for p in _DEVICE_REPORT_PATHS):
            return await call_next(request)

        response = await call_next(request)

        note = getattr(request.state, 'audit', None) or {}
        device_match = _DEVICE_IN_PATH.match(request.url.path)
        record_audit(
            actor=_actor(request),
            source_ip=request.headers.get('cf-connecting-ip') or (request.client.host if request.client else None),
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            action=note.get('action'),
            detail=note.get('detail'),
            device_id=note.get('device_id') or (device_match.group(1) if device_match and device_match.group(1) != 'register' else None),
        )
        return response
