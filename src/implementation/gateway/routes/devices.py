"""
SentinelOTA Edge Gateway — Route: Devices, Registration and Remote Commands

This is the internet-facing control path between the dashboard and a board:

    dashboard (fleet key)                      device (its own token)
    ─────────────────────                      ──────────────────────
    POST /api/devices/register   ─ token ─▶    stored in NVS at provisioning
    POST /api/devices/{id}/commands            POST /api/heartbeat  ◀─ commands
    GET  /api/devices/{id}                     POST /api/devices/{id}/commands/{cid}/result
    DELETE /api/devices/{id}                   POST /api/devices/{id}/ota/status

Reads are open, matching /api/dashboard. Credential hashes are never
returned by any route.
"""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from ..auth import (
    DeviceCaller,
    authorize_device_locked,
    device_credentials,
    hash_device_token,
    new_device_token,
    require_write_auth,
)
from ..commands import (
    COMMAND_TYPES,
    complete_command_locked,
    enqueue_command_locked,
    expire_commands_locked,
)
from ..config import MAX_OTA_HISTORY
from ..deployment import OTA_PHASES, record_ota_status_locked
from ..models import (
    DeviceCommandPayload,
    DeviceCommandResultPayload,
    DeviceOtaStatusPayload,
    DeviceRegisterPayload,
)
from ..state import STATE, STATE_LOCK, persist_state_locked, push_event_locked
from ..utils import normalize_device_type, safe_int, utc_now_iso

router = APIRouter()

_require_write_auth = require_write_auth

DEVICE_ID_RE = re.compile(r'^[A-Za-z0-9_.:-]{1,64}$')


def _check_device_id(device_id: str) -> str:
    device_id = device_id.strip()
    if not DEVICE_ID_RE.match(device_id):
        raise HTTPException(status_code=400, detail='device id must be 1-64 characters of A-Z a-z 0-9 _ . : -')
    return device_id


def _credential_summary_locked(device_id: str) -> dict[str, Any]:
    record = STATE.get('deviceCredentials', {}).get(device_id)
    if not record:
        return {'registered': False}
    return {
        'registered': True,
        'revoked': bool(record.get('revoked')),
        'registeredAt': record.get('createdAt'),
        'deviceType': record.get('deviceType'),
        'label': record.get('label'),
    }


def _device_view_locked(device_id: str) -> dict[str, Any]:
    device = STATE.get('devices', {}).get(device_id)
    return {
        'id': device_id,
        'device': dict(device) if device else None,
        'credentials': _credential_summary_locked(device_id),
        'commands': list(STATE.get('commands', {}).get(device_id, [])),
    }


# ── Registry ──────────────────────────────────────────────────

@router.get('/api/devices')
def list_devices() -> dict[str, Any]:
    with STATE_LOCK:
        expire_commands_locked()
        ids = sorted(set(STATE.get('devices', {})) | set(STATE.get('deviceCredentials', {})))
        devices = []
        for device_id in ids:
            view = _device_view_locked(device_id)
            open_commands = [c for c in view['commands'] if c.get('status') in {'queued', 'delivered'}]
            devices.append({
                **(view['device'] or {'id': device_id, 'status': 'Registered (never seen)'}),
                'credentials': view['credentials'],
                'openCommands': len(open_commands),
            })
    return {'ok': True, 'devices': devices}


@router.get('/api/devices/{device_id}')
def get_device(device_id: str) -> dict[str, Any]:
    device_id = _check_device_id(device_id)
    with STATE_LOCK:
        expire_commands_locked(device_id)
        view = _device_view_locked(device_id)
    if not view['device'] and not view['credentials']['registered']:
        raise HTTPException(status_code=404, detail=f'Device {device_id} is not known to this gateway.')
    return {'ok': True, **view}


@router.post('/api/devices/register')
def register_device(payload: DeviceRegisterPayload, _auth: None = Depends(_require_write_auth)) -> dict[str, Any]:
    """Issue (or rotate) the device's own token. The token is returned once."""
    device_id = _check_device_id(payload.deviceId)
    device_type = normalize_device_type(payload.deviceType) if payload.deviceType else None
    token = new_device_token()

    with STATE_LOCK:
        credentials = STATE.setdefault('deviceCredentials', {})
        rotated = device_id in credentials
        credentials[device_id] = {
            'tokenHash': hash_device_token(token),
            'createdAt': utc_now_iso(),
            'deviceType': device_type,
            'label': (payload.label or '')[:64] or None,
            'revoked': False,
        }
        push_event_locked(
            event_type='security',
            severity='info',
            title='Device Token Rotated' if rotated else 'Device Registered',
            description=f'Device {device_id} was issued a {"new " if rotated else ""}device token.',
            device_id=device_id,
        )
        STATE['updatedAt'] = utc_now_iso()
        persist_state_locked()

    return {'ok': True, 'deviceId': device_id, 'deviceType': device_type, 'token': token, 'rotated': rotated}


@router.post('/api/devices/{device_id}/revoke-token')
def revoke_device_token(device_id: str, _auth: None = Depends(_require_write_auth)) -> dict[str, Any]:
    device_id = _check_device_id(device_id)
    with STATE_LOCK:
        record = STATE.get('deviceCredentials', {}).get(device_id)
        if not record:
            raise HTTPException(status_code=404, detail=f'Device {device_id} has no token.')
        record['revoked'] = True
        record['revokedAt'] = utc_now_iso()
        push_event_locked('security', 'warning', 'Device Token Revoked', f'Token for {device_id} revoked.', device_id)
        persist_state_locked()
    return {'ok': True}


@router.delete('/api/devices/{device_id}')
def remove_device(device_id: str, _auth: None = Depends(_require_write_auth)) -> dict[str, Any]:
    """Forget a device: record, queued commands and token.

    A board that is still powered and holds the fleet key will reappear on its
    next heartbeat — removing a record cannot stop hardware. Revoking its
    token (and enabling OTA_REQUIRE_DEVICE_TOKEN) is what locks it out.
    """
    device_id = _check_device_id(device_id)
    with STATE_LOCK:
        existed = STATE.get('devices', {}).pop(device_id, None) is not None
        STATE.get('commands', {}).pop(device_id, None)
        had_token = STATE.get('deviceCredentials', {}).pop(device_id, None) is not None
        if not existed and not had_token:
            raise HTTPException(status_code=404, detail=f'Device {device_id} is not known to this gateway.')
        push_event_locked('info', 'warning', 'Device Removed', f'Device {device_id} removed from the registry.', device_id)
        STATE['updatedAt'] = utc_now_iso()
        persist_state_locked()
    return {'ok': True, 'removed': device_id}


# ── Commands (dashboard side) ─────────────────────────────────

@router.get('/api/devices/{device_id}/commands')
def list_device_commands(device_id: str) -> dict[str, Any]:
    device_id = _check_device_id(device_id)
    with STATE_LOCK:
        expire_commands_locked(device_id)
        commands = list(STATE.get('commands', {}).get(device_id, []))
    return {'ok': True, 'commands': commands, 'supported': COMMAND_TYPES}


@router.post('/api/devices/{device_id}/commands')
def queue_device_command(
    device_id: str,
    payload: DeviceCommandPayload,
    _auth: None = Depends(_require_write_auth),
) -> dict[str, Any]:
    device_id = _check_device_id(device_id)
    if payload.type not in COMMAND_TYPES:
        raise HTTPException(
            status_code=400,
            detail={'message': f"Unsupported command '{payload.type}'.", 'supported': sorted(COMMAND_TYPES)},
        )

    with STATE_LOCK:
        device = STATE.get('devices', {}).get(device_id)
        if not device:
            raise HTTPException(status_code=404, detail=f'Device {device_id} has never checked in, so it cannot receive commands.')
        if payload.type in {'update', 'check_update'} and safe_int(device.get('ash', 100), 100) <= 40:
            raise HTTPException(status_code=409, detail=f'Device {device_id} is quarantined; updates are blocked until its ASH recovers.')
        command = enqueue_command_locked(device_id, payload.type, dict(payload.params or {}))
        STATE['updatedAt'] = utc_now_iso()
        persist_state_locked()

    return {'ok': True, 'command': command}


@router.post('/api/devices/{device_id}/commands/{command_id}/cancel')
def cancel_device_command(device_id: str, command_id: str, _auth: None = Depends(_require_write_auth)) -> dict[str, Any]:
    device_id = _check_device_id(device_id)
    with STATE_LOCK:
        for command in STATE.get('commands', {}).get(device_id, []):
            if command.get('id') == command_id:
                if command.get('status') != 'queued':
                    raise HTTPException(status_code=409, detail=f"Command is already {command.get('status')}.")
                command['status'] = 'cancelled'
                command['completedAt'] = utc_now_iso()
                persist_state_locked()
                return {'ok': True, 'command': command}
    raise HTTPException(status_code=404, detail='Command not found.')


# ── Device-side reports ───────────────────────────────────────

@router.post('/api/devices/{device_id}/commands/{command_id}/result')
def report_command_result(
    device_id: str,
    command_id: str,
    payload: DeviceCommandResultPayload,
    caller: DeviceCaller = Depends(device_credentials),
) -> dict[str, Any]:
    device_id = _check_device_id(device_id)
    with STATE_LOCK:
        authorize_device_locked(STATE, device_id, caller)
        command = complete_command_locked(device_id, command_id, payload.ok, payload.detail)
        if not command:
            raise HTTPException(status_code=404, detail='Command not found.')
        persist_state_locked()
    return {'ok': True, 'status': command.get('status')}


@router.post('/api/devices/{device_id}/ota/status')
def report_ota_status(
    device_id: str,
    payload: DeviceOtaStatusPayload,
    caller: DeviceCaller = Depends(device_credentials),
) -> dict[str, Any]:
    device_id = _check_device_id(device_id)
    phase = payload.phase.strip().lower()
    if phase not in OTA_PHASES:
        raise HTTPException(status_code=400, detail={'message': f"Unknown phase '{payload.phase}'.", 'phases': list(OTA_PHASES)})
    progress = None if payload.progress is None else max(0, min(100, int(payload.progress)))
    detail = payload.detail[:300]
    version = payload.version[:32]

    with STATE_LOCK:
        authorize_device_locked(STATE, device_id, caller)
        device = STATE.get('devices', {}).get(device_id)
        if not device:
            raise HTTPException(status_code=404, detail=f'Device {device_id} must send a heartbeat first.')

        entry = {'phase': phase, 'version': version, 'progress': progress, 'detail': detail or None, 'at': utc_now_iso()}
        device['ota'] = entry
        history = device.setdefault('otaHistory', [])
        # Progress ticks would flood the history; keep only phase changes.
        if not history or history[-1].get('phase') != phase or history[-1].get('version') != version:
            history.append(entry)
            del history[:-MAX_OTA_HISTORY]

        changed = record_ota_status_locked(device_id, phase, version, progress, detail)

        if phase == 'succeeded':
            push_event_locked('firmware_update', 'success', 'Device Passed Post-Update Health Check',
                              f'{device_id} booted v{version} and confirmed it healthy.', device_id)
        STATE['updatedAt'] = utc_now_iso()
        persist_state_locked()

    return {'ok': True, 'deployments': changed}
