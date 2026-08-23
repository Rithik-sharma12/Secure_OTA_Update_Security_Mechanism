"""
SentinelOTA Edge Gateway — Route: Device Heartbeat
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from ..config import MAX_DEVICE_LOG_ENTRIES
from ..deployment import (
    QUARANTINE_ASH_THRESHOLD,
    confirm_device_version_locked,
    expire_stale_deployments_locked,
)
from ..release import latest_release_for_device_locked
from ..state import (
    STATE,
    STATE_LOCK,
    persist_state_locked,
    push_alert_locked,
    push_event_locked,
)
from ..utils import (
    is_newer_version,
    normalize_device_type,
    safe_float,
    safe_int,
    utc_now_iso,
)

router = APIRouter()


@router.post('/api/heartbeat')
def receive_heartbeat(payload: dict[str, Any]) -> dict[str, Any]:
    device_id = str(payload.get('device_id', '')).strip()
    if not device_id:
        raise HTTPException(status_code=400, detail='Missing device_id')
    if len(device_id) > 128:
        raise HTTPException(status_code=400, detail='device_id is too long')

    ash_score = safe_int(payload.get('ash_score', 0), 0)
    ash_score = max(0, min(100, ash_score))

    status_text = str(payload.get('status', 'Healthy'))[:64]
    device_type = normalize_device_type(str(payload.get('device_type', 'ESP32')))
    logs = payload.get('logs', [])
    if not isinstance(logs, list):
        logs = []

    now_iso = utc_now_iso()

    with STATE_LOCK:
        previous = STATE['devices'].get(device_id, {})
        previous_ash = safe_int(previous.get('ash', 100), 100) if previous else 100

        if not previous:
            push_event_locked(
                event_type='info',
                severity='success',
                title='New Device Registered',
                description=f'Device {device_id} joined the gateway telemetry stream.',
                device_id=device_id,
            )

        if previous_ash > 40 and ash_score <= 40:
            push_alert_locked(f'CRITICAL: Device {device_id} entered quarantine threshold (ASH={ash_score}).')
            push_event_locked(
                event_type='security',
                severity='error',
                title='Device Quarantine Triggered',
                description=f'Device {device_id} ASH dropped from {previous_ash} to {ash_score}.',
                device_id=device_id,
            )

        cpu_usage = safe_float(payload.get('cpu_usage', payload.get('cpuUsage', 0.0)), 0.0)
        memory_usage = safe_float(payload.get('memory_usage', payload.get('memoryUsage', 0.0)), 0.0)
        signal_strength = payload.get('signal_strength', payload.get('signalStrength'))

        STATE['devices'][device_id] = {
            'id': device_id,
            'arch': device_type,
            'fw': str(payload.get('current_version', '0.0.0'))[:64],
            'ash': ash_score,
            'status': status_text,
            'last_seen': now_iso,
            'logs': [str(entry)[:500] for entry in logs][-MAX_DEVICE_LOG_ENTRIES:],
            'cpuUsage': cpu_usage,
            'memoryUsage': memory_usage,
            'uptime': safe_float(payload.get('uptime', 0.0), 0.0),
            'location': str(payload.get('location', 'Edge Gateway Network'))[:128],
            'signalStrength': signal_strength,
            'ram': 'N/A',
        }

        current_version = str(payload.get('current_version', '0.0.0'))

        # A device reporting a version is the only proof the gateway ever gets
        # that an update actually landed. Resolve any deployment waiting on it.
        confirm_device_version_locked(device_id, current_version)
        expire_stale_deployments_locked()

        # What this specific device should be offered, honouring the release's
        # target architectures — an ESP8266 must never be pointed at an ESP32
        # build.
        target_release = latest_release_for_device_locked(device_type)
        latest_version = str(target_release.get('version', '0.0.0')) if target_release else '0.0.0'

        STATE['updatedAt'] = now_iso
        persist_state_locked()

    command = 'ack'
    if (
        target_release
        and ash_score > QUARANTINE_ASH_THRESHOLD
        and is_newer_version(latest_version, current_version)
    ):
        # Only ever advertise a strictly newer build. Signalling on "different"
        # would offer downgrades, which the firmware's anti-rollback then
        # refuses — a pointless download attempt and a confusing device log.
        command = 'update_available'

    return {'command': command, 'gateway_time': now_iso, 'latest_version': latest_version}
