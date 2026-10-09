"""
SentinelOTA Edge Gateway — Remote Device Commands

The gateway cannot open a connection to a device: boards sit behind home
routers, campus NAT and mobile carriers. What it *can* do is answer. Every
heartbeat a device sends (every 15 s) is an opportunity to hand it work, so a
command queued from the dashboard is delivered in the next heartbeat response
and the device reports the outcome back.

    dashboard ──POST /api/devices/{id}/commands──▶ queued
    device    ──POST /api/heartbeat──────────────▶ delivered (in the response)
    device    ──POST /api/devices/{id}/commands/{cid}/result──▶ succeeded | failed
    nobody picks it up within the TTL ─────────────▶ expired

A delivered command whose result never arrives (the response was lost, or the
device reset mid-command) is offered again, up to MAX_DELIVERY_ATTEMPTS.

All *_locked functions assume the caller holds STATE_LOCK.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from .config import COMMAND_TTL_MINUTES, MAX_COMMANDS_PER_DEVICE
from .state import STATE, push_event_locked
from .utils import utc_now_iso

# What a device knows how to do. Anything else is refused at enqueue time, so
# a typo on the dashboard cannot sit in a queue the firmware will never drain.
COMMAND_TYPES: dict[str, str] = {
    'update': 'Check the gateway for assigned firmware and install it now',
    'check_update': 'Run an update check immediately instead of waiting for the poll timer',
    'reboot': 'Restart the device',
    'identify': 'Blink the status LED so the board can be found on the bench',
}

OPEN_STATES = {'queued', 'delivered'}
REDELIVER_AFTER_SECONDS = 90
MAX_DELIVERY_ATTEMPTS = 3


def _parse(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def _queue_locked(device_id: str) -> list[dict[str, Any]]:
    commands = STATE.setdefault('commands', {})
    return commands.setdefault(device_id, [])


def expire_commands_locked(device_id: str | None = None) -> int:
    """Mark open commands past their expiry as expired. Returns how many."""
    now = datetime.now(timezone.utc)
    queues = STATE.get('commands', {})
    device_ids = [device_id] if device_id else list(queues.keys())
    expired = 0
    for current in device_ids:
        for command in queues.get(current, []):
            if command.get('status') not in OPEN_STATES:
                continue
            expires = _parse(command.get('expiresAt'))
            if expires and now >= expires:
                command['status'] = 'expired'
                command['completedAt'] = utc_now_iso()
                command['result'] = 'Device did not pick the command up in time.'
                expired += 1
    return expired


def enqueue_command_locked(
    device_id: str,
    command_type: str,
    params: dict[str, Any] | None = None,
    requested_by: str = 'dashboard',
) -> dict[str, Any]:
    if command_type not in COMMAND_TYPES:
        raise ValueError(f"Unsupported command '{command_type}'.")

    now = datetime.now(timezone.utc).replace(microsecond=0)
    queue = _queue_locked(device_id)

    # Collapse duplicates: three clicks on "Restart" should restart once.
    for existing in queue:
        if existing.get('status') == 'queued' and existing.get('type') == command_type and existing.get('params') == (params or {}):
            return existing

    command = {
        'id': f"cmd-{uuid.uuid4().hex[:12]}",
        'deviceId': device_id,
        'type': command_type,
        'params': params or {},
        'status': 'queued',
        'attempts': 0,
        'requestedBy': requested_by,
        'createdAt': now.isoformat(),
        'expiresAt': (now + timedelta(minutes=COMMAND_TTL_MINUTES)).isoformat(),
        'deliveredAt': None,
        'completedAt': None,
        'result': None,
    }
    queue.insert(0, command)

    # Drop the oldest *finished* entries first; never silently discard work
    # that is still waiting for the device.
    while len(queue) > MAX_COMMANDS_PER_DEVICE:
        for index in range(len(queue) - 1, -1, -1):
            if queue[index].get('status') not in OPEN_STATES:
                queue.pop(index)
                break
        else:
            queue.pop()

    push_event_locked(
        event_type='info',
        severity='info',
        title='Device Command Queued',
        description=f"'{command_type}' queued for {device_id}; delivered on its next heartbeat.",
        device_id=device_id,
    )
    return command


def take_commands_for_delivery_locked(device_id: str) -> list[dict[str, Any]]:
    """Commands to put in this heartbeat response, oldest first.

    Marks them delivered. A delivered command with no result after
    REDELIVER_AFTER_SECONDS is offered again, so a lost HTTP response does not
    strand it.
    """
    expire_commands_locked(device_id)
    now = datetime.now(timezone.utc)
    outgoing: list[dict[str, Any]] = []

    for command in reversed(STATE.get('commands', {}).get(device_id, [])):
        status = command.get('status')
        if status == 'queued':
            pass
        elif status == 'delivered':
            delivered = _parse(command.get('deliveredAt'))
            if not delivered or (now - delivered).total_seconds() < REDELIVER_AFTER_SECONDS:
                continue
            if int(command.get('attempts', 0)) >= MAX_DELIVERY_ATTEMPTS:
                command['status'] = 'failed'
                command['completedAt'] = utc_now_iso()
                command['result'] = 'Delivered repeatedly but the device never reported a result.'
                continue
        else:
            continue

        command['status'] = 'delivered'
        command['attempts'] = int(command.get('attempts', 0)) + 1
        command['deliveredAt'] = utc_now_iso()
        outgoing.append({'id': command['id'], 'type': command['type'], 'params': command.get('params', {})})

    return outgoing


def complete_command_locked(device_id: str, command_id: str, ok: bool, detail: str = '') -> dict[str, Any] | None:
    for command in STATE.get('commands', {}).get(device_id, []):
        if command.get('id') != command_id:
            continue
        if command.get('status') in OPEN_STATES:
            command['status'] = 'succeeded' if ok else 'failed'
            command['completedAt'] = utc_now_iso()
            command['result'] = detail[:500] or None
            push_event_locked(
                event_type='info',
                severity='success' if ok else 'warning',
                title='Device Command Completed' if ok else 'Device Command Failed',
                description=f"{device_id}: '{command.get('type')}' {'succeeded' if ok else 'failed'}"
                + (f' — {detail[:200]}' if detail else '.'),
                device_id=device_id,
            )
        return command
    return None


def cancel_open_commands_locked(device_id: str, command_type: str | None = None) -> int:
    cancelled = 0
    for command in STATE.get('commands', {}).get(device_id, []):
        if command.get('status') == 'queued' and (command_type is None or command.get('type') == command_type):
            command['status'] = 'cancelled'
            command['completedAt'] = utc_now_iso()
            cancelled += 1
    return cancelled
