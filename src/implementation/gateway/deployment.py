"""
SentinelOTA Edge Gateway — Deployment Logic

A deployment is an *assignment*, not an action the gateway can perform. The
gateway cannot push firmware: devices poll, download, flash, and reboot on
their own schedule. So a deployment records which devices should end up on
which release, and is only resolved by evidence — a heartbeat reporting the
target version.

The previous implementation wrote the target version straight into the device
record and logged success. Nothing had happened; the next real heartbeat
overwrote it with the device's actual version. This module never invents
device state.

Lifecycle of one target:

    pending ──heartbeat reports target version──▶ confirmed
       │
       ├──incompatible architecture──▶ failed (never dispatched)
       ├──ASH below quarantine──────▶ failed (never dispatched)
       └──deadline passes───────────▶ failed (timed out)

All functions here assume the caller holds STATE_LOCK.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from .config import MAX_RELEASES
from .state import STATE, push_alert_locked, push_event_locked
from .utils import safe_int, utc_now_iso, version_score

# How long a device has to pick up an assignment before it is considered
# failed. Devices poll every OTA_CHECK_INTERVAL_SECONDS (30s by default), so
# this allows for a device that is asleep, off-network, or mid-reboot.
DEPLOYMENT_TIMEOUT_MINUTES = 30

QUARANTINE_ASH_THRESHOLD = 40


def _iso_to_datetime(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def _recount(deployment: dict[str, Any]) -> None:
    """Recompute counters and overall status from the per-target states."""
    targets: dict[str, Any] = deployment.get('targets', {})
    states = [str(target.get('state', 'pending')) for target in targets.values()]

    confirmed = states.count('confirmed')
    failed = states.count('failed')
    pending = states.count('pending')
    cancelled = states.count('cancelled')

    deployment['successCount'] = confirmed
    deployment['failureCount'] = failed
    deployment['pendingCount'] = pending
    deployment['cancelledCount'] = cancelled

    if pending:
        deployment['status'] = 'in_progress'
        deployment['completedAt'] = None
        return

    if confirmed and (failed or cancelled):
        deployment['status'] = 'partial'
    elif confirmed:
        deployment['status'] = 'success'
    elif cancelled and not failed:
        deployment['status'] = 'cancelled'
    else:
        deployment['status'] = 'failed'

    if not deployment.get('completedAt'):
        deployment['completedAt'] = utc_now_iso()


def create_deployment_locked(
    release: dict[str, Any],
    device_ids: list[str],
) -> dict[str, Any]:
    """Assign `release` to `device_ids`. Never mutates device firmware state."""
    version = str(release.get('version', '0.0.0'))
    compatible = [str(entry) for entry in release.get('compatible', [])]
    now_iso = utc_now_iso()
    deadline = (
        datetime.now(timezone.utc) + timedelta(minutes=DEPLOYMENT_TIMEOUT_MINUTES)
    ).replace(microsecond=0).isoformat()

    targets: dict[str, Any] = {}
    logs: list[str] = []

    for device_id in device_ids:
        device = STATE['devices'].get(device_id)

        if not device:
            targets[device_id] = {
                'state': 'failed',
                'reason': 'Device is not registered on this gateway.',
                'fromVersion': None,
                'confirmedAt': None,
            }
            logs.append(f'{device_id}: not registered — skipped.')
            continue

        device_arch = str(device.get('arch', ''))
        current_version = str(device.get('fw', '0.0.0'))
        ash = safe_int(device.get('ash', 0), 0)

        # Architecture gate. Serving ESP32 firmware to an ESP8266 would brick
        # it, so an incompatible target is refused outright rather than
        # dispatched and left to the device to reject.
        if compatible and device_arch not in compatible:
            targets[device_id] = {
                'state': 'failed',
                'reason': f'Release targets {", ".join(compatible)}; device is {device_arch}.',
                'fromVersion': current_version,
                'confirmedAt': None,
            }
            logs.append(f'{device_id}: incompatible architecture ({device_arch}) — not dispatched.')
            continue

        if ash <= QUARANTINE_ASH_THRESHOLD:
            targets[device_id] = {
                'state': 'failed',
                'reason': f'Device quarantined (ASH={ash}).',
                'fromVersion': current_version,
                'confirmedAt': None,
            }
            logs.append(f'{device_id}: blocked by ASH quarantine ({ash}).')
            push_event_locked(
                event_type='security',
                severity='error',
                title='Deployment Blocked by ASH Policy',
                description=f'Device {device_id} excluded from deployment (ASH={ash}).',
                device_id=device_id,
            )
            continue

        # Already running the target build — nothing to wait for.
        if version_score(current_version) == version_score(version):
            targets[device_id] = {
                'state': 'confirmed',
                'reason': 'Already running the target version.',
                'fromVersion': current_version,
                'confirmedAt': now_iso,
            }
            logs.append(f'{device_id}: already on v{version}.')
            continue

        if version_score(version) < version_score(current_version):
            targets[device_id] = {
                'state': 'failed',
                'reason': f'Anti-rollback: device is on v{current_version}, newer than v{version}.',
                'fromVersion': current_version,
                'confirmedAt': None,
            }
            logs.append(f'{device_id}: rollback refused (v{current_version} -> v{version}).')
            continue

        targets[device_id] = {
            'state': 'pending',
            'reason': None,
            'fromVersion': current_version,
            'confirmedAt': None,
        }
        logs.append(f'{device_id}: assigned v{version}, awaiting device check-in.')

    deployment = {
        'id': f"deployment-{uuid.uuid4().hex[:10]}",
        'releaseId': str(release.get('id', '')),
        'version': version,
        'deviceIds': list(device_ids),
        'targets': targets,
        'startedAt': now_iso,
        'completedAt': None,
        'deadline': deadline,
        'status': 'in_progress',
        'successCount': 0,
        'failureCount': 0,
        'pendingCount': 0,
        'logs': '\n'.join(logs),
    }

    _recount(deployment)

    # Nudge every pending target. Without this a device only notices the
    # assignment on its next poll timer; with it, the next heartbeat (≤15 s)
    # tells the device to go and fetch its assigned build.
    from .commands import enqueue_command_locked

    for device_id, target in targets.items():
        if target.get('state') == 'pending':
            command = enqueue_command_locked(
                device_id,
                'update',
                {'version': version, 'deploymentId': deployment['id']},
                requested_by=f"deployment:{deployment['id']}",
            )
            target['commandId'] = command['id']

    STATE['deployments'].insert(0, deployment)
    STATE['deployments'] = STATE['deployments'][:MAX_RELEASES]

    push_event_locked(
        event_type='deployment',
        severity='info',
        title='Deployment Created',
        description=(
            f"Release v{version} assigned to {len(device_ids)} device(s); "
            f"{deployment['pendingCount']} awaiting check-in."
        ),
    )

    return deployment


def confirm_device_version_locked(device_id: str, reported_version: str) -> list[str]:
    """Resolve pending targets for a device that just reported a version.

    Called from the heartbeat handler. Returns the ids of deployments that
    changed, so the caller can decide whether to persist.
    """
    changed: list[str] = []
    reported_score = version_score(reported_version)

    for deployment in STATE.get('deployments', []):
        if deployment.get('status') != 'in_progress':
            continue

        target = deployment.get('targets', {}).get(device_id)
        if not target or target.get('state') != 'pending':
            continue

        # Confirm on "at least the target version": a device that jumped
        # straight past the assigned build still satisfies the intent, and
        # would otherwise hang pending until it timed out.
        if reported_score >= version_score(str(deployment.get('version', '0.0.0'))):
            target['state'] = 'confirmed'
            target['confirmedAt'] = utc_now_iso()
            target['reason'] = None
            _recount(deployment)
            changed.append(str(deployment.get('id')))

            push_event_locked(
                event_type='firmware_update',
                severity='success',
                title='Device Updated',
                description=(
                    f"Device {device_id} confirmed on v{reported_version} "
                    f"(deployment {deployment.get('id')})."
                ),
                device_id=device_id,
            )

    return changed


def expire_stale_deployments_locked() -> list[str]:
    """Fail targets still pending past the deadline.

    Evaluated lazily whenever deployments are read or a heartbeat arrives, so
    the gateway needs no background scheduler.
    """
    changed: list[str] = []
    now = datetime.now(timezone.utc)

    for deployment in STATE.get('deployments', []):
        if deployment.get('status') != 'in_progress':
            continue

        deadline = _iso_to_datetime(str(deployment.get('deadline', '')))
        if not deadline or now < deadline:
            continue

        timed_out = 0
        for device_id, target in deployment.get('targets', {}).items():
            if target.get('state') == 'pending':
                target['state'] = 'failed'
                target['reason'] = (
                    f'No check-in within {DEPLOYMENT_TIMEOUT_MINUTES} minutes of assignment.'
                )
                timed_out += 1

        if timed_out:
            _recount(deployment)
            changed.append(str(deployment.get('id')))
            push_alert_locked(
                f"Deployment {deployment.get('id')} timed out for {timed_out} device(s)."
            )
            push_event_locked(
                event_type='deployment',
                severity='warning',
                title='Deployment Timed Out',
                description=(
                    f"{timed_out} device(s) did not check in for deployment "
                    f"{deployment.get('id')}."
                ),
            )

    return changed


# Phases a device reports while it works through an update. They are progress
# information only: a target is confirmed solely by a heartbeat that reports
# the new version, exactly as before. 'failed' and 'rolled_back' are the
# exceptions — the device is telling us the assigned build will not land, so
# waiting out the deadline would only hide the reason.
OTA_PHASES = (
    'checking',
    'downloading',
    'verifying',
    'installing',
    'rebooting',
    'health_check',
    'succeeded',
    'failed',
    'rolled_back',
)
TERMINAL_FAILURE_PHASES = {'failed', 'rolled_back'}


def record_ota_status_locked(
    device_id: str,
    phase: str,
    version: str,
    progress: int | None,
    detail: str,
) -> list[str]:
    """Attach a device's OTA progress report to its pending deployment targets."""
    changed: list[str] = []
    reported_score = version_score(version) if version else None
    now_iso = utc_now_iso()

    for deployment in STATE.get('deployments', []):
        if deployment.get('status') != 'in_progress':
            continue
        target = deployment.get('targets', {}).get(device_id)
        if not target or target.get('state') != 'pending':
            continue
        # A report about some other version (an auto-update racing the
        # deployment, say) says nothing about this assignment.
        if reported_score is not None and reported_score != version_score(str(deployment.get('version', '0.0.0'))):
            continue

        target['phase'] = phase
        target['progress'] = progress
        target['phaseDetail'] = detail or None
        target['phaseAt'] = now_iso

        if phase in TERMINAL_FAILURE_PHASES:
            target['state'] = 'failed'
            target['reason'] = (
                f"Device rolled back to its previous firmware: {detail}" if phase == 'rolled_back'
                else f"Device reported update failure: {detail or 'no detail given'}"
            )
            _recount(deployment)
            push_alert_locked(f"Deployment {deployment.get('id')}: {device_id} {phase.replace('_', ' ')} — {detail or 'no detail'}.")
            push_event_locked(
                event_type='firmware_update',
                severity='error',
                title='Device Update Failed' if phase == 'failed' else 'Device Rolled Back',
                description=f"{device_id} could not install v{deployment.get('version')}: {detail or 'no detail given'}.",
                device_id=device_id,
            )
        changed.append(str(deployment.get('id')))

    return changed


def find_deployment_locked(deployment_id: str) -> dict[str, Any] | None:
    return next((d for d in STATE.get('deployments', []) if d.get('id') == deployment_id), None)


def cancel_deployment_locked(deployment: dict[str, Any], actor: str = 'dashboard') -> int:
    """Stop waiting on every pending target and withdraw its queued command.

    A device that already started downloading cannot be stopped mid-flash —
    that is the device's decision — so a target that later reports the new
    version still shows as cancelled here, and the device record shows the
    truth. Returns how many targets were cancelled.
    """
    from .commands import OPEN_STATES

    cancelled = 0
    for device_id, target in deployment.get('targets', {}).items():
        if target.get('state') != 'pending':
            continue
        target['state'] = 'cancelled'
        target['reason'] = f'Cancelled by {actor} before the device confirmed.'
        cancelled += 1
        command_id = target.get('commandId')
        for command in STATE.get('commands', {}).get(device_id, []):
            if command.get('id') == command_id and command.get('status') == 'queued':
                command['status'] = 'cancelled'
                command['completedAt'] = utc_now_iso()
            elif command.get('id') == command_id and command.get('status') in OPEN_STATES:
                command['result'] = 'Deployment cancelled after the device received this command.'

    if cancelled:
        _recount(deployment)
        push_event_locked(
            event_type='deployment',
            severity='warning',
            title='Deployment Cancelled',
            description=f"{cancelled} pending target(s) of {deployment.get('id')} cancelled by {actor}.",
        )
    return cancelled


def retry_targets(deployment: dict[str, Any]) -> list[str]:
    """Device ids worth another attempt: those that failed or were cancelled."""
    return [
        device_id
        for device_id, target in deployment.get('targets', {}).items()
        if target.get('state') in {'failed', 'cancelled'}
    ]
