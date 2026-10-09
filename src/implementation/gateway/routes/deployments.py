"""
SentinelOTA Edge Gateway — Route: Deployments
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from ..audit import audit_note
from ..deployment import (
    cancel_deployment_locked,
    create_deployment_locked,
    expire_stale_deployments_locked,
    find_deployment_locked,
    retry_targets,
)
from ..models import DeploymentCreatePayload
from ..state import (
    STATE,
    STATE_LOCK,
    gateway_snapshot,
    persist_state_locked,
)
from ..utils import utc_now_iso
from ..auth import require_write_auth

router = APIRouter()


# Real API key guard, imported directly so Depends() captures the actual
# function (see gateway/auth.py for why this must not be monkey-patched).
_require_write_auth = require_write_auth


@router.get('/api/deployments')
def list_deployments() -> dict[str, Any]:
    # Deadlines are evaluated lazily on read, so no background scheduler is
    # needed for a deployment to eventually stop showing as in-progress.
    with STATE_LOCK:
        if expire_stale_deployments_locked():
            STATE['updatedAt'] = utc_now_iso()
            persist_state_locked()

    snapshot = gateway_snapshot()
    return {'ok': True, 'deployments': snapshot.get('deployments', [])}


@router.post('/api/deployments')
def create_deployment(payload: DeploymentCreatePayload, request: Request, _auth: None = Depends(_require_write_auth)) -> dict[str, Any]:
    with STATE_LOCK:
        releases = STATE.get('releases', [])
        if not releases:
            raise HTTPException(status_code=404, detail='No releases available for deployment.')

        selected_release = releases[0]
        if payload.releaseId:
            match = next((release for release in releases if release.get('id') == payload.releaseId), None)
            if not match:
                raise HTTPException(status_code=404, detail=f'Release {payload.releaseId} not found.')
            selected_release = match

        if payload.deviceIds:
            target_device_ids = [str(device_id) for device_id in payload.deviceIds]
        else:
            target_device_ids = list(STATE.get('devices', {}).keys())

        if not target_device_ids:
            raise HTTPException(status_code=400, detail='No target devices available for deployment.')

        # Records the assignment only. Devices are marked updated when a
        # heartbeat proves it — the gateway cannot push, so it must not claim
        # a device updated before the device says so.
        deployment = create_deployment_locked(selected_release, target_device_ids)

        STATE['updatedAt'] = utc_now_iso()
        persist_state_locked()

    audit_note(
        request,
        'deployment.created',
        f"v{deployment['version']} -> {len(target_device_ids)} device(s): "
        f"{deployment['pendingCount']} pending, {deployment['failureCount']} refused",
        target_device_ids[0] if len(target_device_ids) == 1 else None,
    )
    return {'ok': True, 'deployment': deployment}


@router.post('/api/deployments/{deployment_id}/cancel')
def cancel_deployment(deployment_id: str, request: Request, _auth: None = Depends(_require_write_auth)) -> dict[str, Any]:
    with STATE_LOCK:
        deployment = find_deployment_locked(deployment_id)
        if not deployment:
            raise HTTPException(status_code=404, detail=f'Deployment {deployment_id} not found.')
        cancelled = cancel_deployment_locked(deployment, request.headers.get('x-actor') or 'dashboard')
        if not cancelled:
            raise HTTPException(status_code=409, detail='Nothing to cancel: no target is still pending.')
        STATE['updatedAt'] = utc_now_iso()
        persist_state_locked()
        result = dict(deployment)
    audit_note(request, 'deployment.cancelled', f'{deployment_id}: {cancelled} target(s) cancelled')
    return {'ok': True, 'deployment': result, 'cancelled': cancelled}


@router.post('/api/deployments/{deployment_id}/retry')
def retry_deployment(deployment_id: str, request: Request, _auth: None = Depends(_require_write_auth)) -> dict[str, Any]:
    """New deployment of the same release for the targets that failed or were cancelled.

    A new record rather than a rewrite, so the history of the first attempt and
    its failure reasons stays visible.
    """
    with STATE_LOCK:
        previous = find_deployment_locked(deployment_id)
        if not previous:
            raise HTTPException(status_code=404, detail=f'Deployment {deployment_id} not found.')
        device_ids = retry_targets(previous)
        if not device_ids:
            raise HTTPException(status_code=409, detail='Nothing to retry: no target failed or was cancelled.')
        release = next((r for r in STATE.get('releases', []) if r.get('id') == previous.get('releaseId')), None)
        if not release:
            raise HTTPException(status_code=404, detail='The release of that deployment no longer exists.')
        deployment = create_deployment_locked(release, device_ids)
        deployment['retryOf'] = deployment_id
        STATE['updatedAt'] = utc_now_iso()
        persist_state_locked()
    audit_note(request, 'deployment.retried', f'{deployment_id} -> {deployment["id"]} for {len(device_ids)} device(s)')
    return {'ok': True, 'deployment': deployment}
