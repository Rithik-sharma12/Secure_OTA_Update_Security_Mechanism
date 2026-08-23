"""
SentinelOTA Edge Gateway — Route: Deployments
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from ..deployment import create_deployment_locked, expire_stale_deployments_locked
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
def create_deployment(payload: DeploymentCreatePayload, _auth: None = Depends(_require_write_auth)) -> dict[str, Any]:
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

    return {'ok': True, 'deployment': deployment}
