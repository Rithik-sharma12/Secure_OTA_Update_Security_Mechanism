"""
SentinelOTA Edge Gateway — Route: Operations (Pipeline, Sync, Download)
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from ..config import FIRMWARE_CACHE_DIR
from ..models import PipelineRunPayload
from ..release import build_pipeline
from ..state import (
    STATE,
    STATE_LOCK,
    persist_state_locked,
    push_alert_locked,
    push_event_locked,
)
from ..utils import safe_cache_path, safe_int, utc_now_iso
from ..auth import require_write_auth

router = APIRouter()


# Real API key guard, imported directly so Depends() captures the actual
# function (see gateway/auth.py for why this must not be monkey-patched).
_require_write_auth = require_write_auth


@router.post('/api/pipeline/run')
def run_pipeline(payload: PipelineRunPayload, _auth: None = Depends(_require_write_auth)) -> dict[str, Any]:
    with STATE_LOCK:
        releases = STATE.get('releases', [])
        if not releases:
            raise HTTPException(status_code=404, detail='No releases available.')

        selected_release = releases[0]
        if payload.releaseId:
            match = next((release for release in releases if release.get('id') == payload.releaseId), None)
            if not match:
                raise HTTPException(status_code=404, detail=f'Release {payload.releaseId} not found.')
            selected_release = match

        pipeline = build_pipeline(str(selected_release.get('id')))
        STATE['pipeline'] = pipeline
        STATE['updatedAt'] = utc_now_iso()
        push_event_locked(
            event_type='info',
            severity='success',
            title='Pipeline Executed',
            description=f"Pipeline rerun completed for release {selected_release.get('version', 'unknown')}.",
        )
        persist_state_locked()

    return {'ok': True, 'pipeline': pipeline}


@router.post('/api/trigger_sync')
def trigger_sync(_auth: None = Depends(_require_write_auth)) -> dict[str, Any]:
    with STATE_LOCK:
        # 'releases' is always present but may be empty on a fresh gateway, so
        # a dict default on .get() never fires — index defensively instead.
        releases = STATE.get('releases') or []
        latest_release = releases[0] if releases else {}
        push_alert_locked(
            f"Manual sync requested for release {latest_release.get('version', 'unknown')}."
        )
        push_event_locked(
            event_type='info',
            severity='info',
            title='Gateway Sync Triggered',
            description='A manual synchronization request was accepted by the gateway.',
        )
        STATE['updatedAt'] = utc_now_iso()
        persist_state_locked()

    return {'ok': True, 'message': 'Sync request accepted.'}


@router.get('/releases/download/{filename}')
def download_firmware(filename: str) -> Any:
    file_path = safe_cache_path(filename)
    if not file_path:
        raise HTTPException(status_code=400, detail='Invalid firmware filename')

    if not file_path.exists():
        raise HTTPException(status_code=404, detail='Firmware not cached on gateway')

    with STATE_LOCK:
        for release in STATE.get('releases', []):
            assets = release.get('assets', [])
            if assets and assets[0].get('name') == filename:
                release['downloadCount'] = safe_int(release.get('downloadCount', 0), 0) + 1
                STATE['updatedAt'] = utc_now_iso()
                persist_state_locked()
                break

    return FileResponse(path=file_path, media_type='application/octet-stream', filename=filename)
