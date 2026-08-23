"""
SentinelOTA Edge Gateway — Route: Dashboard & Events
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from ..config import MAX_EVENTS
from ..state import gateway_snapshot
from ..utils import get_pi_status, utc_now_iso

router = APIRouter()


@router.get('/api/dashboard')
def get_dashboard_data() -> dict[str, Any]:
    snapshot = gateway_snapshot()
    devices = list(snapshot.get('devices', {}).values())
    ash_devices = [
        {
            'id': device['id'],
            'score': device.get('ash', 0),
            'status': device.get('status', 'Unknown'),
        }
        for device in devices
    ]

    return {
        'pi_stats': get_pi_status(),
        'devices': devices,
        'ash_devices': ash_devices,
        'alerts': snapshot.get('alerts', []),
        'events': snapshot.get('events', []),
        'releases': snapshot.get('releases', []),
        'pipeline': snapshot.get('pipeline'),
        'keys': snapshot.get('keys', []),
        'certificates': snapshot.get('certificates', []),
        'deployments': snapshot.get('deployments', []),
        'generatedAt': utc_now_iso(),
    }


@router.get('/api/events')
def list_events(limit: int = 100) -> dict[str, Any]:
    snapshot = gateway_snapshot()
    normalized_limit = max(1, min(limit, MAX_EVENTS))
    return {'ok': True, 'events': snapshot.get('events', [])[:normalized_limit]}
