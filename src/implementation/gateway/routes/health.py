"""
SentinelOTA Edge Gateway — Route: Health & Root
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from ..state import gateway_snapshot
from ..utils import utc_now_iso

router = APIRouter()


@router.get('/')
def root() -> dict[str, Any]:
    return {
        'service': 'SentinelOTA Edge Gateway',
        'status': 'running',
        'time': utc_now_iso(),
        'endpoints': {
            'health': '/healthz',
            'dashboard': '/api/dashboard',
            'manifest': '/releases/latest/manifest',
            'publicKey': '/releases/latest/public-key',
            'download': '/releases/download/{filename}',
            'heartbeat': '/api/heartbeat',
            'releases': '/api/releases',
            'deployments': '/api/deployments',
        },
    }


@router.get('/healthz')
def healthz() -> dict[str, Any]:
    snapshot = gateway_snapshot()
    return {
        'ok': True,
        'service': 'edge-gateway',
        'time': utc_now_iso(),
        'deviceCount': len(snapshot.get('devices', {})),
        'releaseCount': len(snapshot.get('releases', [])),
        'latestManifestVersion': (snapshot.get('manifest') or {}).get('version'),
    }
