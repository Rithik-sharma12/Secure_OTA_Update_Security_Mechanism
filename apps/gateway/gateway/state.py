"""
SecureOTA Edge Gateway — State Management

Thread-safe gateway state with persistence to JSON.
"""

from __future__ import annotations

import copy
import json
from threading import Lock
from typing import Any

from .config import (
    FIRMWARE_CACHE_DIR,
    MANIFEST_FILE,
    MAX_ALERTS,
    MAX_EVENTS,
    STATE_FILE,
)
from .crypto import build_signing_metadata, with_manifest_signature
from .utils import utc_now_iso

import uuid

# ── Global State ──────────────────────────────────────────────
STATE_LOCK = Lock()
STATE: dict[str, Any] = {}


# Held for the life of the process; see claim_state_ownership().
_OWNERSHIP_HANDLE: Any = None


def claim_state_ownership() -> None:
    """Refuse to start if another gateway process is using this cache dir.

    STATE lives in this process's memory and is written back to one JSON file
    under a threading lock. A second process (uvicorn --workers 2, two
    replicas on one volume) would hold its own copy and the two would
    overwrite each other's releases, devices and tokens. Run one process per
    cache directory; this makes the mistake fail at startup instead of losing
    data later.

    Uses an advisory flock, which the OS drops when the process exits. Where
    fcntl is unavailable (Windows) the check is skipped.
    """
    global _OWNERSHIP_HANDLE
    if _OWNERSHIP_HANDLE is not None:
        return
    try:
        import fcntl
    except ImportError:  # pragma: no cover - Windows
        return

    handle = open(FIRMWARE_CACHE_DIR / 'gateway.lock', 'a+', encoding='utf-8')
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        raise RuntimeError(
            f'Another gateway process is already using {FIRMWARE_CACHE_DIR}. The gateway '
            'keeps its state in memory and must run as a single process per cache '
            'directory (no uvicorn --workers > 1, no shared volume between replicas).'
        ) from None
    _OWNERSHIP_HANDLE = handle


def default_state() -> dict[str, Any]:
    """Return a clean default state structure."""
    now_iso = utc_now_iso()
    return {
        'createdAt': now_iso,
        'updatedAt': now_iso,
        'devices': {},
        'alerts': [],
        'events': [],
        'releases': [],
        'manifest': None,
        'pipeline': None,
        'keys': [],
        'certificates': [],
        'deployments': [],
        # device_id -> list of remote commands (see gateway/commands.py)
        'commands': {},
        # device_id -> {'tokenHash', 'createdAt', ...}; never returned by any route
        'deviceCredentials': {},
    }


# Bumped on every persisted change. /api/stream watches it to tell dashboards
# "something changed, refresh" without them having to poll the full state.
STATE_REVISION = 0


def state_revision() -> int:
    return STATE_REVISION


def persist_state_locked() -> None:
    """Write current STATE to disk atomically. Must be called under STATE_LOCK."""
    global STATE_REVISION
    STATE_REVISION += 1
    temp_file = STATE_FILE.with_suffix('.tmp')
    with open(temp_file, 'w', encoding='utf-8') as file:
        json.dump(STATE, file, indent=2)
    temp_file.replace(STATE_FILE)


def push_event_locked(
    event_type: str,
    severity: str,
    title: str,
    description: str,
    device_id: str | None = None,
) -> dict[str, Any]:
    """Push an event to state. Must be called under STATE_LOCK."""
    event = {
        'id': f"event-{uuid.uuid4().hex[:12]}",
        'timestamp': utc_now_iso(),
        'type': event_type,
        'severity': severity,
        'title': title,
        'description': description,
    }
    if device_id:
        event['deviceId'] = device_id

    STATE['events'].insert(0, event)
    STATE['events'] = STATE['events'][:MAX_EVENTS]
    return event


def push_alert_locked(message: str) -> None:
    """Push an alert to state. Must be called under STATE_LOCK."""
    STATE['alerts'].insert(0, f"[{utc_now_iso()}] {message}")
    STATE['alerts'] = STATE['alerts'][:MAX_ALERTS]


def gateway_snapshot() -> dict[str, Any]:
    """Return a deep copy of the current state (thread-safe)."""
    with STATE_LOCK:
        return copy.deepcopy(STATE)


def _refresh_manifest_from_firmware(manifest: dict[str, Any]) -> dict[str, Any] | None:
    """Re-sign and refresh manifest fields from the cached firmware file."""
    from .crypto import sign_firmware_payload
    from .utils import firmware_download_url, normalize_version, safe_cache_path, sha256_bytes

    version = str(manifest.get('version', '')).strip()
    filename = str(manifest.get('filename', '')).strip()
    if not version or not filename:
        return None

    firmware_path = safe_cache_path(filename)
    if not firmware_path or not firmware_path.exists():
        return None

    from .config import SIGNING_ALGORITHM, SIGNING_KEY_ID

    firmware_data = firmware_path.read_bytes()
    refreshed = dict(manifest)
    refreshed['version'] = normalize_version(version)
    refreshed['filename'] = filename
    refreshed['sha256'] = sha256_bytes(firmware_data)
    refreshed['size'] = len(firmware_data)
    refreshed['signature'] = sign_firmware_payload(firmware_data)
    refreshed['signatureAlgorithm'] = SIGNING_ALGORITHM
    refreshed['signatureKeyId'] = SIGNING_KEY_ID
    refreshed['min_hw_rev'] = str(refreshed.get('min_hw_rev') or '1.0')
    refreshed['generated_at'] = str(refreshed.get('generated_at') or utc_now_iso())
    refreshed['url'] = str(refreshed.get('url') or firmware_download_url(filename))
    # Keep downloadUrl in sync — the ESP32 firmware reads that key first.
    refreshed['downloadUrl'] = str(refreshed.get('downloadUrl') or refreshed['url'])
    return with_manifest_signature(refreshed)


def _release_from_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct a release record from a persisted manifest."""
    from .config import DEFAULT_COMPATIBILITY
    from .utils import safe_int

    version = str(manifest.get('version', '0.0.0'))
    filename = str(manifest.get('filename', 'firmware.bin'))
    checksum = str(manifest.get('sha256', 'n/a'))
    size = safe_int(manifest.get('size', 0), 0)
    generated_at = str(manifest.get('generated_at', utc_now_iso()))

    return {
        'id': f"release-{version.replace('.', '-')}-restored",
        'version': version,
        'releaseDate': generated_at,
        'description': 'Release restored from persisted gateway manifest.',
        'assets': [
            {
                'id': f"asset-{checksum[:12] if checksum != 'n/a' else uuid.uuid4().hex[:12]}",
                'name': filename,
                'size': size,
                'checksum': checksum,
                'createdAt': generated_at,
            }
        ],
        'compatible': DEFAULT_COMPATIBILITY.copy(),
        'changelog': 'Restored from persisted gateway state.',
        'downloadCount': 0,
        'status': 'published',
    }


def load_state() -> None:
    """Load persisted gateway state from disk. Initializes signing keys."""
    with STATE_LOCK:
        state = default_state()
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE, 'r', encoding='utf-8') as file:
                    loaded = json.load(file)
                    if isinstance(loaded, dict):
                        state.update(loaded)
            except (OSError, json.JSONDecodeError):
                state = default_state()

        for key in ['devices', 'alerts', 'events', 'releases', 'keys', 'certificates', 'deployments']:
            if key not in state:
                state[key] = [] if key != 'devices' else {}

        if not isinstance(state['devices'], dict):
            state['devices'] = {}
        if not isinstance(state['alerts'], list):
            state['alerts'] = []
        if not isinstance(state['events'], list):
            state['events'] = []
        if not isinstance(state['releases'], list):
            state['releases'] = []
        if not isinstance(state['deployments'], list):
            state['deployments'] = []
        if not isinstance(state.get('commands'), dict):
            state['commands'] = {}
        if not isinstance(state.get('deviceCredentials'), dict):
            state['deviceCredentials'] = {}
        if not isinstance(state.get('keys'), list):
            state['keys'] = default_state()['keys']
        if not isinstance(state.get('certificates'), list):
            state['certificates'] = default_state()['certificates']

        STATE.clear()
        STATE.update(state)

        signing_key, signing_certificate = build_signing_metadata()
        STATE['keys'] = [signing_key]
        STATE['certificates'] = [signing_certificate]

        if isinstance(STATE.get('manifest'), dict):
            refreshed_manifest = _refresh_manifest_from_firmware(STATE['manifest'])
            if refreshed_manifest:
                STATE['manifest'] = refreshed_manifest
                with open(MANIFEST_FILE, 'w', encoding='utf-8') as manifest_file:
                    json.dump(refreshed_manifest, manifest_file, indent=2)

        if not STATE['releases'] and isinstance(STATE.get('manifest'), dict):
            STATE['releases'] = [_release_from_manifest(STATE['manifest'])]

        if not STATE['releases'] and MANIFEST_FILE.exists():
            try:
                with open(MANIFEST_FILE, 'r', encoding='utf-8') as manifest_file:
                    manifest_from_file = json.load(manifest_file)
                if isinstance(manifest_from_file, dict):
                    refreshed_manifest = _refresh_manifest_from_firmware(manifest_from_file)
                    if refreshed_manifest:
                        STATE['manifest'] = refreshed_manifest
                        STATE['releases'] = [_release_from_manifest(refreshed_manifest)]
                        with open(MANIFEST_FILE, 'w', encoding='utf-8') as manifest_file:
                            json.dump(refreshed_manifest, manifest_file, indent=2)
            except (OSError, json.JSONDecodeError, ValueError):
                pass

        STATE['updatedAt'] = utc_now_iso()
        persist_state_locked()
