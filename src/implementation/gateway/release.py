"""
SentinelOTA Edge Gateway — Release, Manifest, and Pipeline Logic
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .config import (
    DEFAULT_RELEASE_ARTIFACT,
    FIRMWARE_CACHE_DIR,
    MANIFEST_FILE,
    MAX_RELEASES,
    SIGNING_ALGORITHM,
    SIGNING_KEY_ID,
)
from .crypto import sign_firmware_payload
from .state import STATE, push_event_locked, persist_state_locked
from .utils import (
    firmware_download_url,
    normalize_version,
    safe_cache_path,
    sha256_bytes,
    utc_now_iso,
)


def resolve_release_artifact_path(version: str, source_file_path: str | None) -> Path:
    """Locate the firmware .bin artifact for a release."""
    candidates: list[Path] = []

    if source_file_path:
        provided = Path(source_file_path).expanduser()
        if not provided.is_absolute():
            provided = (Path.cwd() / provided).resolve()
        candidates.append(provided)

    if DEFAULT_RELEASE_ARTIFACT:
        configured = Path(DEFAULT_RELEASE_ARTIFACT.format(version=version)).expanduser()
        if not configured.is_absolute():
            configured = (Path.cwd() / configured).resolve()
        candidates.append(configured)

    for candidate in candidates:
        if candidate.exists() and candidate.is_file() and candidate.suffix.lower() == '.bin':
            return candidate

    checked_paths = ', '.join(str(path) for path in candidates) if candidates else '(none)'
    raise ValueError(
        'Release artifact not found. Provide sourceFilePath in the release payload or set '
        f'OTA_GATEWAY_RELEASE_ARTIFACT. Checked: {checked_paths}'
    )


def load_release_artifact(version: str, source_file_path: str | None) -> tuple[Path, bytes]:
    """Load and validate a release artifact."""
    artifact_path = resolve_release_artifact_path(version, source_file_path)
    artifact_bytes = artifact_path.read_bytes()
    if not artifact_bytes:
        raise ValueError(f'Release artifact {artifact_path} is empty.')
    return artifact_path, artifact_bytes


def build_pipeline(
    release_id: str,
    stages_data: list[dict[str, Any]],
    started_at: datetime,
) -> dict[str, Any]:
    """Assemble a pipeline record from stages that actually executed.

    This used to fabricate four stages with hardcoded durations, all marked
    'success', describing a build that never ran. Every field here is now
    measured or read back from the artifact — including a real integrity
    re-check — and a failed stage is reported as failed.
    """
    stages: list[dict[str, Any]] = []
    total_duration = 0.0
    overall = 'success'

    for entry in stages_data:
        duration = float(entry.get('duration', 0.0))
        total_duration += duration
        if entry.get('status') != 'success':
            overall = 'failed'

        stages.append(
            {
                'id': f"stage-{uuid.uuid4().hex[:8]}",
                'name': entry['name'],
                'status': entry.get('status', 'success'),
                'startTime': entry['startTime'],
                'endTime': entry['endTime'],
                'logs': entry.get('logs', ''),
                'duration': round(duration, 3),
            }
        )

    return {
        'id': f"pipeline-{uuid.uuid4().hex[:10]}",
        'releaseId': release_id,
        'createdAt': started_at.replace(microsecond=0).isoformat(),
        'stages': stages,
        'status': overall,
        'totalDuration': round(total_duration, 3),
    }


def manifest_for_release_locked(release: dict[str, Any] | None) -> dict[str, Any] | None:
    """Build the signed manifest for an arbitrary release.

    Only the newest release's manifest is kept in STATE, so serving a
    per-architecture manifest means reconstructing older ones from the cached
    binary. The signature is recomputed over the actual bytes on disk, so a
    manifest can never describe a file the gateway no longer has.

    Must be called under STATE_LOCK.
    """
    if not release:
        return None

    version = str(release.get('version', ''))

    # Fast path: the in-memory manifest already describes this release.
    current = STATE.get('manifest')
    if isinstance(current, dict) and str(current.get('version', '')) == version:
        return current

    assets = release.get('assets') or []
    filename = str(assets[0].get('name', '')) if assets else f'firmware_v{version}.bin'

    firmware_path = safe_cache_path(filename)
    if not firmware_path or not firmware_path.exists():
        return None

    payload = firmware_path.read_bytes()
    if not payload:
        return None

    download_url = firmware_download_url(filename)
    return {
        'version': version,
        'filename': filename,
        'sha256': sha256_bytes(payload),
        'size': len(payload),
        'signature': sign_firmware_payload(payload),
        'signatureAlgorithm': SIGNING_ALGORITHM,
        'signatureKeyId': SIGNING_KEY_ID,
        'min_hw_rev': '1.0',
        'generated_at': str(release.get('releaseDate', utc_now_iso())),
        'url': download_url,
        'downloadUrl': download_url,
        'compatible': [str(entry) for entry in release.get('compatible', [])],
    }


def latest_release_for_device_locked(device_type: str) -> dict[str, Any] | None:
    """Newest published release whose `compatible` list covers `device_type`.

    Releases are stored newest-first. A release with an empty `compatible`
    list is treated as universal, which keeps releases created before
    compatibility was enforced usable.

    Must be called under STATE_LOCK.
    """
    for release in STATE.get('releases', []):
        if str(release.get('status', 'published')) != 'published':
            continue

        compatible = [str(entry) for entry in release.get('compatible', [])]
        if not compatible or device_type in compatible:
            return release

    return None


def create_release_locked(
    version: str,
    description: str,
    changelog: str,
    compatible: list[str],
    source_file_path: str | None = None,
    status: str = 'published',
    inferred_download_count: int = 0,
    artifact_bytes: bytes | None = None,
    artifact_label: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Create a release, manifest, and pipeline. Must be called under STATE_LOCK.

    The firmware payload comes from one of two places:
      * `artifact_bytes` — raw bytes uploaded over HTTP (web UI publish flow).
      * `source_file_path` / OTA_GATEWAY_RELEASE_ARTIFACT — a path on the
        gateway's own filesystem (CLI / automation flow).
    `artifact_bytes` wins when both are supplied.
    """
    normalized_version = normalize_version(version)

    existing_versions = {str(release.get('version', '')) for release in STATE['releases']}
    if normalized_version in existing_versions:
        raise ValueError(f'Release {normalized_version} already exists.')

    # Each stage below is timed as it runs; the pipeline record is built from
    # these measurements rather than invented.
    pipeline_started = datetime.now(timezone.utc)
    stages_data: list[dict[str, Any]] = []

    def _stage(name: str, begin: datetime, logs: str, status: str = 'success') -> None:
        end = datetime.now(timezone.utc)
        stages_data.append(
            {
                'name': name,
                'status': status,
                'startTime': begin.replace(microsecond=0).isoformat(),
                'endTime': end.replace(microsecond=0).isoformat(),
                'logs': logs,
                'duration': (end - begin).total_seconds(),
            }
        )

    # ── Stage 1: acquire the artifact ──────────────────────────────
    stage_begin = datetime.now(timezone.utc)
    if artifact_bytes is not None:
        if not artifact_bytes:
            raise ValueError('Uploaded firmware artifact is empty.')
        firmware_payload = artifact_bytes
        source_artifact = artifact_label or 'uploaded via web UI'
    else:
        artifact_path, firmware_payload = load_release_artifact(normalized_version, source_file_path)
        source_artifact = str(artifact_path)

    checksum = sha256_bytes(firmware_payload)
    _stage(
        'artifact',
        stage_begin,
        f'Received {len(firmware_payload)} bytes from {source_artifact}; sha256={checksum}.',
    )

    # ── Stage 2: persist to the firmware cache ─────────────────────
    stage_begin = datetime.now(timezone.utc)
    filename = f"firmware_v{normalized_version}.bin"
    firmware_path = FIRMWARE_CACHE_DIR / filename
    with open(firmware_path, 'wb') as firmware_file:
        firmware_file.write(firmware_payload)
    _stage('store', stage_begin, f'Wrote {firmware_path.name} to the gateway firmware cache.')

    generated_at = utc_now_iso()
    release_id = f"release-{normalized_version.replace('.', '-')}-{uuid.uuid4().hex[:6]}"

    release = {
        'id': release_id,
        'version': normalized_version,
        'releaseDate': generated_at,
        'description': description,
        'assets': [
            {
                'id': f"asset-{uuid.uuid4().hex[:10]}",
                'name': filename,
                'size': len(firmware_payload),
                'checksum': checksum,
                'createdAt': generated_at,
            }
        ],
        'compatible': compatible,
        'changelog': changelog,
        'downloadCount': inferred_download_count,
        'status': status,
        'sourceArtifact': source_artifact,
    }

    # ── Stage 3: sign the manifest ─────────────────────────────────
    stage_begin = datetime.now(timezone.utc)
    signature = sign_firmware_payload(firmware_payload)
    manifest = {
        'version': normalized_version,
        'filename': filename,
        'sha256': checksum,
        'size': len(firmware_payload),
        'signature': signature,
        'signatureAlgorithm': SIGNING_ALGORITHM,
        'signatureKeyId': SIGNING_KEY_ID,
        'min_hw_rev': '1.0',
        'generated_at': generated_at,
        'url': firmware_download_url(filename),
        # The ESP32 firmware reads `downloadUrl` first and only falls back to
        # rebuilding the URL from BACKEND_URL + filename. Emit both keys.
        'downloadUrl': firmware_download_url(filename),
        'compatible': compatible,
    }
    _stage(
        'sign',
        stage_begin,
        f'Manifest signed with {SIGNING_ALGORITHM} key {SIGNING_KEY_ID}; '
        f'targets={", ".join(compatible) or "all"}.',
    )

    # ── Stage 4: verify what was actually written to disk ──────────
    # A genuine integrity check: read the cached file back and confirm it
    # hashes to the value published in the manifest. Catches a truncated or
    # corrupted write before any device downloads it.
    stage_begin = datetime.now(timezone.utc)
    try:
        written_back = firmware_path.read_bytes()
        readback_checksum = sha256_bytes(written_back)
        if readback_checksum == checksum and len(written_back) == len(firmware_payload):
            _stage(
                'verify',
                stage_begin,
                f'Re-read {len(written_back)} bytes from cache; sha256 matches the signed manifest.',
            )
        else:
            _stage(
                'verify',
                stage_begin,
                f'Integrity mismatch: cache sha256={readback_checksum} '
                f'({len(written_back)} bytes) vs manifest {checksum} '
                f'({len(firmware_payload)} bytes).',
                status='failed',
            )
            raise ValueError(
                'Firmware failed post-write integrity check; release not published.'
            )
    except OSError as error:
        _stage('verify', stage_begin, f'Could not re-read cached firmware: {error}', status='failed')
        raise ValueError(f'Firmware cache is unreadable: {error}') from error

    pipeline = build_pipeline(release_id, stages_data, pipeline_started)

    STATE['releases'].insert(0, release)
    STATE['releases'] = STATE['releases'][:MAX_RELEASES]
    STATE['manifest'] = manifest
    STATE['pipeline'] = pipeline

    with open(MANIFEST_FILE, 'w', encoding='utf-8') as manifest_file:
        json.dump(manifest, manifest_file, indent=2)

    push_event_locked(
        event_type='deployment',
        severity='success',
        title='Release Published',
        description=f"Firmware v{normalized_version} published with {len(compatible)} target architecture(s).",
    )

    return release, manifest, pipeline
