"""
SentinelOTA Edge Gateway — Route: GitHub release webhook

Closes the gap between CI and the fleet. Before this, a tag built and signed
firmware into a GitHub Release, and then an operator downloaded the .bin and
uploaded it to the gateway by hand.

    git tag v2.6.0 ──▶ GitHub Actions builds + signs ──▶ GitHub Release
                                                            │ webhook "release: published"
                                                            ▼
                         POST /api/github/webhook ──▶ verify ──▶ publish on gateway

Trust is checked twice, because a webhook only proves *GitHub* sent the event:

1. The request body must carry a valid `X-Hub-Signature-256` HMAC made with
   OTA_GITHUB_WEBHOOK_SECRET, and come from OTA_GITHUB_REPOSITORY.
2. Every downloaded asset must match the SHA-256 that CI published alongside
   it (release-manifest.json, else checksums.txt). When the gateway is also
   given the release AES key and RSA public key (OTA_RELEASE_AES_KEY,
   OTA_RELEASE_RSA_PUBKEY_PATH) it decrypts each secure package and verifies
   the RSA signature exactly as a device would, and derives the plaintext
   digest itself instead of trusting the published one.

Releases are published, never deployed: rolling out stays an operator
decision (or OTA_AUTO_UPDATE).

Configuration
    OTA_GITHUB_WEBHOOK_SECRET    required; the webhook's secret
    OTA_GITHUB_REPOSITORY        owner/name allowed to publish (recommended)
    OTA_GITHUB_TOKEN             for private repositories' asset downloads
    OTA_GITHUB_ASSET_MAP         asset=board pairs, default
                                 "firmware-esp32.bin=ESP32"
    OTA_RELEASE_AES_KEY          optional, enables full package verification
    OTA_RELEASE_RSA_PUBKEY_PATH  optional, PEM public key matching CI's signer
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import urllib.request
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from ..audit import audit_note
from ..package import PackageError, looks_like_secure_package, open_package, parse_package
from ..release import create_release_locked
from ..state import STATE, STATE_LOCK, persist_state_locked, push_event_locked
from ..utils import normalize_device_type, normalize_version, utc_now_iso

router = APIRouter()

MAX_ASSET_BYTES = 32 * 1024 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 30
TAG_RE = re.compile(r'^v?(\d+)\.(\d+)\.(\d+)$')


def _setting(name: str, default: str = '') -> str:
    return os.getenv(name, default).strip()


def _asset_map() -> dict[str, str]:
    raw = _setting('OTA_GITHUB_ASSET_MAP', 'firmware-esp32.bin=ESP32')
    mapping: dict[str, str] = {}
    for pair in raw.split(','):
        if '=' in pair:
            asset, board = pair.split('=', 1)
            if asset.strip() and board.strip():
                mapping[asset.strip()] = normalize_device_type(board.strip())
    return mapping


def verify_signature(secret: str, body: bytes, header: str | None) -> bool:
    if not header or not header.startswith('sha256='):
        return False
    expected = 'sha256=' + hmac.new(secret.encode('utf-8'), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header.strip())


def download_asset(asset: dict[str, Any]) -> bytes:
    """Fetch one release asset. Private repos need OTA_GITHUB_TOKEN.

    Kept as a module function so tests can replace it.
    """
    token = _setting('OTA_GITHUB_TOKEN')
    if token:
        url = str(asset.get('url', ''))  # API URL; returns the bytes with this Accept header
        headers = {'Accept': 'application/octet-stream', 'Authorization': f'Bearer {token}'}
    else:
        url = str(asset.get('browser_download_url', ''))
        headers = {'Accept': 'application/octet-stream'}
    if not url.startswith('https://'):
        raise ValueError(f"Asset {asset.get('name')} has no https download URL.")
    request = urllib.request.Request(url, headers={**headers, 'User-Agent': 'SentinelOTA-gateway'})
    with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:  # noqa: S310 (https only, checked above)
        data = response.read(MAX_ASSET_BYTES + 1)
    if len(data) > MAX_ASSET_BYTES:
        raise ValueError(f"Asset {asset.get('name')} exceeds {MAX_ASSET_BYTES // (1024 * 1024)} MB.")
    return data


def _parse_checksums(text: str) -> dict[str, str]:
    digests: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) == 2 and re.fullmatch(r'[0-9a-fA-F]{64}', parts[0]):
            digests[parts[1].lstrip('*')] = parts[0].lower()
    return digests


def _full_verification_material() -> tuple[bytes, str] | None:
    key_path = _setting('OTA_RELEASE_RSA_PUBKEY_PATH')
    aes_key = _setting('OTA_RELEASE_AES_KEY')
    if not key_path or not aes_key:
        return None
    return Path(key_path).read_bytes(), aes_key


@router.post('/api/github/webhook')
async def github_webhook(request: Request) -> dict[str, Any]:
    secret = _setting('OTA_GITHUB_WEBHOOK_SECRET')
    if not secret:
        raise HTTPException(status_code=503, detail='GitHub webhook is not configured (OTA_GITHUB_WEBHOOK_SECRET).')

    body = await request.body()
    if not verify_signature(secret, body, request.headers.get('x-hub-signature-256')):
        audit_note(request, 'github.rejected', 'Bad or missing X-Hub-Signature-256')
        raise HTTPException(status_code=401, detail='Webhook signature does not verify.')

    event = request.headers.get('x-github-event', '')
    try:
        payload = json.loads(body or b'{}')
    except json.JSONDecodeError as error:
        raise HTTPException(status_code=400, detail='Body is not JSON.') from error

    if event == 'ping':
        return {'ok': True, 'pong': True}
    if event != 'release' or payload.get('action') not in {'published', 'released'}:
        return {'ok': True, 'ignored': f'{event}:{payload.get("action")}'}

    repository = str((payload.get('repository') or {}).get('full_name', ''))
    allowed_repo = _setting('OTA_GITHUB_REPOSITORY')
    if allowed_repo and repository.lower() != allowed_repo.lower():
        audit_note(request, 'github.rejected', f'Release from unexpected repository {repository}')
        raise HTTPException(status_code=403, detail=f'Releases from {repository} are not accepted.')

    release_info = payload.get('release') or {}
    if release_info.get('draft') or release_info.get('prerelease'):
        return {'ok': True, 'ignored': 'draft or prerelease'}

    tag = str(release_info.get('tag_name', ''))
    if not TAG_RE.match(tag):
        return {'ok': True, 'ignored': f'tag {tag!r} is not a firmware version tag'}
    version = normalize_version(tag)

    assets = {str(asset.get('name')): asset for asset in release_info.get('assets', [])}

    # What CI says each asset is. release-manifest.json is written by the
    # workflow; checksums.txt is the fallback for older releases.
    published: dict[str, dict[str, Any]] = {}
    if 'release-manifest.json' in assets:
        manifest = json.loads(download_asset(assets['release-manifest.json']))
        for name, info in (manifest.get('assets') or {}).items():
            published[name] = info
    elif 'checksums.txt' in assets:
        for name, digest in _parse_checksums(download_asset(assets['checksums.txt']).decode('utf-8', 'replace')).items():
            published[name] = {'sha256': digest}

    full_verify = _full_verification_material()
    created: list[dict[str, Any]] = []
    skipped: list[str] = []

    for asset_name, board in _asset_map().items():
        if asset_name not in assets:
            skipped.append(f'{asset_name}: not attached to {tag}')
            continue
        expected = published.get(asset_name, {})
        expected_sha = str(expected.get('sha256', '')).lower()
        if not expected_sha:
            raise HTTPException(
                status_code=422,
                detail=f'{asset_name} has no published SHA-256 (release-manifest.json or checksums.txt); refusing to publish it.',
            )

        try:
            blob = download_asset(assets[asset_name])
        except (OSError, ValueError) as error:
            raise HTTPException(status_code=502, detail=f'Could not download {asset_name}: {error}') from error

        if hashlib.sha256(blob).hexdigest() != expected_sha:
            push_event_locked_safe('GitHub Release Rejected', f'{tag}/{asset_name} does not match its published SHA-256.')
            raise HTTPException(status_code=422, detail=f'{asset_name} does not match its published SHA-256.')

        image_sha = str(expected.get('imageSha256', '') or '').lower() or None
        secure = expected.get('securePackage')
        if secure is None:
            secure = looks_like_secure_package(blob)

        if full_verify and secure:
            public_key_pem, aes_key = full_verify
            try:
                plaintext = open_package(blob, public_key_pem, aes_key)
            except PackageError as error:
                push_event_locked_safe('GitHub Release Rejected', f'{tag}/{asset_name}: {error}')
                raise HTTPException(status_code=422, detail=f'{asset_name} failed package verification: {error}') from error
            derived = hashlib.sha256(plaintext).hexdigest()
            if image_sha and image_sha != derived:
                raise HTTPException(status_code=422, detail=f'{asset_name}: published imageSha256 does not match the decrypted image.')
            image_sha = derived
        elif secure:
            parse_package(blob)  # structural sanity at least

        with STATE_LOCK:
            if any(str(r.get('version')) == version and board in r.get('compatible', []) for r in STATE.get('releases', [])):
                skipped.append(f'{asset_name}: v{version} already published')
                continue
            try:
                release, _manifest, _pipeline = create_release_locked(
                    version=version,
                    description=str(release_info.get('name') or f'Firmware {tag}')[:200],
                    changelog=str(release_info.get('body') or 'Published from GitHub Release.')[:2000],
                    compatible=[board],
                    status='published',
                    artifact_bytes=blob,
                    artifact_label=f'github:{repository}@{tag}/{asset_name}',
                    image_sha256=image_sha,
                    secure_package=bool(secure),
                )
            except ValueError as error:
                skipped.append(f'{asset_name}: {error}')
                continue
            release['source'] = {
                'type': 'github',
                'repository': repository,
                'tag': tag,
                'asset': asset_name,
                'htmlUrl': release_info.get('html_url'),
                'verifiedSignature': bool(full_verify and secure),
                'ingestedAt': utc_now_iso(),
            }
            push_event_locked(
                event_type='firmware_update',
                severity='success',
                title='Release Ingested from GitHub',
                description=f'{repository} {tag} ({asset_name} -> {board}) published'
                + (' with signature verified.' if full_verify and secure else '.'),
            )
            STATE['updatedAt'] = utc_now_iso()
            persist_state_locked()
            created.append({'version': release.get('version'), 'board': board, 'id': release.get('id')})

    audit_note(request, 'github.release', f'{repository} {tag}: published {len(created)}, skipped {len(skipped)}')
    return {'ok': True, 'tag': tag, 'published': created, 'skipped': skipped}


def push_event_locked_safe(title: str, description: str) -> None:
    with STATE_LOCK:
        push_event_locked(event_type='security', severity='error', title=title, description=description)
        persist_state_locked()
