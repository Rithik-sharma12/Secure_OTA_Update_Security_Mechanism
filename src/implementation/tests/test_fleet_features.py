"""
Audit trail, telemetry history, deployment cancel/retry, the live change
stream and GitHub release ingestion — through the real HTTP API.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid

import pytest
from fastapi.testclient import TestClient

import gateway
import gateway.routes.github as github_route
from gateway.package import build_package, firmware_sha256, load_or_create_packaging_key
from gateway.state import state_revision

WEBHOOK_SECRET = 'whsec-test-0123456789'


@pytest.fixture(scope='module')
def client() -> TestClient:
    return TestClient(gateway.app)


@pytest.fixture
def fleet(api_key: str) -> dict[str, str]:
    return {'x-api-key': api_key}


def _device_id() -> str:
    return f'esp32-fleet-{uuid.uuid4().hex[:8]}'


def _heartbeat(client, headers, device_id, version='1.0.0', ash=100, rssi=-60, memory=40.0):
    return client.post(
        '/api/heartbeat',
        headers=headers,
        json={'device_id': device_id, 'device_type': 'ESP32', 'current_version': version, 'ash_score': ash,
              'signalStrength': rssi, 'memoryUsage': memory},
    )


def _publish(client, fleet, version, fill):
    blob = b'\xe9' + bytes([fill]) * 12_000
    response = client.post(
        '/api/releases/upload',
        headers=fleet,
        files={'file': (f'fw_{version}.bin', blob, 'application/octet-stream')},
        data={'version': version, 'compatible': 'ESP32'},
    )
    assert response.status_code == 200, response.text
    return response.json()['release']


# ── Audit ─────────────────────────────────────────────────────

def test_audit_records_actor_action_and_failures(client, fleet):
    device_id = _device_id()
    _heartbeat(client, fleet, device_id)

    client.post(f'/api/devices/{device_id}/commands', headers={**fleet, 'x-actor': 'alice (operator)'}, json={'type': 'reboot'})
    client.post(f'/api/devices/{device_id}/commands', json={'type': 'reboot'})  # no key: 401, still audited
    # A spoofed actor without the key is not believed.
    client.post(f'/api/devices/{device_id}/commands', headers={'x-actor': 'admin'}, json={'type': 'reboot'})

    entries = client.get('/api/audit', params={'device_id': device_id}, headers=fleet).json()['entries']
    assert [e['status'] for e in entries] == [401, 401, 200]
    assert entries[2]['actor'] == 'dashboard:alice (operator)'
    assert entries[2]['action'] == 'command.reboot'
    assert entries[0]['actor'] == 'unauthenticated'

    # Device reports are not audited (they are telemetry, not operator actions).
    assert all(e['path'] != '/api/heartbeat' for e in client.get('/api/audit', headers=fleet).json()['entries'])


def test_audit_requires_fleet_key(client):
    assert client.get('/api/audit').status_code == 401


# ── Telemetry history ─────────────────────────────────────────

def test_telemetry_history_is_recorded_and_bucketed(client, fleet):
    device_id = _device_id()
    for i in range(6):
        _heartbeat(client, fleet, device_id, version='1.0.0' if i < 3 else '1.1.0', rssi=-50 - i, memory=30.0 + i)

    series = client.get(f'/api/devices/{device_id}/telemetry', params={'hours': 1, 'points': 10}).json()
    assert series['rawSamples'] == 6
    assert series['points'], series
    last = series['points'][-1]
    assert last['fw'] == '1.1.0'
    assert -56 <= last['rssi'] <= -50
    assert series['bucketSeconds'] >= 15


# ── Deployment cancel / retry ─────────────────────────────────

def test_cancel_withdraws_pending_targets_and_queued_commands(client, fleet):
    device_id = _device_id()
    _heartbeat(client, fleet, device_id, version='3.0.0')
    release = _publish(client, fleet, '3.1.0', 0x31)

    deployment = client.post('/api/deployments', headers=fleet, json={'releaseId': release['id'], 'deviceIds': [device_id]}).json()['deployment']
    cancelled = client.post(f"/api/deployments/{deployment['id']}/cancel", headers=fleet)
    assert cancelled.status_code == 200
    body = cancelled.json()
    assert body['cancelled'] == 1
    assert body['deployment']['status'] == 'cancelled'
    assert body['deployment']['targets'][device_id]['state'] == 'cancelled'

    # The queued update never reaches the device.
    assert _heartbeat(client, fleet, device_id, version='3.0.0').json()['commands'] == []
    # And the per-device manifest no longer points at the cancelled assignment
    # beyond normal auto-update (which offers the newest release anyway).
    assert client.post(f"/api/deployments/{deployment['id']}/cancel", headers=fleet).status_code == 409


def test_retry_creates_a_new_deployment_for_failed_targets(client, fleet):
    device_id = _device_id()
    _heartbeat(client, fleet, device_id, version='4.0.0')
    release = _publish(client, fleet, '4.1.0', 0x41)
    first = client.post('/api/deployments', headers=fleet, json={'releaseId': release['id'], 'deviceIds': [device_id]}).json()['deployment']
    client.post(f'/api/devices/{device_id}/ota/status', headers=fleet, json={'phase': 'failed', 'version': '4.1.0', 'detail': 'flash write'})

    assert client.post(f"/api/deployments/{first['id']}/retry").status_code == 401
    retried = client.post(f"/api/deployments/{first['id']}/retry", headers=fleet)
    assert retried.status_code == 200
    second = retried.json()['deployment']
    assert second['id'] != first['id']
    assert second['retryOf'] == first['id']
    assert second['targets'][device_id]['state'] == 'pending'


# ── Live stream ───────────────────────────────────────────────

def test_stream_announces_changes(client, fleet):
    before = state_revision()
    _heartbeat(client, fleet, _device_id())
    assert state_revision() > before

    with client.stream('GET', '/api/stream', params={'max_seconds': 1}) as response:
        assert response.headers['content-type'].startswith('text/event-stream')
        text = ''.join(response.iter_text())
    assert 'event: hello' in text
    assert 'event: bye' in text
    hello = json.loads(text.split('event: hello\ndata: ', 1)[1].split('\n', 1)[0])
    assert hello['revision'] >= before + 1


# ── GitHub release webhook ────────────────────────────────────

def _signed(body: dict) -> tuple[bytes, dict[str, str]]:
    raw = json.dumps(body).encode()
    signature = 'sha256=' + hmac.new(WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return raw, {'x-hub-signature-256': signature, 'x-github-event': 'release', 'content-type': 'application/json'}


def _release_event(tag: str, assets: dict[str, bytes], repo='team/SecureOTA') -> dict:
    return {
        'action': 'published',
        'repository': {'full_name': repo},
        'release': {
            'tag_name': tag,
            'name': f'Firmware {tag}',
            'body': 'CI build',
            'draft': False,
            'prerelease': False,
            'html_url': f'https://github.com/{repo}/releases/{tag}',
            'assets': [{'name': n, 'browser_download_url': f'https://example.invalid/{n}', 'url': f'https://api.invalid/{n}'} for n in assets],
        },
    }


@pytest.fixture
def webhook_env(monkeypatch, tmp_path):
    monkeypatch.setenv('OTA_GITHUB_WEBHOOK_SECRET', WEBHOOK_SECRET)
    monkeypatch.setenv('OTA_GITHUB_REPOSITORY', 'team/SecureOTA')
    monkeypatch.setenv('OTA_GITHUB_ASSET_MAP', 'firmware-esp32.bin=ESP32')
    store: dict[str, bytes] = {}
    monkeypatch.setattr(github_route, 'download_asset', lambda asset: store[asset['name']])
    return store


def test_webhook_rejects_bad_signature_and_foreign_repo(client, webhook_env):
    raw, headers = _signed(_release_event('v9.1.0', {}))
    assert client.post('/api/github/webhook', content=raw, headers={**headers, 'x-hub-signature-256': 'sha256=00'}).status_code == 401

    raw, headers = _signed(_release_event('v9.1.0', {}, repo='someone/else'))
    assert client.post('/api/github/webhook', content=raw, headers=headers).status_code == 403


def test_webhook_publishes_verified_secure_release(client, webhook_env, monkeypatch, tmp_path):
    keys = tmp_path / 'ci'
    keys.mkdir()
    private = load_or_create_packaging_key(keys / 'priv.pem', keys / 'pub.pem')
    aes = 'Q' * 32
    firmware = b'\xe9' + b'\x5a' * 20_000
    package = build_package(firmware, private, aes)

    monkeypatch.setenv('OTA_RELEASE_RSA_PUBKEY_PATH', str(keys / 'pub.pem'))
    monkeypatch.setenv('OTA_RELEASE_AES_KEY', aes)

    manifest = {'assets': {'firmware-esp32.bin': {'sha256': hashlib.sha256(package).hexdigest(), 'securePackage': True}}}
    webhook_env['firmware-esp32.bin'] = package
    webhook_env['release-manifest.json'] = json.dumps(manifest).encode()

    raw, headers = _signed(_release_event('v9.2.0', webhook_env))
    response = client.post('/api/github/webhook', content=raw, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()['published'][0]['version'] == '9.2.0'

    served = client.get('/releases/latest/manifest', params={'device_type': 'ESP32'}).json()
    assert served['version'] == '9.2.0'
    assert served['securePackage'] is True
    # Derived by decrypting, not taken on trust from the manifest.
    assert served['imageSha256'] == firmware_sha256(firmware)

    # Redelivery of the same event is harmless.
    again = client.post('/api/github/webhook', content=raw, headers=headers).json()
    assert again['published'] == [] and 'already published' in again['skipped'][0]


def test_webhook_refuses_tampered_asset(client, webhook_env):
    good = b'\xe9' + b'\x01' * 5000
    webhook_env['firmware-esp32.bin'] = good + b'tampered'
    webhook_env['checksums.txt'] = f'{hashlib.sha256(good).hexdigest()}  firmware-esp32.bin\n'.encode()
    raw, headers = _signed(_release_event('v9.3.0', webhook_env))
    response = client.post('/api/github/webhook', content=raw, headers=headers)
    assert response.status_code == 422
    assert 'does not match' in response.json()['detail']


def test_webhook_ping_and_unconfigured(client, monkeypatch):
    monkeypatch.delenv('OTA_GITHUB_WEBHOOK_SECRET', raising=False)
    assert client.post('/api/github/webhook', content=b'{}').status_code == 503
    monkeypatch.setenv('OTA_GITHUB_WEBHOOK_SECRET', WEBHOOK_SECRET)
    raw = b'{"zen":"hi"}'
    sig = 'sha256=' + hmac.new(WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    assert client.post('/api/github/webhook', content=raw, headers={'x-hub-signature-256': sig, 'x-github-event': 'ping'}).json()['pong']
