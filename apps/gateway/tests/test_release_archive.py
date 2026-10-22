"""
Archiving a release, through the real HTTP API.

An archived release must stop being offered everywhere a device or operator
could pick it up: the global manifest, per-device manifests, the deployment
endpoint and /api/releases/latest. Restoring it must undo exactly that.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

import gateway


@pytest.fixture(scope='module')
def client() -> TestClient:
    return TestClient(gateway.app)


@pytest.fixture
def fleet(api_key: str) -> dict[str, str]:
    return {'x-api-key': api_key}


def _publish(client, fleet, version, fill):
    blob = b'\xe9' + bytes([fill]) * 9_000
    response = client.post(
        '/api/releases/upload',
        headers=fleet,
        files={'file': (f'fw_{version}.bin', blob, 'application/octet-stream')},
        data={'version': version, 'compatible': 'ESP32'},
    )
    assert response.status_code == 200, response.text
    return response.json()['release']


def _unique_version(major: int) -> str:
    return f'{major}.{uuid.uuid4().int % 900 + 10}.{uuid.uuid4().int % 900 + 10}'


def test_archive_requires_write_key(client, fleet):
    release = _publish(client, fleet, _unique_version(70), 0x21)
    assert client.post(f"/api/releases/{release['id']}/archive").status_code == 401
    listed = client.get('/api/releases', headers=fleet).json()['releases']
    assert next(r for r in listed if r['id'] == release['id'])['status'] == 'published'


def test_archive_unknown_release_is_404(client, fleet):
    assert client.post('/api/releases/release-does-not-exist/archive', headers=fleet).status_code == 404
    assert client.post('/api/releases/release-does-not-exist/unarchive', headers=fleet).status_code == 404


def test_archived_release_is_not_offered_and_can_be_restored(client, fleet):
    older = _publish(client, fleet, _unique_version(80), 0x31)
    newer = _publish(client, fleet, _unique_version(81), 0x32)

    assert client.get('/releases/latest/manifest', headers=fleet).json()['version'] == newer['version']

    response = client.post(f"/api/releases/{newer['id']}/archive", headers={**fleet, 'x-actor': 'alice (admin)'})
    assert response.status_code == 200, response.text
    assert response.json()['release']['status'] == 'archived'

    # Archiving twice is a conflict, not a silent success.
    assert client.post(f"/api/releases/{newer['id']}/archive", headers=fleet).status_code == 409

    # Global and per-architecture manifests fall back to the older release.
    assert client.get('/releases/latest/manifest', headers=fleet).json()['version'] == older['version']
    per_type = client.get('/releases/latest/manifest', params={'device_type': 'ESP32'}, headers=fleet).json()
    assert per_type['version'] == older['version']
    assert client.get('/api/releases/latest', headers=fleet).json()['release']['id'] == older['id']

    # It cannot be deployed explicitly.
    deploy = client.post('/api/deployments', headers=fleet, json={'releaseId': newer['id'], 'deviceIds': ['x']})
    assert deploy.status_code == 409

    # Recorded in the audit trail with the operator's name.
    entries = client.get('/api/audit', headers=fleet).json()['entries']
    archived = next(e for e in entries if e['path'] == f"/api/releases/{newer['id']}/archive" and e['status'] == 200)
    assert archived['action'] == 'release.archived'
    assert archived['actor'] == 'dashboard:alice (admin)'

    restored = client.post(f"/api/releases/{newer['id']}/unarchive", headers=fleet)
    assert restored.status_code == 200, restored.text
    assert restored.json()['release']['status'] == 'published'
    assert client.post(f"/api/releases/{newer['id']}/unarchive", headers=fleet).status_code == 409
    assert client.get('/releases/latest/manifest', headers=fleet).json()['version'] == newer['version']


def test_pending_deployment_target_skips_archived_release(client, fleet):
    device_id = f'esp32-archive-{uuid.uuid4().hex[:8]}'
    client.post(
        '/api/heartbeat',
        headers=fleet,
        json={'device_id': device_id, 'device_type': 'ESP32', 'current_version': '1.0.0', 'ash_score': 100},
    )
    release = _publish(client, fleet, _unique_version(90), 0x41)
    deploy = client.post('/api/deployments', headers=fleet, json={'releaseId': release['id'], 'deviceIds': [device_id]})
    assert deploy.status_code == 200, deploy.text

    offered = client.get('/releases/latest/manifest', params={'device_id': device_id}, headers=fleet).json()
    assert offered['version'] == release['version']

    assert client.post(f"/api/releases/{release['id']}/archive", headers=fleet).status_code == 200
    offered = client.get('/releases/latest/manifest', params={'device_id': device_id}, headers=fleet).json()
    assert offered.get('version') != release['version']
    client.post(f"/api/releases/{release['id']}/unarchive", headers=fleet)


def test_pipeline_rerun_reverifies_the_cached_artifact(client, fleet):
    release = _publish(client, fleet, _unique_version(95), 0x51)
    response = client.post('/api/pipeline/run', headers=fleet, json={'releaseId': release['id']})
    assert response.status_code == 200, response.text
    pipeline = response.json()['pipeline']
    assert pipeline['releaseId'] == release['id']
    assert pipeline['status'] == 'success'
    assert [stage['name'] for stage in pipeline['stages']] == ['artifact', 'verify', 'sign']
    assert release['assets'][0]['checksum'] in pipeline['stages'][1]['logs']
