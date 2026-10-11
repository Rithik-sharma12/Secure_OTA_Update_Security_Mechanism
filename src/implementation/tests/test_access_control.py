"""
Who may read what from the gateway, and where releases may be loaded from.

Reads used to be open: anyone who could reach the port could list the fleet,
pull telemetry and download plain firmware. Operator reads now need the
gateway key; the two reads a board makes while updating (manifest and
firmware download) also accept a current device token.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import gateway
import gateway.release as release_module


@pytest.fixture(scope='module')
def client() -> TestClient:
    return TestClient(gateway.app)


@pytest.fixture
def fleet(api_key: str) -> dict[str, str]:
    return {'x-api-key': api_key}


def _device_token(client, fleet) -> tuple[str, str]:
    device_id = f'esp32-acl-{uuid.uuid4().hex[:8]}'
    token = client.post('/api/devices/register', headers=fleet, json={'deviceId': device_id}).json()['token']
    return device_id, token


@pytest.fixture(scope='module')
def published(client, api_key) -> str:
    response = client.post(
        '/api/releases/upload',
        headers={'x-api-key': api_key},
        files={'file': ('fw.bin', b'\xe9' + b'\x11' * 4095, 'application/octet-stream')},
        data={'version': '17.1.0', 'compatible': 'ESP32'},
    )
    assert response.status_code == 200, response.text
    return response.json()['release']['assets'][0]['name']


OPERATOR_READS = [
    '/api/dashboard',
    '/api/events',
    '/api/devices',
    '/api/deployments',
    '/api/releases',
    '/api/releases/latest',
]


@pytest.mark.parametrize('path', OPERATOR_READS)
def test_operator_reads_need_the_gateway_key(client, fleet, published, path):
    assert client.get(path).status_code == 401
    assert client.get(path, headers={'x-api-key': 'wrong'}).status_code == 401
    assert client.get(path, headers=fleet).status_code == 200


@pytest.mark.parametrize('path', OPERATOR_READS)
def test_a_device_token_does_not_reveal_the_fleet(client, fleet, published, path):
    _, token = _device_token(client, fleet)
    assert client.get(path, headers={'x-device-token': token}).status_code == 401


def test_a_device_token_can_fetch_its_update(client, fleet, published):
    _, token = _device_token(client, fleet)
    headers = {'x-device-token': token}

    manifest = client.get('/releases/latest/manifest', params={'device_type': 'ESP32'}, headers=headers)
    assert manifest.status_code == 200
    assert client.get(f'/releases/download/{published}', headers=headers).status_code == 200


def test_update_reads_refuse_anonymous_and_revoked_callers(client, fleet, published):
    assert client.get('/releases/latest/manifest', params={'device_type': 'ESP32'}).status_code == 401
    assert client.get(f'/releases/download/{published}').status_code == 401

    device_id, token = _device_token(client, fleet)
    assert client.post(f'/api/devices/{device_id}/revoke-token', headers=fleet).status_code == 200
    headers = {'x-device-token': token}
    assert client.get(f'/releases/download/{published}', headers=headers).status_code == 401


def test_public_signing_key_stays_public(client):
    assert client.get('/releases/latest/public-key').status_code == 200


# ── sourceFilePath ────────────────────────────────────────────


def _create(client, fleet, version, source):
    return client.post(
        '/api/releases',
        headers=fleet,
        json={'version': version, 'compatible': ['ESP32'], 'sourceFilePath': str(source)},
    )


def test_source_file_path_is_disabled_by_default(client, fleet, tmp_path, monkeypatch):
    monkeypatch.setattr(release_module, 'ARTIFACT_DIRS', [])
    artifact = tmp_path / 'fw.bin'
    artifact.write_bytes(b'\xe9' * 64)

    response = _create(client, fleet, '17.2.0', artifact)
    assert response.status_code == 400
    assert 'disabled' in response.json()['detail']


def test_source_file_path_is_confined_to_artifact_dirs(client, fleet, tmp_path, monkeypatch):
    allowed = tmp_path / 'allowed'
    allowed.mkdir()
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'fw.bin').write_bytes(b'\xe9' * 64)
    (allowed / 'fw.bin').write_bytes(b'\xe9' * 64)
    (allowed / 'link.bin').symlink_to(outside / 'fw.bin')
    monkeypatch.setattr(release_module, 'ARTIFACT_DIRS', [allowed.resolve()])

    for escape in (outside / 'fw.bin', allowed / '..' / 'outside' / 'fw.bin', allowed / 'link.bin'):
        response = _create(client, fleet, '17.3.0', escape)
        assert response.status_code == 400, escape
        assert 'outside OTA_GATEWAY_ARTIFACT_DIRS' in response.json()['detail']

    assert _create(client, fleet, '17.3.0', allowed / 'fw.bin').status_code == 200
    # Relative paths resolve inside the first artifact directory.
    (allowed / 'next.bin').write_bytes(b'\xe9' * 64)
    assert _create(client, fleet, '17.4.0', Path('next.bin')).status_code == 200
