"""
Internet control path: registration, per-device tokens, heartbeat-delivered
commands, deployment-targeted manifests and device OTA status reports.

Driven through the real HTTP API, the way the dashboard and an ESP32 use it.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

import gateway
import gateway.auth as gateway_auth
from gateway.state import STATE, STATE_LOCK


@pytest.fixture(scope='module')
def client() -> TestClient:
    return TestClient(gateway.app)


@pytest.fixture
def fleet(api_key: str) -> dict[str, str]:
    return {'x-api-key': api_key}


def _device_id() -> str:
    return f'esp32-test-{uuid.uuid4().hex[:8]}'


def _heartbeat(client, headers, device_id, version='1.0.0', ash=100, device_type='ESP32'):
    return client.post(
        '/api/heartbeat',
        headers=headers,
        json={'device_id': device_id, 'device_type': device_type, 'current_version': version, 'ash_score': ash},
    )


def _publish(client, fleet, version, fill: int, compatible='ESP32'):
    blob = b'\xe9' + bytes([fill]) * (20_000 - 1)
    response = client.post(
        '/api/releases/upload',
        headers=fleet,
        files={'file': (f'fw_{version}.bin', blob, 'application/octet-stream')},
        data={'version': version, 'compatible': compatible},
    )
    assert response.status_code == 200, response.text
    return response.json()['release']


# ── Registration and device tokens ────────────────────────────

def test_register_issues_token_that_authenticates_only_its_device(client, fleet):
    device_a, device_b = _device_id(), _device_id()

    registered = client.post('/api/devices/register', headers=fleet, json={'deviceId': device_a, 'deviceType': 'esp32'})
    assert registered.status_code == 200
    token = registered.json()['token']
    assert len(token) >= 40

    # Its own token works without the fleet key.
    assert _heartbeat(client, {'x-device-token': token}, device_a).status_code == 200
    assert _heartbeat(client, {'Authorization': f'Bearer {token}'}, device_a).status_code == 200

    # The same token cannot speak for another board, even with the fleet key alongside.
    assert _heartbeat(client, {'x-device-token': token}, device_b).status_code == 401
    assert _heartbeat(client, {'x-device-token': token, **fleet}, device_b).status_code == 401

    # No credentials at all.
    assert _heartbeat(client, {}, device_a).status_code == 401


def test_token_hash_is_never_exposed(client, fleet):
    device_id = _device_id()
    token = client.post('/api/devices/register', headers=fleet, json={'deviceId': device_id}).json()['token']
    _heartbeat(client, {'x-device-token': token}, device_id)

    for path in ('/api/dashboard', '/api/devices', f'/api/devices/{device_id}'):
        body = client.get(path).text
        assert token not in body
        assert gateway_auth.hash_device_token(token) not in body


def test_register_requires_fleet_key(client):
    assert client.post('/api/devices/register', json={'deviceId': _device_id()}).status_code == 401


def test_revoked_token_is_refused(client, fleet):
    device_id = _device_id()
    token = client.post('/api/devices/register', headers=fleet, json={'deviceId': device_id}).json()['token']
    assert client.post(f'/api/devices/{device_id}/revoke-token', headers=fleet).status_code == 200
    assert _heartbeat(client, {'x-device-token': token}, device_id).status_code == 401


def test_require_device_token_blocks_fleet_key_for_registered_devices(client, fleet, monkeypatch):
    registered, legacy = _device_id(), _device_id()
    client.post('/api/devices/register', headers=fleet, json={'deviceId': registered})
    monkeypatch.setattr(gateway_auth, 'REQUIRE_DEVICE_TOKEN', True)

    assert _heartbeat(client, fleet, registered).status_code == 401
    # A board that was never issued a token keeps working on the fleet key.
    assert _heartbeat(client, fleet, legacy).status_code == 200


def test_rejects_malformed_device_ids(client, fleet):
    assert client.post('/api/devices/register', headers=fleet, json={'deviceId': 'bad id/../x'}).status_code == 400


# ── Commands delivered through heartbeats ─────────────────────

def test_command_round_trip(client, fleet):
    device_id = _device_id()
    token = client.post('/api/devices/register', headers=fleet, json={'deviceId': device_id}).json()['token']
    device = {'x-device-token': token}
    _heartbeat(client, device, device_id)

    queued = client.post(f'/api/devices/{device_id}/commands', headers=fleet, json={'type': 'reboot'})
    assert queued.status_code == 200
    command_id = queued.json()['command']['id']

    # Double-click on Restart collapses into one command.
    again = client.post(f'/api/devices/{device_id}/commands', headers=fleet, json={'type': 'reboot'})
    assert again.json()['command']['id'] == command_id

    delivered = _heartbeat(client, device, device_id).json()['commands']
    assert [c['id'] for c in delivered] == [command_id]
    assert delivered[0]['type'] == 'reboot'

    # Not handed out twice while the device is working on it.
    assert _heartbeat(client, device, device_id).json()['commands'] == []

    result = client.post(f'/api/devices/{device_id}/commands/{command_id}/result', headers=device, json={'ok': True, 'detail': 'restarting'})
    assert result.status_code == 200
    assert result.json()['status'] == 'succeeded'

    history = client.get(f'/api/devices/{device_id}/commands').json()['commands']
    assert history[0]['status'] == 'succeeded'


def test_command_needs_fleet_key_and_known_device(client, fleet):
    device_id = _device_id()
    assert client.post(f'/api/devices/{device_id}/commands', json={'type': 'reboot'}).status_code == 401
    assert client.post(f'/api/devices/{device_id}/commands', headers=fleet, json={'type': 'reboot'}).status_code == 404
    _heartbeat(client, fleet, device_id)
    assert client.post(f'/api/devices/{device_id}/commands', headers=fleet, json={'type': 'format_disk'}).status_code == 400


def test_other_device_cannot_report_results(client, fleet):
    device_a, device_b = _device_id(), _device_id()
    token_b = client.post('/api/devices/register', headers=fleet, json={'deviceId': device_b}).json()['token']
    _heartbeat(client, fleet, device_a)
    command_id = client.post(f'/api/devices/{device_a}/commands', headers=fleet, json={'type': 'identify'}).json()['command']['id']

    forged = client.post(
        f'/api/devices/{device_a}/commands/{command_id}/result',
        headers={'x-device-token': token_b},
        json={'ok': True},
    )
    assert forged.status_code == 401


def test_quarantined_device_gets_no_update_command(client, fleet):
    device_id = _device_id()
    _heartbeat(client, fleet, device_id, ash=30)
    refused = client.post(f'/api/devices/{device_id}/commands', headers=fleet, json={'type': 'update'})
    assert refused.status_code == 409
    # Reboot is still allowed — it is how an operator recovers a board.
    assert client.post(f'/api/devices/{device_id}/commands', headers=fleet, json={'type': 'reboot'}).status_code == 200


def test_remove_device(client, fleet):
    device_id = _device_id()
    _heartbeat(client, fleet, device_id)
    assert client.delete(f'/api/devices/{device_id}').status_code == 401
    assert client.delete(f'/api/devices/{device_id}', headers=fleet).status_code == 200
    assert client.get(f'/api/devices/{device_id}').status_code == 404


# ── Deployments drive what a specific device is offered ───────

def test_deployment_targets_a_specific_release_and_nudges_the_device(client, fleet):
    device_id = _device_id()
    _heartbeat(client, fleet, device_id, version='7.0.0')

    assigned = _publish(client, fleet, '7.1.0', 0x11)
    _publish(client, fleet, '7.2.0', 0x22)  # newer, but not what was assigned

    deployment = client.post(
        '/api/deployments',
        headers=fleet,
        json={'releaseId': assigned['id'], 'deviceIds': [device_id]},
    ).json()['deployment']
    assert deployment['targets'][device_id]['state'] == 'pending'

    # The device is told now, not at its next poll.
    beat = _heartbeat(client, fleet, device_id, version='7.0.0').json()
    assert beat['command'] == 'update_available'
    assert beat['target_version'] == '7.1.0'
    assert [c['type'] for c in beat['commands']] == ['update']
    assert beat['commands'][0]['params']['version'] == '7.1.0'

    # And the per-device manifest names the assigned build, not the newest.
    manifest = client.get('/releases/latest/manifest', params={'device_id': device_id, 'device_type': 'ESP32'}).json()
    assert manifest['version'] == '7.1.0'
    assert manifest['signature']

    # Progress reports land on the deployment target.
    status = client.post(
        f'/api/devices/{device_id}/ota/status',
        headers=fleet,
        json={'phase': 'downloading', 'version': '7.1.0', 'progress': 40},
    )
    assert status.status_code == 200
    target = client.get('/api/deployments').json()['deployments'][0]['targets'][device_id]
    assert target['phase'] == 'downloading' and target['progress'] == 40 and target['state'] == 'pending'

    # The heartbeat must not wipe the OTA status the device reported.
    _heartbeat(client, fleet, device_id, version='7.0.0')
    assert client.get(f'/api/devices/{device_id}').json()['device']['ota']['phase'] == 'downloading'

    # Confirmation still comes only from a heartbeat on the new version.
    _heartbeat(client, fleet, device_id, version='7.1.0')
    deployments = {d['id']: d for d in client.get('/api/deployments').json()['deployments']}
    assert deployments[deployment['id']]['targets'][device_id]['state'] == 'confirmed'


def test_device_reported_failure_fails_the_target_immediately(client, fleet):
    device_id = _device_id()
    _heartbeat(client, fleet, device_id, version='8.0.0')
    release = _publish(client, fleet, '8.1.0', 0x33)
    deployment_id = client.post(
        '/api/deployments', headers=fleet, json={'releaseId': release['id'], 'deviceIds': [device_id]}
    ).json()['deployment']['id']

    client.post(
        f'/api/devices/{device_id}/ota/status',
        headers=fleet,
        json={'phase': 'rolled_back', 'version': '8.1.0', 'detail': 'health check timed out'},
    )
    deployments = {d['id']: d for d in client.get('/api/deployments').json()['deployments']}
    target = deployments[deployment_id]['targets'][device_id]
    assert target['state'] == 'failed'
    assert 'health check timed out' in target['reason']
    assert deployments[deployment_id]['status'] == 'failed'


def test_status_report_rejects_unknown_phase_and_unknown_device(client, fleet):
    device_id = _device_id()
    assert client.post(f'/api/devices/{device_id}/ota/status', headers=fleet, json={'phase': 'downloading'}).status_code == 404
    _heartbeat(client, fleet, device_id)
    assert client.post(f'/api/devices/{device_id}/ota/status', headers=fleet, json={'phase': 'exploding'}).status_code == 400


def test_auto_update_off_offers_nothing_without_a_deployment(client, fleet, monkeypatch):
    import gateway.config as gateway_config

    device_id = _device_id()
    _heartbeat(client, fleet, device_id, version='1.0.0')
    monkeypatch.setattr(gateway_config, 'AUTO_UPDATE', False)

    manifest = client.get('/releases/latest/manifest', params={'device_id': device_id}).json()
    assert manifest['updateAvailable'] is False
    assert manifest['version'] == '1.0.0'
    assert _heartbeat(client, fleet, device_id, version='1.0.0').json()['command'] == 'ack'
