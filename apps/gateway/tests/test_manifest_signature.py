"""
Stage 5 of the device pipeline: the gateway's Ed25519 signature over the
manifest statement (version, sha256, imageSha256, size).

The device side is firmware/lib/sota_core (sota_manifest_message,
sota_verify_manifest); its native test uses the same statement layout as
these tests, so a change on either side fails one of them.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi.testclient import TestClient

import gateway
from gateway.crypto import manifest_signing_message, verify_manifest_signature

FIRMWARE = b'\xe9' + b'\x22' * (30_000 - 1)


@pytest.fixture(scope='module')
def client() -> TestClient:
    return TestClient(gateway.app)


@pytest.fixture
def auth(api_key: str) -> dict[str, str]:
    return {'x-api-key': api_key}


def _publish(client, auth, version, blob=FIRMWARE):
    return client.post(
        '/api/releases/upload',
        headers=auth,
        files={'file': (f'firmware_v{version}.bin', blob, 'application/octet-stream')},
        data={'version': version, 'compatible': 'ESP32'},
    )


def _device_key(client) -> Ed25519PublicKey:
    key_hex = client.get('/releases/latest/public-key').json()['publicKeyHex']
    assert len(key_hex) == 64
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))


def test_statement_layout_matches_the_firmware():
    # Byte for byte what sota_manifest_message() builds on the device.
    assert manifest_signing_message('2.5.1', 'a' * 64, 'b' * 64, 1004384) == (
        b'SOTA-MANIFEST-V1\n2.5.1\n' + b'a' * 64 + b'\n' + b'b' * 64 + b'\n1004384'
    )
    assert manifest_signing_message('1.0.0', 'A' * 64, None, 1).endswith(b'\n' + b'a' * 64 + b'\n\n1')


@pytest.mark.parametrize('bad', [('', 'a' * 64), ('1.0\n0', 'a' * 64), ('1.0.0', 'abc')])
def test_unsignable_fields_are_refused(bad):
    with pytest.raises(ValueError):
        manifest_signing_message(bad[0], bad[1], None, 1)


def test_published_manifest_verifies_with_the_device_key(client, auth):
    response = _publish(client, auth, '83.1.0')
    assert response.status_code == 200, response.text
    manifest = response.json()['manifest']
    signature = base64.b64decode(manifest['manifestSignature'])
    message = manifest_signing_message(manifest['version'], manifest['sha256'], manifest.get('imageSha256'), manifest['size'])
    _device_key(client).verify(signature, message)  # raises if invalid
    assert manifest['manifestSignatureAlgorithm'] == 'Ed25519'


def test_device_manifest_carries_the_signature(client, auth):
    _publish(client, auth, '83.2.0')
    served = client.get('/releases/latest/manifest?device_type=ESP32', headers=auth).json()
    message = manifest_signing_message(served['version'], served['sha256'], served.get('imageSha256'), served['size'])
    _device_key(client).verify(base64.b64decode(served['manifestSignature']), message)


def test_gateway_assisted_check_answers_one_bit(client, auth):
    manifest = _publish(client, auth, '83.3.0').json()['manifest']
    body = {
        'version': manifest['version'],
        'sha256': manifest['sha256'],
        'imageSha256': manifest.get('imageSha256'),
        'size': manifest['size'],
        'signature': manifest['manifestSignature'],
    }
    assert client.post('/api/verify/manifest', json=body, headers=auth).json() == {'valid': True}

    for field, value in (('version', '83.3.1'), ('size', manifest['size'] + 1), ('sha256', 'f' * 64)):
        tampered = {**body, field: value}
        assert client.post('/api/verify/manifest', json=tampered, headers=auth).json() == {'valid': False}

    assert client.post('/api/verify/manifest', json={**body, 'signature': 'AAAA'}, headers=auth).json() == {'valid': False}


def test_verify_rejects_malformed_signature():
    assert not verify_manifest_signature('1.0.0', 'a' * 64, None, 1, 'not base64')


def test_an_artifact_shaped_like_a_statement_is_not_published(client, auth):
    statement = manifest_signing_message('89.9.9', 'a' * 64, None, 1)
    response = _publish(client, auth, '89.9.9', blob=statement)
    assert response.status_code >= 400


def test_registration_hands_out_the_gateway_key(client, auth):
    data = client.post('/api/devices/register', json={'deviceId': 'esp32-sigtest'}, headers=auth).json()
    assert data['gatewayKey'] == client.get('/releases/latest/public-key').json()['publicKeyHex']
