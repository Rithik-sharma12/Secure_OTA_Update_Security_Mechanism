"""
Factory (first-flash) images: a merged bootloader + partition table + app
written over USB at 0x0 to bring up a blank board, which then updates over the
air. See gateway/factory.py.
"""

from __future__ import annotations

import hashlib
import uuid

import pytest
from fastapi.testclient import TestClient

import gateway
from gateway.factory import APP_OFFSET, FactoryImageError, app_digest, validate_factory_image
from gateway.package import build_package, firmware_sha256, load_or_create_packaging_key

AES_KEY = 'Vb7Xq9Zm2Kd4Rn1TyP6sJ8wG3hL5cF0e'


@pytest.fixture(scope='module')
def client() -> TestClient:
    return TestClient(gateway.app)


@pytest.fixture
def fleet(api_key: str) -> dict[str, str]:
    return {'x-api-key': api_key}


def _app(fill: int) -> bytes:
    # 0xE9 is the ESP image magic every app image starts with.
    return b'\xe9' + bytes([fill]) * 40_959


def _merged(app: bytes, bootloader_offset: int = 0x1000) -> bytes:
    """What `esptool merge_bin` produces: 0xFF gaps, app last at 0x10000."""
    image = bytearray(b'\xff' * APP_OFFSET)
    image[bootloader_offset] = 0xE9
    image[bootloader_offset + 1:bootloader_offset + 64] = b'\x01' * 63
    return bytes(image) + app


def _upload(client, fleet, version, app, factory=None, **form):
    files = {'file': (f'fw_{version}.bin', app, 'application/octet-stream')}
    if factory is not None:
        files['factoryImage'] = (f'fw_{version}-full.bin', factory, 'application/octet-stream')
    return client.post(
        '/api/releases/upload',
        headers=fleet,
        files=files,
        data={'version': version, 'compatible': 'ESP8266', **form},
    )


# ── Validation ──────────────────────────────────────────────────────


def test_app_region_of_a_merged_image_is_the_app():
    app = _app(0x21)
    assert app_digest(_merged(app)) == hashlib.sha256(app).hexdigest()


@pytest.mark.parametrize('offset', [0x1000, 0x0])
def test_valid_factory_image_for_both_bootloader_offsets(offset):
    app = _app(0x22)
    record = validate_factory_image(_merged(app, offset), firmware_sha256(app))
    assert record['appSha256'] == firmware_sha256(app)
    assert record['size'] == APP_OFFSET + len(app)


def test_app_only_image_is_not_a_factory_image():
    app = _app(0x23) * 3  # large enough to reach 0x10000, but no app header there
    with pytest.raises(FactoryImageError, match='No ESP application image'):
        validate_factory_image(app, firmware_sha256(app))


def test_factory_image_of_another_build_is_refused():
    with pytest.raises(FactoryImageError, match='not this release'):
        validate_factory_image(_merged(_app(0x24)), firmware_sha256(_app(0x25)))


def test_factory_image_needs_a_known_plaintext_digest():
    with pytest.raises(FactoryImageError, match='imageSha256'):
        validate_factory_image(_merged(_app(0x26)), None)


# ── Publish and download ────────────────────────────────────────────


def test_plain_release_with_factory_image(client, fleet, api_key):
    app = _app(0x31)
    factory = _merged(app)
    response = _upload(client, fleet, '41.0.0', app, factory)
    assert response.status_code == 200, response.text
    release = response.json()['release']
    assert release['factoryImage']['appSha256'] == firmware_sha256(app)
    # Devices are never pointed at the plain factory image.
    assert 'factory' not in response.text.split('"manifest"', 1)[1].lower()

    served = client.get('/api/releases/factory', params={'device_type': 'ESP8266'}, headers=fleet)
    assert served.status_code == 200
    assert served.content == factory
    assert served.headers['x-firmware-version'] == '41.0.0'
    assert served.headers['x-firmware-sha256'] == hashlib.sha256(factory).hexdigest()


def test_factory_download_is_operator_only(client, fleet):
    device_id = f'esp-factory-{uuid.uuid4().hex[:8]}'
    token = client.post('/api/devices/register', headers=fleet, json={'deviceId': device_id}).json()['token']
    params = {'device_type': 'ESP8266'}
    assert client.get('/api/releases/factory', params=params).status_code == 401
    assert client.get('/api/releases/factory', params=params, headers={'x-device-token': token}).status_code == 401


def test_newer_release_without_factory_still_serves_the_older_one(client, fleet):
    assert _upload(client, fleet, '41.1.0', _app(0x32)).status_code == 200
    served = client.get('/api/releases/factory', params={'device_type': 'ESP8266'}, headers=fleet)
    assert served.status_code == 200
    assert served.headers['x-firmware-version'] == '41.0.0'
    assert served.headers['x-latest-version'] == '41.1.0'


def test_mismatched_factory_image_fails_the_publish(client, fleet):
    response = _upload(client, fleet, '41.2.0', _app(0x33), _merged(_app(0x34)))
    assert response.status_code == 400
    assert 'not this release' in response.json()['detail']


def test_secure_release_binds_factory_image_to_the_plaintext(client, fleet, tmp_path):
    private = load_or_create_packaging_key(tmp_path / 'p.pem', tmp_path / 'pub.pem')
    app = _app(0x35)
    package = build_package(app, private, AES_KEY, version='41.3.0')

    # Without the plaintext digest the gateway cannot tie the two together.
    refused = _upload(client, fleet, '41.3.0', package, _merged(app), securePackage='true')
    assert refused.status_code == 400
    assert 'imageSha256' in refused.json()['detail']

    accepted = _upload(
        client, fleet, '41.3.0', package, _merged(app),
        securePackage='true', imageSha256=firmware_sha256(app),
    )
    assert accepted.status_code == 200, accepted.text
    served = client.get('/api/releases/factory', params={'device_type': 'ESP8266'}, headers=fleet)
    assert served.headers['x-firmware-version'] == '41.3.0'
    assert served.content[APP_OFFSET:] == app


def test_unknown_architecture_has_no_factory_image(client, fleet):
    response = client.get('/api/releases/factory', params={'device_type': 'STM32F103'}, headers=fleet)
    assert response.status_code == 404
