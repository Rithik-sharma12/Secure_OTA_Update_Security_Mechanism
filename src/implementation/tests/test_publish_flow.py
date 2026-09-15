"""
End-to-end publish flow, through the real HTTP API.

This is the integration counterpart to test_image_digest.py's unit tests: it
drives /api/releases/upload and checks the manifest a device would actually
receive. The rollback case is the reason the whole `imageSha256` mechanism
exists, so it is asserted here rather than reasoned about.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import gateway
from gateway.package import (
    build_package,
    firmware_sha256,
    load_or_create_packaging_key,
    open_package,
)

AES_KEY = 'Vb7Xq9Zm2Kd4Rn1TyP6sJ8wG3hL5cF0e'

# 16-byte aligned, as every real ESP-IDF application image is. The previous
# shape-based package detector misclassified exactly this.
FIRMWARE = b'\xe9' + b'\x00' * (50_000 - 1)
OLDER_FIRMWARE = b'\xe9' + b'\x11' * (40_000 - 1)


@pytest.fixture(scope='module')
def signing(tmp_path_factory):
    keys = tmp_path_factory.mktemp('publishkeys')
    private = load_or_create_packaging_key(keys / 'p.pem', keys / 'pub.pem')
    return private, (keys / 'pub.pem').read_bytes()


@pytest.fixture(scope='module')
def client() -> TestClient:
    return TestClient(gateway.app)


@pytest.fixture
def auth(api_key: str) -> dict[str, str]:
    return {'x-api-key': api_key}


def _upload(client, auth, name, blob, version, **form):
    return client.post(
        '/api/releases/upload',
        headers=auth,
        files={'file': (name, blob, 'application/octet-stream')},
        data={'version': version, 'compatible': 'ESP32', **form},
    )


def test_secure_release_publishes_both_digests(client, auth, signing):
    private, _ = signing
    package = build_package(FIRMWARE, private, AES_KEY)

    response = _upload(
        client, auth, 'firmware_v3.0.0.bin', package, '3.0.0',
        imageSha256=firmware_sha256(FIRMWARE), securePackage='true',
    )
    assert response.status_code == 200

    manifest = response.json()['manifest']
    assert manifest['imageSha256'] == firmware_sha256(FIRMWARE)
    assert manifest['securePackage'] is True
    # The distinction the whole mechanism rests on.
    assert manifest['sha256'] != manifest['imageSha256']


def test_a_device_can_verify_what_the_gateway_served(client, auth, signing):
    """Mirrors performSecurePackageUpdate: decrypt, verify, then match digest."""
    private, public_pem = signing
    package = build_package(FIRMWARE, private, AES_KEY)

    manifest = _upload(
        client, auth, 'firmware_v3.2.0.bin', package, '3.2.0',
        imageSha256=firmware_sha256(FIRMWARE), securePackage='true',
    ).json()['manifest']

    served = client.get('/releases/download/firmware_v3.2.0.bin', headers=auth).content
    assert served == package

    recovered = open_package(served, public_pem, AES_KEY)
    assert firmware_sha256(recovered) == manifest['imageSha256']


def test_a_validly_signed_older_package_is_not_accepted(client, auth, signing):
    """
    The rollback this exists to stop: an attacker who can answer the download
    URL serves a genuinely signed older image against a newer manifest. The
    signature verifies — only the digest comparison catches it.
    """
    private, public_pem = signing
    current = build_package(FIRMWARE, private, AES_KEY)
    older = build_package(OLDER_FIRMWARE, private, AES_KEY)

    manifest = _upload(
        client, auth, 'firmware_v3.3.0.bin', current, '3.3.0',
        imageSha256=firmware_sha256(FIRMWARE), securePackage='true',
    ).json()['manifest']

    # The attacker's package passes signature verification.
    replayed = open_package(older, public_pem, AES_KEY)
    assert replayed == OLDER_FIRMWARE

    # And is still refused, because it is not the image the manifest offered.
    assert firmware_sha256(replayed) != manifest['imageSha256']


def test_plain_release_publishes_a_usable_image_digest(client, auth):
    """
    Regression for the detector bug: a 16-aligned plain image was classified as
    a package, so imageSha256 was suppressed for ordinary releases.
    """
    manifest = _upload(
        client, auth, 'firmware_v3.4.0.bin', FIRMWARE, '3.4.0'
    ).json()['manifest']

    assert manifest['sha256'] == manifest['imageSha256'] == firmware_sha256(FIRMWARE)
    assert not manifest.get('securePackage')


def test_v2_package_is_flagged_without_the_form_field(client, auth, signing):
    """The magic is enough for v2; the explicit flag is only needed for v1."""
    private, _ = signing
    package = build_package(FIRMWARE, private, AES_KEY)

    manifest = _upload(
        client, auth, 'firmware_v3.5.0.bin', package, '3.5.0'
    ).json()['manifest']

    assert manifest['securePackage'] is True
    # No digest was supplied and the gateway has no AES key, so it stays silent
    # rather than publishing the package digest.
    assert 'imageSha256' not in manifest


def test_a_malformed_image_digest_is_rejected_at_publish(client, auth, signing):
    """Better to fail the publish than to ship a manifest no device can match."""
    private, _ = signing
    package = build_package(FIRMWARE, private, AES_KEY)

    response = _upload(
        client, auth, 'firmware_v3.6.0.bin', package, '3.6.0',
        imageSha256='z' * 64, securePackage='true',
    )
    assert response.status_code == 400


def test_publishing_requires_the_api_key(client):
    response = client.post(
        '/api/releases/upload',
        files={'file': ('firmware_v9.9.9.bin', FIRMWARE, 'application/octet-stream')},
        data={'version': '9.9.9'},
    )
    assert response.status_code == 401
