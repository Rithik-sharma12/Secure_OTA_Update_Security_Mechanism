"""
Tests for the plaintext-image digest published as the manifest's `imageSha256`.

The manifest's `sha256` covers the artifact exactly as served. In secure mode
that artifact is an encrypted package, so a device that decrypts before
comparing can never match it. The firmware reads `imageSha256` instead, and
these tests pin the rule that decides what goes there.

Getting this wrong is not a subtle failure: every secure update would be
refused after a correct signature check, and three refusals quarantine the
device.
"""

from __future__ import annotations

import pytest

from gateway.package import (
    build_package,
    firmware_sha256,
    is_hex_digest,
    load_or_create_packaging_key,
    looks_like_secure_package,
    parse_package,
)
from gateway.release import image_digest_for_release, release_is_secure_package
from gateway.utils import sha256_bytes

AES_KEY = 'Vb7Xq9Zm2Kd4Rn1TyP6sJ8wG3hL5cF0e'
FIRMWARE = b'\xe9\x06\x02\x20' + bytes(range(256)) * 30 + b'end'


@pytest.fixture(scope='module')
def package(tmp_path_factory) -> bytes:
    keys = tmp_path_factory.mktemp('digestkeys')
    private = load_or_create_packaging_key(keys / 'p.pem', keys / 'pub.pem')
    return build_package(FIRMWARE, private, AES_KEY)


# ── The core distinction ─────────────────────────────────────────────


def test_package_digest_differs_from_image_digest(package):
    """If these were equal the bug this guards against could not occur."""
    assert sha256_bytes(package) != firmware_sha256(FIRMWARE)


def test_plain_release_publishes_the_artifact_digest():
    """For a plain image the served bytes are the image, so the two agree."""
    assert image_digest_for_release({}, FIRMWARE) == sha256_bytes(FIRMWARE)


def test_secure_release_does_not_publish_the_package_digest(package):
    """
    The gateway has no AES key, so it cannot derive the plaintext digest. It
    must publish nothing rather than the package digest — publishing the wrong
    one fails every secure update.
    """
    assert image_digest_for_release({}, package) != sha256_bytes(package)
    assert image_digest_for_release({}, package) is None


def test_supplied_image_digest_is_used_for_a_secure_release(package):
    """The packaging tool prints this digest for the publisher to pass on."""
    release = {'imageSha256': firmware_sha256(FIRMWARE)}
    assert image_digest_for_release(release, package) == firmware_sha256(FIRMWARE)


def test_supplied_digest_is_normalised(package):
    release = {'imageSha256': '  ' + firmware_sha256(FIRMWARE).upper() + '  '}
    assert image_digest_for_release(release, package) == firmware_sha256(FIRMWARE)


@pytest.mark.parametrize('bad', ['', '   ', 'deadbeef', 'x' * 63, 'x' * 65, None])
def test_malformed_supplied_digest_falls_back(package, bad):
    """A 65-character typo must not be published as a digest."""
    assert image_digest_for_release({'imageSha256': bad}, package) is None


def test_a_supplied_digest_still_wins_for_a_plain_artifact():
    digest = 'a' * 64
    assert image_digest_for_release({'imageSha256': digest}, FIRMWARE) == digest


def test_none_release_is_handled():
    assert image_digest_for_release(None, FIRMWARE) == sha256_bytes(FIRMWARE)


# ── Package detection ────────────────────────────────────────────────


def test_v2_package_is_detected_by_magic(package):
    assert looks_like_secure_package(package)


def test_v1_package_is_not_detectable_from_its_bytes(package):
    """
    A v1 package has no header, and the obvious shape test is worthless:
    IV_BYTES + RSA_SIGNATURE_BYTES is 272, itself 16-aligned, so the test
    reduces to "larger than 272 and 16-aligned" — true of essentially every
    ESP-IDF image. Publishers mark a v1 package explicitly instead.
    """
    parsed = parse_package(package)
    v1 = parsed.iv + parsed.signature + parsed.ciphertext
    assert not looks_like_secure_package(v1)


def test_a_real_sized_plain_image_is_not_called_a_package():
    """
    Regression for the heuristic this replaced. A 1 MiB image is 16-aligned, so
    the old shape test classified it as a package and suppressed imageSha256
    for every ordinary release.
    """
    image = b'\xe9' + b'\x00' * (1024 * 1024 - 1)
    assert len(image) % 16 == 0
    assert not looks_like_secure_package(image)
    assert image_digest_for_release({}, image) == sha256_bytes(image)


def test_small_images_are_not_mistaken_for_packages():
    assert not looks_like_secure_package(b'')
    assert not looks_like_secure_package(b'\xe9' * 100)
    assert not looks_like_secure_package(b'\xe9' * 272)


# ── Explicit publisher flags ─────────────────────────────────────────


def test_explicit_secure_flag_suppresses_the_digest_for_a_v1_package(package):
    """The only way a v1 package can be recognised."""
    parsed = parse_package(package)
    v1 = parsed.iv + parsed.signature + parsed.ciphertext
    assert image_digest_for_release({'securePackage': True}, v1) is None


def test_explicit_secure_flag_with_a_supplied_digest_publishes_it(package):
    parsed = parse_package(package)
    v1 = parsed.iv + parsed.signature + parsed.ciphertext
    release = {'securePackage': True, 'imageSha256': firmware_sha256(FIRMWARE)}
    assert image_digest_for_release(release, v1) == firmware_sha256(FIRMWARE)


def test_explicit_false_flag_overrides_the_magic(package):
    """An operator who says it is not a package is believed."""
    assert image_digest_for_release({'securePackage': False}, package) == sha256_bytes(package)


def test_release_is_secure_package_prefers_the_explicit_flag(package):
    assert release_is_secure_package({'securePackage': True}, FIRMWARE)
    assert not release_is_secure_package({'securePackage': False}, package)
    assert release_is_secure_package({}, package)          # falls back to magic
    assert not release_is_secure_package({}, FIRMWARE)


# ── Digest validation ────────────────────────────────────────────────


@pytest.mark.parametrize(
    'bad',
    [
        'z' * 64,                      # 64 chars but not hex
        'g' * 64,
        firmware_sha256(b'x')[:63] + 'z',
        ' ' * 64,
    ],
)
def test_sixty_four_non_hex_characters_are_rejected(package, bad):
    """
    A length-only check would publish a 64-character typo, and every secure
    device would then fail the comparison and quarantine itself.
    """
    assert image_digest_for_release({'imageSha256': bad}, package) is None


def test_is_hex_digest_boundaries():
    assert is_hex_digest('a' * 64)
    assert is_hex_digest('0123456789abcdef' * 4)
    assert not is_hex_digest('a' * 63)
    assert not is_hex_digest('a' * 65)
    assert not is_hex_digest('')
    assert not is_hex_digest('z' * 64)
