"""
Tests for the secure firmware package format (gateway/package.py).

These cover the format the ESP32 parses in performSecurePackageUpdate(). The
framing test in particular mirrors the arithmetic the firmware does on
Content-Length; if it drifts, a device downloads a package it cannot cut into
the right pieces.
"""

from __future__ import annotations

import pytest

from gateway.package import (
    AES_BLOCK_BYTES,
    CIPHER_ALG_AES256_CBC_PKCS7,
    HEADER_BYTES,
    IV_BYTES,
    MAGIC_V2,
    RSA_SIGNATURE_BYTES,
    SIG_ALG_ED25519,
    SIG_ALG_RSA2048_PKCS1V15_SHA256,
    PackageError,
    build_package,
    firmware_sha256,
    generate_aes_key,
    load_or_create_packaging_key,
    normalize_aes_key,
    open_package,
    parse_package,
)

AES_KEY = 'Vb7Xq9Zm2Kd4Rn1TyP6sJ8wG3hL5cF0e'  # 32 chars, as ota_config.h carries it
FIRMWARE = bytes(range(256)) * 37 + b'not-block-aligned'


@pytest.fixture(scope='module')
def keypair(tmp_path_factory):
    keys = tmp_path_factory.mktemp('pkgkeys')
    private = load_or_create_packaging_key(keys / 'priv.pem', keys / 'pub.pem')
    return private, (keys / 'pub.pem').read_bytes()


# ── Round trip ───────────────────────────────────────────────────────


def test_round_trip_recovers_the_exact_firmware(keypair):
    private, public_pem = keypair
    package = build_package(FIRMWARE, private, AES_KEY)
    assert open_package(package, public_pem, AES_KEY) == FIRMWARE


def test_package_declares_v2_header(keypair):
    private, _ = keypair
    package = build_package(FIRMWARE, private, AES_KEY)

    assert package.startswith(MAGIC_V2)

    parsed = parse_package(package)
    assert parsed.format_version == 2
    assert parsed.signature_alg == SIG_ALG_RSA2048_PKCS1V15_SHA256
    assert parsed.cipher_alg == CIPHER_ALG_AES256_CBC_PKCS7
    assert len(parsed.iv) == IV_BYTES
    assert len(parsed.signature) == RSA_SIGNATURE_BYTES


def test_ciphertext_is_block_aligned(keypair):
    """The firmware refuses a payload that is not a whole number of blocks."""
    private, _ = keypair
    for size in (1, 15, 16, 17, 4096):
        parsed = parse_package(build_package(b'x' * size, private, AES_KEY))
        assert len(parsed.ciphertext) % AES_BLOCK_BYTES == 0


def test_framing_matches_what_the_firmware_computes(keypair):
    """
    esp32_ota_main.ino derives the encrypted size as

        contentLength - (SECURE_HEADER_BYTES + SECURE_IV_BYTES + signatureLength)

    A mismatch here means the device miscounts the payload and aborts, so this
    is the contract between the two codebases.
    """
    private, _ = keypair
    package = build_package(FIRMWARE, private, AES_KEY)
    parsed = parse_package(package)

    framing = HEADER_BYTES + IV_BYTES + RSA_SIGNATURE_BYTES
    assert len(package) - framing == len(parsed.ciphertext)


def test_each_package_uses_a_fresh_iv(keypair):
    """CBC with a reused IV leaks whether two images share a prefix."""
    private, _ = keypair
    ivs = {parse_package(build_package(FIRMWARE, private, AES_KEY)).iv for _ in range(8)}
    assert len(ivs) == 8


# ── Tamper detection ─────────────────────────────────────────────────


def test_flipped_signature_byte_is_rejected(keypair):
    private, public_pem = keypair
    package = bytearray(build_package(FIRMWARE, private, AES_KEY))
    package[HEADER_BYTES + IV_BYTES] ^= 0xFF

    with pytest.raises(PackageError, match='Signature does not verify'):
        open_package(bytes(package), public_pem, AES_KEY)


def test_flipped_ciphertext_byte_is_rejected(keypair):
    private, public_pem = keypair
    package = bytearray(build_package(FIRMWARE, private, AES_KEY))
    package[-1] ^= 0xFF

    with pytest.raises(PackageError):
        open_package(bytes(package), public_pem, AES_KEY)


def test_ciphertext_tampering_in_the_middle_is_rejected(keypair):
    """A flip away from the padding block must still fail, via the signature."""
    private, public_pem = keypair
    package = bytearray(build_package(FIRMWARE, private, AES_KEY))
    midpoint = HEADER_BYTES + IV_BYTES + RSA_SIGNATURE_BYTES + 32
    package[midpoint] ^= 0x01

    with pytest.raises(PackageError):
        open_package(bytes(package), public_pem, AES_KEY)


def test_wrong_aes_key_is_rejected(keypair):
    _, public_pem = keypair
    private, _ = keypair
    package = build_package(FIRMWARE, private, AES_KEY)

    with pytest.raises(PackageError):
        open_package(package, public_pem, 'Z' * 32)


def test_signature_from_a_different_key_is_rejected(keypair, tmp_path):
    private, _ = keypair
    other_public = load_or_create_packaging_key(
        tmp_path / 'other-priv.pem', tmp_path / 'other-pub.pem'
    )
    del other_public

    package = build_package(FIRMWARE, private, AES_KEY)

    with pytest.raises(PackageError, match='Signature does not verify'):
        open_package(package, (tmp_path / 'other-pub.pem').read_bytes(), AES_KEY)


# ── Header validation ────────────────────────────────────────────────


def test_unknown_signature_algorithm_is_refused(keypair):
    """A device must reject what it cannot verify, not guess at it."""
    private, _ = keypair
    package = bytearray(build_package(FIRMWARE, private, AES_KEY))
    package[6] = 99

    with pytest.raises(PackageError, match='Unsupported signature algorithm'):
        parse_package(bytes(package))


def test_unknown_cipher_algorithm_is_refused(keypair):
    private, _ = keypair
    package = bytearray(build_package(FIRMWARE, private, AES_KEY))
    package[7] = 99

    with pytest.raises(PackageError, match='Unsupported cipher algorithm'):
        parse_package(bytes(package))


def test_declared_ed25519_parses_but_does_not_open(keypair):
    """
    The id is reserved so the format can carry Ed25519 later. Until the device
    can verify it, opening such a package must fail loudly rather than fall
    through to the RSA verifier.
    """
    private, public_pem = keypair
    package = bytearray(build_package(FIRMWARE, private, AES_KEY))
    package[6] = SIG_ALG_ED25519

    assert parse_package(bytes(package)).signature_alg == SIG_ALG_ED25519

    with pytest.raises(PackageError, match='not implemented'):
        open_package(bytes(package), public_pem, AES_KEY)


@pytest.mark.parametrize('length', [0, 1, HEADER_BYTES, HEADER_BYTES + IV_BYTES])
def test_truncated_package_is_refused(keypair, length):
    private, _ = keypair
    package = build_package(FIRMWARE, private, AES_KEY)

    with pytest.raises(PackageError):
        parse_package(package[:length])


def test_header_fits_inside_the_iv():
    """
    The firmware's v1 branch reads SECURE_HEADER_BYTES speculatively and reuses
    them as the front of the IV, which only works while the header is no larger
    than the IV.
    """
    assert HEADER_BYTES <= IV_BYTES


# ── Legacy v1 ────────────────────────────────────────────────────────


def test_v1_package_still_parses_and_verifies(keypair):
    private, public_pem = keypair
    parsed = parse_package(build_package(FIRMWARE, private, AES_KEY))
    v1 = parsed.iv + parsed.signature + parsed.ciphertext

    legacy = parse_package(v1)
    assert legacy.format_version == 1
    assert legacy.iv == parsed.iv
    assert legacy.ciphertext == parsed.ciphertext
    assert open_package(v1, public_pem, AES_KEY) == FIRMWARE


def test_v1_too_short_is_refused():
    with pytest.raises(PackageError):
        parse_package(b'\x00' * (IV_BYTES + RSA_SIGNATURE_BYTES))


# ── Inputs ───────────────────────────────────────────────────────────


def test_empty_firmware_is_refused(keypair):
    private, _ = keypair
    with pytest.raises(PackageError, match='empty firmware'):
        build_package(b'', private, AES_KEY)


@pytest.mark.parametrize('bad_key', ['', 'short', 'x' * 31, 'x' * 33])
def test_aes_key_must_be_exactly_32_bytes(bad_key):
    with pytest.raises(PackageError, match='32 bytes'):
        normalize_aes_key(bad_key)


def test_ascii_and_raw_keys_are_equivalent():
    assert normalize_aes_key(AES_KEY) == AES_KEY.encode('ascii')
    raw = generate_aes_key()
    assert normalize_aes_key(raw) == raw
    assert len(raw) == 32


def test_explicit_iv_is_honoured(keypair):
    private, _ = keypair
    iv = bytes(range(IV_BYTES))
    assert parse_package(build_package(FIRMWARE, private, AES_KEY, iv=iv)).iv == iv


def test_wrong_length_iv_is_refused(keypair):
    private, _ = keypair
    with pytest.raises(PackageError, match='IV must be'):
        build_package(FIRMWARE, private, AES_KEY, iv=b'\x00' * 8)


# ── Key handling ─────────────────────────────────────────────────────


def test_key_is_reused_across_calls(tmp_keys_dir):
    """Regenerating on every publish would invalidate every deployed device."""
    first = load_or_create_packaging_key(tmp_keys_dir / 'p.pem', tmp_keys_dir / 'pub.pem')
    public_after_first = (tmp_keys_dir / 'pub.pem').read_bytes()

    second = load_or_create_packaging_key(tmp_keys_dir / 'p.pem', tmp_keys_dir / 'pub.pem')

    assert first.private_numbers() == second.private_numbers()
    assert (tmp_keys_dir / 'pub.pem').read_bytes() == public_after_first


def test_regenerate_replaces_the_key(tmp_keys_dir):
    first = load_or_create_packaging_key(tmp_keys_dir / 'p.pem', tmp_keys_dir / 'pub.pem')
    second = load_or_create_packaging_key(
        tmp_keys_dir / 'p.pem', tmp_keys_dir / 'pub.pem', regenerate=True
    )
    assert first.private_numbers() != second.private_numbers()


def test_private_key_is_not_world_readable(tmp_keys_dir):
    path = tmp_keys_dir / 'p.pem'
    load_or_create_packaging_key(path, tmp_keys_dir / 'pub.pem')
    assert path.stat().st_mode & 0o077 == 0


def test_non_rsa_key_file_is_rejected(tmp_keys_dir):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    path = tmp_keys_dir / 'ed25519.pem'
    path.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    with pytest.raises(PackageError, match='not an RSA private key'):
        load_or_create_packaging_key(path, tmp_keys_dir / 'pub.pem')


# ── Digest ───────────────────────────────────────────────────────────


def test_firmware_sha256_is_lowercase_hex_of_the_plaintext():
    import hashlib

    digest = firmware_sha256(FIRMWARE)
    assert digest == hashlib.sha256(FIRMWARE).hexdigest()
    assert len(digest) == 64
    assert digest == digest.lower()


def test_digest_is_of_the_plaintext_not_the_package(keypair):
    """
    The device compares this against what it computes from the *decrypted*
    image, so hashing the package instead would never match.
    """
    private, _ = keypair
    package = build_package(FIRMWARE, private, AES_KEY)
    assert firmware_sha256(FIRMWARE) != firmware_sha256(package)
