"""
SentinelOTA Edge Gateway — Secure Firmware Package Format

This module is the single definition of the encrypted package that
`esp32_ota_main.ino` parses in `performSecurePackageUpdate()`. Both the
gateway and `firmware/tools/create_secure_test_package.py` build
packages through here, so the format cannot drift between the thing that
produces packages and the thing that documents them.

Why RSA here when the gateway signs manifests with Ed25519
----------------------------------------------------------
The gateway has always signed *manifests* with Ed25519 (see crypto.py), while
the firmware's secure path verifies a 256-byte RSA-2048 PKCS#1 v1.5 signature
over SHA-256. Those are different algorithms with different signature lengths,
so nothing the gateway produced could ever satisfy the device — in practice
only the standalone bench tool made packages a device would accept, and the
gateway's signature was decorative.

The device side is constrained: the ESP32 Arduino core's mbedTLS build exposes
RSA and ECDSA through `mbedtls_pk_verify` but not Ed25519, so verifying Ed25519
on-device would mean vendoring a new crypto library into the firmware. Rather
than do that blind, the gateway gains the ability to sign packages with an
RSA-2048 key that the existing firmware already verifies. Ed25519 stays where
it works: signing the manifest metadata the dashboard displays.

The header carries an explicit algorithm identifier so an Ed25519 package
variant can be introduced later without a flag day — a device that does not
recognise the algorithm rejects the package instead of misparsing it.

Package layout
--------------
Version 2 (produced by this module)::

    offset  size  field
    0       6     magic          b'SOTAv2'
    6       1     signature_alg  1 = RSA-2048 PKCS#1 v1.5 over SHA-256 of the
                                     plaintext firmware (legacy, unversioned)
                                 2 = Ed25519 (reserved, not yet verified on-device)
                                 3 = RSA-2048 PKCS#1 v1.5 over SHA-256 of the
                                     version statement below (default)
    7       1     cipher_alg     1 = AES-256-CBC with PKCS#7 padding
    8       2     signature_len  big-endian
    -- signature_alg 3 only --
    10      1     version_len    1..32
    11      v     version        ASCII, e.g. b'2.5.0'
    --
    ..      16    iv
    ..      n     signature
    ..      ...   ciphertext

Why the version is signed (signature_alg 3)
-------------------------------------------
With signature_alg 1 the signature covers only the firmware bytes, so the
version a device compares against its own comes from the manifest — which
travels over plain HTTP in local mode and is never signature-checked on the
device. Anyone who can answer the manifest request could then pair a genuinely
signed OLD image with a "newer" version string and roll the board back.

signature_alg 3 signs a version statement instead::

    SHA-256( b'SOTA-FW\x00' || version || b'\x00' || SHA-256(firmware) )

so the version is vouched for by the release key, not by the transport. The
device refuses a package whose signed version is not strictly newer than the
running firmware, whatever the manifest says. The firmware rejects signature
algorithm 1 and v1 packages unless built with OTA_ALLOW_UNVERSIONED_PACKAGES.

Version 1 (legacy, still parsed by the firmware and by `parse_package`)::

    [16-byte IV][256-byte RSA signature][AES-256-CBC ciphertext]

The signature covers the plaintext firmware, so a device must decrypt before it
can verify. That is why the firmware hashes as it decrypts and only calls
`Update.end(true)` — the call that switches the boot partition — after both the
signature and the manifest digest have checked out.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC_V2 = b'SOTAv2'

SIG_ALG_RSA2048_PKCS1V15_SHA256 = 1
SIG_ALG_ED25519 = 2
SIG_ALG_RSA2048_VERSIONED = 3

VERSION_STATEMENT_PREFIX = b'SOTA-FW\x00'
MAX_VERSION_BYTES = 32

CIPHER_ALG_AES256_CBC_PKCS7 = 1

IV_BYTES = 16
RSA_SIGNATURE_BYTES = 256
AES_KEY_BYTES = 32
AES_BLOCK_BYTES = 16
HEADER_BYTES = 10  # magic(6) + sig_alg(1) + cipher_alg(1) + sig_len(2)

RSA_KEY_SIZE_BITS = 2048
RSA_PUBLIC_EXPONENT = 65537


class PackageError(ValueError):
    """Raised when a package cannot be built, parsed, or verified."""


@dataclass(frozen=True)
class ParsedPackage:
    """A package broken into its parts, before any cryptographic checking."""

    format_version: int
    signature_alg: int
    cipher_alg: int
    iv: bytes
    signature: bytes
    ciphertext: bytes
    version: str | None = None


# ── Key management ───────────────────────────────────────────────────


def load_or_create_packaging_key(
    private_key_path: Path,
    public_key_path: Path,
    *,
    regenerate: bool = False,
) -> rsa.RSAPrivateKey:
    """Load the RSA package-signing key, generating one on first use.

    The private key is written unencrypted, matching how the Ed25519 manifest
    key is handled. That is acceptable only because both are expected to live
    on a volume the operator controls (`gateway_keys/`, git-ignored and mounted
    as a Docker volume). Anyone who can read this file can sign firmware for
    the entire fleet.
    """
    if private_key_path.exists() and not regenerate:
        loaded = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
        if not isinstance(loaded, rsa.RSAPrivateKey):
            raise PackageError(f'{private_key_path} is not an RSA private key.')
        if loaded.key_size != RSA_KEY_SIZE_BITS:
            raise PackageError(
                f'{private_key_path} is RSA-{loaded.key_size}; the firmware reads a fixed '
                f'{RSA_SIGNATURE_BYTES}-byte signature and needs RSA-{RSA_KEY_SIZE_BITS}.'
            )
        private_key = loaded
    else:
        private_key = rsa.generate_private_key(
            public_exponent=RSA_PUBLIC_EXPONENT,
            key_size=RSA_KEY_SIZE_BITS,
        )
        private_key_path.parent.mkdir(parents=True, exist_ok=True)
        private_key_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        private_key_path.chmod(0o600)

    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_key


def generate_aes_key() -> bytes:
    """A fresh 32-byte AES-256 key from the system CSPRNG."""
    return secrets.token_bytes(AES_KEY_BYTES)


def normalize_aes_key(key: str | bytes) -> bytes:
    """Accept the 32-character ASCII form used by ota_config.h, or raw bytes.

    `FIRMWARE_ENC_KEY` in the firmware is a C string literal, so deployments
    carry the key as 32 printable characters rather than 32 arbitrary bytes.
    That costs roughly half the key's entropy (~190 bits of the nominal 256
    for the alphanumeric alphabet) and is still far beyond brute force, so it
    is supported rather than fought.
    """
    key_bytes = key.encode('ascii') if isinstance(key, str) else bytes(key)
    if len(key_bytes) != AES_KEY_BYTES:
        raise PackageError(
            f'AES key must be exactly {AES_KEY_BYTES} bytes; got {len(key_bytes)}.'
        )
    return key_bytes


# ── Build ────────────────────────────────────────────────────────────


def version_statement(version: str, firmware_bytes: bytes) -> bytes:
    """The bytes a signature_alg 3 signature covers (hashed again by RSA)."""
    return (
        VERSION_STATEMENT_PREFIX
        + _encode_version(version)
        + b'\x00'
        + hashlib.sha256(firmware_bytes).digest()
    )


def _encode_version(version: str) -> bytes:
    text = str(version).strip()
    if text[:1] in ('v', 'V'):
        text = text[1:]
    parts = text.split('.')
    if len(parts) != 3 or not all(part.isdigit() and len(part) <= 3 for part in parts):
        raise PackageError(
            f'Package version must be MAJOR.MINOR.PATCH with each part 0-999; got {version!r}.'
        )
    encoded = '.'.join(str(int(part)) for part in parts).encode('ascii')
    if len(encoded) > MAX_VERSION_BYTES:
        raise PackageError(f'Package version is longer than {MAX_VERSION_BYTES} bytes.')
    return encoded


def build_package(
    firmware_bytes: bytes,
    private_key: rsa.RSAPrivateKey,
    aes_key: str | bytes,
    *,
    version: str | None,
    iv: bytes | None = None,
) -> bytes:
    """Sign, encrypt, and frame a firmware image into a v2 secure package.

    `version` is required and is signed together with the image
    (signature_alg 3). Passing None deliberately builds the legacy unversioned
    form (signature_alg 1), which current firmware refuses unless it was built
    with OTA_ALLOW_UNVERSIONED_PACKAGES.
    """
    if not firmware_bytes:
        raise PackageError('Refusing to package an empty firmware image.')

    if version is None:
        signature_alg = SIG_ALG_RSA2048_PKCS1V15_SHA256
        signed_message = firmware_bytes
        version_field = b''
    else:
        signature_alg = SIG_ALG_RSA2048_VERSIONED
        encoded_version = _encode_version(version)
        signed_message = version_statement(version, firmware_bytes)
        version_field = bytes([len(encoded_version)]) + encoded_version

    aes_key_bytes = normalize_aes_key(aes_key)

    if private_key.key_size != RSA_KEY_SIZE_BITS:
        raise PackageError(
            f'Signing key is RSA-{private_key.key_size}; the firmware needs '
            f'RSA-{RSA_KEY_SIZE_BITS}.'
        )

    signature = private_key.sign(
        signed_message,
        asym_padding.PKCS1v15(),
        hashes.SHA256(),
    )
    if len(signature) != RSA_SIGNATURE_BYTES:
        raise PackageError(
            f'Unexpected signature length {len(signature)}; the firmware reads '
            f'exactly {RSA_SIGNATURE_BYTES} bytes.'
        )

    if iv is None:
        iv = secrets.token_bytes(IV_BYTES)
    elif len(iv) != IV_BYTES:
        raise PackageError(f'IV must be {IV_BYTES} bytes; got {len(iv)}.')

    padder = sym_padding.PKCS7(AES_BLOCK_BYTES * 8).padder()
    padded = padder.update(firmware_bytes) + padder.finalize()

    encryptor = Cipher(algorithms.AES(aes_key_bytes), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    header = (
        MAGIC_V2
        + bytes([signature_alg])
        + bytes([CIPHER_ALG_AES256_CBC_PKCS7])
        + len(signature).to_bytes(2, 'big')
        + version_field
    )
    return header + iv + signature + ciphertext


# ── Parse and verify ─────────────────────────────────────────────────


def parse_package(package: bytes) -> ParsedPackage:
    """Split a v1 or v2 package into its parts without verifying anything."""
    if package.startswith(MAGIC_V2):
        if len(package) < HEADER_BYTES + IV_BYTES:
            raise PackageError('Package truncated inside the v2 header.')

        signature_alg = package[6]
        cipher_alg = package[7]
        signature_len = int.from_bytes(package[8:10], 'big')

        if cipher_alg != CIPHER_ALG_AES256_CBC_PKCS7:
            raise PackageError(f'Unsupported cipher algorithm id {cipher_alg}.')
        if signature_alg not in (
            SIG_ALG_RSA2048_PKCS1V15_SHA256,
            SIG_ALG_ED25519,
            SIG_ALG_RSA2048_VERSIONED,
        ):
            raise PackageError(f'Unsupported signature algorithm id {signature_alg}.')

        iv_start = HEADER_BYTES
        version: str | None = None
        if signature_alg == SIG_ALG_RSA2048_VERSIONED:
            version_len = package[HEADER_BYTES]
            if not 1 <= version_len <= MAX_VERSION_BYTES:
                raise PackageError(f'Invalid signed version length {version_len}.')
            raw_version = package[HEADER_BYTES + 1:HEADER_BYTES + 1 + version_len]
            if len(raw_version) != version_len:
                raise PackageError('Package truncated inside the signed version.')
            try:
                version = raw_version.decode('ascii')
            except UnicodeDecodeError as exc:
                raise PackageError('Signed version is not ASCII.') from exc
            iv_start = HEADER_BYTES + 1 + version_len

        sig_start = iv_start + IV_BYTES
        ct_start = sig_start + signature_len

        if len(package) < sig_start:
            raise PackageError('Package truncated inside the v2 header.')
        if len(package) <= ct_start:
            raise PackageError('Package has no ciphertext after the header.')

        return ParsedPackage(
            format_version=2,
            signature_alg=signature_alg,
            cipher_alg=cipher_alg,
            iv=package[iv_start:sig_start],
            signature=package[sig_start:ct_start],
            ciphertext=package[ct_start:],
            version=version,
        )

    # Legacy v1: no header, fixed-width IV and RSA signature.
    minimum = IV_BYTES + RSA_SIGNATURE_BYTES
    if len(package) <= minimum:
        raise PackageError(
            f'Package is {len(package)} bytes; a v1 package needs more than {minimum}.'
        )

    return ParsedPackage(
        format_version=1,
        signature_alg=SIG_ALG_RSA2048_PKCS1V15_SHA256,
        cipher_alg=CIPHER_ALG_AES256_CBC_PKCS7,
        iv=package[:IV_BYTES],
        signature=package[IV_BYTES:minimum],
        ciphertext=package[minimum:],
    )


def open_package(package: bytes, public_key_pem: bytes, aes_key: str | bytes) -> bytes:
    """Decrypt a package and verify its signature, returning the firmware.

    This is the host-side mirror of what the device does, so the gateway can
    prove a package it just built is one a device would actually accept
    before publishing it.
    """
    parsed = parse_package(package)

    if parsed.signature_alg not in (SIG_ALG_RSA2048_PKCS1V15_SHA256, SIG_ALG_RSA2048_VERSIONED):
        raise PackageError(
            f'Signature algorithm id {parsed.signature_alg} is declared but not '
            'implemented here.'
        )

    if len(parsed.ciphertext) % AES_BLOCK_BYTES != 0:
        raise PackageError(
            f'Ciphertext is {len(parsed.ciphertext)} bytes, not a multiple of the '
            f'{AES_BLOCK_BYTES}-byte AES block size.'
        )

    aes_key_bytes = normalize_aes_key(aes_key)
    decryptor = Cipher(algorithms.AES(aes_key_bytes), modes.CBC(parsed.iv)).decryptor()
    padded = decryptor.update(parsed.ciphertext) + decryptor.finalize()

    try:
        unpadder = sym_padding.PKCS7(AES_BLOCK_BYTES * 8).unpadder()
        firmware_bytes = unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        # Wrong AES key, or a corrupted package. Both land here.
        raise PackageError(f'PKCS#7 padding is invalid: {exc}') from exc

    public_key = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise PackageError('Public key is not an RSA key.')

    if parsed.signature_alg == SIG_ALG_RSA2048_VERSIONED:
        signed_message = version_statement(parsed.version or '', firmware_bytes)
    else:
        signed_message = firmware_bytes

    try:
        public_key.verify(
            parsed.signature,
            signed_message,
            asym_padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise PackageError('Signature does not verify against the supplied public key.') from exc

    return firmware_bytes


def looks_like_secure_package(payload: bytes) -> bool:
    """True when an artifact is recognisably a v2 secure package.

    Detection is by magic only, and deliberately so. The obvious shape test for
    a headerless v1 package — big enough for the IV and signature, with a
    block-aligned remainder — is worthless in practice: IV_BYTES +
    RSA_SIGNATURE_BYTES is 272, itself a multiple of 16, so the test collapses
    to `len(payload) > 272 and len(payload) % 16 == 0`. ESP-IDF application
    images are always 16-byte aligned, so that matches essentially every plain
    firmware image ever published and would suppress `imageSha256` for all of
    them.

    A v1 package therefore cannot be detected from its bytes. Publishers mark
    one explicitly with the `secure_package` flag on the release; this function
    only supplies the default.
    """
    return payload.startswith(MAGIC_V2)


def is_hex_digest(value: str) -> bool:
    """True for exactly 64 hex characters — a well-formed SHA-256 digest.

    A length check alone would let a 64-character typo through and be published
    as a digest, which fails every update on a device that compares it.
    """
    if len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def firmware_sha256(firmware_bytes: bytes) -> str:
    """Lowercase hex SHA-256, matching the manifest's `sha256` field.

    The device compares this against what it computes from the decrypted image
    before switching the boot partition, which is what binds a manifest
    version to a specific set of bytes.
    """
    return hashlib.sha256(firmware_bytes).hexdigest()
