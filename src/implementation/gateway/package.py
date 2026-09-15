"""
SentinelOTA Edge Gateway — Secure Firmware Package Format

This module is the single definition of the encrypted package that
`esp32_ota_main.ino` parses in `performSecurePackageUpdate()`. Both the
gateway and `CODE/frimware_code/tools/create_secure_test_package.py` build
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
    6       1     signature_alg  1 = RSA-2048 PKCS#1 v1.5 over SHA-256
                                 2 = Ed25519 (reserved, not yet verified on-device)
    7       1     cipher_alg     1 = AES-256-CBC with PKCS#7 padding
    8       2     signature_len  big-endian
    10      16    iv
    26      n     signature      over the PLAINTEXT firmware bytes
    26+n    ...   ciphertext

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


def build_package(
    firmware_bytes: bytes,
    private_key: rsa.RSAPrivateKey,
    aes_key: str | bytes,
    *,
    iv: bytes | None = None,
) -> bytes:
    """Sign, encrypt, and frame a firmware image into a v2 secure package."""
    if not firmware_bytes:
        raise PackageError('Refusing to package an empty firmware image.')

    aes_key_bytes = normalize_aes_key(aes_key)

    if private_key.key_size != RSA_KEY_SIZE_BITS:
        raise PackageError(
            f'Signing key is RSA-{private_key.key_size}; the firmware needs '
            f'RSA-{RSA_KEY_SIZE_BITS}.'
        )

    signature = private_key.sign(
        firmware_bytes,
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
        + bytes([SIG_ALG_RSA2048_PKCS1V15_SHA256])
        + bytes([CIPHER_ALG_AES256_CBC_PKCS7])
        + len(signature).to_bytes(2, 'big')
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
        if signature_alg not in (SIG_ALG_RSA2048_PKCS1V15_SHA256, SIG_ALG_ED25519):
            raise PackageError(f'Unsupported signature algorithm id {signature_alg}.')

        iv_start = HEADER_BYTES
        sig_start = iv_start + IV_BYTES
        ct_start = sig_start + signature_len

        if len(package) <= ct_start:
            raise PackageError('Package has no ciphertext after the header.')

        return ParsedPackage(
            format_version=2,
            signature_alg=signature_alg,
            cipher_alg=cipher_alg,
            iv=package[iv_start:sig_start],
            signature=package[sig_start:ct_start],
            ciphertext=package[ct_start:],
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

    if parsed.signature_alg != SIG_ALG_RSA2048_PKCS1V15_SHA256:
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

    try:
        public_key.verify(
            parsed.signature,
            firmware_bytes,
            asym_padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise PackageError('Signature does not verify against the supplied public key.') from exc

    return firmware_bytes


def firmware_sha256(firmware_bytes: bytes) -> str:
    """Lowercase hex SHA-256, matching the manifest's `sha256` field.

    The device compares this against what it computes from the decrypted image
    before switching the boot partition, which is what binds a manifest
    version to a specific set of bytes.
    """
    return hashlib.sha256(firmware_bytes).hexdigest()
