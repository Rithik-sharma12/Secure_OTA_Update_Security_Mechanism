"""
SentinelOTA Edge Gateway — Ed25519 Cryptographic Operations

Key management, firmware signing, and fingerprint generation.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .config import (
    KEYS_DIR,
    PRIVATE_SIGNING_KEY_PATH,
    PUBLIC_SIGNING_KEY_PATH,
    SIGNING_ALGORITHM,
    SIGNING_KEY_ID,
)
from .utils import now_plus_days, utc_now_iso

from typing import Any

# Module-level cache for the signing key
_signing_key_cache: Ed25519PrivateKey | None = None


def _write_signing_material(private_key: Ed25519PrivateKey) -> None:
    """Persist both private and public key PEM files."""
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(PRIVATE_SIGNING_KEY_PATH, 'wb') as private_file:
        private_file.write(private_bytes)

    with open(PUBLIC_SIGNING_KEY_PATH, 'wb') as public_file:
        public_file.write(public_bytes)


def load_or_create_signing_key() -> Ed25519PrivateKey:
    """Load an existing Ed25519 key from disk, or generate a new one."""
    if PRIVATE_SIGNING_KEY_PATH.exists():
        with open(PRIVATE_SIGNING_KEY_PATH, 'rb') as private_file:
            key_data = private_file.read()

        loaded = serialization.load_pem_private_key(key_data, password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise RuntimeError('Configured signing key is not an Ed25519 private key.')

        if not PUBLIC_SIGNING_KEY_PATH.exists():
            _write_signing_material(loaded)

        return loaded

    generated = Ed25519PrivateKey.generate()
    _write_signing_material(generated)
    return generated


def get_signing_key() -> Ed25519PrivateKey:
    """Return the cached signing key, loading/creating on first access."""
    global _signing_key_cache

    if _signing_key_cache is None:
        _signing_key_cache = load_or_create_signing_key()

    return _signing_key_cache


def signing_fingerprint_hex() -> str:
    """SHA-256 fingerprint of the public key in hex."""
    raw_public = get_signing_key().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw_public).hexdigest()


def sign_firmware_payload(payload: bytes) -> str:
    """Sign a firmware payload and return base64-encoded signature."""
    signature = get_signing_key().sign(payload)
    return base64.b64encode(signature).decode('ascii')


def build_signing_metadata() -> tuple[dict[str, Any], dict[str, Any]]:
    """Build key record and certificate record for dashboard display."""
    from datetime import datetime, timezone

    if PRIVATE_SIGNING_KEY_PATH.exists():
        created_at = datetime.fromtimestamp(
            PRIVATE_SIGNING_KEY_PATH.stat().st_mtime,
            tz=timezone.utc,
        ).replace(microsecond=0).isoformat()
    else:
        created_at = utc_now_iso()

    fingerprint = signing_fingerprint_hex()

    key_record = {
        'id': SIGNING_KEY_ID,
        'name': 'Gateway Ed25519 Signing Key',
        'type': 'ECDSA',
        'keySize': 256,
        'createdAt': created_at,
        'expiresAt': now_plus_days(1825),
        'active': True,
    }

    certificate_record = {
        'id': 'cert-gateway-signing-key',
        'name': 'Gateway Signing Public Key',
        'issuer': 'SentinelOTA Local Signing Authority',
        'subject': f'CN={SIGNING_KEY_ID}',
        'validFrom': created_at,
        'validTo': now_plus_days(1825),
        'fingerprint': fingerprint,
    }

    return key_record, certificate_record
