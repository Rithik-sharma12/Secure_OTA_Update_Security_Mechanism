"""
SecureOTA Edge Gateway — Ed25519 Cryptographic Operations

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
from .utils import utc_now_iso

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


# ── Manifest statement (stage 5 of the device pipeline) ─────────────────
#
# The device cannot afford to verify a signature over a whole firmware image
# (an ATmega328P cannot even hold one), so the gateway also signs a short
# statement that binds the manifest fields the device acts on. The device
# checks the downloaded bytes against `sha256` (stage 4) and this signature
# over `sha256` (stage 5), which together bind the image to the gateway key.
#
# The exact byte layout is shared with firmware/lib/sota_core
# (sota_manifest_message); changing either side breaks every device.
MANIFEST_SIGNATURE_PREFIX = 'SOTA-MANIFEST-V1'
MANIFEST_SIGNATURE_FORMAT = 'SOTA-MANIFEST-V1: prefix, version, sha256, imageSha256, size; newline separated'


def manifest_signing_message(version: str, sha256: str, image_sha256: str | None, size: int) -> bytes:
    """The statement a device verifies with the gateway's Ed25519 public key."""
    version = str(version).strip()
    sha256 = str(sha256 or '').strip().lower()
    image_sha256 = str(image_sha256 or '').strip().lower()
    if not version or len(version) > 32 or any(ch in version for ch in '\r\n'):
        raise ValueError('Manifest version cannot be signed.')
    if len(sha256) != 64:
        raise ValueError('Manifest sha256 must be 64 hex characters.')
    if image_sha256 and len(image_sha256) != 64:
        raise ValueError('Manifest imageSha256 must be 64 hex characters.')
    return '\n'.join([MANIFEST_SIGNATURE_PREFIX, version, sha256, image_sha256, str(int(size))]).encode('ascii')


def with_manifest_signature(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of `manifest` carrying `manifestSignature` over its current fields."""
    signed = dict(manifest)
    try:
        message = manifest_signing_message(
            str(signed.get('version', '')),
            str(signed.get('sha256', '')),
            signed.get('imageSha256'),
            int(signed.get('size', 0)),
        )
    except (TypeError, ValueError):
        # Not a full release manifest (for example "no update assigned").
        return signed
    signed['manifestSignature'] = base64.b64encode(get_signing_key().sign(message)).decode('ascii')
    signed['manifestSignatureAlgorithm'] = SIGNING_ALGORITHM
    signed['manifestSignatureFormat'] = MANIFEST_SIGNATURE_FORMAT
    return signed


def verify_manifest_signature(version: str, sha256: str, image_sha256: str | None, size: int, signature_b64: str) -> bool:
    """Gateway-assisted stage 5 for boards that cannot run Ed25519 themselves."""
    from cryptography.exceptions import InvalidSignature

    try:
        message = manifest_signing_message(version, sha256, image_sha256, size)
        signature = base64.b64decode(signature_b64, validate=True)
    except (TypeError, ValueError):
        return False
    if len(signature) != 64:
        return False
    try:
        get_signing_key().public_key().verify(signature, message)
    except InvalidSignature:
        return False
    return True


def public_key_hex() -> str:
    """The raw 32-byte Ed25519 public key in hex, as devices store it."""
    return get_signing_key().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


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
        # Was reported as 'ECDSA'. The key is Ed25519 (EdDSA over Curve25519),
        # which is a different algorithm with a different signature format —
        # the key vault page was telling operators the wrong thing about the
        # key they are trusting.
        'type': SIGNING_ALGORITHM,
        'keySize': 256,
        'createdAt': created_at,
        # An Ed25519 key has no expiry. A date computed as "now + 5 years" on
        # every request was shown as if it were one.
        'expiresAt': None,
        'active': True,
    }

    certificate_record = {
        'id': 'cert-gateway-signing-key',
        'name': 'Gateway Signing Public Key',
        # Not an X.509 certificate: a bare public key the gateway generated
        # itself. No issuer and no validity window exist, so none are claimed.
        'issuer': 'Self-generated by this gateway',
        'subject': f'CN={SIGNING_KEY_ID}',
        'validFrom': created_at,
        'validTo': None,
        'fingerprint': fingerprint,
    }

    return key_record, certificate_record
