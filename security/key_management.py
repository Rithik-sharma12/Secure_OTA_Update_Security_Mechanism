"""Cryptographic key management: generation, rotation, and secure storage."""

import json
import logging
import os
import secrets
from base64 import b64decode, b64encode
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from server.security.crypto import (
    decrypt_aes_gcm,
    derive_key_pbkdf2,
    encrypt_aes_gcm,
    generate_ec_keypair,
    generate_rsa_keypair,
)

logger = logging.getLogger(__name__)

SALT_SIZE = 32
KEY_METADATA_FILE = "key_metadata.json"


class KeyStore:
    """Manages cryptographic key pairs with encrypted-at-rest storage.

    Private keys are encrypted with AES-256-GCM using a key derived from
    the provided passphrase via PBKDF2-HMAC-SHA256 before being written
    to disk. The salt and nonce are stored alongside the ciphertext.
    """

    def __init__(self, key_dir: str) -> None:
        self._key_dir = Path(key_dir)
        self._key_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._metadata_path = self._key_dir / KEY_METADATA_FILE

    def generate_rsa_signing_keypair(
        self,
        key_name: str,
        passphrase: bytes | None = None,
        key_size: int = 4096,
    ) -> tuple[str, str]:
        """Generate and store an RSA key pair for firmware signing.

        Args:
            key_name: Logical name for the key (used as filename prefix).
            passphrase: Optional passphrase to encrypt the private key at rest.
            key_size: RSA modulus size in bits.

        Returns:
            Tuple of (private_key_path, public_key_path).
        """
        private_pem, public_pem = generate_rsa_keypair(key_size)
        return self._store_keypair(key_name, private_pem, public_pem, passphrase)

    def generate_ec_signing_keypair(
        self,
        key_name: str,
        passphrase: bytes | None = None,
    ) -> tuple[str, str]:
        """Generate and store an EC P-256 key pair.

        Args:
            key_name: Logical name for the key.
            passphrase: Optional passphrase for private key encryption.

        Returns:
            Tuple of (private_key_path, public_key_path).
        """
        private_pem, public_pem = generate_ec_keypair()
        return self._store_keypair(key_name, private_pem, public_pem, passphrase)

    def _store_keypair(
        self,
        key_name: str,
        private_pem: bytes,
        public_pem: bytes,
        passphrase: bytes | None,
    ) -> tuple[str, str]:
        """Write a key pair to disk, optionally encrypting the private key."""
        pub_path = self._key_dir / f"{key_name}_public.pem"
        priv_path = self._key_dir / f"{key_name}_private.pem"

        pub_path.write_bytes(public_pem)
        pub_path.chmod(0o644)

        if passphrase:
            self._write_encrypted_key(priv_path, private_pem, passphrase)
        else:
            priv_path.write_bytes(private_pem)
            priv_path.chmod(0o600)

        self._update_metadata(key_name, str(pub_path), str(priv_path))
        logger.info("Key pair stored: %s", key_name)
        return str(priv_path), str(pub_path)

    def _write_encrypted_key(self, path: Path, private_pem: bytes, passphrase: bytes) -> None:
        """Encrypt a private key with AES-256-GCM and write to path."""
        salt = secrets.token_bytes(SALT_SIZE)
        derived_key = derive_key_pbkdf2(passphrase, salt)
        ciphertext, nonce, tag = encrypt_aes_gcm(derived_key, private_pem)
        payload = {
            "salt": b64encode(salt).decode(),
            "nonce": b64encode(nonce).decode(),
            "tag": b64encode(tag).decode(),
            "ciphertext": b64encode(ciphertext).decode(),
        }
        path.write_text(json.dumps(payload))
        path.chmod(0o600)

    def load_private_key(self, key_name: str, passphrase: bytes | None = None) -> bytes:
        """Load and optionally decrypt a stored private key.

        Args:
            key_name: Logical key name.
            passphrase: Required if the key was stored encrypted.

        Returns:
            PEM-encoded private key bytes.

        Raises:
            FileNotFoundError: If the key file does not exist.
            ValueError: If decryption fails or passphrase is incorrect.
        """
        priv_path = self._key_dir / f"{key_name}_private.pem"
        if not priv_path.exists():
            raise FileNotFoundError(f"Private key not found: {key_name}")

        raw = priv_path.read_bytes()

        # Detect encrypted JSON vs plain PEM
        if raw.strip().startswith(b"{"):
            if passphrase is None:
                raise ValueError("Passphrase required to decrypt private key")
            payload = json.loads(raw.decode())
            salt = b64decode(payload["salt"])
            nonce = b64decode(payload["nonce"])
            tag = b64decode(payload["tag"])
            ciphertext = b64decode(payload["ciphertext"])
            derived_key = derive_key_pbkdf2(passphrase, salt)
            return decrypt_aes_gcm(derived_key, ciphertext, nonce, tag)

        return raw

    def load_public_key(self, key_name: str) -> bytes:
        """Load a stored public key PEM.

        Raises:
            FileNotFoundError: If the key file does not exist.
        """
        pub_path = self._key_dir / f"{key_name}_public.pem"
        if not pub_path.exists():
            raise FileNotFoundError(f"Public key not found: {key_name}")
        return pub_path.read_bytes()

    def rotate_key(
        self,
        key_name: str,
        passphrase: bytes | None = None,
        key_type: str = "rsa",
        key_size: int = 4096,
    ) -> tuple[str, str]:
        """Rotate a key pair: archive the old one and generate a new one.

        Args:
            key_name: Logical key name to rotate.
            passphrase: Passphrase for the new private key.
            key_type: 'rsa' or 'ec'.
            key_size: RSA key size (ignored for EC).

        Returns:
            Tuple of (new_private_key_path, new_public_key_path).
        """
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
        self._archive_key(key_name, timestamp)

        if key_type == "ec":
            return self.generate_ec_signing_keypair(key_name, passphrase)
        return self.generate_rsa_signing_keypair(key_name, passphrase, key_size)

    def _archive_key(self, key_name: str, suffix: str) -> None:
        """Rename existing key files to archive them before rotation."""
        for variant in ("public", "private"):
            src = self._key_dir / f"{key_name}_{variant}.pem"
            if src.exists():
                dst = self._key_dir / f"{key_name}_{variant}_archived_{suffix}.pem"
                src.rename(dst)
                logger.info("Archived key: %s → %s", src.name, dst.name)

    def _update_metadata(self, key_name: str, pub_path: str, priv_path: str) -> None:
        """Persist key metadata including creation timestamp."""
        metadata: dict = {}
        if self._metadata_path.exists():
            try:
                metadata = json.loads(self._metadata_path.read_text())
            except json.JSONDecodeError:
                pass

        metadata[key_name] = {
            "public_key": pub_path,
            "private_key": priv_path,
            "created_at": datetime.now(UTC).isoformat(),
        }
        self._metadata_path.write_text(json.dumps(metadata, indent=2))

    def list_keys(self) -> dict:
        """Return key metadata for all stored key pairs."""
        if not self._metadata_path.exists():
            return {}
        try:
            return json.loads(self._metadata_path.read_text())
        except json.JSONDecodeError:
            return {}
