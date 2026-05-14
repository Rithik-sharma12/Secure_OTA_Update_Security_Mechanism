"""Cryptographic primitives: RSA-SHA256, ECDSA, AES-256-GCM, PBKDF2."""

import hashlib
import hmac
import logging
import os
import secrets
from base64 import b64decode, b64encode

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)

AES_KEY_SIZE = 32  # 256 bits
AES_NONCE_SIZE = 12  # 96 bits (recommended for GCM)
PBKDF2_KEY_LENGTH = 32
PBKDF2_ITERATIONS = 600_000


def verify_rsa_sha256_signature(public_key_pem: bytes, data: bytes, signature: bytes) -> bool:
    """Verify an RSA-SHA256 PKCS#1v1.5 signature.

    Args:
        public_key_pem: PEM-encoded RSA public key.
        data: The original signed data.
        signature: The raw signature bytes to verify.

    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(public_key, rsa.RSAPublicKey):
            logger.warning("Key is not an RSA public key")
            return False
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        logger.debug("RSA-SHA256 signature verification failed")
        return False
    except Exception as exc:
        logger.error("RSA-SHA256 verification error: %s", exc)
        return False


def sign_rsa_sha256(private_key_pem: bytes, data: bytes) -> bytes:
    """Sign data with an RSA private key using SHA-256 and PKCS#1v1.5 padding.

    Args:
        private_key_pem: PEM-encoded RSA private key (optionally passphrase-protected).
        data: The data to sign.

    Returns:
        Raw signature bytes.

    Raises:
        ValueError: If the key cannot be loaded or is not RSA.
    """
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Provided key is not an RSA private key")
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def verify_ecdsa_signature(public_key_pem: bytes, data: bytes, signature: bytes) -> bool:
    """Verify an ECDSA (P-256 / SHA-256) DER-encoded signature.

    Args:
        public_key_pem: PEM-encoded EC public key.
        data: The original signed data.
        signature: DER-encoded ECDSA signature bytes.

    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            logger.warning("Key is not an EC public key")
            return False
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        logger.debug("ECDSA signature verification failed")
        return False
    except Exception as exc:
        logger.error("ECDSA verification error: %s", exc)
        return False


def sign_ecdsa(private_key_pem: bytes, data: bytes) -> bytes:
    """Sign data with an EC private key using ECDSA/SHA-256.

    Args:
        private_key_pem: PEM-encoded EC private key.
        data: The data to sign.

    Returns:
        DER-encoded ECDSA signature bytes.

    Raises:
        ValueError: If the key is not an EC key.
    """
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("Provided key is not an EC private key")
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


def encrypt_aes_gcm(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM.

    Args:
        key: 32-byte AES key.
        plaintext: Data to encrypt.

    Returns:
        Tuple of (ciphertext, nonce, tag). The tag is the last 16 bytes
        of the raw AESGCM output and is separated for API clarity.

    Raises:
        ValueError: If the key length is not 32 bytes.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES key must be {AES_KEY_SIZE} bytes, got {len(key)}")
    nonce = secrets.token_bytes(AES_NONCE_SIZE)
    aesgcm = AESGCM(key)
    # AESGCM.encrypt returns ciphertext || tag (16-byte tag appended)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    tag = ciphertext_with_tag[-16:]
    ciphertext = ciphertext_with_tag[:-16]
    return ciphertext, nonce, tag


def decrypt_aes_gcm(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
    """Decrypt AES-256-GCM ciphertext and authenticate the tag.

    Args:
        key: 32-byte AES key.
        ciphertext: Encrypted data (without tag).
        nonce: 12-byte nonce used during encryption.
        tag: 16-byte authentication tag.

    Returns:
        Decrypted plaintext.

    Raises:
        ValueError: If decryption or authentication fails.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES key must be {AES_KEY_SIZE} bytes, got {len(key)}")
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext + tag, None)
    except InvalidTag as exc:
        raise ValueError("AES-GCM authentication tag verification failed") from exc


def compute_sha256(data: bytes) -> str:
    """Compute the SHA-256 digest of data and return a lowercase hex string.

    Args:
        data: Bytes to hash.

    Returns:
        64-character lowercase hexadecimal digest.
    """
    return hashlib.sha256(data).hexdigest()


def generate_rsa_keypair(key_size: int = 4096) -> tuple[bytes, bytes]:
    """Generate an RSA key pair and return PEM-encoded bytes.

    Args:
        key_size: RSA modulus size in bits (minimum 2048, default 4096).

    Returns:
        Tuple of (private_key_pem, public_key_pem).

    Raises:
        ValueError: If key_size is below 2048.
    """
    if key_size < 2048:
        raise ValueError("RSA key size must be at least 2048 bits")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def generate_ec_keypair(curve: ec.EllipticCurve | None = None) -> tuple[bytes, bytes]:
    """Generate an EC key pair (default P-256) and return PEM-encoded bytes.

    Args:
        curve: Elliptic curve to use; defaults to SECP256R1 (P-256).

    Returns:
        Tuple of (private_key_pem, public_key_pem).
    """
    if curve is None:
        curve = ec.SECP256R1()
    private_key = ec.generate_private_key(curve)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def derive_key_pbkdf2(
    password: bytes,
    salt: bytes,
    iterations: int = PBKDF2_ITERATIONS,
    key_length: int = PBKDF2_KEY_LENGTH,
) -> bytes:
    """Derive a cryptographic key from a password using PBKDF2-HMAC-SHA256.

    Args:
        password: Password bytes.
        salt: Random salt bytes (minimum 16 bytes recommended).
        iterations: Number of PBKDF2 iterations (default 600,000 per OWASP).
        key_length: Desired key length in bytes (default 32).

    Returns:
        Derived key bytes of length `key_length`.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Compare two byte strings in constant time to prevent timing attacks."""
    return hmac.compare_digest(a, b)


def encode_signature_b64(signature: bytes) -> str:
    """Base64-encode a signature for storage or transport."""
    return b64encode(signature).decode("ascii")


def decode_signature_b64(signature_b64: str) -> bytes:
    """Decode a Base64-encoded signature.

    Raises:
        ValueError: If the input is not valid Base64.
    """
    try:
        return b64decode(signature_b64)
    except Exception as exc:
        raise ValueError("Invalid Base64-encoded signature") from exc
