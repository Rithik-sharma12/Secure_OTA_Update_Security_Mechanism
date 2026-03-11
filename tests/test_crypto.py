"""Tests for cryptographic primitives in server/security/crypto.py."""

import os
import pytest

from server.security.crypto import (
    compute_sha256,
    constant_time_compare,
    decode_signature_b64,
    decrypt_aes_gcm,
    derive_key_pbkdf2,
    encode_signature_b64,
    encrypt_aes_gcm,
    generate_ec_keypair,
    generate_rsa_keypair,
    sign_ecdsa,
    sign_rsa_sha256,
    verify_ecdsa_signature,
    verify_rsa_sha256_signature,
)


# ── RSA-SHA256 ────────────────────────────────────────────────────────────────

class TestRSASHA256:
    """Tests for RSA-SHA256 sign/verify operations."""

    def test_sign_verify_roundtrip(self) -> None:
        """A signature created with sign_rsa_sha256 must verify successfully."""
        private_pem, public_pem = generate_rsa_keypair(key_size=2048)
        data = b"Hello, OTA firmware payload!"
        sig = sign_rsa_sha256(private_pem, data)
        assert verify_rsa_sha256_signature(public_pem, data, sig) is True

    def test_verify_rejects_tampered_data(self) -> None:
        """Modifying the data after signing must cause verification to fail."""
        private_pem, public_pem = generate_rsa_keypair(key_size=2048)
        data = b"Original firmware data"
        sig = sign_rsa_sha256(private_pem, data)
        tampered = data + b"\x00"
        assert verify_rsa_sha256_signature(public_pem, tampered, sig) is False

    def test_verify_rejects_wrong_signature(self) -> None:
        """A random byte string must not pass RSA signature verification."""
        _, public_pem = generate_rsa_keypair(key_size=2048)
        data = b"some data"
        bad_sig = os.urandom(256)
        assert verify_rsa_sha256_signature(public_pem, data, bad_sig) is False

    def test_verify_rejects_wrong_key(self) -> None:
        """Signature created with key A must not verify against key B."""
        private_a, _ = generate_rsa_keypair(key_size=2048)
        _, public_b = generate_rsa_keypair(key_size=2048)
        data = b"cross-key test"
        sig = sign_rsa_sha256(private_a, data)
        assert verify_rsa_sha256_signature(public_b, data, sig) is False

    def test_sign_requires_rsa_key(self) -> None:
        """sign_rsa_sha256 must raise ValueError for a non-RSA key."""
        private_ec, _ = generate_ec_keypair()
        with pytest.raises(ValueError, match="not an RSA"):
            sign_rsa_sha256(private_ec, b"data")

    def test_keypair_generation_minimum_size(self) -> None:
        """generate_rsa_keypair must reject keys smaller than 2048 bits."""
        with pytest.raises(ValueError):
            generate_rsa_keypair(key_size=1024)

    def test_keypair_generation_pem_format(self) -> None:
        """Generated keys must be valid PEM-encoded bytes."""
        priv, pub = generate_rsa_keypair(key_size=2048)
        assert priv.startswith(b"-----BEGIN RSA PRIVATE KEY-----")
        assert pub.startswith(b"-----BEGIN PUBLIC KEY-----")


# ── ECDSA ─────────────────────────────────────────────────────────────────────

class TestECDSA:
    """Tests for ECDSA P-256 sign/verify operations."""

    def test_sign_verify_roundtrip(self) -> None:
        """An ECDSA signature must verify correctly."""
        private_pem, public_pem = generate_ec_keypair()
        data = b"ECDSA firmware payload"
        sig = sign_ecdsa(private_pem, data)
        assert verify_ecdsa_signature(public_pem, data, sig) is True

    def test_verify_rejects_tampered_data(self) -> None:
        """Modified data must fail ECDSA verification."""
        private_pem, public_pem = generate_ec_keypair()
        data = b"Original ECDSA data"
        sig = sign_ecdsa(private_pem, data)
        assert verify_ecdsa_signature(public_pem, data + b"x", sig) is False

    def test_verify_rejects_random_signature(self) -> None:
        """Random bytes must not pass ECDSA verification."""
        _, public_pem = generate_ec_keypair()
        assert verify_ecdsa_signature(public_pem, b"data", os.urandom(64)) is False

    def test_sign_requires_ec_key(self) -> None:
        """sign_ecdsa must raise ValueError for an RSA key."""
        private_rsa, _ = generate_rsa_keypair(key_size=2048)
        with pytest.raises(ValueError, match="not an EC"):
            sign_ecdsa(private_rsa, b"data")

    def test_ec_public_key_pem_format(self) -> None:
        """EC public key must be a valid SubjectPublicKeyInfo PEM."""
        _, public_pem = generate_ec_keypair()
        assert public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")


# ── AES-256-GCM ───────────────────────────────────────────────────────────────

class TestAESGCM:
    """Tests for AES-256-GCM encrypt/decrypt operations."""

    def test_encrypt_decrypt_roundtrip(self) -> None:
        """Decrypted ciphertext must equal the original plaintext."""
        key = os.urandom(32)
        plaintext = b"Sensitive firmware decryption key material"
        ciphertext, nonce, tag = encrypt_aes_gcm(key, plaintext)
        recovered = decrypt_aes_gcm(key, ciphertext, nonce, tag)
        assert recovered == plaintext

    def test_encrypt_produces_different_nonces(self) -> None:
        """Each encryption call must use a unique nonce."""
        key = os.urandom(32)
        _, nonce1, _ = encrypt_aes_gcm(key, b"data")
        _, nonce2, _ = encrypt_aes_gcm(key, b"data")
        assert nonce1 != nonce2

    def test_decrypt_rejects_wrong_key(self) -> None:
        """Decryption with a wrong key must raise ValueError."""
        key = os.urandom(32)
        wrong_key = os.urandom(32)
        plaintext = b"secret"
        ciphertext, nonce, tag = encrypt_aes_gcm(key, plaintext)
        with pytest.raises(ValueError):
            decrypt_aes_gcm(wrong_key, ciphertext, nonce, tag)

    def test_decrypt_rejects_tampered_ciphertext(self) -> None:
        """Bit-flipping the ciphertext must cause authentication to fail."""
        key = os.urandom(32)
        ciphertext, nonce, tag = encrypt_aes_gcm(key, b"tamper test")
        tampered = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]
        with pytest.raises(ValueError):
            decrypt_aes_gcm(key, tampered, nonce, tag)

    def test_wrong_key_size_raises(self) -> None:
        """Providing a 16-byte key instead of 32 must raise ValueError."""
        with pytest.raises(ValueError, match="32 bytes"):
            encrypt_aes_gcm(os.urandom(16), b"data")

    def test_nonce_length(self) -> None:
        """Nonce must be 12 bytes (96 bits per NIST recommendation)."""
        _, nonce, _ = encrypt_aes_gcm(os.urandom(32), b"test")
        assert len(nonce) == 12

    def test_tag_length(self) -> None:
        """Authentication tag must be 16 bytes."""
        _, _, tag = encrypt_aes_gcm(os.urandom(32), b"test")
        assert len(tag) == 16

    def test_empty_plaintext(self) -> None:
        """Encrypting empty bytes must succeed and round-trip correctly."""
        key = os.urandom(32)
        ciphertext, nonce, tag = encrypt_aes_gcm(key, b"")
        recovered = decrypt_aes_gcm(key, ciphertext, nonce, tag)
        assert recovered == b""


# ── SHA-256 ───────────────────────────────────────────────────────────────────

class TestSHA256:
    """Tests for compute_sha256."""

    def test_known_digest(self) -> None:
        """SHA-256 of empty bytes must equal the known constant."""
        result = compute_sha256(b"")
        assert result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_returns_lowercase_hex(self) -> None:
        """Output must be a 64-character lowercase hex string."""
        result = compute_sha256(b"OTA test")
        assert len(result) == 64
        assert result == result.lower()

    def test_deterministic(self) -> None:
        """Same input must always produce the same digest."""
        data = b"deterministic test data"
        assert compute_sha256(data) == compute_sha256(data)

    def test_different_inputs_different_digests(self) -> None:
        """Different inputs must produce different digests."""
        assert compute_sha256(b"a") != compute_sha256(b"b")


# ── PBKDF2 ────────────────────────────────────────────────────────────────────

class TestPBKDF2:
    """Tests for derive_key_pbkdf2."""

    def test_produces_32_byte_key(self) -> None:
        """Default key derivation must produce a 32-byte key."""
        key = derive_key_pbkdf2(b"password", os.urandom(32))
        assert len(key) == 32

    def test_same_inputs_same_output(self) -> None:
        """Identical password and salt must yield identical keys."""
        salt = os.urandom(32)
        k1 = derive_key_pbkdf2(b"password", salt, iterations=1000)
        k2 = derive_key_pbkdf2(b"password", salt, iterations=1000)
        assert k1 == k2

    def test_different_salts_different_keys(self) -> None:
        """Different salts must produce different derived keys."""
        k1 = derive_key_pbkdf2(b"password", os.urandom(32), iterations=1000)
        k2 = derive_key_pbkdf2(b"password", os.urandom(32), iterations=1000)
        assert k1 != k2

    def test_different_passwords_different_keys(self) -> None:
        """Different passwords must produce different derived keys."""
        salt = os.urandom(32)
        k1 = derive_key_pbkdf2(b"password1", salt, iterations=1000)
        k2 = derive_key_pbkdf2(b"password2", salt, iterations=1000)
        assert k1 != k2


# ── Encoding helpers ──────────────────────────────────────────────────────────

class TestEncodingHelpers:
    """Tests for signature Base64 encode/decode helpers."""

    def test_roundtrip(self) -> None:
        """encode then decode must reproduce the original bytes."""
        original = os.urandom(512)
        assert decode_signature_b64(encode_signature_b64(original)) == original

    def test_invalid_base64_raises(self) -> None:
        """Passing non-Base64 data must raise ValueError."""
        with pytest.raises(ValueError):
            decode_signature_b64("not!valid!base64!!!")


# ── Constant time compare ─────────────────────────────────────────────────────

class TestConstantTimeCompare:
    def test_equal_bytes(self) -> None:
        assert constant_time_compare(b"abc", b"abc") is True

    def test_unequal_bytes(self) -> None:
        assert constant_time_compare(b"abc", b"xyz") is False
