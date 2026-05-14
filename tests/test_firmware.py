"""Tests for firmware management: bundle building, signing, and verification."""

import os
import struct
import tempfile
from pathlib import Path

import pytest

from cli.firmware_builder import (
    BUNDLE_HEADER_MAGIC,
    BUNDLE_HEADER_SIZE,
    build_firmware_bundle,
    parse_bundle_header,
)
from server.security.crypto import (
    compute_sha256,
    decode_signature_b64,
    encode_signature_b64,
    generate_rsa_keypair,
    sign_rsa_sha256,
    verify_rsa_sha256_signature,
)


class TestFirmwareBundleBuilder:
    """Tests for cli.firmware_builder.build_firmware_bundle."""

    def test_build_creates_file(self, tmp_path: Path) -> None:
        """build_firmware_bundle must create the output .fw file."""
        binary = tmp_path / "firmware.bin"
        binary.write_bytes(b"\x00" * 1024)
        meta = build_firmware_bundle(str(binary), "1.0.0", "esp32", output_path=str(tmp_path / "fw.fw"))
        assert Path(meta["path"]).exists()

    def test_build_header_magic(self, tmp_path: Path) -> None:
        """Bundle must start with the OTAH magic bytes."""
        binary = tmp_path / "fw.bin"
        binary.write_bytes(b"\xDE\xAD\xBE\xEF" * 256)
        meta = build_firmware_bundle(str(binary), "2.0.0", "esp32")
        bundle_data = Path(meta["path"]).read_bytes()
        magic = struct.unpack_from("<I", bundle_data, 0)[0]
        assert magic == BUNDLE_HEADER_MAGIC

    def test_build_embeds_version(self, tmp_path: Path) -> None:
        """Bundle header must contain the correct version string."""
        binary = tmp_path / "fw.bin"
        binary.write_bytes(b"\x01" * 512)
        meta = build_firmware_bundle(str(binary), "3.1.4", "esp32")
        header = parse_bundle_header(meta["path"])
        assert header["version"] == "3.1.4"

    def test_build_embeds_min_counter(self, tmp_path: Path) -> None:
        """Bundle header must encode the provided min_counter value."""
        binary = tmp_path / "fw.bin"
        binary.write_bytes(b"\x02" * 256)
        meta = build_firmware_bundle(str(binary), "1.0.0", "esp32", min_counter=7)
        header = parse_bundle_header(meta["path"])
        assert header["min_counter"] == 7

    def test_build_sha256_in_metadata(self, tmp_path: Path) -> None:
        """Returned metadata must include a valid 64-character SHA-256 hex string."""
        binary = tmp_path / "fw.bin"
        payload = b"\xAB" * 1024
        binary.write_bytes(payload)
        meta = build_firmware_bundle(str(binary), "1.0.0", "esp32")
        assert len(meta["hash_sha256"]) == 64

    def test_build_rejects_long_version(self, tmp_path: Path) -> None:
        """Version strings longer than 31 characters must raise ValueError."""
        binary = tmp_path / "fw.bin"
        binary.write_bytes(b"\x00" * 64)
        with pytest.raises(ValueError, match="31"):
            build_firmware_bundle(str(binary), "v" * 32, "esp32")

    def test_build_raises_for_missing_binary(self, tmp_path: Path) -> None:
        """Providing a non-existent binary path must raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            build_firmware_bundle(str(tmp_path / "missing.bin"), "1.0.0", "esp32")

    def test_parse_invalid_magic(self, tmp_path: Path) -> None:
        """parse_bundle_header must raise ValueError for wrong magic."""
        bad = tmp_path / "bad.fw"
        bad.write_bytes(b"\xFF" * BUNDLE_HEADER_SIZE)
        with pytest.raises(ValueError, match="magic"):
            parse_bundle_header(str(bad))

    def test_parse_file_too_small(self, tmp_path: Path) -> None:
        """parse_bundle_header must raise ValueError for files smaller than header."""
        tiny = tmp_path / "tiny.fw"
        tiny.write_bytes(b"\x00" * 4)
        with pytest.raises(ValueError, match="too small"):
            parse_bundle_header(str(tiny))


class TestFirmwareSigningVerification:
    """Tests for firmware signing with RSA-SHA256."""

    def test_sign_and_verify_bundle(self, tmp_path: Path) -> None:
        """A signed firmware bundle must pass signature verification."""
        private_pem, public_pem = generate_rsa_keypair(key_size=2048)
        binary = tmp_path / "fw.bin"
        binary.write_bytes(os.urandom(2048))
        meta = build_firmware_bundle(str(binary), "1.0.0", "esp32")

        bundle_data = Path(meta["path"]).read_bytes()
        sig = sign_rsa_sha256(private_pem, bundle_data)
        assert verify_rsa_sha256_signature(public_pem, bundle_data, sig) is True

    def test_signature_detects_tampering(self, tmp_path: Path) -> None:
        """Altering the bundle after signing must invalidate the signature."""
        private_pem, public_pem = generate_rsa_keypair(key_size=2048)
        binary = tmp_path / "fw2.bin"
        binary.write_bytes(os.urandom(1024))
        meta = build_firmware_bundle(str(binary), "2.0.0", "esp32")

        bundle_data = Path(meta["path"]).read_bytes()
        sig = sign_rsa_sha256(private_pem, bundle_data)

        # Flip a byte in the payload section
        tampered = bytearray(bundle_data)
        tampered[BUNDLE_HEADER_SIZE + 10] ^= 0xFF
        assert verify_rsa_sha256_signature(public_pem, bytes(tampered), sig) is False

    def test_base64_signature_roundtrip(self) -> None:
        """Encoding a signature to Base64 and back must preserve the bytes."""
        private_pem, _ = generate_rsa_keypair(key_size=2048)
        sig = sign_rsa_sha256(private_pem, b"roundtrip test data")
        encoded = encode_signature_b64(sig)
        decoded = decode_signature_b64(encoded)
        assert decoded == sig


class TestFirmwareChecksum:
    """Tests for SHA-256 checksum computation on firmware data."""

    def test_checksum_known_value(self) -> None:
        """compute_sha256 of a known payload must match precomputed reference."""
        data = b"\x00" * 32
        expected = "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
        assert compute_sha256(data) == expected

    def test_checksum_changes_on_bit_flip(self) -> None:
        """Flipping a single bit must change the SHA-256 digest."""
        data = b"\xAA" * 128
        tampered = bytearray(data)
        tampered[64] ^= 0x01
        assert compute_sha256(data) != compute_sha256(bytes(tampered))
