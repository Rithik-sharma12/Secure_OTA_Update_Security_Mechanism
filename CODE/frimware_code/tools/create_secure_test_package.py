#!/usr/bin/env python3
"""
Generate a secure OTA firmware package for local ESP32 testing.

Output package format (must match esp32_ota_main.ino secure OTA parser):
  [16-byte IV][256-byte RSA-SHA256 signature][AES-256-CBC encrypted firmware]
"""

from __future__ import annotations

import argparse
import secrets
import string
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def generate_ascii_aes_key(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def ensure_rsa_keypair(private_key_path: Path, public_key_path: Path, regenerate: bool) -> rsa.RSAPrivateKey:
    if private_key_path.exists() and not regenerate:
        private_key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise TypeError("Existing private key is not RSA.")
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        private_key_path.parent.mkdir(parents=True, exist_ok=True)
        private_key_path.write_bytes(private_pem)

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.write_bytes(public_pem)
    return private_key


def build_secure_package(firmware_bytes: bytes, private_key: rsa.RSAPrivateKey, aes_key: bytes) -> bytes:
    signature = private_key.sign(
        firmware_bytes,
        asym_padding.PKCS1v15(),
        hashes.SHA256(),
    )
    if len(signature) != 256:
        raise ValueError(f"Unexpected RSA signature length {len(signature)}; expected 256 bytes for RSA-2048.")

    iv = secrets.token_bytes(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(firmware_bytes) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return iv + signature + ciphertext


def verify_secure_package(package: bytes, public_pem: bytes, aes_key: bytes) -> None:
    if len(package) <= 272:
        raise ValueError("Package too small; expected at least IV + signature + payload.")

    iv = package[:16]
    signature = package[16:272]
    ciphertext = package[272:]

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    firmware_bytes = unpadder.update(padded) + unpadder.finalize()

    public_key = serialization.load_pem_public_key(public_pem)
    public_key.verify(
        signature,
        firmware_bytes,
        asym_padding.PKCS1v15(),
        hashes.SHA256(),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Create secure OTA test package for ESP32 firmware")
    parser.add_argument(
        "--firmware",
        default=".pio/build/esp32dev/firmware.bin",
        help="Path to plain firmware binary",
    )
    parser.add_argument(
        "--output",
        default="release-assets/firmware-esp32-secure-test.bin",
        help="Path to write secure firmware package",
    )
    parser.add_argument(
        "--keys-dir",
        default="secure-test-keys",
        help="Directory where test key material is stored",
    )
    parser.add_argument(
        "--aes-key",
        default="",
        help="Optional 32-character ASCII AES key; generated if omitted",
    )
    parser.add_argument(
        "--regenerate-rsa",
        action="store_true",
        help="Regenerate RSA keypair even if existing key files are present",
    )
    args = parser.parse_args()

    firmware_path = Path(args.firmware)
    if not firmware_path.exists():
        raise FileNotFoundError(f"Firmware not found: {firmware_path}")

    output_path = Path(args.output)
    keys_dir = Path(args.keys_dir)
    private_key_path = keys_dir / "firmware_test_private.pem"
    public_key_path = keys_dir / "firmware_test_public.pem"
    aes_key_path = keys_dir / "firmware_test_aes_key.txt"
    snippet_path = keys_dir / "ota_config_secure_snippet.h"

    private_key = ensure_rsa_keypair(private_key_path, public_key_path, args.regenerate_rsa)

    if args.aes_key:
        aes_key_text = args.aes_key.strip()
    elif aes_key_path.exists():
        aes_key_text = aes_key_path.read_text(encoding="utf-8").strip()
    else:
        aes_key_text = generate_ascii_aes_key(32)

    if len(aes_key_text) != 32:
        raise ValueError("AES key must be exactly 32 ASCII characters.")

    aes_key_bytes = aes_key_text.encode("ascii")
    aes_key_path.parent.mkdir(parents=True, exist_ok=True)
    aes_key_path.write_text(aes_key_text + "\n", encoding="utf-8")

    firmware_bytes = firmware_path.read_bytes()
    package = build_secure_package(firmware_bytes, private_key, aes_key_bytes)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(package)

    public_pem = public_key_path.read_text(encoding="utf-8").strip()
    snippet = (
        f"#define FIRMWARE_ENC_KEY \"{aes_key_text}\"\n\n"
        f"static const char FIRMWARE_PUB_KEY[] = R\"KEY(\n"
        f"{public_pem}\n"
        f")KEY\";\n"
    )
    snippet_path.write_text(snippet, encoding="utf-8")

    verify_secure_package(package, public_key_path.read_bytes(), aes_key_bytes)

    print(f"Plain firmware:  {firmware_path.resolve()}")
    print(f"Secure package:  {output_path.resolve()}")
    print(f"RSA private key: {private_key_path.resolve()}")
    print(f"RSA public key:  {public_key_path.resolve()}")
    print(f"AES key file:    {aes_key_path.resolve()}")
    print(f"Config snippet:  {snippet_path.resolve()}")
    print("Verification: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
