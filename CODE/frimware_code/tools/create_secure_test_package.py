#!/usr/bin/env python3
"""
Generate a secure OTA firmware package for local ESP32 testing.

The package format itself lives in src/implementation/gateway/package.py, which
is what the gateway uses to publish. This script is a thin bench wrapper around
it, so a package produced here is byte-for-byte the same shape as one the
gateway produces — previously the two had drifted, and only this script made
packages the firmware would accept.

Typical use:

    python tools/create_secure_test_package.py \
        --firmware .pio/build/esp32dev/firmware.bin \
        --output release-assets/firmware-esp32-secure-test.bin

It writes the RSA keypair, the AES key, and an ota_config.h snippet into
--keys-dir, then re-opens the package it just built and checks the signature
verifies, so a broken package never reaches a board.
"""

from __future__ import annotations

import argparse
import secrets
import string
import sys
from pathlib import Path

# The gateway package lives outside this tool's tree; add the implementation
# root to sys.path rather than duplicating the format definition here.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_IMPLEMENTATION_ROOT = _REPO_ROOT / 'src' / 'implementation'
if str(_IMPLEMENTATION_ROOT) not in sys.path:
    sys.path.insert(0, str(_IMPLEMENTATION_ROOT))

try:
    from gateway.package import (  # noqa: E402
        PackageError,
        build_package,
        firmware_sha256,
        load_or_create_packaging_key,
        open_package,
    )
except ImportError as exc:  # pragma: no cover - environment problem, not logic
    raise SystemExit(
        f'Could not import the gateway package module from {_IMPLEMENTATION_ROOT}.\n'
        f'Install the gateway requirements first:\n'
        f'    pip install -r {_IMPLEMENTATION_ROOT / "requirements.txt"}\n'
        f'Original error: {exc}'
    ) from exc


def generate_ascii_aes_key(length: int = 32) -> str:
    """A 32-character key, because FIRMWARE_ENC_KEY is a C string literal."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Create a secure OTA package for ESP32 bench testing.'
    )
    parser.add_argument(
        '--firmware',
        default='.pio/build/esp32dev/firmware.bin',
        help='Path to the plain firmware binary',
    )
    parser.add_argument(
        '--output',
        default='release-assets/firmware-esp32-secure-test.bin',
        help='Path to write the secure firmware package',
    )
    parser.add_argument(
        '--keys-dir',
        default='secure-test-keys',
        help='Directory where test key material is stored',
    )
    parser.add_argument(
        '--aes-key',
        default='',
        help='Optional 32-character ASCII AES key; generated if omitted',
    )
    parser.add_argument(
        '--regenerate-rsa',
        action='store_true',
        help='Regenerate the RSA keypair even if key files already exist',
    )
    args = parser.parse_args()

    firmware_path = Path(args.firmware)
    if not firmware_path.exists():
        raise SystemExit(f'Firmware not found: {firmware_path}')

    output_path = Path(args.output)
    keys_dir = Path(args.keys_dir)
    private_key_path = keys_dir / 'firmware_test_private.pem'
    public_key_path = keys_dir / 'firmware_test_public.pem'
    aes_key_path = keys_dir / 'firmware_test_aes_key.txt'
    snippet_path = keys_dir / 'ota_config_secure_snippet.h'

    private_key = load_or_create_packaging_key(
        private_key_path,
        public_key_path,
        regenerate=args.regenerate_rsa,
    )

    if args.aes_key:
        aes_key_text = args.aes_key.strip()
    elif aes_key_path.exists():
        aes_key_text = aes_key_path.read_text(encoding='utf-8').strip()
    else:
        aes_key_text = generate_ascii_aes_key(32)

    if len(aes_key_text) != 32:
        raise SystemExit('AES key must be exactly 32 ASCII characters.')

    aes_key_path.parent.mkdir(parents=True, exist_ok=True)
    aes_key_path.write_text(aes_key_text + '\n', encoding='utf-8')
    aes_key_path.chmod(0o600)

    firmware_bytes = firmware_path.read_bytes()

    try:
        package = build_package(firmware_bytes, private_key, aes_key_text)
    except PackageError as exc:
        raise SystemExit(f'Could not build the package: {exc}') from exc

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(package)

    public_pem = public_key_path.read_text(encoding='utf-8').strip()
    snippet_path.write_text(
        f'#define FIRMWARE_ENC_KEY "{aes_key_text}"\n\n'
        f'static const char FIRMWARE_PUB_KEY[] = R"KEY(\n{public_pem}\n)KEY";\n',
        encoding='utf-8',
    )

    # Round-trip the package exactly as a device would, so a package that a
    # board will reject never leaves this script.
    try:
        recovered = open_package(package, public_key_path.read_bytes(), aes_key_text)
    except PackageError as exc:
        raise SystemExit(f'Self-check failed, package not usable: {exc}') from exc

    if recovered != firmware_bytes:
        raise SystemExit('Self-check failed: decrypted image differs from the input.')

    digest = firmware_sha256(firmware_bytes)

    print(f'Plain firmware:  {firmware_path.resolve()} ({len(firmware_bytes)} bytes)')
    print(f'Secure package:  {output_path.resolve()} ({len(package)} bytes)')
    print(f'RSA private key: {private_key_path.resolve()}')
    print(f'RSA public key:  {public_key_path.resolve()}')
    print(f'AES key file:    {aes_key_path.resolve()}')
    print(f'Config snippet:  {snippet_path.resolve()}')
    print(f'Firmware sha256: {digest}')
    print()
    print('Publish this digest as the manifest `sha256` field. The firmware')
    print('compares it against the decrypted image before switching partitions,')
    print('which is what stops a validly signed older package being replayed.')
    print('Verification: OK')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
