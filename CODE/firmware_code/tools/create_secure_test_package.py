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
        --version 2.5.0 \
        --output release-assets/firmware-esp32-secure-test.bin

It writes the RSA keypair, the AES key, and an ota_config.h snippet into
--keys-dir, then re-opens the package it just built and checks the signature
verifies, so a broken package never reaches a board.
"""

from __future__ import annotations

import argparse
import importlib.util
import secrets
import string
import sys
from pathlib import Path

# The package format lives in the gateway tree. Load that one file directly
# rather than importing the `gateway` package: importing the package runs the
# gateway's configuration, which refuses to start without OTA_GATEWAY_API_KEY
# and creates cache directories in the working directory.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_PACKAGE_MODULE = _REPO_ROOT / 'src' / 'implementation' / 'gateway' / 'package.py'


def _load_package_module():
    spec = importlib.util.spec_from_file_location('secureota_package', _PACKAGE_MODULE)
    if spec is None or spec.loader is None:
        raise SystemExit(f'Package format module not found at {_PACKAGE_MODULE}.')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations through sys.modules
    try:
        spec.loader.exec_module(module)
    except ImportError as exc:  # pragma: no cover - environment problem, not logic
        raise SystemExit(
            'Could not load the package format module. Install its dependency first:\n'
            '    pip install cryptography\n'
            f'Original error: {exc}'
        ) from exc
    return module


_package = _load_package_module()
PackageError = _package.PackageError
build_package = _package.build_package
firmware_sha256 = _package.firmware_sha256
load_or_create_packaging_key = _package.load_or_create_packaging_key
open_package = _package.open_package


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
        '--version',
        required=True,
        help='Firmware version (MAJOR.MINOR.PATCH). It is signed into the package, '
             'must equal FIRMWARE_VERSION in the image, and must match the version '
             'the release is published under',
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
        package = build_package(firmware_bytes, private_key, aes_key_text, version=args.version)
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
    print('Publish with imageSha256 set to the digest above and securePackage')
    print('true, so the manifest can vouch for the decrypted image:')
    print()
    print(f'  curl -X POST "$OTA_GATEWAY_URL/api/releases/upload" \\')
    print(f'       -H "x-api-key: $OTA_GATEWAY_API_KEY" \\')
    print(f'       -F "file=@{output_path}" \\')
    print(f'       -F "version={args.version}" \\')
    print(f'       -F "imageSha256={digest}" \\')
    print(f'       -F "securePackage=true"')
    print()
    print('Without imageSha256 the device can verify the signature but cannot')
    print('tell the image matches the version offered, so a validly signed')
    print('older package can be replayed against a newer manifest.')
    print('Verification: OK')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
