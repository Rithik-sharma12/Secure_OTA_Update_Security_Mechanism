"""Firmware packaging: combine binary, header, and metadata into an OTA bundle."""

import hashlib
import json
import struct
from datetime import UTC, datetime
from pathlib import Path

# OTA firmware bundle header format (64 bytes):
#   0x00  magic        uint32  0x4F544148 ("OTAH")
#   0x04  min_counter  uint32  minimum anti-rollback counter
#   0x08  version      char[32]
#   0x28  payload_size uint32  size of firmware payload in bytes
#   0x2C  reserved     char[20]

BUNDLE_HEADER_MAGIC = 0x4F544148  # "OTAH"
BUNDLE_HEADER_SIZE = 64
BUNDLE_HEADER_FORMAT = "<I I 32s I 20s"  # little-endian


def build_firmware_bundle(
    binary_path: str,
    version: str,
    platform: str,
    min_counter: int = 0,
    output_path: str | None = None,
) -> dict:
    """Package a raw firmware binary into an OTA bundle with a header.

    The bundle prepends a 64-byte header containing the version string
    and minimum anti-rollback counter value, making it self-describing.

    Args:
        binary_path:  Path to the raw firmware binary.
        version:      Semantic version string (e.g. "1.2.3").
        platform:     Target platform identifier (e.g. "esp32").
        min_counter:  Minimum anti-rollback counter required by this firmware.
        output_path:  Where to write the bundle (default: <binary_path>.fw).

    Returns:
        Dictionary with bundle metadata: path, hash, size, version.

    Raises:
        FileNotFoundError: If binary_path does not exist.
        ValueError: If the version string exceeds 31 characters.
    """
    binary = Path(binary_path)
    if not binary.exists():
        raise FileNotFoundError(f"Binary not found: {binary_path}")

    if len(version) > 31:
        raise ValueError("Version string exceeds 31-character limit")

    payload = binary.read_bytes()
    payload_size = len(payload)

    version_bytes = version.encode("ascii").ljust(32, b"\x00")[:32]
    header = struct.pack(
        BUNDLE_HEADER_FORMAT,
        BUNDLE_HEADER_MAGIC,
        min_counter,
        version_bytes,
        payload_size,
        b"\x00" * 20,
    )
    assert len(header) == BUNDLE_HEADER_SIZE

    bundle_data = header + payload

    if output_path is None:
        output_path = str(binary.with_suffix(".fw"))

    Path(output_path).write_bytes(bundle_data)

    sha256 = hashlib.sha256(bundle_data).hexdigest()
    metadata = {
        "path": output_path,
        "version": version,
        "platform": platform,
        "min_counter": min_counter,
        "payload_size": payload_size,
        "bundle_size": len(bundle_data),
        "hash_sha256": sha256,
        "created_at": datetime.now(UTC).isoformat(),
    }

    # Write sidecar metadata JSON
    meta_path = Path(output_path).with_suffix(".json")
    meta_path.write_text(json.dumps(metadata, indent=2))

    return metadata


def parse_bundle_header(bundle_path: str) -> dict:
    """Read and parse the 64-byte header from an OTA bundle file.

    Args:
        bundle_path: Path to the .fw bundle file.

    Returns:
        Dictionary with header fields: magic, min_counter, version, payload_size.

    Raises:
        FileNotFoundError: If bundle_path does not exist.
        ValueError: If the magic value is wrong or the file is too small.
    """
    data = Path(bundle_path).read_bytes()
    if len(data) < BUNDLE_HEADER_SIZE:
        raise ValueError(f"Bundle too small ({len(data)} bytes); minimum is {BUNDLE_HEADER_SIZE}")

    header_bytes = data[:BUNDLE_HEADER_SIZE]
    magic, min_counter, version_raw, payload_size, _ = struct.unpack(
        BUNDLE_HEADER_FORMAT, header_bytes
    )

    if magic != BUNDLE_HEADER_MAGIC:
        raise ValueError(f"Invalid bundle magic: 0x{magic:08X} (expected 0x{BUNDLE_HEADER_MAGIC:08X})")

    version = version_raw.rstrip(b"\x00").decode("ascii", errors="replace")
    return {
        "magic": f"0x{magic:08X}",
        "min_counter": min_counter,
        "version": version,
        "payload_size": payload_size,
        "bundle_size": len(data),
    }
