"""
SentinelOTA Edge Gateway — Utility Functions
"""

from __future__ import annotations

import hashlib
import os
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .config import ALLOWED_DEVICE_TYPES, FIRMWARE_CACHE_DIR, PUBLIC_BASE_URL


def utc_now_iso() -> str:
    """Return current UTC time as ISO-8601 string (no microseconds)."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def now_plus_days(days: int) -> str:
    """Return UTC time N days from now as ISO-8601 string."""
    return (datetime.now(timezone.utc) + timedelta(days=days)).replace(microsecond=0).isoformat()


def safe_cache_path(filename: str) -> Path | None:
    """Validate and resolve a filename within the firmware cache directory."""
    if not filename or '/' in filename or '\\' in filename:
        return None

    candidate = (FIRMWARE_CACHE_DIR / filename).resolve()
    return candidate if candidate.parent == FIRMWARE_CACHE_DIR else None


def normalize_version(version: str) -> str:
    """Normalize a semantic version string (strip leading 'v', validate digits)."""
    candidate = version.strip().lstrip('v')
    if not candidate:
        raise ValueError('Version cannot be empty.')

    segments = candidate.split('.')
    if not all(segment.isdigit() for segment in segments):
        raise ValueError('Version must be numeric dot-separated (for example 2.1.0).')

    return candidate


def normalize_compatibility(raw_value: Any) -> list[str]:
    """Normalize a list of device types, filtering to allowed values."""
    from .config import DEFAULT_COMPATIBILITY

    values = raw_value if isinstance(raw_value, list) else []
    normalized: list[str] = []

    for entry in values:
        text = str(entry).strip()
        if not text:
            continue
        if text in ALLOWED_DEVICE_TYPES and text not in normalized:
            normalized.append(text)

    return normalized or DEFAULT_COMPATIBILITY.copy()


def normalize_device_type(device_type: str) -> str:
    """Normalize a device type string, defaulting to ESP32."""
    candidate = device_type.strip()
    return candidate if candidate in ALLOWED_DEVICE_TYPES else 'ESP32'


def version_score(version: str) -> int:
    """Map a semantic version to a comparable integer.

    Mirrors the firmware's anti-rollback arithmetic exactly
    (major*10000 + minor*100 + patch) so the gateway and the device agree on
    what counts as newer. Unparseable input scores 0 rather than raising, so a
    malformed heartbeat can never take the gateway down.
    """
    candidate = str(version).strip().lstrip('vV')
    parts = candidate.split('.')
    numbers: list[int] = []

    for part in parts[:3]:
        digits = ''.join(ch for ch in part if ch.isdigit())
        numbers.append(int(digits) if digits else 0)

    while len(numbers) < 3:
        numbers.append(0)

    major, minor, patch = numbers[0], numbers[1], numbers[2]
    return major * 10000 + minor * 100 + patch


def is_newer_version(candidate: str, current: str) -> bool:
    """True when `candidate` is strictly newer than `current`."""
    return version_score(candidate) > version_score(current)


def firmware_download_url(filename: str) -> str:
    """Build the download URL for a firmware file."""
    if PUBLIC_BASE_URL:
        return f"{PUBLIC_BASE_URL}/releases/download/{filename}"
    return f"/releases/download/{filename}"


def sha256_bytes(payload: bytes) -> str:
    """Compute SHA-256 hex digest of a byte payload."""
    return hashlib.sha256(payload).hexdigest()


def safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert a value to float."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_int(value: Any, default: int = 0) -> int:
    """Safely convert a value to int."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def get_pi_status() -> dict[str, str]:
    """Detect host/Raspberry Pi status (IP, temperature, load)."""
    status = {'ip': 'Unknown', 'temp': 'Unknown', 'load': 'Unknown'}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 80))
        status['ip'] = sock.getsockname()[0]
        sock.close()

        thermal_file = '/sys/class/thermal/thermal_zone0/temp'
        if os.path.exists(thermal_file):
            with open(thermal_file, 'r', encoding='utf-8') as file:
                status['temp'] = f"{round(float(file.read()) / 1000, 1)}C"
        else:
            status['temp'] = 'N/A (Not Pi)'

        status['load'] = str(os.getloadavg()[0]) if hasattr(os, 'getloadavg') else '0.0'
    except OSError:
        status['ip'] = 'Unavailable'
        status['temp'] = 'Unavailable'
        status['load'] = 'Unavailable'

    return status
