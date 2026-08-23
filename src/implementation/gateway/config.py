"""
SentinelOTA Edge Gateway — Configuration

All gateway settings read from environment variables with sensible defaults.
"""

from __future__ import annotations

import os
from pathlib import Path

# ── Network ───────────────────────────────────────────────────
HOST: str = os.getenv('OTA_GATEWAY_HOST', os.getenv('OTA_HOST', '0.0.0.0'))
PORT: int = int(os.getenv('OTA_GATEWAY_PORT', os.getenv('OTA_PORT', '5000')))

# ── File System ───────────────────────────────────────────────
FIRMWARE_CACHE_DIR: Path = Path(os.getenv('OTA_GATEWAY_CACHE_DIR', 'gateway_firmware_cache')).resolve()
STATE_FILE: Path = FIRMWARE_CACHE_DIR / 'gateway_state.json'
MANIFEST_FILE: Path = FIRMWARE_CACHE_DIR / 'manifest.json'
KEYS_DIR: Path = Path(os.getenv('OTA_GATEWAY_KEYS_DIR', 'gateway_keys')).resolve()
PRIVATE_SIGNING_KEY_PATH: Path = KEYS_DIR / 'ed25519_private_key.pem'
PUBLIC_SIGNING_KEY_PATH: Path = KEYS_DIR / 'ed25519_public_key.pem'

# ── Authentication ────────────────────────────────────────────
API_KEY: str = os.getenv('OTA_GATEWAY_API_KEY', '').strip()

# ── Signing ───────────────────────────────────────────────────
PUBLIC_BASE_URL: str = os.getenv('OTA_GATEWAY_PUBLIC_URL', '').rstrip('/')
SIGNING_KEY_ID: str = os.getenv('OTA_GATEWAY_SIGNING_KEY_ID', 'gateway-ed25519-primary').strip() or 'gateway-ed25519-primary'
SIGNING_ALGORITHM: str = 'Ed25519'
DEFAULT_RELEASE_ARTIFACT: str = os.getenv('OTA_GATEWAY_RELEASE_ARTIFACT', '').strip()

# ── Limits ────────────────────────────────────────────────────
MAX_DEVICE_LOG_ENTRIES: int = int(os.getenv('OTA_MAX_DEVICE_LOG_ENTRIES', '50'))
MAX_EVENTS: int = int(os.getenv('OTA_MAX_EVENTS', '500'))
MAX_ALERTS: int = int(os.getenv('OTA_MAX_ALERTS', '200'))
MAX_RELEASES: int = int(os.getenv('OTA_MAX_RELEASES', '50'))

# ── Device Types ──────────────────────────────────────────────
ALLOWED_DEVICE_TYPES: set[str] = {'ATmega328P', 'ESP8266', 'ESP32', 'STM32F103'}
DEFAULT_COMPATIBILITY: list[str] = [
    device_type.strip()
    for device_type in os.getenv('OTA_DEFAULT_COMPATIBILITY', 'ESP32').split(',')
    if device_type.strip() in ALLOWED_DEVICE_TYPES
]
if not DEFAULT_COMPATIBILITY:
    DEFAULT_COMPATIBILITY = ['ESP32']

# ── Ensure Directories ───────────────────────────────────────
FIRMWARE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
KEYS_DIR.mkdir(parents=True, exist_ok=True)
