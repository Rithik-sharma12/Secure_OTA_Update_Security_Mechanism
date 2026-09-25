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

# Without an API key every write endpoint is open, which on this gateway means
# anyone who can reach the port can publish firmware to the whole fleet. That
# is a reasonable default for a laptop and a catastrophic one anywhere else,
# so it now has to be asked for by name.
ALLOW_OPEN_WRITES: bool = os.getenv('OTA_GATEWAY_ALLOW_OPEN_WRITES', '').strip().lower() in {'1', 'true', 'yes'}

if not API_KEY and not ALLOW_OPEN_WRITES:
    raise RuntimeError(
        'OTA_GATEWAY_API_KEY is not set, so every write endpoint — including '
        'firmware publishing — would accept unauthenticated requests. Set a key, '
        'or set OTA_GATEWAY_ALLOW_OPEN_WRITES=true to accept that risk on a '
        'trusted local network.'
    )

# ── CORS ──────────────────────────────────────────────────────
# Previously '*' together with allow_credentials=True. Browsers reject that
# combination outright, so the permissive intent never worked, and the
# wildcard meant any origin could drive the gateway from a victim's browser.
# Origins are now listed explicitly; the wildcard is still reachable but only
# without credentials.
_DEFAULT_CORS_ORIGINS = 'http://localhost:3000,http://127.0.0.1:3000'

# os.getenv's default only applies when the variable is *unset*. A .env file
# that lists the key with no value hands back '', which would leave the origin
# list empty and block every browser request — so treat blank as unset.
_CORS_ORIGINS_RAW = os.getenv('OTA_GATEWAY_CORS_ORIGINS', '').strip() or _DEFAULT_CORS_ORIGINS

CORS_ALLOW_ORIGINS: list[str] = [
    origin.strip().rstrip('/')
    for origin in _CORS_ORIGINS_RAW.split(',')
    if origin.strip()
]
CORS_ALLOW_CREDENTIALS: bool = '*' not in CORS_ALLOW_ORIGINS

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
