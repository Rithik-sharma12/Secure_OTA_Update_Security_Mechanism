"""
Shared pytest setup for the gateway suite.

gateway/config.py reads the environment and creates directories at import
time, and it now raises when no API key is configured. Both have to be settled
before anything under `gateway.` is imported, so this module does it at
collection time rather than in a fixture.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

_TMP_ROOT = Path(tempfile.mkdtemp(prefix='sentinel-gateway-tests-'))

# A real key, so the auth tests exercise the comparison path rather than the
# "open by design" short circuit.
TEST_API_KEY = 'test-gateway-key-0123456789abcdef'

os.environ.setdefault('OTA_GATEWAY_API_KEY', TEST_API_KEY)
os.environ.setdefault('OTA_GATEWAY_CACHE_DIR', str(_TMP_ROOT / 'cache'))
os.environ.setdefault('OTA_GATEWAY_KEYS_DIR', str(_TMP_ROOT / 'keys'))


@pytest.fixture(scope='session')
def api_key() -> str:
    return TEST_API_KEY


@pytest.fixture
def tmp_keys_dir(tmp_path: Path) -> Path:
    keys = tmp_path / 'keys'
    keys.mkdir()
    return keys
