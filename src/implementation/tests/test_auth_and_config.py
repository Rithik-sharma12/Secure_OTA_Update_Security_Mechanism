"""
Tests for the gateway's write-authentication guard and its startup policy.

These pin the behaviour that stops an unauthenticated caller publishing
firmware to the whole fleet, so they are the ones to look at first if anything
here starts failing.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from gateway.auth import require_write_auth

IMPLEMENTATION_ROOT = Path(__file__).resolve().parents[1]


# ── The guard itself ─────────────────────────────────────────────────


@pytest.fixture
def client(api_key: str) -> TestClient:
    """A minimal app with one endpoint behind the real write guard."""
    from fastapi import Depends

    app = FastAPI()

    @app.post('/write')
    def write(_: None = Depends(require_write_auth)) -> dict[str, bool]:
        return {'ok': True}

    return TestClient(app)


def test_correct_key_in_header_is_accepted(client, api_key):
    assert client.post('/write', headers={'x-api-key': api_key}).status_code == 200


def test_correct_key_as_bearer_is_accepted(client, api_key):
    response = client.post('/write', headers={'authorization': f'Bearer {api_key}'})
    assert response.status_code == 200


def test_bearer_scheme_is_case_insensitive(client, api_key):
    response = client.post('/write', headers={'authorization': f'bEaReR {api_key}'})
    assert response.status_code == 200


def test_correct_key_as_query_parameter_is_accepted(client, api_key):
    assert client.post(f'/write?api_key={api_key}').status_code == 200


def test_missing_key_is_rejected(client):
    assert client.post('/write').status_code == 401


@pytest.mark.parametrize(
    'bad_key',
    [
        '',
        'wrong',
        'test-gateway-key-0123456789abcde',   # one char short
        'test-gateway-key-0123456789abcdef0',  # one char long
        'TEST-GATEWAY-KEY-0123456789ABCDEF',   # wrong case
        'test-gateway-key-0123456789abcdeF',   # last char differs
    ],
)
def test_wrong_key_is_rejected(client, bad_key):
    assert client.post('/write', headers={'x-api-key': bad_key}).status_code == 401


def test_prefix_of_the_real_key_is_rejected(client, api_key):
    """
    The comparison must not accept a prefix, and must not short-circuit on the
    first differing byte either — see the compare_digest note in auth.py.
    """
    for cut in range(1, len(api_key)):
        assert client.post('/write', headers={'x-api-key': api_key[:cut]}).status_code == 401


def test_key_is_compared_with_compare_digest():
    """
    A plain `!=` leaks the matching prefix length through timing. Asserting on
    timing is flaky, so assert on the implementation instead.
    """
    import inspect

    source = inspect.getsource(require_write_auth)
    assert 'compare_digest' in source, 'write auth must use hmac.compare_digest'


def test_whitespace_around_the_key_is_tolerated(client, api_key):
    response = client.post('/write', headers={'x-api-key': f'  {api_key}  '})
    assert response.status_code == 200


def test_guard_raises_http_401_not_a_bare_error(api_key):
    with pytest.raises(HTTPException) as excinfo:
        require_write_auth(api_key='definitely-wrong', x_api_key=None, authorization=None)
    assert excinfo.value.status_code == 401


# ── Startup policy ───────────────────────────────────────────────────
#
# config.py decides at import time, so each case runs in its own interpreter.


def _import_gateway(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    child_env = dict(os.environ)
    child_env.update(env)
    child_env['OTA_GATEWAY_CACHE_DIR'] = tempfile.mkdtemp()
    child_env['OTA_GATEWAY_KEYS_DIR'] = tempfile.mkdtemp()
    return subprocess.run(
        [sys.executable, '-c', 'import gateway; print(gateway.app.title)'],
        env=child_env,
        cwd=IMPLEMENTATION_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_gateway_refuses_to_start_without_an_api_key():
    """
    An empty key means every write endpoint is open, and publishing firmware is
    a write endpoint. That must be an explicit choice, not a default.
    """
    result = _import_gateway({'OTA_GATEWAY_API_KEY': '', 'OTA_GATEWAY_ALLOW_OPEN_WRITES': ''})

    assert result.returncode != 0
    assert 'OTA_GATEWAY_API_KEY' in result.stderr


def test_open_writes_can_be_opted_into_explicitly():
    result = _import_gateway(
        {'OTA_GATEWAY_API_KEY': '', 'OTA_GATEWAY_ALLOW_OPEN_WRITES': 'true'}
    )

    assert result.returncode == 0, result.stderr
    assert 'SentinelOTA' in result.stdout


def test_open_writes_flag_accepts_the_usual_spellings():
    for value in ('1', 'true', 'TRUE', 'yes'):
        result = _import_gateway(
            {'OTA_GATEWAY_API_KEY': '', 'OTA_GATEWAY_ALLOW_OPEN_WRITES': value}
        )
        assert result.returncode == 0, f'{value!r} should enable open writes: {result.stderr}'


def test_unset_key_with_a_falsey_flag_still_refuses():
    for value in ('0', 'false', 'no', 'maybe'):
        result = _import_gateway(
            {'OTA_GATEWAY_API_KEY': '', 'OTA_GATEWAY_ALLOW_OPEN_WRITES': value}
        )
        assert result.returncode != 0, f'{value!r} must not enable open writes'


# ── CORS ─────────────────────────────────────────────────────────────


def _read_cors(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    child_env = dict(os.environ)
    child_env.update(env)
    child_env['OTA_GATEWAY_CACHE_DIR'] = tempfile.mkdtemp()
    child_env['OTA_GATEWAY_KEYS_DIR'] = tempfile.mkdtemp()
    return subprocess.run(
        [
            sys.executable,
            '-c',
            'from gateway.config import CORS_ALLOW_ORIGINS, CORS_ALLOW_CREDENTIALS;'
            'print(repr(CORS_ALLOW_ORIGINS)); print(CORS_ALLOW_CREDENTIALS)',
        ],
        env=child_env,
        cwd=IMPLEMENTATION_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_default_cors_origins_are_local_and_explicit(api_key):
    result = _read_cors({'OTA_GATEWAY_API_KEY': api_key, 'OTA_GATEWAY_CORS_ORIGINS': ''})
    origins, credentials = result.stdout.strip().splitlines()

    assert '*' not in origins
    assert 'localhost:3000' in origins
    assert credentials == 'True'


def test_wildcard_origin_disables_credentials(api_key):
    """
    '*' with allow_credentials=True is rejected by browsers, so the previous
    config was permissive in intent and broken in practice.
    """
    result = _read_cors({'OTA_GATEWAY_API_KEY': api_key, 'OTA_GATEWAY_CORS_ORIGINS': '*'})
    _, credentials = result.stdout.strip().splitlines()

    assert credentials == 'False'


def test_configured_origins_are_parsed_and_trimmed(api_key):
    result = _read_cors(
        {
            'OTA_GATEWAY_API_KEY': api_key,
            'OTA_GATEWAY_CORS_ORIGINS': ' https://ota.example.com/ , https://b.example.com ',
        }
    )
    origins = result.stdout.strip().splitlines()[0]

    assert 'https://ota.example.com' in origins
    assert 'https://ota.example.com/' not in origins  # trailing slash stripped
    assert 'https://b.example.com' in origins
