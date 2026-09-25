"""
Tests for gateway/utils.py.

The version arithmetic here has to agree with the firmware's, and
safe_cache_path is the only thing standing between a filename in a request and
the gateway's filesystem, so both get close attention.
"""

from __future__ import annotations

import pytest

from gateway.config import FIRMWARE_CACHE_DIR
from gateway.utils import (
    is_newer_version,
    normalize_compatibility,
    normalize_version,
    safe_cache_path,
    sha256_bytes,
    version_score,
)


# ── Version arithmetic ───────────────────────────────────────────────
#
# esp32_ota_main.ino computes FIRMWARE_VERSION_N as major*10000 + minor*100 +
# patch and refuses anything scoring lower than its own. version_score() must
# produce the same number or the two ends disagree about what a downgrade is.


@pytest.mark.parametrize(
    ('version', 'expected'),
    [
        ('2.4.1', 20401),
        ('v2.4.1', 20401),
        ('0.0.0', 0),
        ('1.0.0', 10000),
        ('0.1.0', 100),
        ('0.0.1', 1),
        ('2.4', 20400),
        ('3', 30000),
    ],
)
def test_version_score_matches_the_firmware_formula(version, expected):
    assert version_score(version) == expected


def test_version_score_of_the_shipped_firmware_version():
    """esp32_ota_main.ino hardcodes FIRMWARE_VERSION_N 20401 for v2.4.1."""
    assert version_score('2.4.1') == 20401


@pytest.mark.parametrize('garbage', ['', 'not-a-version', 'v', '...', 'abc.def.ghi'])
def test_unparseable_versions_score_zero_rather_than_raising(garbage):
    """A malformed heartbeat must not be able to take the gateway down."""
    assert version_score(garbage) == 0


def test_newer_version_is_detected():
    assert is_newer_version('2.5.0', '2.4.1')
    assert is_newer_version('3.0.0', '2.99.99')
    assert is_newer_version('2.4.2', '2.4.1')


def test_same_version_is_not_newer():
    assert not is_newer_version('2.4.1', '2.4.1')
    assert not is_newer_version('v2.4.1', '2.4.1')


def test_older_version_is_not_newer():
    """This is the anti-rollback check; it must never return True."""
    assert not is_newer_version('2.4.0', '2.4.1')
    assert not is_newer_version('1.9.9', '2.0.0')
    assert not is_newer_version('0.0.1', '2.4.1')


def test_unparseable_candidate_never_counts_as_newer():
    assert not is_newer_version('garbage', '2.4.1')
    assert not is_newer_version('', '0.0.1')


def test_component_overflow_is_a_known_limitation():
    """
    The major*10000 + minor*100 + patch packing assumes each component stays
    under 100. 2.4.100 collides with 2.5.0. Documented here rather than fixed,
    because changing it means changing the firmware's arithmetic too, and the
    two must move together.
    """
    assert version_score('2.4.100') == version_score('2.5.0')


# ── Version normalisation ────────────────────────────────────────────


@pytest.mark.parametrize(
    ('raw', 'expected'),
    [('2.4.1', '2.4.1'), ('v2.4.1', '2.4.1'), ('  2.4.1  ', '2.4.1'), ('10.20.30', '10.20.30')],
)
def test_normalize_version_strips_prefix_and_whitespace(raw, expected):
    assert normalize_version(raw) == expected


@pytest.mark.parametrize('bad', ['', '   ', 'v', 'two.four.one', '2.4.x', '2..1', '-1.0.0'])
def test_normalize_version_rejects_non_numeric(bad):
    with pytest.raises(ValueError):
        normalize_version(bad)


# ── Path safety ──────────────────────────────────────────────────────


def test_plain_filename_resolves_inside_the_cache():
    resolved = safe_cache_path('firmware_v2.4.1.bin')
    assert resolved is not None
    assert resolved.parent == FIRMWARE_CACHE_DIR


@pytest.mark.parametrize(
    'attack',
    [
        '../../../etc/passwd',
        '..\\..\\windows\\system32\\config\\sam',
        '/etc/passwd',
        'subdir/firmware.bin',
        'subdir\\firmware.bin',
        '',
    ],
)
def test_traversal_and_separators_are_refused(attack):
    assert safe_cache_path(attack) is None


def test_dotdot_without_a_separator_cannot_escape():
    """'..' alone has no separator, so it must still not resolve to the parent."""
    assert safe_cache_path('..') is None


# ── Compatibility list ───────────────────────────────────────────────


def test_known_device_types_pass_through():
    assert normalize_compatibility(['ESP32', 'ESP8266']) == ['ESP32', 'ESP8266']


def test_unknown_device_types_are_dropped():
    result = normalize_compatibility(['ESP32', 'PDP-11', 'ESP8266'])
    assert 'PDP-11' not in result
    assert 'ESP32' in result


# ── Digest ───────────────────────────────────────────────────────────


def test_sha256_matches_the_known_vector():
    assert sha256_bytes(b'') == (
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    )


def test_sha256_is_lowercase_hex():
    digest = sha256_bytes(b'firmware')
    assert len(digest) == 64
    assert digest == digest.lower()
