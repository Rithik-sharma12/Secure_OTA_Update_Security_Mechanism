"""
End to end, with nothing mocked but the hardware:

    SotaUartAgent (C++, compiled for the PC; stdin/stdout is its UART)
        <-> LinkHost (apps/agent/sota_link.py)
        <-> the real gateway app (FastAPI TestClient)

Covers the five stages on the ATmega328P path (gateway-assisted Ed25519) and
the STM32F103 path (Ed25519 on the board), and the attacks each stage stops.
Needs a C/C++ compiler and the gateway's Python dependencies; skipped otherwise.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'apps' / 'agent'))
sys.path.insert(0, str(ROOT / 'apps' / 'gateway'))

if not shutil.which('c++') or not shutil.which('cc'):
    pytest.skip('needs a C and C++ compiler', allow_module_level=True)

os.environ.setdefault('OTA_GATEWAY_API_KEY', 'e2e-gateway-key-0123456789abcdef')
import tempfile  # noqa: E402

_TMP = Path(tempfile.mkdtemp(prefix='sota-e2e-'))
os.environ.setdefault('OTA_GATEWAY_CACHE_DIR', str(_TMP / 'cache'))
os.environ.setdefault('OTA_GATEWAY_KEYS_DIR', str(_TMP / 'keys'))

fastapi_testclient = pytest.importorskip('fastapi.testclient')
gateway = pytest.importorskip('gateway')

from sota_link import LinkHost  # noqa: E402

API_KEY = os.environ['OTA_GATEWAY_API_KEY']
FIRMWARE = bytes((i * 31 + 7) & 0xFF for i in range(3000))  # not a multiple of the chunk size


@pytest.fixture(scope='module')
def agent_binary(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp('bin') / 'sota_agent_host'
    script = ROOT / 'firmware' / 'lib' / 'sota_board' / 'test' / 'build.sh'
    subprocess.run(['sh', str(script), str(out)], check=True, capture_output=True)
    return out


@pytest.fixture(scope='module')
def client():
    return fastapi_testclient.TestClient(gateway.app)


@pytest.fixture(scope='module')
def published(client):
    """v1.1.0 for both UART boards, and a token per test device."""
    headers = {'x-api-key': API_KEY}
    for board in ('ATmega328P', 'STM32F103'):
        response = client.post(
            '/api/releases/upload',
            headers=headers,
            files={'file': (f'{board}_v1.1.0.bin', FIRMWARE, 'application/octet-stream')},
            data={'version': '1.1.0' if board == 'ATmega328P' else '1.1.1', 'compatible': board},
        )
        assert response.status_code == 200, response.text
    return client.get('/releases/latest/public-key').json()['publicKeyHex']


def _token(client, device_id: str) -> str:
    data = client.post('/api/devices/register', json={'deviceId': device_id}, headers={'x-api-key': API_KEY}).json()
    return data['token']


def _http(client, token):
    def http(method, url, body):
        path = url.replace('http://gateway', '')
        response = client.request(method, path, json=body, headers={'x-device-token': token})
        return response.status_code, response.content
    return http


def boot(binary, host, tmp_path, version, device_id, key=None, tamper=None):
    """Run one boot of the board; relay every line through the link host."""
    args = [str(binary), version, device_id, str(tmp_path / 'eeprom.bin'), str(tmp_path / 'staged.bin')]
    if key:
        args.append(key)
    proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
    log = []
    for line in proc.stdout:
        log.append(line.rstrip())
        reply = host.handle(line)
        if reply and tamper:
            reply = tamper(reply)
        if reply:
            proc.stdin.write(reply + '\n')
            proc.stdin.flush()
    proc.wait(timeout=30)
    health = next((int(l.split()[-1]) for l in log if l.startswith('# result')), None)
    return proc.returncode, health, log


def _host(client, device_id):
    return LinkHost('http://gateway', _http(client, _token(client, device_id)), log=lambda _m: None)


def test_atmega_installs_a_verified_update_and_confirms_it(agent_binary, client, published, tmp_path):
    host = _host(client, 'atmega-e2e-1')
    code, _, log = boot(agent_binary, host, tmp_path, '1.0.0', 'atmega-e2e-1')
    assert code == 42, log                                   # reset into the bootloader
    assert (tmp_path / 'staged.bin').read_bytes() == FIRMWARE
    assert any('SOTA:VERIFY' in l for l in log)              # S5 was gateway-assisted

    # The bootloader copied it; the new image boots and passes its self-test.
    code, health, log = boot(agent_binary, host, tmp_path, '1.1.0', 'atmega-e2e-1')
    assert code == 0 and health == 100, log                  # confirmed, nothing newer
    device = client.get('/api/devices/atmega-e2e-1', headers={'x-api-key': API_KEY}).json()['device']
    assert device['fw'] == '1.1.0' and device['arch'] == 'ATmega328P'


def test_stm32_checks_the_signature_on_the_board(agent_binary, client, published, tmp_path):
    host = _host(client, 'stm32-e2e-1')
    code, _, log = boot(agent_binary, host, tmp_path, '1.0.0', 'stm32-e2e-1', key=published)
    assert code == 42, log
    assert not any('SOTA:VERIFY' in l for l in log)          # no help from the gateway


def test_altered_byte_is_stopped_at_stage_4(agent_binary, client, published, tmp_path):
    host = _host(client, 'atmega-e2e-2')

    def flip(reply):
        if reply.startswith('SOTA:DATA 256 '):
            return reply[:-2] + ('00' if reply[-2:] != '00' else '01')
        return reply

    code, health, log = boot(agent_binary, host, tmp_path, '1.0.0', 'atmega-e2e-2', tamper=flip)
    assert code == 1 and health == 80, log                   # -20 for the SHA-256 mismatch
    assert not (tmp_path / 'staged.bin').exists()


def test_forged_signature_is_stopped_at_stage_5(agent_binary, client, published, tmp_path):
    host = _host(client, 'atmega-e2e-3')

    def forge(reply):
        if reply.startswith('SOTA:MANIFEST'):
            head, _, sig = reply.rpartition(' g=')
            return f'{head} g={"A" * 86}=='
        return reply

    code, health, log = boot(agent_binary, host, tmp_path, '1.0.0', 'atmega-e2e-3', tamper=forge)
    assert code == 1 and health == 70, log                   # -30 for an invalid signature


def test_forged_signature_is_stopped_on_the_stm32_too(agent_binary, client, published, tmp_path):
    host = _host(client, 'stm32-e2e-2')

    def forge(reply):
        if reply.startswith('SOTA:MANIFEST'):
            head, _, _sig = reply.rpartition(' g=')
            return f'{head} g={"B" * 86}=='
        return reply

    code, health, _ = boot(agent_binary, host, tmp_path, '1.0.0', 'stm32-e2e-2', key=published, tamper=forge)
    assert code == 1 and health == 70


def test_downgrade_is_refused_at_stage_2(agent_binary, client, published, tmp_path):
    host = _host(client, 'atmega-e2e-4')
    code, health, _ = boot(agent_binary, host, tmp_path, '2.0.0', 'atmega-e2e-4')
    assert code == 1 and health == 80                        # -20 for an older version on offer


def test_failed_self_test_skips_that_version(agent_binary, client, published, tmp_path):
    host = _host(client, 'atmega-e2e-5')
    assert boot(agent_binary, host, tmp_path, '1.0.0', 'atmega-e2e-5')[0] == 42
    # No bootloader copied the image: the old version boots again.
    code, health, log = boot(agent_binary, host, tmp_path, '1.0.0', 'atmega-e2e-5')
    assert health == 75, log                                 # -25 self-test failure
    assert code == 0                                         # and v1.1.0 is not downloaded again
