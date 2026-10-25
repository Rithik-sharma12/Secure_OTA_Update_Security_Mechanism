#!/usr/bin/env python3
"""
Build the SecureOTA firmware and produce the two images the console needs.

    python firmware/tools/build_firmware.py            # ESP32 DevKit (esp32dev)
    python firmware/tools/build_firmware.py esp32s3    # or esp32c3

Output, in firmware/dist/<env>/:

    firmware.bin       app image. Publish it on the Releases page, or flash it
                       at 0x10000 on a board that already has a bootloader.
    firmware-full.bin  bootloader + partition table + boot_app0 + app merged at
                       0x0. Flash this on a blank or unknown board from
                       Devices -> Flash over USB (browser).
    firmware-ota.bin   signed, encrypted OTA package (SOTAv2) of firmware.bin.
                       Publish THIS on the Releases page, with the
                       "Plaintext image SHA-256" from build-info.json. Boards
                       built with these keys verify it before writing, which is
                       what makes over-the-air updates safe over plain http.
    SHA256SUMS.txt     SHA-256 of every file.
    build-info.json    version, environment, chip, offsets and digests.

Toolchain: PlatformIO by default. Pass --arduino-cli (or set ARDUINO_CLI to
the arduino-cli executable) to build with arduino-cli and the Arduino-ESP32
2.0.17 core instead; it gives the same image layout. ARDUINO_CLI_CONFIG may
name an arduino-cli config file.

Release keys: the first run creates an RSA-2048 signing key pair and an
AES-256 key in firmware/secure-keys/ (git-ignored; back it up, every board
you flash trusts only these keys) and writes the public key and AES key into
ota_config.h. Pass --no-secure for a build without them; such boards accept
updates only from an https:// gateway.

If esp32_ota_main/ota_config.h does not exist it is created from the example.
A build whose Wi-Fi and gateway settings are still placeholders is a generic
image: the board boots, prints SOTA:READY and waits for the console to
provision it over USB (Devices -> Set up a new board). That is the normal way
to bring up new boards; the same image works for every board.
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

FIRMWARE_DIR = Path(__file__).resolve().parents[1]
SKETCH_DIR = FIRMWARE_DIR / 'esp32_ota_main'
CONFIG = SKETCH_DIR / 'ota_config.h'
KEYS_DIR = FIRMWARE_DIR / 'secure-keys'
PRIVATE_KEY = KEYS_DIR / 'release_signing_private.pem'
PUBLIC_KEY = KEYS_DIR / 'release_signing_public.pem'
AES_KEY = KEYS_DIR / 'release_aes_key.txt'
PACKAGE_MODULE = FIRMWARE_DIR.parent / 'apps' / 'gateway' / 'gateway' / 'package.py'

# env -> (esptool chip name, second-stage bootloader offset)
ENVIRONMENTS = {
    'esp32dev': ('esp32', 0x1000),
    'esp32s3': ('esp32s3', 0x0),
    'esp32c3': ('esp32c3', 0x0),
}
# env -> arduino-cli FQBN. DIO flash mode and the default partition table match
# PlatformIO's esp32dev build, so both toolchains produce the same layout.
ARDUINO_FQBN = {
    'esp32dev': 'esp32:esp32:esp32:FlashMode=dio,PartitionScheme=default,DebugLevel=info',
    'esp32s3': 'esp32:esp32:esp32s3:FlashMode=dio,PartitionScheme=default,DebugLevel=info',
    'esp32c3': 'esp32:esp32:esp32c3:FlashMode=dio,PartitionScheme=default,DebugLevel=info',
}
ARDUINO_CORE = 'esp32:esp32@2.0.17'
PARTITIONS_OFFSET = 0x8000
BOOT_APP0_OFFSET = 0xE000
APP_OFFSET = 0x10000


def fail(message: str) -> None:
    print(f'\nERROR: {message}', file=sys.stderr)
    sys.exit(1)


def run(cmd: list[str], **kwargs) -> None:
    print('>', ' '.join(cmd), flush=True)
    result = subprocess.run(cmd, **kwargs)
    if result.returncode != 0:
        fail(f'command failed with exit code {result.returncode}')


def ensure_platformio() -> None:
    probe = subprocess.run([sys.executable, '-m', 'platformio', '--version'], capture_output=True, text=True)
    if probe.returncode == 0:
        print(probe.stdout.strip())
        return
    print('PlatformIO is not installed for this Python. Installing it (one time)...', flush=True)
    run([sys.executable, '-m', 'pip', 'install', '--quiet', 'platformio'])


def ensure_config() -> bool:
    """Returns True when the build is generic (settings left to USB provisioning)."""
    if not CONFIG.exists():
        shutil.copyfile(SKETCH_DIR / 'ota_config.h.example', CONFIG)
        print(f'Created {CONFIG.relative_to(FIRMWARE_DIR.parent)} from the example.')
    text = CONFIG.read_text(encoding='utf-8', errors='replace')
    generic = bool(re.search(r'#define\s+WIFI_SSID\s+"(CHANGE_ME|YOUR_|)', text))
    https = re.search(r'#define\s+BACKEND_URL\s+"https://', text) is not None
    no_ca = re.search(r'OTA_ROOT_CA\[\]\s*PROGMEM\s*=\s*""\s*;', text) is not None
    if https and no_ca:
        print('WARNING: BACKEND_URL is https:// but OTA_ROOT_CA is empty: the board will not verify the server certificate.')
    return generic


def load_package_module():
    """The gateway's package format, loaded as a single file (see create_secure_test_package.py)."""
    import importlib.util

    try:
        import cryptography  # noqa: F401
    except ImportError:
        print('Installing the cryptography package (one time)...', flush=True)
        run([sys.executable, '-m', 'pip', 'install', '--quiet', 'cryptography'])
    spec = importlib.util.spec_from_file_location('secureota_package', PACKAGE_MODULE)
    if spec is None or spec.loader is None:
        fail(f'package format module not found at {PACKAGE_MODULE}')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def config_value(text: str, name: str) -> str | None:
    match = re.search(rf'#define\s+{name}\s+"([^"]*)"', text)
    if match:
        return match.group(1)
    match = re.search(rf'{name}\[\]\s*=\s*R"KEY\((.*?)\)KEY"', text, re.S)
    return match.group(1).strip() if match else None


def ensure_release_keys(package) -> str:
    """Create the release keys once and compile them into ota_config.h. Returns the AES key."""
    import secrets
    import string

    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    new_pair = not PRIVATE_KEY.exists()
    package.load_or_create_packaging_key(PRIVATE_KEY, PUBLIC_KEY)
    if AES_KEY.exists():
        aes = AES_KEY.read_text(encoding='utf-8').strip()
    else:
        alphabet = string.ascii_letters + string.digits
        aes = ''.join(secrets.choice(alphabet) for _ in range(32))
        AES_KEY.write_text(aes + '\n', encoding='utf-8')
    if len(aes) != 32:
        fail(f'{AES_KEY} must hold exactly 32 characters.')
    if new_pair:
        print(f'Created release keys in {KEYS_DIR.relative_to(FIRMWARE_DIR.parent)}. Back this folder up: '
              'boards built now only accept updates signed with it.')

    public_pem = PUBLIC_KEY.read_text(encoding='utf-8').strip()
    text = CONFIG.read_text(encoding='utf-8', errors='replace')
    current_aes = config_value(text, 'FIRMWARE_ENC_KEY')
    current_pub = config_value(text, 'FIRMWARE_PUB_KEY')
    if current_aes and current_pub:
        if current_aes != aes or current_pub.strip() != public_pem:
            fail('ota_config.h already holds different FIRMWARE_ENC_KEY / FIRMWARE_PUB_KEY values than '
                 f'{KEYS_DIR.name}/. Put the matching keys in {KEYS_DIR.name}/ or clear them in ota_config.h.')
        return aes
    text = re.sub(r'#define\s+FIRMWARE_ENC_KEY\s+"[^"]*"', f'#define FIRMWARE_ENC_KEY  "{aes}"', text, count=1)
    pub_block = f'static const char FIRMWARE_PUB_KEY[] = R"KEY(\n{public_pem}\n)KEY";'
    text, count = re.subn(r'#define\s+FIRMWARE_PUB_KEY\s+"[^"]*"', lambda _m: pub_block, text, count=1)
    if count == 0:
        fail('Could not find the FIRMWARE_PUB_KEY line in ota_config.h to fill in.')
    CONFIG.write_text(text, encoding='utf-8')
    print('Wrote the release public key and AES key into ota_config.h.')
    return aes


def firmware_version() -> str:
    text = (SKETCH_DIR / 'esp32_ota_main.ino').read_text(encoding='utf-8', errors='replace')
    match = re.search(r'#define\s+FIRMWARE_VERSION\s+"([^"]+)"', text)
    return match.group(1) if match else 'unknown'


def platformio_core_dir() -> Path:
    return Path(os.environ.get('PLATFORMIO_CORE_DIR') or Path.home() / '.platformio')


def find_boot_app0(core: Path) -> Path:
    patterns = [
        core / 'packages' / 'framework-arduinoespressif32*' / 'tools' / 'partitions' / 'boot_app0.bin',
        # arduino-cli data directory layout
        core / 'packages' / 'esp32' / 'hardware' / 'esp32' / '*' / 'tools' / 'partitions' / 'boot_app0.bin',
    ]
    for pattern in patterns:
        candidates = sorted(glob.glob(str(pattern)))
        if candidates:
            return Path(candidates[-1])
    fail(f'boot_app0.bin not found under {core / "packages"}. Did the build finish?')
    return Path()


# ------------------------------------------------------------- arduino-cli

def arduino_cli_command() -> list[str] | None:
    exe = os.environ.get('ARDUINO_CLI') or shutil.which('arduino-cli')
    if not exe:
        return None
    cmd = [exe]
    if os.environ.get('ARDUINO_CLI_CONFIG'):
        cmd += ['--config-file', os.environ['ARDUINO_CLI_CONFIG']]
    return cmd


def arduino_data_dir(cli: list[str]) -> Path:
    probe = subprocess.run(cli + ['config', 'get', 'directories.data'], capture_output=True, text=True)
    value = probe.stdout.strip()
    if probe.returncode != 0 or not value:
        fail('could not read the arduino-cli data directory (arduino-cli config get directories.data).')
    return Path(value)


def build_with_arduino_cli(env: str, build_dir: Path) -> Path:
    """Compile with arduino-cli into build_dir using the PlatformIO file names. Returns the core dir."""
    cli = arduino_cli_command()
    if cli is None:
        fail('arduino-cli not found. Install it from https://arduino.github.io/arduino-cli/ or set ARDUINO_CLI.')
    data = arduino_data_dir(cli)
    installed = subprocess.run(cli + ['core', 'list'], capture_output=True, text=True).stdout
    if not re.search(r'^esp32:esp32\s+2\.0\.17\b', installed, re.M):
        print(f'Installing the Arduino-ESP32 core {ARDUINO_CORE} (one time)...', flush=True)
        run(cli + ['core', 'install', ARDUINO_CORE,
                   '--additional-urls', 'https://espressif.github.io/arduino-esp32/package_esp32_index.json'])
    libraries = subprocess.run(cli + ['lib', 'list'], capture_output=True, text=True).stdout
    if 'ArduinoJson' not in libraries:
        print('Installing ArduinoJson 7 (one time)...', flush=True)
        run(cli + ['lib', 'install', 'ArduinoJson@7.2.1'])
    # A fixed build path lets arduino-cli reuse the compiled core between runs.
    out = build_dir / 'arduino-build'
    out.mkdir(parents=True, exist_ok=True)
    # sota_core (Ed25519 manifest check, stage 5) lives in firmware/lib; PlatformIO
    # finds it on its own, arduino-cli has to be told.
    run(cli + ['compile', '--fqbn', ARDUINO_FQBN[env], '--library', str(FIRMWARE_DIR / 'lib' / 'sota_core'),
               '--build-path', str(out), str(SKETCH_DIR)])
    name = SKETCH_DIR.name + '.ino'
    for source, target in ((f'{name}.bin', 'firmware.bin'),
                           (f'{name}.bootloader.bin', 'bootloader.bin'),
                           (f'{name}.partitions.bin', 'partitions.bin')):
        if not (out / source).exists():
            fail(f'arduino-cli did not produce {source}')
        shutil.copyfile(out / source, build_dir / target)
    return data


def esptool_command(core: Path) -> list[str]:
    script = core / 'packages' / 'tool-esptoolpy' / 'esptool.py'
    if script.exists():
        return [sys.executable, str(script)]
    # Fall back to a pip-installed esptool, installing it once if needed.
    probe = subprocess.run([sys.executable, '-m', 'esptool', 'version'], capture_output=True)
    if probe.returncode != 0:
        print('Installing esptool (one time)...', flush=True)
        run([sys.executable, '-m', 'pip', 'install', '--quiet', 'esptool'])
    return [sys.executable, '-m', 'esptool']


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1 << 16), b''):
            digest.update(block)
    return digest.hexdigest()


def merge(env: str, build_dir: Path, out: Path, core: Path) -> None:
    chip, boot_offset = ENVIRONMENTS[env]
    parts = {
        boot_offset: build_dir / 'bootloader.bin',
        PARTITIONS_OFFSET: build_dir / 'partitions.bin',
        BOOT_APP0_OFFSET: find_boot_app0(core),
        APP_OFFSET: build_dir / 'firmware.bin',
    }
    for path in parts.values():
        if not path.exists():
            fail(f'missing build output {path}')
    cmd = esptool_command(core) + ['--chip', chip, 'merge_bin', '-o', str(out),
                                   '--flash_mode', 'dio', '--flash_size', '4MB']
    for offset, path in parts.items():
        cmd += [hex(offset), str(path)]
    run(cmd)


def main() -> None:
    args = [arg for arg in sys.argv[1:] if not arg.startswith('--')]
    secure = '--no-secure' not in sys.argv
    use_arduino_cli = '--arduino-cli' in sys.argv or bool(os.environ.get('ARDUINO_CLI'))
    env = args[0] if args else 'esp32dev'
    if env not in ENVIRONMENTS:
        fail(f'unknown environment "{env}". Use one of: {", ".join(ENVIRONMENTS)}')

    if not use_arduino_cli:
        ensure_platformio()
    generic = ensure_config()
    version = firmware_version()
    package = load_package_module() if secure else None
    aes = ensure_release_keys(package) if package else None
    print(f'\nBuilding SecureOTA firmware v{version} for {env}...', flush=True)
    build_dir = FIRMWARE_DIR / '.pio' / 'build' / env
    if use_arduino_cli:
        build_dir.mkdir(parents=True, exist_ok=True)
        core = build_with_arduino_cli(env, build_dir)
    else:
        run([sys.executable, '-m', 'platformio', 'run', '-d', str(FIRMWARE_DIR), '-e', env])
        core = platformio_core_dir()
    dist = FIRMWARE_DIR / 'dist' / env
    dist.mkdir(parents=True, exist_ok=True)
    app = dist / 'firmware.bin'
    full = dist / 'firmware-full.bin'
    shutil.copyfile(build_dir / 'firmware.bin', app)
    merge(env, build_dir, full, core)

    outputs = [app, full]
    image_sha256 = sha256(app)
    ota = dist / 'firmware-ota.bin'
    if package and aes:
        private_key = package.load_or_create_packaging_key(PRIVATE_KEY, PUBLIC_KEY)
        payload = package.build_package(app.read_bytes(), private_key, aes, version=version)
        # Open it exactly as a board would before it leaves this script.
        if package.open_package(payload, PUBLIC_KEY.read_bytes(), aes) != app.read_bytes():
            fail('self-check failed: the OTA package does not decrypt to firmware.bin')
        ota.write_bytes(payload)
        outputs.append(ota)
    elif ota.exists():
        ota.unlink()

    sums = {path.name: sha256(path) for path in outputs}
    (dist / 'SHA256SUMS.txt').write_text(''.join(f'{h}  {n}\n' for n, h in sums.items()), encoding='ascii')
    chip, boot_offset = ENVIRONMENTS[env]
    info = {
        'version': version,
        'environment': env,
        'chip': chip,
        'generic': generic,
        'secure': bool(package),
        'toolchain': 'arduino-cli' if use_arduino_cli else 'platformio',
        'imageSha256': image_sha256,
        'files': {
            'firmware.bin': {'flashAddress': hex(APP_OFFSET), 'bytes': app.stat().st_size, 'sha256': sums[app.name]},
            'firmware-full.bin': {'flashAddress': '0x0', 'bytes': full.stat().st_size, 'sha256': sums[full.name],
                                  'bootloaderOffset': hex(boot_offset)},
        },
    }
    if ota.exists():
        info['files']['firmware-ota.bin'] = {'bytes': ota.stat().st_size, 'sha256': sums[ota.name],
                                             'publishAs': {'version': version, 'imageSha256': image_sha256,
                                                           'securePackage': True}}
    (dist / 'build-info.json').write_text(json.dumps(info, indent=2) + '\n', encoding='utf-8')

    rel = dist.relative_to(FIRMWARE_DIR.parent)
    print(f'\nDone. SecureOTA firmware v{version} ({env}) is in {rel}:')
    print(f'  firmware-full.bin  {full.stat().st_size:>9,} bytes  flash at 0x0 on a new board (Devices -> Flash over USB)')
    if ota.exists():
        print(f'  firmware-ota.bin   {ota.stat().st_size:>9,} bytes  publish on the Releases page for over-the-air updates')
        print(f'                     version {version}, plaintext image SHA-256 {image_sha256}')
    else:
        print(f'  firmware.bin       {app.stat().st_size:>9,} bytes  publish for an https:// gateway (no release keys in this build)')
    if generic:
        print('\nThis is a generic image: after flashing, the board waits for Wi-Fi and gateway settings.')
        print('Give them in the console: Devices -> Set up a new board (or Provision over USB).')


if __name__ == '__main__':
    main()
