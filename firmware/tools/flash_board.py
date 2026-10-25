#!/usr/bin/env python3
"""
Flash SecureOTA firmware over USB the way the Arduino IDE's Upload button does.

    scripts\\flash-board.cmd                 find the board, flash firmware-full.bin, show it booting
    scripts\\flash-board.cmd --port COM5     a specific port
    scripts\\flash-board.cmd --erase         wipe the whole chip first (Wi-Fi settings, old OTA slot)
    scripts\\flash-board.cmd --list          list serial ports and stop

What it does, in order:
  1. Picks firmware\\dist\\<env>\\firmware-full.bin and checks it against build-info.json.
  2. Finds the board: the USB-serial chips ESP32 boards use (CP210x, CH340/CH9102,
     FTDI, Espressif native USB). Bluetooth COM ports are ignored.
  3. Makes sure no other program has the port open (Serial Monitor, PuTTY, a browser tab).
  4. Runs esptool exactly like the Arduino IDE: automatic reset into download mode
     (DTR/RTS), write at 0x0, hard reset. A transfer that drops data is retried at a
     lower speed; a board without automatic reset gets a manual BOOT/EN window.
  5. Watches the serial port for a few seconds and reports what the board printed.

Uses the esptool that ships with the Arduino IDE or PlatformIO when present (the
same one the IDE uses), otherwise installs esptool with pip on first run.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

FIRMWARE_DIR = Path(__file__).resolve().parents[1]
DIST = FIRMWARE_DIR / 'dist'

# USB-serial bridges found on ESP32 / ESP8266 boards (vendor id, product id).
KNOWN_ADAPTERS = {
    (0x10C4, 0xEA60): 'Silicon Labs CP210x',
    (0x1A86, 0x7523): 'WCH CH340',
    (0x1A86, 0x55D4): 'WCH CH9102',
    (0x1A86, 0x5523): 'WCH CH341',
    (0x0403, 0x6001): 'FTDI FT232R',
    (0x0403, 0x6015): 'FTDI FT231X',
    (0x303A, 0x1001): 'Espressif native USB',
}

BAUDS = [921600, 460800, 115200]
MANUAL_STEPS = 'Press and HOLD the BOOT button, press and release EN (RST), then release BOOT.'
# esptool output meaning "connected, then the transfer broke": worth a slower retry.
DATA_ERRORS = ('Serial data stream stopped', 'Invalid head of packet', 'Timed out waiting for packet',
               'Packet content transfer stopped', 'checksum error', 'MD5 of file does not match', 'Possible serial noise')
CONNECT_ERRORS = ('Failed to connect', 'Wrong boot mode detected', 'No serial data received')


def say(text: str = '') -> None:
    print(text, flush=True)


def ensure(module: str, package: str) -> None:
    try:
        __import__(module)
    except ImportError:
        say(f'Installing {package} (first run only)...')
        in_venv = sys.prefix != getattr(sys, 'base_prefix', sys.prefix)
        flags = ['--quiet'] if in_venv else ['--user', '--quiet']
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', *flags, package])


# ------------------------------------------------------------------ esptool

def find_esptool() -> tuple[list[str], str]:
    """The esptool command to run, and where it came from. Arduino IDE's first."""
    home = Path.home()
    arduino_roots = [
        Path(os.environ.get('LOCALAPPDATA', home / 'AppData' / 'Local')) / 'Arduino15',
        home / '.arduino15',
        home / 'Library' / 'Arduino15',
    ]
    for root in arduino_roots:
        for pattern in ('packages/esp32/tools/esptool_py/*/esptool.exe',
                        'packages/esp32/tools/esptool_py/*/esptool',
                        'packages/esp32/tools/esptool_py/*/esptool.py'):
            found = sorted(glob.glob(str(root / pattern)))
            if found:
                exe = found[-1]
                cmd = [sys.executable, exe] if exe.endswith('.py') else [exe]
                return cmd, f'Arduino IDE ({Path(exe).parent.name})'
    pio = home / '.platformio' / 'packages' / 'tool-esptoolpy' / 'esptool.py'
    if pio.is_file():
        return [sys.executable, str(pio)], 'PlatformIO'
    ensure('esptool', 'esptool')
    return [sys.executable, '-m', 'esptool'], 'pip esptool'


# ------------------------------------------------------------------ image

def pick_image(args) -> tuple[Path, dict]:
    if args.file:
        image = Path(args.file).resolve()
        info_path = image.parent / 'build-info.json'
    else:
        image = DIST / args.env / 'firmware-full.bin'
        info_path = DIST / args.env / 'build-info.json'
    if not image.is_file():
        say(f'No firmware at {image}.')
        say('Build it first:  scripts\\build-firmware.cmd')
        sys.exit(1)
    info = {}
    if info_path.is_file():
        try:
            info = json.loads(info_path.read_text(encoding='utf-8'))
        except ValueError:
            info = {}
    expected = (info.get('files', {}).get(image.name) or {}).get('sha256')
    if expected:
        actual = hashlib.sha256(image.read_bytes()).hexdigest()
        if actual != expected:
            say(f'{image.name} does not match build-info.json (it changed after the build). Rebuild it.')
            sys.exit(1)
    return image, info


# ------------------------------------------------------------------ ports

def list_candidates(show_all: bool = False):
    from serial.tools import list_ports
    ports = []
    for p in list_ports.comports():
        adapter = KNOWN_ADAPTERS.get((p.vid or 0, p.pid or 0))
        text = f'{p.description or ""} {p.hwid or ""}'.lower()
        bluetooth = 'bluetooth' in text or 'bthenum' in text
        ports.append((p.device, adapter, p.description or '', bluetooth))
    if show_all:
        return ports
    return [p for p in ports if p[1] and not p[3]]


def choose_port(requested: str | None) -> str:
    if requested:
        return requested
    candidates = list_candidates()
    if len(candidates) == 1:
        device, adapter, _, _ = candidates[0]
        say(f'Board: {device} ({adapter})')
        return device
    if not candidates:
        say('No ESP board found on USB.')
        others = list_candidates(show_all=True)
        if others:
            say('Serial ports present (none is a CP210x / CH340 / FTDI / ESP USB adapter):')
            for device, _, description, bluetooth in others:
                say(f'  {device}  {description}{"  (Bluetooth: not a board)" if bluetooth else ""}')
        say('Check that:')
        say('  - the cable carries data (charge-only cables show no port at all),')
        say('  - the driver is installed: CP210x from silabs.com, CH340 from wch-ic.com,')
        say('  - the board appears in Device Manager > Ports (COM & LPT) when plugged in.')
        say('Or name the port yourself:  scripts\\flash-board.cmd --port COM5')
        sys.exit(1)
    say('More than one board is connected:')
    for i, (device, adapter, _, _) in enumerate(candidates, 1):
        say(f'  {i}. {device}  {adapter}')
    choice = input('Number of the board to flash: ').strip()
    if not choice.isdigit() or not 1 <= int(choice) <= len(candidates):
        sys.exit('No board chosen.')
    return candidates[int(choice) - 1][0]


def ensure_port_free(port: str) -> None:
    """Fail early, and clearly, when another program holds the port."""
    import serial
    for attempt in range(3):
        try:
            s = serial.Serial()
            s.port, s.baudrate = port, 115200
            s.dtr = s.rts = False  # do not reset the board just by looking
            s.open()
            s.close()
            return
        except serial.SerialException as exc:
            text = str(exc)
            if 'FileNotFoundError' in text or 'could not open port' in text and 'cannot find' in text.lower():
                sys.exit(f'{port} does not exist. Run with --list to see the ports.')
            say(f'{port} is in use by another program ({text.splitlines()[0][:80]}).')
            say('Close whichever of these is open, then press Enter:')
            say('  Arduino IDE Serial Monitor / Serial Plotter, PlatformIO or VS Code serial monitor,')
            say('  PuTTY / Tera Term, the dashboard Serial Monitor, a browser tab using "Flash over USB".')
            if attempt < 2:
                input()
    sys.exit(f'{port} is still busy.')


# ------------------------------------------------------------------ flashing

def run_esptool(cmd: list[str]) -> tuple[int, str]:
    """Run esptool, echoing its output live; return exit code and the full text."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
                            encoding='utf-8', errors='replace')
    out = []
    assert proc.stdout
    for line in proc.stdout:
        out.append(line)
        if line.startswith(('WARNING: Deprecated', 'Warning: Deprecated')):
            continue
        sys.stdout.write(line)
        sys.stdout.flush()
    proc.wait()
    return proc.returncode, ''.join(out)


def flash(esptool: list[str], port: str, image: Path, chip: str, baud: int, erase: bool, before: str, attempts: int):
    cmd = esptool + ['--chip', chip, '--port', port, '--baud', str(baud), '--before', before, '--after', 'hard_reset']
    if attempts:
        cmd += ['--connect-attempts', str(attempts)]
    cmd += ['write_flash', '-z', '--flash_mode', 'keep', '--flash_freq', 'keep', '--flash_size', 'keep']
    if erase:
        cmd.append('--erase-all')
    cmd += ['0x0', str(image)]
    return run_esptool(cmd)


def _connected(text: str) -> bool:
    return 'Writing at' in text or re.search(r'Chip (is|type)', text) is not None


def flash_with_retries(esptool, port, image, chip, start_baud, erase) -> bool:
    bauds = [b for b in BAUDS if b <= start_baud] or [115200]
    manual = False
    text = ''
    for baud in bauds:
        before, attempts = ('no_reset', 40) if manual else ('default_reset', 7)
        say(f'\n--- Uploading at {baud} baud{" (manual download mode)" if manual else ""} ---')
        code, text = flash(esptool, port, image, chip, baud, erase, before, attempts)
        if code == 0:
            return True
        if not _connected(text):
            if manual:
                break
            # The IDE's "Failed to connect": no working auto-reset on this board,
            # or the adapter's DTR/RTS lines do not reach EN/IO0.
            say('\nThe board did not enter download mode automatically.')
            say(MANUAL_STEPS)
            say('Do it now; the upload starts as soon as the board answers (about 40 s window).')
            manual = True
            code, text = flash(esptool, port, image, chip, baud, erase, 'no_reset', 40)
            if code == 0:
                return True
            if not _connected(text):
                break
        if not any(e in text for e in DATA_ERRORS):
            break  # not a speed problem; a slower retry would only repeat it
        say(f'\nThe transfer broke at {baud} baud (cable, hub or adapter dropping data). Retrying slower.')
    say('\nUpload failed.')
    if 'waiting for download' in text:
        say('The board was in download mode but did not answer: another program may be using the port,')
        say('or the cable/USB hub drops data. Close serial tools, use a USB port on the computer itself,')
        say('try another cable, then run this again.')
    elif not _connected(text):
        say('The board never answered. Check the cable carries data and the CP210x/CH340 driver, then')
        say(f'retry and put the board in download mode by hand: {MANUAL_STEPS}')
    return False


def watch_boot(port: str, seconds: float) -> None:
    import serial
    say(f'\n--- Board output ({int(seconds)} s) ---')
    try:
        s = serial.Serial()
        s.port, s.baudrate, s.timeout = port, 115200, 0.2
        s.dtr = s.rts = False  # IO0 and EN released: let the firmware run
        s.open()
    except serial.SerialException as exc:
        say(f'(could not open {port} to watch the boot: {exc})')
        return
    seen = []
    deadline = time.time() + seconds
    pending = b''
    try:
        while time.time() < deadline:
            pending += s.read(256)
            while b'\n' in pending:
                raw, pending = pending.split(b'\n', 1)
                line = raw.decode('utf-8', 'replace').rstrip('\r')
                seen.append(line)
                say(f'  {line}')
                if line.startswith('SOTA:READY') or '[OTA] Setup complete' in line:
                    deadline = min(deadline, time.time() + 1.5)
    finally:
        s.close()
    text = '\n'.join(seen)
    m = re.search(r'Firmware v(\d+\.\d+\.\d+)', text)
    if m or 'SOTA:READY' in text:
        say(f'\nOK: the board is running SecureOTA{" v" + m.group(1) if m else ""}.')
        if 'SOTA:READY' in text:
            say('It has no Wi-Fi settings yet: finish in the dashboard, Devices, "Set up a new board"')
            say('(tick "already runs SecureOTA firmware"), or with the agent\'s Provision button.')
    elif 'waiting for download' in text:
        say('\nThe board is still in download mode. Release BOOT and press EN (RST) once.')
    elif 'Brownout' in text:
        say('\nThe board resets from low supply voltage. Use a USB port on the computer itself or a shorter cable.')
    elif not seen:
        say('\nThe board printed nothing. Press EN (RST) once; if it stays silent, check the cable.')


def main() -> None:
    parser = argparse.ArgumentParser(description='Flash SecureOTA firmware over USB, like the Arduino IDE Upload button.')
    parser.add_argument('--port', help='serial port, e.g. COM5 (found automatically when omitted)')
    parser.add_argument('--env', default='esp32dev', help='build environment under firmware/dist (default esp32dev)')
    parser.add_argument('--file', help='a different full image to flash at 0x0')
    parser.add_argument('--baud', type=int, default=921600, help='upload speed (default 921600, falls back automatically)')
    parser.add_argument('--erase', action='store_true', help='erase the whole flash first')
    parser.add_argument('--no-monitor', action='store_true', help='do not watch the board boot afterwards')
    parser.add_argument('--list', action='store_true', help='list serial ports and exit')
    parser.add_argument('--esptool', help=argparse.SUPPRESS)  # command override, for tests
    args = parser.parse_args()

    ensure('serial', 'pyserial')
    if args.list:
        for device, adapter, description, bluetooth in list_candidates(show_all=True):
            tag = adapter or ('Bluetooth, not a board' if bluetooth else 'unknown adapter')
            say(f'{device:10} {tag:28} {description}')
        return

    image, info = pick_image(args)
    chip = str(info.get('chip') or 'esp32')
    say(f'Firmware: {image}  (v{info.get("version", "?")}, {image.stat().st_size // 1024} KB, {chip})')
    esptool, source = (args.esptool.split(), 'given') if args.esptool else find_esptool()
    say(f'esptool:  {source}')
    port = choose_port(args.port)
    ensure_port_free(port)

    started = time.time()
    if not flash_with_retries(esptool, port, image, chip, args.baud, args.erase):
        sys.exit(1)
    say(f'\nUploaded in {time.time() - started:.1f} s.')
    if not args.no_monitor:
        time.sleep(0.3)
        watch_boot(port, 8.0)


if __name__ == '__main__':
    main()
