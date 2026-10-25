#!/usr/bin/env python3
"""
Make a self-contained Arduino IDE sketch folder for the ESP32 firmware.

    python firmware/tools/export_arduino_sketch.py
    -> firmware/arduino-ide/esp32_ota_main/   (open esp32_ota_main.ino in the Arduino IDE)

The folder holds the sketch, ca_bundle.h, your ota_config.h (Wi-Fi, gateway,
release keys) and the sota_core sources (Ed25519 stage 5), so the IDE needs
only the ESP32 core 2.0.17 and the ArduinoJson library. It contains your
secrets: it is git-ignored and must not be shared.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

FIRMWARE = Path(__file__).resolve().parents[1]
SKETCH = FIRMWARE / 'esp32_ota_main'
CORE = FIRMWARE / 'lib' / 'sota_core' / 'src'
OUT = FIRMWARE / 'arduino-ide' / 'esp32_ota_main'


def main() -> None:
    config = SKETCH / 'ota_config.h'
    if not config.is_file():
        sys.exit('firmware/esp32_ota_main/ota_config.h is missing. Run scripts\\build-firmware.cmd once '
                 '(it creates it with the release keys), or copy ota_config.h.example and fill it in.')
    OUT.mkdir(parents=True, exist_ok=True)
    for name in ('esp32_ota_main.ino', 'ca_bundle.h', 'ota_config.h'):
        shutil.copy2(SKETCH / name, OUT / name)
    for source in sorted(CORE.iterdir()):
        if source.suffix in ('.c', '.h'):
            shutil.copy2(source, OUT / source.name)
    (OUT.parent / '.gitignore').write_text('# Copies of the sketch plus ota_config.h (secrets): never commit.\n*\n')
    print(f'Sketch folder ready: {OUT}')
    for item in sorted(OUT.iterdir()):
        print(f'  {item.name}')
    print('Open esp32_ota_main.ino in the Arduino IDE.')


if __name__ == '__main__':
    main()
