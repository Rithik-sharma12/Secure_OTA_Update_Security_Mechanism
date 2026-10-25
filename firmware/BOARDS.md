# SecureOTA firmware for each board

All four boards run the same five-stage check before anything is installed:

| Stage | What is checked | Health score if it fails |
|---|---|---|
| S1 Connectivity and health | Gateway (or link host) answers; score above 40 | -1 (unreachable); at 40 or below the board stops updating |
| S2 Manifest validation | Every field present, strictly newer version, image fits, plain image on boards that take only plain images | -10 field missing, -20 older version offered, -15 too large |
| S3 Chunk-based download | Image streamed in chunks into the inactive area / staging flash | -15 size mismatch, -1 link error |
| S4 SHA-256 integrity | Digest of the received bytes equals the manifest `sha256` | -20 |
| S5 Ed25519 signature | The gateway's signature over `version`, `sha256`, `imageSha256`, `size` | -30 |

The signed statement and the checks live in one shared C library, `lib/sota_core`, so every board checks the same bytes the gateway signs (`apps/gateway/gateway/crypto.py`).

| Board | Folder | Reaches the gateway | S5 runs | Image goes to | Rollback |
|---|---|---|---|---|---|
| ESP32 | `esp32_ota_main/` | Wi-Fi (HTTP/HTTPS) | On the board (sota_core / Monocypher), plus the RSA-2048 package signature in secure mode | Inactive OTA partition | Automatic: the bootloader returns to the previous partition when the self-test fails |
| ESP8266 | `esp8266_ota_main/` | Wi-Fi (HTTP/HTTPS) | On the board, inside `Update.end()` | OTA area, copied by eboot | None in hardware: a failed self-test is recorded (-25) and that version is skipped |
| STM32F103 | `stm32f103_ota_agent/` | UART link host | On the board (about 1.5 KB RAM) | External SPI flash (W25Qxx) | Staged image only; needs a copy bootloader (not in this repository yet) |
| ATmega328P | `atmega328p_ota_agent/` | UART link host | Gateway-assisted: the board sends the fields and its computed digest, the gateway answers one bit | External SPI flash, copied by the DualOptiboot bootloader | None: a failed self-test is recorded (-25) and that version is skipped |

## What has been tested, and how

| Check | ESP32 | ESP8266 | STM32F103 | ATmega328P |
|---|---|---|---|---|
| Compiles for the real chip | Yes (Arduino-ESP32 2.0.17, 75% of flash) | Yes (core 3.1.2, NodeMCU) | Yes (STM32duino 2.8.1, Blue Pill, 36 KB of 64 KB) | Yes (Arduino AVR 1.8.6, Uno, 11.8 KB, 1.4 KB RAM) |
| Five-stage logic tested end to end against the real gateway | Earlier QEMU run (before stage 5 was added) | No | Yes, compiled for the PC (`apps/agent/tests/test_uart_agent_e2e.py`) | Yes, same test |
| Run on hardware | Yes, before stage 5 was added | No | No | No |

The UART end-to-end test runs the real agent code, compiled for the PC, against the real link host and gateway. It covers a clean update, the post-install self-test, a flipped byte (stopped at S4), a forged signature (stopped at S5, both gateway-assisted and on the board), a downgrade (stopped at S2) and a failed self-test.

## Building

The shared libraries are in `lib/`:

- `lib/sota_core`: manifest statement, Ed25519 (Monocypher 4.0.2), SHA-256, version and health rules. Plain C, any board.
- `lib/sota_board`: UART link client, W25Qxx SPI flash driver and the five-stage agent for the two UART boards. Arduino C++.

PlatformIO picks them up automatically for the ESP32 project. For arduino-cli pass them with `--library`; in the Arduino IDE copy both folders into your `Arduino/libraries` folder.

| Board | arduino-cli board (FQBN) | Extra libraries |
|---|---|---|
| ESP32 | `esp32:esp32:esp32` (or `scripts\build-firmware.cmd`) | ArduinoJson 7 |
| ESP8266 | `esp8266:esp8266:nodemcuv2` | ArduinoJson 7 |
| STM32F103 | `STMicroelectronics:stm32:GenF1:pnum=BLUEPILL_F103C8` | none |
| ATmega328P | `arduino:avr:uno` | none |

Example:

```
arduino-cli compile --fqbn arduino:avr:uno --library firmware/lib/sota_core --library firmware/lib/sota_board firmware/atmega328p_ota_agent
```

Board settings:

- ESP8266: copy `esp8266_ota_main/ota_config.h.example` to `ota_config.h` and fill in Wi-Fi, gateway URL, device token and `GATEWAY_ED25519_PUBKEY` (from `GET /releases/latest/public-key`, field `publicKeyHex`). Without the key the board refuses every update.
- STM32F103: set `GATEWAY_ED25519_PUBKEY` and `DEVICE_ID` at the top of the sketch.
- ATmega328P: set `DEVICE_ID`. No key is needed on the board.
- ESP32: the dashboard writes the key to the board during USB setup (`gateway_key`). A board set up before this change skips S5 and says so in its log until it is set up again.

## The UART link (STM32F103, ATmega328P)

These boards have no network. Wire the board's serial port to a computer or Raspberry Pi and run the link host there:

```
python apps/agent/sota_link.py --port COM7 --gateway http://192.168.1.20:5000 --token <device token>
```

Get the device token from the dashboard (register the device) or `POST /api/devices/register`. The link host only relays: the board hashes every byte it receives and the signature covers that digest, so a link host that alters the image only gets the update rejected.

One request line from the board, one reply line from the host:

| Board sends | Host does | Host replies |
|---|---|---|
| `SOTA:HELLO id=<id> t=<type> v=<version> h=<health> q=<0/1>` | `POST /api/heartbeat` | `SOTA:ACK` |
| `SOTA:MANIFEST?` | `GET /releases/latest/manifest?device_id&device_type` | `SOTA:MANIFEST v= s= i= n= g=`, `SOTA:NONE` or `SOTA:ERR <why>` |
| `SOTA:CHUNK <offset> <length>` | Downloads the image once, then serves it from memory | `SOTA:DATA <offset> <hex>` |
| `SOTA:VERIFY v= s= i= n= g=` | `POST /api/verify/manifest` | `SOTA:VERDICT 1` or `SOTA:VERDICT 0` |
| `SOTA:STATUS <phase> <version>` | `POST /api/devices/<id>/ota/status` | `SOTA:ACK` |
| `# <text>` | Prints it as the board's log | nothing |

Chunks are 64 bytes on the ATmega328P (2 KB of RAM) and 256 bytes on the STM32F103.

### Hardware for the UART boards

- SPI flash (W25Q16 or larger): CS on D8 for the ATmega328P (Moteino layout), PA4 for the STM32F103.
- ATmega328P: install the DualOptiboot bootloader (LowPowerLab). It copies the image from SPI flash into the ATmega on reset. The header (`FLXIMG:` + length + `:`) is written only after S4 and S5 have passed.
- STM32F103: the agent verifies and stages the image behind a `SOTAIMG1` header. A bootloader that copies it into internal flash is still to be written; until then build with `SOTA_STM32_BOOTLOADER 0` (default) and the board reports the image as staged.

## Tests

```
sh firmware/lib/sota_core/test/run.sh                          # C library against vectors signed like the gateway
cd apps/agent && python -m pytest tests                         # UART agent + link host + gateway, end to end
cd apps/gateway && python -m pytest tests/test_manifest_signature.py
```
