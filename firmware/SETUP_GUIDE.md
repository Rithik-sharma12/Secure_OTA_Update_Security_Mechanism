# ESP32 OTA Firmware – Setup & Flash Guide

## Project Structure

```
esp32_ota/
├── esp32_ota_main.ino       # Main firmware source
├── ota_config.h             # ← YOUR SECRETS (add to .gitignore)
├── platformio.ini            # Build & board configuration
└── .github/
    └── workflows/
        └── firmware-release.yml  # Auto-build & release CI
```

---

## Step 1 – Install Tools

### Option A – PlatformIO (recommended)
```bash
pip install platformio
# Installs esptool + compiler automatically on first build
```

### Option B – Arduino IDE 2.x
1. Open **File → Preferences**
2. Add to "Additional boards manager URLs":
   `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`
3. Install **ESP32 by Espressif** from Boards Manager
4. Install library **ArduinoJson** (v7) from Library Manager

---

## Step 2 – Configure Secrets

1. Open `ota_config.h` and fill in Wi-Fi, OTA, backend, and device identity values.
2. Optional secure OTA mode:
  - Set `FIRMWARE_ENC_KEY` (must be exactly 32 characters)
  - Set `FIRMWARE_PUB_KEY` (PEM public key used for signature verification)
  - If these are not configured, firmware automatically falls back to plain OTA package mode.
3. Add to `.gitignore`:
   ```
  ota_config.h
   ```

---

## Step 3 – Build Firmware

### With PlatformIO (CLI)
```bash
cd esp32_ota

# Build only
pio run -e esp32dev

# The compiled binary is at:
# .pio/build/esp32dev/firmware.bin
```

### With Arduino IDE
- Open `esp32_ota_main.ino`
- Select your board: **Tools → Board → ESP32 Arduino → ESP32 Dev Module**
- Click **Sketch → Export Compiled Binary** (creates `*.bin` next to .ino)

---

## Step 4 – Flash via USB / Serial COM Port

This is the first-time flash. After this, all future updates can be OTA.

### Method A – PlatformIO (auto-detects port)
```bash
pio run -e esp32dev --target upload
# Auto-finds your COM port and flashes
```

### Method B – esptool (manual, any OS)
```bash
# Install
pip install esptool

# Windows – replace COM3 with your port (Device Manager → Ports)
esptool.py --chip esp32 --port COM3 --baud 921600 \
  write_flash -z 0x0 firmware.bin

# macOS/Linux – replace /dev/tty.usbserial-XXXX
esptool.py --chip esp32 --port /dev/tty.usbserial-XXXX --baud 921600 \
  write_flash -z 0x0 firmware.bin

# If the device doesn't enter download mode automatically:
# Hold BOOT button → press RESET → release BOOT → run command
```

### Method C – Arduino IDE
- **Tools → Port** – select your COM/tty port
- Click **Upload** (Ctrl+U)

### Method D – From your OTA IDE (Terminal tab)
```bash
# In the OTA IDE built-in terminal:
build firmware-esp32.bin
deploy --port COM3 --method serial
```

---

## Step 5 – Verify the Device is Running

Open Serial Monitor at **115200 baud**:
```
[OTA] Firmware v2.4.0 starting...
[Health] Loaded: score=100 quarantine=0
[WiFi] Connecting to MyNetwork.....
[WiFi] Connected – IP: 10.10.72.15
[OTA] Setup complete
```

Note the **IP address** – you need it for network OTA. (`[ArduinoOTA] Listening
on port 3232` only appears in builds from the `esp32dev_ota` environment.)

---

## Step 6 – Update Over Network (ArduinoOTA, development only)

> **ArduinoOTA skips every security check.** It flashes whatever image it is
> sent: no signature check, no anti-rollback, no quarantine. Its only
> protection is `OTA_PASSWORD`, which is compiled into every board. It is
> therefore compiled in only by the `esp32dev_ota` PlatformIO environment
> (`-DOTA_ENABLE_ARDUINO_OTA=1`). Release builds (`esp32dev`, `esp32s3`,
> `esp32c3`, and the CI release workflow) do not listen on port 3232. Use it
> on a bench board, then reflash a release build before deployment.

### From Arduino IDE
- **Tools → Port** – select the device under "Network ports"
  (shows as `esp32-ota-device-01 at 10.10.72.15`)
- Click **Upload**

### From PlatformIO
Edit `platformio.ini` → update `upload_port` with the device IP:
```ini
[env:esp32dev_ota]
upload_protocol = espota
upload_port     = 10.10.72.15
upload_flags    = --auth=your_ota_password_here
```
Then:
```bash
pio run -e esp32dev_ota --target upload
```

### From OTA IDE Terminal
```bash
deploy --host 10.10.72.15 --method ota --password your_ota_password
```

---

## Step 7 – GitHub Auto-Release (CI/CD)

### One-time setup
1. Push your code to GitHub
2. Add these secrets at: **Settings → Secrets and variables → Actions**
   - `WIFI_SSID`
   - `WIFI_PASSWORD`
   - `OTA_PASSWORD`
  - `BACKEND_URL` (for example, `http://192.168.1.100:5000`)
  - `BACKEND_API_KEY` (optional)
  - `DEVICE_ID` (for telemetry identity)
  - `FIRMWARE_ENC_KEY` (32-character AES key; required for secure package mode)
  - `FIRMWARE_PUB_KEY` (PEM public key, used by device)
  - `FIRMWARE_PRIV_KEY` (PEM private key, used by CI signing step)

### Create a release
```bash
git add -A
git commit -m "feat: add new sensor readings"
git tag v2.5.0
git push origin main --tags
```

GitHub Actions automatically:
1. Builds firmware for esp32, esp32s3, esp32c3
2. Creates a GitHub Release with the `.bin` files attached
3. Devices poll for the new version every 15 minutes and self-update

---

## Manual GitHub OTA Trigger

Hold the **BOOT button for 3 seconds** → device immediately checks GitHub
and downloads any newer release.

---

## Security Build Switches

All default to the safe value. Set them in `ota_config.h` only for bench work.

| Switch | Default | Effect when set to 1 |
|--------|---------|----------------------|
| `OTA_ENABLE_ARDUINO_OTA` | 0 | Listen for unauthenticated-image ArduinoOTA pushes (set by `esp32dev_ota`) |
| `OTA_ALLOW_UNVERSIONED_PACKAGES` | 0 | Accept packages whose signature does not cover the version (v1 and `signature_alg 1`) |
| `OTA_ALLOW_PLAIN_OVER_HTTP` | 0 | Without secure keys, accept a plain image from an `http://` gateway |
| `OTA_ALLOW_INSECURE_TLS` | 0 | Talk to an `https://` gateway without verifying its certificate |
| `OTA_ALLOW_UNVERIFIED_OTA` | 0 | Flash a plain image that has no manifest sha256 |
| `OTA_PROVISIONING_REQUIRES_BUTTON` | 0 | Serial `SOTA:PROVISION` / `SOTA:RESET-CONFIG` only while BOOT is held (for hardened boards) |

### Signed versions and anti-rollback

Secure packages are built by `apps/gateway/gateway/package.py` (through
`tools/create_secure_test_package.py --version X.Y.Z` or the release
workflow). The RSA signature covers the release version as well as the image,
and the device refuses a package whose *signed* version is not newer than its
own `FIRMWARE_VERSION` or differs from the manifest. A gateway, or anyone
answering an `http://` manifest request, therefore cannot roll a board back by
pairing an old signed image with a new version number.

Packages from the old openssl-based workflow (v1, or v2 with
`signature_alg 1`) are refused unless the firmware was built with
`OTA_ALLOW_UNVERSIONED_PACKAGES=1`. Rebuild old packages with the tool, which
needs `--version`.

Versions must be `MAJOR.MINOR.PATCH` with each part 0–999. They are compared
as `major*1000000 + minor*1000 + patch`. The release workflow refuses a tag
that does not match `FIRMWARE_VERSION` in `esp32_ota_main.ino`.

### What the keys protect, and what they don't

* `FIRMWARE_PUB_KEY` (RSA-2048) is what makes an image trustworthy. Keep the
  private key off the gateway host if you can (CI secret, offline machine).
* `FIRMWARE_ENC_KEY` (AES-256) is **one key for the whole fleet**, compiled
  into every board. It keeps the image confidential in transit and at rest on
  the gateway, but anyone who reads one board's flash can decrypt every
  package. It gives no integrity; that is the signature's job.
* Without secure keys, a plain image is checked only against the manifest's
  sha256. That is accepted only from an `https://` gateway with a configured
  `OTA_ROOT_CA`, since over `http://` an attacker on the path can rewrite both.

### Hardening a deployed board

Without these, anyone with physical access can read every secret on the board
(Wi-Fi password, fleet key, device token, AES key) with `esptool read_flash`
and flash any image over USB, bypassing all of the above:

1. **Flash encryption** (release mode) so flash contents cannot be read back.
2. **Secure Boot V2** so the ROM only boots images signed with your secure-boot
   key. This is separate from, and in addition to, the OTA package signature.
3. **Disable UART download mode** (`esp_efuse` / `espefuse.py burn_efuse
   UART_DOWNLOAD_DIS`, or secure download mode), so the USB port cannot be used
   to reflash or dump the chip.
4. Build with `OTA_PROVISIONING_REQUIRES_BUTTON=1`, so the serial provisioning
   protocol cannot silently repoint the board at another gateway.
5. Give every board its own device token (Devices → Provision over USB) and set
   `OTA_REQUIRE_DEVICE_TOKEN=true` on the gateway, then rotate the fleet key off
   the boards.

These are one-way eFuse operations; follow Espressif's *Security Features*
guide for your chip and test on a sacrificial board first.

---

## Health Score Reference

| Event | Score Change |
|-------|-------------|
| Successful OTA update | +10 |
| Successful poll (1/min) | +1 |
| Network error | -1 |
| OTA failure | -25 |
| Score < 40 | Quarantine (OTA disabled) |

A version that fails its post-update health gate is remembered on the board and
not offered again; publish a newer version to retry.

To reset quarantine: power-cycle and send a manual reset from OTA IDE →
Devices → [device] → Reset Quarantine.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Won't enter download mode | Hold BOOT → press RESET → release BOOT |
| `A fatal error occurred: Failed to connect` | Wrong baud rate or port, try 115200 |
| ArduinoOTA not visible in IDE | Ensure device and PC on same Wi-Fi subnet |
| GitHub OTA not triggering | Check BACKEND_URL and release availability from your gateway |
| OTA password rejected | OTA_PASSWORD must match `upload_flags --auth=` |
| Flash too full | Use `pio run -e esp32dev --target upload` with default partition table |
