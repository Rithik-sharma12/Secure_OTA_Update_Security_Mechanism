# Pushing Firmware to an ESP32 from the Web Dashboard

How to flash an ESP32 once over USB, then push every future update from the
browser with no cable attached.

---

## How it works

The device is never pushed to directly. It **polls** the gateway, which is why
this works over Wi-Fi, behind NAT, and with the device on battery:

```
  Browser                Gateway                    ESP32
     |                      |                         |
     |  upload .bin ------->|                         |
     |                      | sign manifest (Ed25519) |
     |                      |<---- poll manifest -----|   every 30 s
     |                      |----- v2.5.0 available ->|
     |                      |<---- download .bin -----|
     |                      |                         | verify + flash + reboot
     |                      |<---- heartbeat v2.5.0 --|
```

The dashboard shows the new version arriving on the device a few seconds after
you publish.

---

## One-time setup

### 1. Point the gateway at an address the ESP32 can reach

This is the step that most often gets missed. The manifest handed to the device
contains a download URL built from `OTA_LOCAL_URL` (local mode). If that says
`localhost`, the ESP32 will try to download from *itself* and every update will
fail.

Find your PC's LAN IP (`ipconfig` on Windows — look for IPv4 Address, e.g.
`192.168.1.20`), then edit `.env.docker`:

```bash
OTA_LOCAL_URL=http://192.168.1.20:5000
```

Restart so the gateway picks it up:

```bash
docker compose --env-file ./Secure_OTA_Update_Security_Mechanism/.env.docker up -d gateway
```

Confirm the URL the device will actually be given:

```bash
curl -s http://localhost:5000/releases/latest/manifest
```

The `downloadUrl` field must show your LAN IP, not `localhost`.

> Your PC firewall must allow inbound TCP on port 5000, or the ESP32's download
> will time out even with the correct IP.

### 2. Fill in the device config

Edit `CODE/frimware_code/esp32_ota_main/ota_config.h`:

```c
#define WIFI_SSID       "your-wifi"
#define WIFI_PASSWORD   "your-wifi-password"
#define OTA_PASSWORD    "pick-an-ota-password"
#define DEVICE_HOSTNAME "esp32-ota-device-01"

#define BACKEND_URL     "http://192.168.1.20:5000"   // same LAN IP as above
#define DEVICE_ID       "ESP32_DEVICE_001"
#define DEVICE_TYPE     "ESP32"
#define BACKEND_API_KEY "sentinel_ota_secure_gateway_key_2026"  // OTA_GATEWAY_API_KEY

#define OTA_CHECK_INTERVAL_SECONDS 30   // how fast a publish reaches the device
```

The ESP32 and your PC must be on the **same Wi-Fi network**.

### 3. Flash once over USB

This first flash is the only one that needs a cable.

```bash
cd CODE/frimware_code
pio run -e esp32dev --target upload
pio device monitor          # watch it join Wi-Fi and start polling
```

You should see the device appear in the dashboard under **Devices**, and its
heartbeats arrive in the gateway log.

---

## Publishing an update (the repeatable loop)

### Step 1 — Bump the version in the firmware

In `esp32_ota_main.ino`, raise **both** lines together:

```c
#define FIRMWARE_VERSION    "2.5.0"
#define FIRMWARE_VERSION_N  20500   // major*10000 + minor*100 + patch
```

This matters: the device compares `FIRMWARE_VERSION_N` against the published
version and **refuses anything not strictly newer** (anti-rollback). Publishing
a version equal to or below what's running is a no-op.

### Step 2 — Build the binary (don't upload)

```bash
cd CODE/frimware_code
pio run -e esp32dev
```

The artifact you need is:

```
CODE/frimware_code/.pio/build/esp32dev/firmware.bin
```

*Arduino IDE instead of PlatformIO?* Use **Sketch → Export Compiled Binary**,
then take the `.bin` from the sketch folder.

### Step 3 — Publish it from the dashboard

1. Open <http://localhost:3000> and log in.
2. Go to **Releases**.
3. In **Publish Firmware Update**, choose your `firmware.bin`.
4. Set the **Version** to match Step 1 (e.g. `2.5.0`). If the filename contains
   a version, it's filled in for you.
5. Add a changelog, pick the target device types, and press **Publish Release**.

On success the card shows the published version, size, and SHA-256, and the new
release appears in the list below.

### Step 4 — Watch the device take it

Within `OTA_CHECK_INTERVAL_SECONDS` (default 30) the device downloads, verifies,
flashes, and reboots. On the serial monitor:

```
[Backend] Checking for firmware update...
[Backend] Current v2.4.1 (20401), Remote 2.5.0 (20500)
[Backend] Update available: http://192.168.1.20:5000/releases/download/firmware_v2.5.0.bin
[Update] Plain OTA 100%
[Backend] Update successful. Rebooting.
```

The dashboard's **Devices** panel then reports the device on the new version.

That's the whole loop: **bump → build → publish → done.** No cable after the
first flash.

---

## Enabling signature-verified updates (optional)

Out of the box the device uses the plain OTA path: it checks the size, but not a
signature. The gateway *always* Ed25519-signs the manifest, and the firmware can
additionally verify an encrypted, RSA-signed package.

To turn that on, set both values in `ota_config.h`:

- `FIRMWARE_ENC_KEY` — exactly 32 bytes (AES-256).
- `FIRMWARE_PUB_KEY` — your RSA-2048 public key in PEM form.

The firmware enables secure mode only when **both** are present
(`isSecureOtaConfigured()`); otherwise it falls back to plain OTA. Build secure
packages with `CODE/frimware_code/tools/create_secure_test_package.py`.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Failed to check manifest: 404` | No release published yet. Normal on a fresh gateway — publish one. |
| Device never updates, no serial errors | Published version isn't higher than the running one. Anti-rollback blocked it — bump `FIRMWARE_VERSION_N`. |
| `Secure package GET failed` / download times out | `OTA_LOCAL_URL` still points at `localhost`, or the firewall blocks port 5000. |
| `Release 2.5.0 already exists` (409) | Versions are immutable. Publish a new version number. |
| Publish returns 401 | Dashboard session expired — log in again. |
| Publish returns 502 | The dashboard can't reach the gateway. Check `docker compose ps` and `EDGE_GATEWAY_URL`. |
| Device shows `Quarantined` | ASH score fell below 40 after repeated failures. It stops taking updates until the score recovers to 100. |

### Verifying the server side without hardware

This is a production deployment: there is no device simulator, and every device
in the dashboard is real. To check the gateway half of the pipeline after a
publish, inspect what a device would be served:

```bash
# the manifest a device receives — downloadUrl must be your LAN IP/domain
curl -s http://localhost:5000/releases/latest/manifest

# the firmware itself must be downloadable at that address
curl -sI http://<your-lan-ip>:5000/releases/download/firmware_v2.5.0.bin
```

If both succeed and `downloadUrl` is routable from the device network, the
server side is correct and any remaining failure is on the device (Wi-Fi
credentials, `BACKEND_URL`, or firewall).
