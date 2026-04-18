# FINAL RUN: End-to-End Secure OTA Demo

This runbook gives a full demo path for this project from firmware development to secure signing, GitHub release publishing, gateway import, OTA device update, and proof that the system is working.

It is written for Windows PowerShell and the current repository layout.

## 1. What This Demo Proves

After finishing this document, you will have shown:

1. Firmware is developed and versioned correctly.
2. Firmware is signed by developer keys for secure OTA package validation.
3. Firmware release is published from GitHub.
4. Gateway imports the release and exposes manifest and download endpoints.
5. ESP32 pulls the update over the air and reboots to new firmware.
6. Runtime APIs and smoke tests confirm the system is healthy.

## 2. Important Security Model (Read First)

This project uses two different signature layers:

1. Gateway manifest signature
   - Algorithm: Ed25519 (gateway runtime signing).
   - Purpose: release metadata integrity on gateway APIs.

2. Device firmware package signature
   - Algorithm: RSA SHA-256 signature + AES-256-CBC encrypted payload.
   - Purpose: what ESP32 secure OTA path verifies before flashing.

For secure device flashing, you must provide RSA key material and a 32-character AES key in firmware config and release signing.

## 3. Prerequisites

Install these tools:

- Node.js 20+
- pnpm
- Python 3.10+
- PlatformIO
- OpenSSL
- Git
- Optional: GitHub CLI (gh) for release asset download

Repository root used in this guide:

```powershell
Set-Location C:\Users\Rithik Sharma\Desktop\OTA_IOT
```

## 4. Start Gateway and OTA IDE

### 4.1 Start gateway backend

```powershell
Set-Location .\src\implementation
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Optional but recommended for write API protection
$env:OTA_GATEWAY_API_KEY = "CHANGE_ME_STRONG_GATEWAY_KEY"

uvicorn edge_gateway:app --host 0.0.0.0 --port 5000
```

Keep this terminal running.

### 4.2 Start OTA IDE

Open a new terminal:

```powershell
Set-Location C:\Users\Rithik Sharma\Desktop\OTA_IOT\CODE\OTA_IDE
Copy-Item .env.example .env.local -Force

# Edit .env.local values before running:
# OTA_ADMIN_USERNAME
# OTA_ADMIN_PASSWORD
# EDGE_GATEWAY_URL=http://127.0.0.1:5000
# EDGE_GATEWAY_API_KEY=<same as OTA_GATEWAY_API_KEY>

pnpm install
pnpm dev
```

UI URL:

- http://localhost:3000

Gateway health URL:

- http://127.0.0.1:5000/healthz

## 5. Firmware Development Step

### 5.1 Edit firmware and bump version

Update the firmware code at:

- CODE/frimware_code/esp32_ota_main/esp32_ota_main.ino

Set both fields together:

```cpp
#define FIRMWARE_VERSION    "2.4.2"
#define FIRMWARE_VERSION_N  20402
```

Rule:

- version_n = major*10000 + minor*100 + patch

### 5.2 Configure firmware runtime connection

Edit:

- CODE/frimware_code/esp32_ota_main/ota_config.h

Set at least:

- WIFI_SSID
- WIFI_PASSWORD
- BACKEND_URL (gateway URL reachable by ESP32)
- BACKEND_API_KEY (match gateway API key if enforced)
- DEVICE_ID

### 5.3 Build firmware

```powershell
Set-Location C:\Users\Rithik Sharma\Desktop\OTA_IOT\CODE\frimware_code
pio run -e esp32dev
```

Expected build output:

- CODE/frimware_code/.pio/build/esp32dev/firmware.bin

## 6. Developer Signature Setup (Secure OTA Package)

If you already have developer keys, use them. Otherwise create a demo keypair.

### 6.1 Generate RSA signing keys (one-time)

```powershell
Set-Location C:\Users\Rithik Sharma\Desktop\OTA_IOT\CODE\frimware_code\release-assets

openssl genrsa -out dev_sign_private.pem 2048
openssl rsa -in dev_sign_private.pem -pubout -out dev_sign_public.pem
```

### 6.2 Configure firmware secure keys

In CODE/frimware_code/esp32_ota_main/ota_config.h:

1. Set FIRMWARE_ENC_KEY to exactly 32 characters.
2. Copy PEM public key contents from dev_sign_public.pem into FIRMWARE_PUB_KEY.

Example AES key requirement:

- Exactly 32 ASCII characters.
- Same key must be used when encrypting release artifact.

### 6.3 Produce secure package locally (RSA sign + AES encrypt)

```powershell
Set-Location C:\Users\Rithik Sharma\Desktop\OTA_IOT

$Version = "2.4.2"
$BuildBin = "C:\Users\Rithik Sharma\Desktop\OTA_IOT\CODE\frimware_code\.pio\build\esp32dev\firmware.bin"
$OutDir = "C:\Users\Rithik Sharma\Desktop\OTA_IOT\CODE\frimware_code\release-assets"
$PrivKey = Join-Path $OutDir "dev_sign_private.pem"
$AesKey = "REPLACE_WITH_EXACTLY_32_CHARS_KEY"

if ($AesKey.Length -ne 32) { throw "Aes key must be exactly 32 characters." }

$AesKeyHex = -join ([System.Text.Encoding]::ASCII.GetBytes($AesKey) | ForEach-Object { $_.ToString("x2") })
$IvHex = (& openssl rand -hex 16).Trim()

& openssl dgst -sha256 -sign $PrivKey -out (Join-Path $OutDir "firmware.sig") $BuildBin
& openssl enc -aes-256-cbc -in $BuildBin -out (Join-Path $OutDir "firmware.enc") -K $AesKeyHex -iv $IvHex

$IvBytes = for ($i = 0; $i -lt $IvHex.Length; $i += 2) { [Convert]::ToByte($IvHex.Substring($i, 2), 16) }
[IO.File]::WriteAllBytes((Join-Path $OutDir "firmware.iv"), [byte[]]$IvBytes)

$securePayload = New-Object System.Collections.Generic.List[byte]
$securePayload.AddRange([IO.File]::ReadAllBytes((Join-Path $OutDir "firmware.iv")))
$securePayload.AddRange([IO.File]::ReadAllBytes((Join-Path $OutDir "firmware.sig")))
$securePayload.AddRange([IO.File]::ReadAllBytes((Join-Path $OutDir "firmware.enc")))

$SecureBin = Join-Path $OutDir "firmware-esp32-secure-test.bin"
[IO.File]::WriteAllBytes($SecureBin, $securePayload.ToArray())

Write-Host "Secure package created: $SecureBin"
```

Secure package format produced above matches firmware parser expectations:

- 16-byte IV
- 256-byte RSA signature
- encrypted firmware payload

## 7. GitHub Release Pipeline (Build + Sign + Publish)

This repo currently stores workflow content at:

- CODE/frimware_code/firmware-release.yml

GitHub Actions only runs files under .github/workflows, so copy it first.

### 7.1 Activate workflow path

```powershell
Set-Location C:\Users\Rithik Sharma\Desktop\OTA_IOT
New-Item -ItemType Directory -Path .github\workflows -Force | Out-Null
Copy-Item .\CODE\frimware_code\firmware-release.yml .\.github\workflows\firmware-release.yml -Force
```

### 7.2 Configure GitHub secrets

In GitHub repository settings, add:

- WIFI_SSID
- WIFI_PASSWORD
- OTA_PASSWORD
- BACKEND_URL
- BACKEND_API_KEY
- DEVICE_ID
- FIRMWARE_ENC_KEY
- FIRMWARE_PUB_KEY
- FIRMWARE_PRIV_KEY

Notes:

- FIRMWARE_ENC_KEY must be exactly 32 characters.
- FIRMWARE_PUB_KEY must match FIRMWARE_PRIV_KEY.
- Firmware device public key in ota_config.h must match the private key used for signing.

### 7.3 Push code and tag release

```powershell
Set-Location C:\Users\Rithik Sharma\Desktop\OTA_IOT
git add -A
git commit -m "demo: secure ota release v2.4.2"
git tag v2.4.2
git push origin main
git push origin v2.4.2
```

Expected:

- GitHub workflow runs.
- Release assets appear in GitHub Release v2.4.2.

## 8. Pull Signed Firmware From GitHub and Publish to Gateway

Device does not pull directly from GitHub in this architecture.

Actual flow is:

- GitHub Release -> gateway import -> gateway manifest endpoint -> device pull OTA

### 8.1 Download release asset from GitHub

```powershell
Set-Location C:\Users\Rithik Sharma\Desktop\OTA_IOT

$Repo = "Rithik-sharma12/Secure_OTA_Update_Security_Mechanism"
$Tag = "v2.4.2"
$DownloadDir = "C:\Users\Rithik Sharma\Desktop\OTA_IOT\CODE\frimware_code\release-assets\github-v2.4.2"
New-Item -ItemType Directory -Path $DownloadDir -Force | Out-Null

# Requires GitHub CLI login
gh auth login
gh release download $Tag --repo $Repo --pattern "firmware-esp32-*.bin" --dir $DownloadDir
```

### 8.2 Create gateway release from downloaded asset

```powershell
$Gateway = "http://127.0.0.1:5000"
$GatewayApiKey = "CHANGE_ME_STRONG_GATEWAY_KEY"

$SourceBin = (Get-ChildItem $DownloadDir -Filter "firmware-esp32-*.bin" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName

$Body = @{
  version = "2.4.2"
  description = "GitHub signed release import"
  changelog = "End-to-end secure OTA demo"
  compatible = @("ESP32")
  sourceFilePath = $SourceBin
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method Post -Uri "$Gateway/api/releases" -Headers @{ "x-api-key" = $GatewayApiKey } -ContentType "application/json" -Body $Body
```

Now gateway publishes:

- GET /releases/latest/manifest
- GET /releases/download/{filename}

## 9. Prepare Device for OTA Update Demo

### 9.1 First flash over USB

Flash baseline firmware by serial once.

```powershell
Set-Location C:\Users\Rithik Sharma\Desktop\OTA_IOT\CODE\frimware_code
pio run -e esp32dev --target upload
pio device monitor -b 115200
```

### 9.2 Ensure update condition is valid

To show update in demo, device version must be lower than release version.

Example:

- Device running 2.4.1
- Gateway latest manifest version 2.4.2

### 9.3 Trigger OTA check

Either:

- wait scheduled poll interval, or
- hold BOOT button for 3 seconds for manual check.

Expected serial path:

1. Backend check starts.
2. Newer version detected.
3. Secure package attempted (if keys configured).
4. Update succeeds and board reboots.

## 10. Verify System Is Working

Use all checks below as demo acceptance criteria.

### 10.1 Gateway manifest and latest release check

```powershell
$latest = Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/releases/latest"
$latest.release.version
$latest.manifest.version
```

Expected: both show your demo release version.

### 10.2 Manifest checksum integrity check

```powershell
$manifest = Invoke-RestMethod -Uri "http://127.0.0.1:5000/releases/latest/manifest"
$file = Join-Path $env:TEMP $manifest.filename
Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:5000/releases/download/$($manifest.filename)" -OutFile $file

$actual = (Get-FileHash -Path $file -Algorithm SHA256).Hash.ToLower()
"Expected: $($manifest.sha256)"
"Actual  : $actual"
"Match   : $($actual -eq $manifest.sha256)"
```

Expected: Match True.

### 10.3 Heartbeat decision check (before and after update)

```powershell
# Before update (old version): expect update_available
$oldPayload = @{
  device_id = "ESP32_DEMO_OLD"
  device_type = "ESP32"
  current_version = "2.4.1"
  ash_score = 95
  status = "Healthy"
} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:5000/api/heartbeat" -Body $oldPayload -ContentType "application/json"

# After update (new version): expect ack
$newPayload = @{
  device_id = "ESP32_DEMO_NEW"
  device_type = "ESP32"
  current_version = "2.4.2"
  ash_score = 95
  status = "Healthy"
} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:5000/api/heartbeat" -Body $newPayload -ContentType "application/json"
```

Expected:

- Old version heartbeat returns command update_available.
- New version heartbeat returns command ack.

### 10.4 Full integration smoke test

```powershell
Set-Location C:\Users\Rithik Sharma\Desktop\OTA_IOT\src\implementation

$env:OTA_TEST_ADMIN_USERNAME = "your-admin-user"
$env:OTA_TEST_ADMIN_PASSWORD = "your-admin-password"
$env:OTA_GATEWAY_API_KEY = "CHANGE_ME_STRONG_GATEWAY_KEY"
$env:OTA_TEST_FIRMWARE_PATH = "C:\Users\Rithik Sharma\Desktop\OTA_IOT\CODE\frimware_code\.pio\build\esp32dev\firmware.bin"

python integration_smoke_test.py
```

Expected final output:

- Integration smoke test passed: backend, frontend APIs, and auth middleware are connected.

## 11. Quick Demo Script (Presentation Order)

Use this order in viva or final demo:

1. Show code change and version bump in esp32_ota_main.ino.
2. Build firmware with pio run -e esp32dev.
3. Show signing step (local secure package or GitHub workflow).
4. Show GitHub Release asset exists.
5. Pull release asset and publish to gateway /api/releases.
6. Open /releases/latest/manifest and show new version.
7. Trigger ESP32 OTA check.
8. Show serial logs for update and reboot.
9. Show heartbeat command now returns ack on updated version.
10. Run integration_smoke_test.py and show pass output.

## 12. Pass or Fail Criteria

Demo is PASS only if all are true:

1. Firmware build succeeds.
2. Signed package is created (or GitHub signing step succeeds).
3. Gateway release create API succeeds for target version.
4. Manifest version equals release version.
5. Downloaded artifact hash matches manifest hash.
6. Device updates over OTA and reboots.
7. Post-update heartbeat returns ack.
8. Integration smoke test passes.

## 13. Common Failure Fixes

1. Release creation fails with missing artifact
   - Provide sourceFilePath in POST /api/releases or set OTA_GATEWAY_RELEASE_ARTIFACT.

2. Secure OTA fails then falls back
   - Verify FIRMWARE_PUB_KEY matches private signing key.
   - Verify FIRMWARE_ENC_KEY is exactly 32 chars and identical in pack step.

3. Device never updates
   - Confirm BACKEND_URL reachable from ESP32 network.
   - Confirm manifest version is higher than current firmware version.

4. 401 from gateway write APIs
   - Use correct OTA_GATEWAY_API_KEY in x-api-key header.

5. OTA IDE cannot sync runtime snapshot
   - Check EDGE_GATEWAY_URL and EDGE_GATEWAY_API_KEY in CODE/OTA_IDE/.env.local.

---

End of full demo runbook.