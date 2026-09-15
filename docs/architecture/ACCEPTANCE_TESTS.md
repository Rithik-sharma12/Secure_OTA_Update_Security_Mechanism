# SecureOTA — Acceptance Test Checklist

Executable verification for every item in `BACKEND_AUDIT.md`. Nothing here modifies the system under test.

**Automated suite:** `.\acceptance-test.ps1` — 40 checks, no admin rights needed.
**Last executed result:** 31 PASS · 9 FAIL (expected) · 0 unexpected.

```powershell
cd docs\architecture
.\acceptance-test.ps1              # run everything, then tear down
.\acceptance-test.ps1 -KeepRunning # leave the gateway up for manual poking
```

The suite starts an **isolated** gateway (port 5099, scratch cache and scratch keys). Your real `gateway_keys/`, `gateway_firmware_cache/` and `.env.docker` are never touched.

**Reading the results**

| Tag | Meaning |
|---|---|
| `PASS` | Control verified working |
| `FAIL (expected)` | A known audit gap. **Each must become PASS after remediation — that is the acceptance criterion for the fix.** |
| `FAIL` | A control the audit found working has broken. Regression — investigate immediately. |

---

## Part 1 — Manual harness

To run individual commands, start the gateway yourself:

```powershell
$env:OTA_GATEWAY_CACHE_DIR  = "$env:TEMP\ota-test-cache"
$env:OTA_GATEWAY_KEYS_DIR   = "$env:TEMP\ota-test-keys"
$env:OTA_GATEWAY_API_KEY    = "test-key-123"
$env:OTA_GATEWAY_PUBLIC_URL = "http://127.0.0.1:5099"
cd src\implementation
python -m uvicorn gateway:app --host 127.0.0.1 --port 5099
```

Helper for status codes (PowerShell throws on 4xx, which is the usual trap):

```powershell
function St($u,$m='GET',$b,$h=@{}) {
  try { $p=@{Uri=$u;Method=$m;Headers=$h;UseBasicParsing=$true;TimeoutSec=15}
        if($b){$p.Body=$b;$p.ContentType='application/json'}
        (Invoke-WebRequest @p).StatusCode }
  catch { if($_.Exception.Response){[int]$_.Exception.Response.StatusCode}else{'ERR'} } }
```

---

## Part 2 — ✅ IMPLEMENTED AND VERIFIED

Run these to confirm the controls the audit found working.

### AT-1 · Service architecture

```powershell
St http://127.0.0.1:5099/healthz        # expect 200
St http://127.0.0.1:5099/openapi.json   # expect 200
St http://127.0.0.1:5099/docs           # expect 200
```
**Pass:** all 200. `/healthz` body contains `deviceCount` and `releaseCount`.

### AT-2 · Write authentication — `gateway/auth.py`

```powershell
St http://127.0.0.1:5099/api/trigger_sync POST                       # expect 401
St http://127.0.0.1:5099/api/trigger_sync POST $null @{'x-api-key'='wrong'}       # expect 401
St http://127.0.0.1:5099/api/trigger_sync POST $null @{'x-api-key'='test-key-123'} # expect 200
St http://127.0.0.1:5099/api/deployments POST '{}'                   # expect 401
St http://127.0.0.1:5099/api/releases/upload POST                    # expect 401
St http://127.0.0.1:5099/api/pipeline/run POST                       # expect 401
```
**Pass:** 401 without/with wrong key on every write endpoint; 200 with the valid key.
**Why it matters:** confirms `Depends(require_write_auth)` binds the real guard. An earlier design used a per-module placeholder reassigned at app construction, which silently left every write endpoint open.

### AT-4 · OTA policy enforcement

```powershell
# publish a release targeting ESP32 first (see AT-7 helper), then:
St "http://127.0.0.1:5099/releases/latest/manifest?device_type=ESP32"    # expect 200
St "http://127.0.0.1:5099/releases/latest/manifest?device_type=ESP8266"  # expect 404

$hb='{"device_id":"T1","device_type":"ESP32","current_version":"9.9.9","ash_score":100}'
(Invoke-RestMethod http://127.0.0.1:5099/api/heartbeat -Method POST -Body $hb -ContentType 'application/json').command
# expect: ack               (device newer than release - no downgrade offered)

$hb='{"device_id":"T2","device_type":"ESP32","current_version":"1.0.0","ash_score":100}'
# expect: update_available

$hb='{"device_id":"T3","device_type":"ESP32","current_version":"1.0.0","ash_score":10}'
# expect: ack               (quarantined - update withheld)
```
**Pass:** 200 / 404 / `ack` / `update_available` / `ack` respectively.
**Why it matters:** AT-4.2 is what stops an ESP32 image being written to an ESP8266, which would permanently brick it.

### AT-5 · Cryptography — signature is genuine, not a placeholder

```powershell
python - <<'PY'
import urllib.request, json, base64, hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
b='http://127.0.0.1:5099'
m=json.load(urllib.request.urlopen(b+'/releases/latest/manifest?device_type=ESP32'))
pk=json.load(urllib.request.urlopen(b+'/releases/latest/public-key'))
blob=urllib.request.urlopen(b+'/releases/download/'+m['filename']).read()
pub=serialization.load_pem_public_key(pk['publicKeyPem'].encode())
print('sha256 match      :', hashlib.sha256(blob).hexdigest()==m['sha256'])
try: pub.verify(base64.b64decode(m['signature']), blob); print('signature verifies: True')
except InvalidSignature: print('signature verifies: False  <-- FAKE')
try: pub.verify(base64.b64decode(m['signature']), blob[:-1]+bytes([blob[-1]^1])); print('tampered accepted : True  <-- BROKEN')
except InvalidSignature: print('tampered rejected : True')
PY
```
**Pass:** `sha256 match: True`, `signature verifies: True`, `tampered rejected: True`.
**Why it matters:** proves authenticity, not just integrity. SHA-256 alone would be recomputable by an attacker.

### AT-6 · Input validation

```powershell
St http://127.0.0.1:5099/releases/download/../../../../etc/passwd        # expect 404
St http://127.0.0.1:5099/releases/download/..%2f..%2f..%2fetc%2fpasswd   # expect 404
St http://127.0.0.1:5099/api/heartbeat POST '{"device_type":"ESP32"}'    # expect 400 (no device_id)
St http://127.0.0.1:5099/api/heartbeat POST ('{"device_id":"'+('A'*500)+'"}')  # expect 400
St http://127.0.0.1:5099/api/heartbeat POST '{ broken'                   # expect 422
```
Then confirm clamping — send `ash_score: 99999` and `-500`, and check `/api/dashboard` shows `100` and `0`.

### AT-7 · Firmware upload validation

Upload helper:

```powershell
function Up($ver,$name,$path) {
@"
import urllib.request
b='http://127.0.0.1:5099'; k='test-key-123'
data=open(r'$path','rb').read(); bnd='----x'; nl='\r\n'
def p(n,v): return f'--{bnd}{nl}Content-Disposition: form-data; name="{n}"{nl}{nl}{v}{nl}'
body=(p('version','$ver')+p('compatible','ESP32')).encode()
body+=f'--{bnd}{nl}Content-Disposition: form-data; name="file"; filename="$name"{nl}Content-Type: application/octet-stream{nl}{nl}'.encode()
body+=data+f'{nl}--{bnd}--{nl}'.encode()
r=urllib.request.Request(b+'/api/releases/upload',data=body,headers={'x-api-key':k,'Content-Type':f'multipart/form-data; boundary={bnd}'})
try: urllib.request.urlopen(r,timeout=60); print(200)
except urllib.error.HTTPError as e: print(e.code)
"@ | python - }

Up '1.0.0' 'ok.bin'   'C:\path\to\any.bin'   # expect 200
Up '1.0.1' 'evil.txt' 'C:\path\to\any.txt'   # expect 400
Up '1.0.0' 'dup.bin'  'C:\path\to\any.bin'   # expect 409
Up 'abc'   'v.bin'    'C:\path\to\any.bin'   # expect 400
```
For the size cap, create a 33 MB file and expect **413**.

### AT-9 · Persistence and concurrency

State file exists at `$env:OTA_GATEWAY_CACHE_DIR\gateway_state.json` after any heartbeat. For load, run AT-9.2 in the automated suite.

**Observed:** 200/200 succeeded. Throughput varies with fleet size — **218 req/s on an empty registry, 112 req/s once 61 devices were loaded.** That degradation is the whole-file rewrite in `persist_state_locked()` and is the measured basis for the ~100-device ceiling.

---

## Part 3 — ⚠️ IMPLEMENTED BUT NOT VERIFIED

These have code but were not exercised. Procedures to verify them yourself.

### AT-D1 · Dashboard operator authentication

```powershell
cd CODE\OTA_IDE
pnpm dev
```
Then:
1. `POST http://localhost:3000/api/auth/login` with the correct username/password → expect a session cookie.
2. Same with a wrong password → expect 401.
3. Call a protected route with **no** cookie → expect 401.
4. Call it with a **tampered** cookie value → expect 401.
5. `POST /api/auth/logout`, then reuse the old cookie → expect 401.

**Pass:** 1 succeeds, 2–5 all rejected.
**Files:** `lib/auth.ts` (`loginWithPassword`, `authenticateRequest`, `revokeRequestToken`), `lib/api-security.ts`.

### AT-D2 · Serial flash with WiFi provisioning ⚠️ HARDWARE REQUIRED

1. Connect an ESP32 by USB. Open the dashboard Serial tab.
2. Confirm the COM port is auto-detected.
3. Confirm **WiFi Network / WiFi Password fields appear** for ESP32, and **disappear** when the board is switched to ATmega328P.
4. Click Flash with the SSID blank → expect it to be blocked with "WiFi network missing".
5. Enter a real SSID/password, flash, and watch the job log for `Configuring WiFi for SSID "<name>"` — **the password must never appear in the log.**
6. After flashing, confirm the temp workspace under `%TEMP%\ota-flash-*` has been deleted.
7. Confirm the device joins WiFi and a heartbeat reaches the gateway.

**Files:** `lib/serial-upload-jobs.ts` (`prepareFlashWorkspace`, `replaceDefine`), `components/devices/DeviceConnectionCard.tsx`.

### AT-D3 · Device-side secure OTA install ⚠️ HARDWARE REQUIRED

1. Flash firmware v1.0.0 with `FIRMWARE_ENC_KEY` and `FIRMWARE_PUB_KEY` populated.
2. Publish a signed, encrypted v1.1.0.
3. Watch the serial monitor for: `Secure OTA configuration detected` → block progress → `Signature verified` → reboot.
4. Confirm the device reports v1.1.0 on its next heartbeat.

**Then the negative test — this is the important one:** corrupt one byte of the `.bin` after signing, republish, and confirm the serial log shows `ERROR: Signature verification failed` and the device **stays on v1.0.0**.

**Files:** `esp32_ota_main.ino:445-656`.

---

## Part 4 — ❌ FAILED TESTS: root cause, impact, fix, verification

Nine known gaps. Each maps to one `FAIL (expected)` in the suite.

---

### F-1 · AT-3.1 / AT-3.2 / AT-3.3 — No device identity → forged deployment confirmation

**1. Root cause**
`POST /api/heartbeat` declares no auth dependency. Every other write route uses `Depends(require_write_auth)`; this one does not. The handler then *creates* a device record for any `device_id` it has never seen, and calls `confirm_device_version_locked()`, which resolves pending deployment targets purely on the reported version string.

**2. Exact file / function**
- `src/implementation/gateway/routes/heartbeat.py:36` — `receive_heartbeat(payload: dict)`, no `Depends`
- `src/implementation/gateway/routes/heartbeat.py:59-96` — implicit device creation
- `src/implementation/gateway/deployment.py:205` — `confirm_device_version_locked()`
- Absent: any `routes/devices.py`

**3. Impact — CRITICAL**
Anyone who can reach the gateway can (a) invent arbitrary devices, (b) poison the registry, (c) **mark a deployment successful that never occurred**, and (d) suppress a real device's update by reporting a high version on its behalf. The fleet compliance record — the thing an operator uses to decide whether a rollout worked — is forgeable. Reproduced in AT-3.3.

**4. Fix required**
1. Derive `DEVICE_ID` from the eFuse MAC at runtime instead of the `#define`.
2. Add `POST /api/devices/register`, validating a bootstrap credential, issuing a per-device token, storing only `token_hash`.
3. Persist the token in NVS on the device.
4. Guard `/api/heartbeat` with a token dependency; reject unknown or revoked tokens.
5. Roll out behind `OTA_REQUIRE_DEVICE_AUTH` so fielded devices are not stranded mid-migration.

**5. Test after fix**
`AT-3.1`, `AT-3.2`, `AT-3.3` must all flip to **PASS**. Additionally, by hand: a registered device with its real token still heartbeats successfully (200), and the same request with the token altered by one character returns 401.

---

### F-2 · No rollback — a failed update bricks the device

*(Not in the automated suite — hardware only.)*

**1. Root cause**
`CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y` is set, so the bootloader supports trial boots. But `initArduino()` calls `esp_ota_mark_app_valid_cancel_rollback()` **before `setup()`**, gated on two weak symbols. The sketch overrides neither, so the image is confirmed valid before WiFi is attempted.

**2. Exact file / function**
- `framework-arduinoespressif32/cores/esp32/esp32-hal-misc.c:222-239` — `initArduino()`
- `esp32-hal-misc.c:204-208` — weak `verifyOta()` / `verifyRollbackLater()`
- `CODE/frimware_code/esp32_ota_main/esp32_ota_main.ino` — overrides neither

**3. Impact — CRITICAL**
A new firmware that boots but cannot join WiFi, crashes in `loop()`, or cannot reach the gateway will be selected by the bootloader forever. Recovery requires physical USB access to every affected board. Because updates are fleet-wide, one bad release can brick every device simultaneously.

**4. Fix required**
1. Add `bool verifyRollbackLater() { return true; }` to the sketch.
2. `#include "esp_ota_ops.h"`.
3. Define the health check: WiFi associated **and** heartbeat returned 2xx **and** ASH above quarantine, within a deadline.
4. On pass → `esp_ota_mark_app_valid_cancel_rollback()`. On fail → `esp_ota_mark_app_invalid_rollback_and_reboot()`.
5. Arm a hardware watchdog so a hang forces the reset that triggers bootloader fallback.

**5. Test after fix ⚠️ HARDWARE REQUIRED**
1. Flash good firmware v1.0.0; confirm heartbeat.
2. Build v1.1.0 with a deliberately wrong WiFi password.
3. Publish and deploy it.
4. Watch serial: device reboots into v1.1.0, fails to associate, logs the rollback, reboots again.
5. **Accept only if** the device comes back reporting **v1.0.0** with no human intervention, and the deployment target moves to `failed`/`ROLLED_BACK`.
6. Repeat with a firmware that hangs in `setup()` — the watchdog path must produce the same outcome.

---

### F-3 · AT-11.1 — Ed25519 private key committed to git

**1. Root cause** Key generated inside the repo tree before `.gitignore` existed; gitignore does not apply retroactively to tracked files.

**2. Exact file** `gateway_keys/ed25519_private_key.pem`, introduced in commit `367720b`, reachable from `origin/main`.

**3. Impact — CRITICAL** Anyone with repo access can forge manifests that the gateway would serve as authentic. Note the currently-live key at `src/implementation/gateway_keys/` differs, so the active signing path may be intact — **verify which key was ever in production before assuming the blast radius is small.**

**4. Fix required**
1. Confirm whether the exposed key was ever live.
2. Generate a replacement; re-provision devices carrying the old public key.
3. `git rm --cached`, commit, then purge with `git filter-repo` (or BFG) and force-push.
4. Notify anyone who cloned — history rewrite invalidates their copies.

**5. Test after fix** `AT-11.1` → PASS. Also `git log --all -- gateway_keys/ed25519_private_key.pem` returns nothing, and `git cat-file -e HEAD:gateway_keys/ed25519_private_key.pem` fails.

---

### F-4 · Authorization declared but never enforced

*(Not automatable against the gateway — the role model lives in the dashboard.)*

**1. Root cause** `role: 'admin' | 'operator' | 'viewer'` is stored and typed, but no code path ever compares it. `withSecureApi` exposes only `requireAuth`.

**2. Exact file / function** `CODE/OTA_IDE/lib/api-security.ts:12-32` (`SecureApiOptions`), `lib/local-database.ts:16`, `lib/client-auth.ts:7`.

**3. Impact — HIGH** Any authenticated user — including one created as `viewer` — can publish firmware and create deployments. Privilege separation is cosmetic.

**4. Fix required** Add `requiredRole` to `SecureApiOptions`; enforce in `withSecureApi` with 403 on mismatch; apply to `/api/firmware/publish`, deployment routes, and `/api/runtime/command`.

**5. Test after fix** Create a `viewer` user; obtain its session; `POST /api/firmware/publish` → expect **403**. Repeat as `admin` → expect 200. Confirm the 403 is produced server-side (curl directly, not through the UI).

---

### F-5 · AT-8.3 — No offline detection

**1. Root cause** Nothing computes staleness from `last_seen`. Grep for `offline|online|stale` in `routes/dashboard.py` and `state.py` returns zero matches.

**2. Exact file** `src/implementation/gateway/routes/dashboard.py`; `state.py` `gateway_snapshot()`.

**3. Impact — MEDIUM** A device that dies, loses power, or is stolen shows its last-known status forever. Operators cannot distinguish "healthy" from "gone". Fleet health is unmeasurable, and the "device offline" alert class cannot exist.

**4. Fix required** Add a threshold (e.g. 3 missed intervals) and derive `online` in the snapshot from `now - last_seen`. Emit an event on the healthy→offline transition.

**5. Test after fix** `AT-8.3` → PASS. Manually: send a heartbeat, confirm `online: true`; wait past the threshold, confirm `online: false` **and** an offline event; resume heartbeat, confirm `online: true` again.

---

### F-6 · AT-6.7 — No rate limiting

**1. Root cause** No limiter middleware anywhere.

**2. Exact file** `src/implementation/gateway/__init__.py` `create_app()` — CORS is the only middleware.

**3. Impact — MEDIUM** Unbounded heartbeat flooding grows the state file and forces a whole-file rewrite per request, which is a cheap denial of service. Combined with F-1 (no auth) it needs no credentials at all.

**4. Fix required** Per-IP and per-device limits on `/api/heartbeat`; return 429 with `Retry-After`.

**5. Test after fix** `AT-6.7` → PASS (at least one 429 in 40 rapid requests). Confirm a normal 15-second cadence is never throttled.

---

### F-7 · AT-11.3 — CI secrets not configured

**1. Root cause** Never set. `gh secret list` returns empty.

**2. Exact file** `.github/workflows/firmware-release.yml` — the `ota_config.h` heredoc and the signing step.

**3. Impact — HIGH** A release tag today would compile with **empty** WiFi credentials and empty keys, and the signing step warns and continues, publishing **unsigned** binaries that devices with secure OTA provisioned would reject.

**4. Fix required** Set the nine secrets (`complete-setup.ps1 -Phase secrets`), and change the signing step to hard-fail rather than warn when keys are absent on a release tag.

**5. Test after fix** `AT-11.3` → PASS. Then push a tag to a scratch branch and confirm the run produces a signed artifact; separately, temporarily unset a signing secret and confirm the run **fails** instead of publishing unsigned.

---

### F-8 · AT-10.1 / AT-10.2 — No automated tests

**1. Root cause** None written. `integration_smoke_test.py` referenced in the README does not exist.

**2. Exact location** No `test_*.py`, `conftest.py`, `*.test.ts` anywhere outside `node_modules`; no `test` script in `CODE/OTA_IDE/package.json`.

**3. Impact — HIGH** No regression protection. Every behaviour verified in this audit could silently break on the next commit, including the write-auth guard, whose earlier broken form left all write endpoints open while appearing protected.

**4. Fix required** pytest for the gateway starting with the highest-risk logic: `require_write_auth`, `version_score`/`is_newer_version`, `latest_release_for_device_locked`, `safe_cache_path`, `create_deployment_locked`. Wire into CI so failures block.

**5. Test after fix** `AT-10.1` → PASS; `pytest` reports non-zero tests, all passing; a deliberately introduced regression (e.g. remove the guard from one route) makes CI fail.

---

## Part 5 — End-to-end ⚠️ HARDWARE REQUIRED

Only meaningful after F-1 and F-2 are fixed.

**E2E-1 · Happy path** — flash bootstrap over USB with WiFi credentials → device registers and receives a token → heartbeat appears → publish a signed release → create a deployment → device downloads, verifies, installs, reboots → health check passes → deployment reports **SUCCESS**.
**Accept only if** the deployment reaches SUCCESS *from a device-reported version*, never from a timeout or an assumption.

**E2E-2 · Deliberate failure** — build firmware with a wrong WiFi password → publish and deploy → device installs, reboots, fails the health check, rolls back → returns on the **previous** version → deployment reports **ROLLED_BACK** with a reason, and an alert is raised.
**Accept only if** no human intervention was required and no USB cable was touched.

---

## Summary

| Category | Count | Verify with |
|---|---|---|
| ✅ Verified working | 31 | `.\acceptance-test.ps1` |
| ❌ Known gaps | 9 | Same suite — each must flip to PASS |
| ⚠️ Needs dashboard runtime | 1 | AT-D1 |
| ⚠️ Needs ESP32 hardware | 4 | AT-D2, AT-D3, F-2 test, E2E-1/2 |

**The 9 expected failures are the definition of done.** When `.\acceptance-test.ps1` reports `FAIL (expected): 0`, the backend gaps identified in the audit are closed — with the exception of the hardware items, which no script can prove.
