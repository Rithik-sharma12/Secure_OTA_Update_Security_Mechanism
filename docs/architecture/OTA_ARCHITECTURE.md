# SecureOTA — Complete OTA Architecture

**Status:** Architecture study. No implementation changes proposed for immediate execution; see §10 for the phased roadmap.
**Scope:** ESP32 firmware, FastAPI gateway, Next.js dashboard, SecureOTA IDE, GitHub Actions.

---

## 0. Provenance of technical claims

Every ESP32 claim below is grounded in a file that was read during this study, not recalled. Where a claim depends on framework behaviour, the source file and version are cited so it can be re-verified when the toolchain moves.

| Claim source | Path / version |
|---|---|
| Partition layout | `packages/esp32/hardware/esp32/3.3.8/tools/partitions/default.csv` |
| Partition scheme selection | `platformio.ini` (no `board_build.partitions` → board default) |
| OTA write path | `libraries/Update/src/Updater.cpp` (`esp_ota_*` calls) |
| Rollback bootloader config | `framework-arduinoespressif32/tools/sdk/esp32/sdkconfig` |
| Rollback validation timing | `framework-arduinoespressif32/cores/esp32/esp32-hal-misc.c:203-239` |
| Device OTA logic | `CODE/frimware_code/esp32_ota_main/esp32_ota_main.ino` |
| Gateway behaviour | `src/implementation/gateway/**` (all modules read) |
| CI pipeline | `.github/workflows/firmware-release.yml` |

**Framework:** This project uses **Arduino-ESP32**, not bare ESP-IDF. Arduino-ESP32 is a wrapper *over* ESP-IDF, so ESP-IDF partition and `esp_ota_ops` semantics apply — but Arduino adds behaviour of its own, and §1.7 documents one such difference that is decisive for rollback.

Two different Arduino core versions are installed and in active use — see §4.5, this is a defect.

---

## 1. ESP32 OTA fundamentals

### 1.1 Flash layout — as actually configured

`platformio.ini` sets no `board_build.partitions`, so `esp32dev` uses the core's `default.csv`. Verbatim, for 4 MB flash:

```
Name      Type  SubType   Offset     Size       Purpose
────────────────────────────────────────────────────────────────────────
(bootloader)                0x1000    ~28 KB    Second-stage bootloader
(partition table)           0x8000     3 KB     Describes the map below
nvs       data  nvs        0x9000     20 KB     Key-value store (ASH score lives here)
otadata   data  ota        0xE000      8 KB     Which slot boots + its trial state
app0      app   ota_0     0x10000   1.25 MB     Firmware slot A
app1      app   ota_1    0x150000   1.25 MB     Firmware slot B
spiffs    data  spiffs   0x290000   1.375 MB    Filesystem
coredump  data  coredump 0x3F0000     64 KB     Post-crash dump
```

**Correction to the brief:** the requested diagram shows a *factory* partition. `default.csv` has **no factory partition**. The initial serial flash writes to `app0`, which is an OTA slot, not a factory image. This matters for recovery: there is no pristine fallback image that OTA can never overwrite. If both slots end up bad, USB reflash is the only path. A `factory` partition is a design option (§10 Phase 4), not something the current layout provides.

**Size ceiling:** 1.25 MB per slot. Current build is well under, but a firmware that grows past 1.25 MB cannot OTA at all — `Update.begin()` fails with "Not enough space", which the code already handles (`esp32_ota_main.ino:530`, `:683`).

### 1.2 Why the running image cannot be overwritten

The ESP32 executes code from flash via a memory-mapped cache (XIP — execute in place). Instruction fetches stream from the active partition continuously. Erasing or rewriting the region currently being executed pulls the instruction stream out from under the CPU, so the write is not merely unsafe, it is impossible to complete.

Hence the A/B (ping-pong) model: firmware is always written to the slot that is **not** running. `Updater.cpp:231-233` enforces this explicitly:

```c
_partition = esp_ota_get_next_update_partition(NULL);
if (!_partition || _partition == esp_ota_get_running_partition()) {
  return false;   // refuse to write the running slot
}
```

### 1.3 otadata — the 8 KB that decides everything

`otadata` holds two mirrored copies (for power-fail atomicity) of a small record: which slot should boot, and that slot's **image state**. ESP-IDF defines the states as:

| State | Meaning |
|---|---|
| `ESP_OTA_IMG_NEW` | Just written; not yet attempted |
| `ESP_OTA_IMG_PENDING_VERIFY` | Booted once, on trial, not yet confirmed |
| `ESP_OTA_IMG_VALID` | Confirmed good; boots indefinitely |
| `ESP_OTA_IMG_INVALID` | Rejected; never selected again |
| `ESP_OTA_IMG_ABORTED` | Trial ended without confirmation |

The bootloader reads otadata on every reset and selects a partition from it. **Rollback is entirely a function of these states** — there is no other mechanism.

### 1.4 The A/B update cycle

```
Initial state          After download          After reboot + confirm
─────────────          ──────────────          ──────────────────────
app0: v1.0.0 (running) app0: v1.0.0 (running)  app0: v1.0.0 (spare)
app1: empty            app1: v1.1.0 (written)  app1: v1.1.0 (running, VALID)
otadata → app0 VALID   otadata → app1 NEW      otadata → app1 VALID
```

The next update reverses direction and overwrites `app0`. The previous known-good image survives exactly until the update *after* the one that replaced it — one generation of history, no more.

### 1.5 What the current firmware actually does

`performSecurePackageUpdate()` (`esp32_ota_main.ino:445-656`) implements a single-pass streaming installer:

1. **Structural pre-validation** (`:466-480`) — declared length must exceed IV(16) + signature(256); ciphertext length must be a multiple of 16. **No flash operation begins until both hold.**
2. **Header ingestion** (`:487-493`) — read IV and RSA signature into fixed buffers.
3. **Crypto init** (`:506-528`) — parse RSA public key, start SHA-256, set AES-256 key.
4. **`Update.begin(encryptedSize, U_FLASH)`** (`:530`) — reserves the inactive slot. Internally `esp_ota_get_next_update_partition()`.
5. **Block loop** (`:544-611`) — for each 16-byte block: AES-CBC decrypt → SHA-256 update over *plaintext* → `Update.write()` to the inactive slot. **Peak RAM attributable to the payload is one cipher block**, regardless of image size. This is what makes a 1 MB image installable on a device with ~300 KB free heap.
6. **PKCS#7 padding validation** (`:568-586`) on the final block.
7. **`mbedtls_pk_verify()`** (`:624-634`) — RSA-2048 over the accumulated SHA-256 of the plaintext.
8. **`Update.end(true)`** (`:638`) — **only on successful verification.** This calls `esp_ota_set_boot_partition()`, flipping otadata to the new slot.
9. **Failure path** (`:646-648`) — `Update.abort()`, boot partition untouched, device continues on the running image.

**The essential property: the device may write unverified bytes, but it can never boot them.** Verification precedes the otadata flip, and abort leaves the running image authoritative.

`performPlainPackageUpdate()` (`:658-724`) is the fallback: length reconciliation only, no signature. It is attempted when secure OTA is unprovisioned or the secure path fails (`:417-432`). It provides integrity assurance against truncation, **not authenticity**.

### 1.6 Boot sequence

```
Reset
  ↓
ROM bootloader (mask ROM, immutable) → loads second-stage bootloader from 0x1000
  ↓
Second-stage bootloader
  ├── reads partition table (0x8000)
  ├── reads otadata (0xE000)
  ├── selects target slot from otadata
  ├── if state == PENDING_VERIFY and rollback enabled → this is a trial boot
  ├── verifies image header/checksum (and signature, if Secure Boot enabled — it is NOT here)
  └── maps slot into instruction cache, jumps to app entry
  ↓
app_main → initArduino()   ← ROLLBACK IS RESOLVED HERE, see §1.7
  ↓
setup()
  ↓
loop()
```

### 1.7 ⚠ The rollback defect — verified, and the single most important finding

The shipped SDK **has rollback compiled in**:

```
CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y
CONFIG_APP_ROLLBACK_ENABLE=y
# CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK is not set
```

So the machinery exists. But `esp32-hal-misc.c:222-239`:

```c
void initArduino() {
#ifdef CONFIG_APP_ROLLBACK_ENABLE
    if (!verifyRollbackLater()) {                       // weak → false
        const esp_partition_t *running = esp_ota_get_running_partition();
        esp_ota_img_states_t ota_state;
        if (esp_ota_get_state_partition(running, &ota_state) == ESP_OK) {
            if (ota_state == ESP_OTA_IMG_PENDING_VERIFY) {
                if (verifyOta()) {                      // weak → true
                    esp_ota_mark_app_valid_cancel_rollback();
                } else {
                    esp_ota_mark_app_invalid_rollback_and_reboot();
                }
            }
        }
    }
#endif
```

`verifyOta()` and `verifyRollbackLater()` are **weak symbols** (`:204-208`) that a sketch may override. `esp32_ota_main.ino` overrides **neither** (verified by grep).

**Therefore, in the current firmware:**

- The new image is marked `ESP_OTA_IMG_VALID` inside `initArduino()`, which runs **before `setup()`**
- WiFi has not been attempted; the gateway has not been contacted; `loop()` has not executed
- The rollback window closes before a single line of application logic runs

**Consequence:** if v1.1.0 boots but cannot join WiFi, crashes in `loop()`, or cannot reach the gateway, the bootloader will keep selecting it forever. The device is bricked in the field and requires physical USB recovery. The platform *appears* to have rollback because the bootloader config is enabled; it does not.

**This is threat #16 (boot-loop after update) in §8, currently unmitigated.**

**Fix (Phase 1, §10):** override both hooks in the sketch —

```cpp
// Defer the validity decision from initArduino() to application logic.
bool verifyRollbackLater() { return true; }
```

— then, after a health check passes (WiFi associated + gateway heartbeat accepted + ASH above threshold), call `esp_ota_mark_app_valid_cancel_rollback()`. On health-check failure, call `esp_ota_mark_app_invalid_rollback_and_reboot()`, which reverts otadata to the previous slot and resets. Requires `#include "esp_ota_ops.h"`.

A watchdog must back this: if the app hangs before either call, the trial state persists and the *next* reset rolls back — which is the desired behaviour, but only if something forces that reset.

### 1.8 Anti-rollback: two distinct meanings

These are frequently conflated. They are different mechanisms at different layers.

| | Application-level (implemented) | Hardware-level (not enabled) |
|---|---|---|
| Mechanism | Integer version compare before download | eFuse secure version counter |
| Where | `esp32_ota_main.ino:298` + `gateway/utils.py:95` | `CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK` |
| Enforced by | Firmware and gateway agreeing on arithmetic | Bootloader, irreversibly |
| Bypassable | Yes — by anyone who can flash over USB, or forge a manifest | No — eFuse burns are one-way |
| Status | **Working, symmetric** | **Off** (`is not set`, confirmed) |

The implemented scheme reduces both sides to `major*10000 + minor*100 + patch` and requires strictly greater. `gateway/utils.py:72-97` mirrors `parseVersion()` at `esp32_ota_main.ino:782-808` exactly, so the gateway never advertises what the device would refuse. This is good design and should be kept.

But it is a *policy* control, not a *security* control. Enabling hardware anti-rollback requires Secure Boot v2 and eFuse burning — irreversible, bricks the device on error, and precludes downgrade forever. Recommended only for a production fleet, never on development boards (§10 Phase 4).

---

## 2. OTA sequence — full lifecycle

### 2.1 Initial provisioning (USB / serial)

```
Developer            SecureOTA IDE          arduino-cli        ESP32           Gateway
   │                       │                     │               │                │
   ├─ connect USB ────────────────────────────────────────────▶  │                │
   │                       ├─ enumerate COM ports                │                │
   │                       │  (serial-port-detection.ts)         │                │
   ├─ pick port, board ───▶│                                     │                │
   ├─ enter SSID + pass ──▶│                                     │                │
   │                       ├─ copy sketch → temp workspace       │                │
   │                       ├─ patch ota_config.h (WIFI_SSID/PASSWORD)             │
   │                       ├─ compile ─────────▶│               │                │
   │                       │                     ├─ esptool ───▶ │ write app0     │
   │                       ├─ delete workspace   │               │                │
   │                       │  (credentials gone) │               ├─ reboot        │
   │                       │                     │               ├─ join WiFi     │
   │                       │                     │               ├─ heartbeat ───▶│
   │                       │                     │               │                ├─ implicit
   │                       │                     │               │                │  registration
   │                       │                     │               │◀── ack ────────┤
```

Implemented in `lib/serial-upload-jobs.ts`. **Note the last step:** there is no explicit registration call — the device appears in the registry as a side effect of its first heartbeat (`routes/heartbeat.py:59-66`). See §4.3 for why this is a gap.

### 2.2 Firmware release (CI)

```
Developer → git tag v1.1.0 → GitHub Actions
                                  ├─ write ota_config.h from secrets
                                  ├─ pio check (advisory)
                                  ├─ pio run × 3 boards   ← the real gate
                                  ├─ sha256 + RSA sign + AES encrypt
                                  └─ publish GitHub Release
                                        │
                                        ▼
                          (MANUAL TODAY) operator uploads .bin
                                        │
                                        ▼
                          Gateway POST /api/releases/upload
                                  ├─ store to cache
                                  ├─ Ed25519 sign manifest
                                  └─ read-back verify → publish
```

**The dotted step is the gap:** GitHub Release → gateway is manual. There is no webhook, no gateway-side pull. See §4.4.

### 2.3 OTA update

```
ESP32                                   Gateway
  │                                        │
  ├─ heartbeat (every 15 s) ──────────────▶│ resolve compatible release
  │◀── {command: update_available, ...} ───┤ (arch + ASH + strictly-newer)
  │                                        │
  ├─ GET /releases/latest/manifest ───────▶│ re-sign over cached bytes
  │◀── manifest {version, sha256, sig} ────┤
  │                                        │
  ├─ compare version scores                │
  │    ≤ current → refuse, no download     │
  │                                        │
  ├─ GET /releases/download/{file} ───────▶│
  │◀── IV ‖ RSA-sig ‖ AES-CBC payload ─────┤
  │                                        │
  ├─ per block: decrypt → hash → write app1│
  ├─ verify RSA(SHA-256(plaintext))        │
  │    fail → Update.abort(), STOP         │
  ├─ Update.end(true) → otadata → app1     │
  ├─ ESP.restart()                         │
  │                                        │
  ├─ [bootloader selects app1]             │
  ├─ ⚠ initArduino() marks VALID           │  ← §1.7 defect: too early
  ├─ setup(), WiFi, loop()                 │
  ├─ heartbeat {current_version: 1.1.0} ──▶│ confirm_device_version_locked()
  │                                        │ target pending → confirmed
```

### 2.4 Intended rollback (after Phase 1 fix)

```
  ├─ [bootloader selects app1, state=PENDING_VERIFY]
  ├─ initArduino(): verifyRollbackLater() → TRUE, no auto-validate
  ├─ setup(): WiFi join
  │     ├─ success → heartbeat accepted → esp_ota_mark_app_valid_cancel_rollback()
  │     │                                  otadata: app1 VALID. Done.
  │     └─ failure → esp_ota_mark_app_invalid_rollback_and_reboot()
  │                    otadata: app1 INVALID, boot ← app0
  │                    reboot → v1.0.0 runs again
  │
  └─ hang before either call → watchdog reset → bootloader sees PENDING_VERIFY
                                → ABORTED → falls back to app0
```

---

## 3. Component responsibility matrix

| Responsibility | IDE | Gateway | Dashboard | GitHub Actions | Firmware | Bootloader |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| COM port enumeration | ● | ✗ | ○ | ✗ | ✗ | ✗ |
| Serial flash (esptool) | ● | ✗ | ○ | ✗ | ✗ | ✗ |
| WiFi credential injection | ● | ✗ | ○ | ● | ✗ | ✗ |
| Operator authentication | ✗ | ✗ | ● | ✗ | ✗ | ✗ |
| Device identity | ✗ | ◐ | ✗ | ✗ | ◐ | ✗ |
| Firmware compile | ● | ✗ | ✗ | ● | ✗ | ✗ |
| Firmware signing (release) | ✗ | ● Ed25519 | ✗ | ● RSA | ✗ | ✗ |
| Manifest generation | ✗ | ● | ✗ | ✗ | ✗ | ✗ |
| Architecture compatibility | ✗ | ● | ✗ | ✗ | ✗ | ✗ |
| Version arbitration | ✗ | ● | ✗ | ✗ | ● | ✗ |
| Firmware download | ✗ | ✗ | ✗ | ✗ | ● | ✗ |
| Signature verification | ✗ | ✗ | ✗ | ✗ | ● RSA | ✗ |
| Write to inactive slot | ✗ | ✗ | ✗ | ✗ | ● | ✗ |
| Boot slot selection | ✗ | ✗ | ✗ | ✗ | ◐ set | ● decide |
| Trial-state resolution | ✗ | ✗ | ✗ | ✗ | ✗ **gap** | ● |
| Rollback execution | ✗ | ✗ | ✗ | ✗ | ✗ **gap** | ● |
| Health scoring (ASH) | ✗ | ◐ | ✗ | ✗ | ● | ✗ |
| Deployment tracking | ✗ | ● | ○ | ✗ | ✗ | ✗ |
| Audit log | ✗ | ✗ **gap** | ● | ✗ | ✗ | ✗ |

● owns · ◐ partial · ○ displays only · ✗ not involved

**The load-bearing rule:** the backend cannot touch the operator's COM ports. Serial is inherently local — USB enumeration and esptool invocation happen in the IDE/dashboard process on the operator's machine. The backend receives *results*, never device handles. This is correctly implemented today (`serial-upload-jobs.ts` shells out locally; the gateway has no serial code at all). Note this also means serial flashing is **non-functional inside Docker** — no serial hardware in the container.

---

## 4. Repository analysis

### 4.1 Gateway — `src/implementation/gateway/` (FastAPI)

**Implemented and genuinely good — do not rewrite:**

| Module | What it does | Verdict |
|---|---|---|
| `release.py` | Per-architecture manifest resolution; re-signs over cached bytes at service time; measured 4-stage pipeline with read-back verification that aborts on mismatch | **Keep.** Architecturally sound |
| `deployment.py` | Evidence-based state machine; never writes `device['fw']`; lazy timeout expiry, no scheduler | **Keep.** The comments document a real past bug worth not reintroducing |
| `crypto.py` | Ed25519 load-or-create, SHA-256 fingerprint | Keep |
| `utils.py` | `version_score()` mirroring firmware arithmetic; `safe_cache_path()` traversal guard | Keep |
| `auth.py` | API-key guard imported directly so `Depends()` binds the real function | **Keep.** Fixes a prior vulnerability; the docstring explains why |
| `state.py` | Lock-guarded dict + atomic whole-file JSON persistence | Keep for now; see §6 |

**Complete API surface (16 endpoints, enumerated):**

```
GET  /                          GET  /healthz
GET  /api/dashboard             GET  /api/events
GET  /api/releases              POST /api/releases          [auth]
GET  /api/releases/latest       POST /api/releases/upload   [auth]
GET  /api/deployments           POST /api/deployments       [auth]
POST /api/heartbeat             POST /api/trigger_sync      [auth]
GET  /releases/latest/manifest  POST /api/pipeline/run      [auth]
GET  /releases/latest/public-key
GET  /releases/download/{filename}
```

**Gaps:**

- **No `/api/devices/register`.** Devices materialise from their first heartbeat.
- **`POST /api/heartbeat` is unauthenticated.** No `Depends(require_write_auth)` on it (verified). Any host that can reach the gateway can forge telemetry for any `device_id` — including a version report that falsely confirms a deployment (`confirm_device_version_locked`). **This is the highest-severity gap in the backend.**
- **One shared fleet API key.** `OTA_GATEWAY_API_KEY` is a single secret; no per-device credentials, so a key extracted from one device's flash authenticates as any device.
- **No user/role model in the gateway.** Operator auth lives only in the dashboard tier.
- **No audit log in the gateway.** Audit rows are written by the dashboard (`lib/api-security.ts`); gateway-side writes are unaudited.
- No firmware storage abstraction (local filesystem only), no webhook receiver, no rollback command channel.

### 4.2 Dashboard — `CODE/OTA_IDE/` (Next.js 16 / React 19)

**Implemented:** operator auth (scrypt + sha256 token hashes, expiry, revocation), `withSecureApi` wrapper writing an audit row per request, snapshot aggregation, serial upload job pipeline with WiFi provisioning, firmware publish forwarding with server-side key attachment.

**Watch:** two separate NeDB layers — `lib/local-database.ts` (`OTA_LOCAL_DB_DIR`, **is** volume-mounted) and `lib/db.ts` (hardcoded `process.cwd()/.data`, **not** mounted → webhook/dead-letter data is lost on container recreate). This is a live data-loss bug.

**Note:** `pnpm lint` is declared as `eslint .` but eslint is not installed and no config exists. `pnpm build` and `tsc` are the only working gates.

### 4.3 Firmware — `CODE/frimware_code/`

**Implemented well:** bounded streaming secure install, deferred activation, PKCS#7 validation, NTP sentinel for TLS (`:183` — rejects epoch-0 clocks properly), pinned-root-CA support with an explicit warning when absent, ASH health scoring persisted to NVS with hysteresis (quarantine <40, recovery at 100).

**Gaps:** no rollback hooks (§1.7); no explicit registration; no post-update health gate; `DEVICE_ID` is a compile-time constant so every device flashed from one build shares an identity; secure-OTA failure silently falls back to unauthenticated plain OTA (`:417-432`) — acceptable for dev, not for production.

### 4.4 CI — `.github/workflows/firmware-release.yml`

Now correctly located and, after this session's fixes, structurally sound: builds three boards, signs and encrypts, publishes a Release. **Inert until secrets are configured** (`gh secret list` returns zero).

**Gaps:** no unit tests (compile is the only gate); `pio check` is advisory; **no delivery to the gateway** — the Release is the end of the pipeline, and an operator must manually download and re-upload. No provenance attestation, no SBOM.

### 4.5 ⚠ Toolchain skew — defect

| Path | Core |
|---|---|
| CI (`pio run`) | framework-arduinoespressif32 `3.20017` = Arduino core **2.0.17** |
| IDE serial flash (`arduino-cli`) | esp32 core **3.3.8** |

A major version apart — different bundled ESP-IDF, different ArduinoJson expectations, potentially different default partition CSVs. **Firmware validated in CI is not the firmware the IDE flashes.** Pin both to one version (§10 Phase 1).

### 4.6 SecureOTA-IDE — `riteshvijaykumar/SecureOTA-IDE`

Architecturally disconnected from this stack. Modules implemented in the prior session (GitHub release pipeline, packet crypto, device registry, UDP listener, relevance checker — 42 tests passing) are sound but **cannot build into an IDE here**: upstream requires Node `>=18.17.0 <21`, machine has Node 24. Its "Secure OTA" feature is explicitly marked future scope and shares no code with this platform. **Recommendation: leave it out of the OTA critical path.** Treat as a parallel research track.

---

## 5. API contract

### 5.1 ESP32 ↔ Gateway

Existing, keep:

```
POST /api/heartbeat                                → {command, gateway_time, latest_version}
GET  /releases/latest/manifest?device_type=ESP32   → signed manifest | 404
GET  /releases/download/{filename}                 → firmware bytes
GET  /releases/latest/public-key                   → {algorithm, keyId, fingerprint, publicKeyPem}
```

Proposed additions (additive, non-breaking):

```
POST /api/devices/register     {device_id, mac, chip_id, device_type, fw, bootstrap_token}
                               → {device_token, poll_interval}
POST /api/devices/{id}/ota/status  {deployment_id, state, detail}
                               → 204   (drives the state machine in §7)
```

`/api/heartbeat` must gain per-device token auth. Keep the unauthenticated form behind a config flag for one release to avoid bricking fielded devices, then retire it.

### 5.2 IDE/Dashboard ↔ Gateway

```
GET  /api/dashboard                       (existing)
POST /api/releases/upload    [fleet key]  (existing)
POST /api/deployments        [fleet key]  (existing)
GET  /api/deployments                     (existing)
POST /api/deployments/{id}/rollback       (proposed)
```

The dashboard already isolates the fleet key server-side — the browser never sees it. Preserve that.

### 5.3 GitHub ↔ Gateway

Entirely absent. Proposed:

```
POST /api/github/webhook   X-Hub-Signature-256   ← on `release: published`
     → gateway pulls the asset, verifies the RSA signature and SHA-256 against
       the release manifest, then runs create_release_locked()
```

Verify the HMAC signature *and* re-verify the artifact signature. A webhook proves GitHub sent it; it does not prove the artifact is trustworthy.

---

## 6. Database design

Current state is a single lock-guarded dict persisted as one JSON file (`state.py`), plus two NeDB stores in the dashboard. Honest assessment:

**Adequate now** — a handful of devices, single gateway process, whole-file writes are atomic and fast at this scale.

**Breaks at:** concurrent gateway replicas (no shared state), ~10³ devices (whole-file rewrite per heartbeat becomes O(n) per write), any query beyond "give me everything", and retention (`MAX_EVENTS=500` silently discards history — unusable for audit).

**Recommendation: PostgreSQL, but not yet.** Migrate at Phase 3, after the security gaps are closed. Sequencing matters — porting a schema while the auth model is still changing means doing it twice.

```
users ──< user_roles >── roles ──< role_permissions >── permissions
  │
  └──< audit_logs >── devices
                        │
  device_credentials >──┤ (device_id FK, token_hash, issued_at, revoked_at)
       telemetry >──────┤ (device_id FK, recorded_at, metrics JSONB)
          events >──────┤
          alerts >──────┤
deployment_devices >────┘
       │
       └──> deployments ──> firmware_releases ──< firmware_artifacts
                                  │
                                  └──> pipeline_runs ──> github_repositories
```

| Table | Key columns | Notes |
|---|---|---|
| `devices` | `id` PK, `device_type`, `current_version`, `ash_score`, `last_seen`, `status` | `device_type` constrained to the allowed set |
| `device_credentials` | `id` PK, `device_id` FK, `token_hash`, `issued_at`, `revoked_at` | Never store the token itself |
| `telemetry` | `id` PK, `device_id` FK, `recorded_at`, `metrics` JSONB | Partition by month; this is the high-volume table |
| `firmware_releases` | `id` PK, `version` UNIQUE, `compatible` text[], `status`, `released_at` | `version` unique enforces immutability |
| `firmware_artifacts` | `id` PK, `release_id` FK, `filename`, `sha256`, `size`, `signature`, `sig_algorithm` | |
| `deployments` | `id` PK, `release_id` FK, `status`, `started_at`, `deadline` | |
| `deployment_devices` | `deployment_id` FK, `device_id` FK, `state`, `from_version`, `confirmed_at`, `reason` | Composite PK; **this is the state machine in §7** |
| `audit_logs` | `id` PK, `actor_id`, `action`, `resource`, `at`, `detail` JSONB | Append-only; no UPDATE/DELETE grant |

---

## 7. OTA state machine

The brief asks for 11 states. The gateway currently has **three** target states (`pending`, `confirmed`, `failed`) because it only observes what heartbeats tell it — it has no download or install visibility. The richer machine requires the device to report progress (`POST /api/devices/{id}/ota/status`, §5.1).

```
                      ┌──────────┐
                      │ PENDING  │ assignment created
                      └────┬─────┘
         ┌─────────────────┼──────────────────────┐
    arch mismatch      device polls          deadline (30 min)
    ASH quarantine          │                     │
    downgrade               ▼                     ▼
         │            ┌─────────────┐        ┌────────┐
         └───────────▶│ DOWNLOADING │        │ FAILED │
                      └──────┬──────┘             ▲
                    net loss │ complete           │
                        ─────┼──────────▶─────────┤
                             ▼                    │
                      ┌───────────┐               │
                      │ VERIFYING │───sig/hash────┤
                      └─────┬─────┘   mismatch    │
                            │ verified            │
                            ▼                     │
                      ┌────────────┐              │
                      │ INSTALLING │──write fail──┤
                      └─────┬──────┘              │
                            │ Update.end(true)    │
                            ▼                     │
                      ┌───────────┐               │
                      │ REBOOTING │               │
                      └─────┬─────┘               │
                            ▼                     │
                    ┌──────────────┐              │
                    │ HEALTH_CHECK │              │
                    └──┬────────┬──┘              │
                  pass │        │ fail / timeout  │
                       ▼        ▼                 │
                 ┌─────────┐  ┌─────────────┐     │
                 │ SUCCESS │  │ ROLLED_BACK │─────┘
                 └─────────┘  └─────────────┘
```

**Transition rules:**

- Only `HEALTH_CHECK → SUCCESS` is terminal-good, and it fires **only** on a heartbeat reporting `version_score ≥ target` (`deployment.py:225`). Never on download completion, never on reboot.
- `≥` not `==` deliberately: a device that jumped past the assigned build satisfies the intent and would otherwise hang until timeout.
- `FAILED` is reachable pre-dispatch (arch/ASH/downgrade) without any bytes transferred.
- `ROLLED_BACK` requires the §1.7 fix. **It is currently unreachable.**
- Timeouts are evaluated lazily on heartbeat and on deployment read — no scheduler.

---

## 8. Security model and threat analysis

### 8.1 The four properties, kept distinct

| Property | Provides | Mechanism here |
|---|---|---|
| **Integrity** | Bytes unaltered | SHA-256 |
| **Authenticity** | Bytes came from us | RSA-2048 (device), Ed25519 (manifest) |
| **Confidentiality** | Bytes unreadable in transit | AES-256-CBC + TLS |
| **Anti-rollback** | No return to known-bad | Version score compare |

**Why SHA-256 alone gives no authenticity.** A hash is a public, keyless function. An attacker who substitutes firmware simply recomputes the hash over their own image and ships both. The device's comparison passes. A hash detects *accident*, never *adversary*. It only becomes an authenticity control when the hash itself is signed — which is precisely what the RSA signature over `SHA-256(plaintext)` does at `:624`.

**Why encryption alone gives no authenticity.** AES-CBC provides confidentiality, not origin proof. Anyone holding the symmetric key can *produce* ciphertext as easily as read it — and here the key is compiled into every device's flash, so extracting it from one board yields forgery capability against the whole fleet. CBC is also malleable: bit-flips in ciphertext produce controlled plaintext changes. Encryption without a signature means "unreadable by third parties" — not "written by us".

**Why signatures work.** Asymmetric: signing needs the private key (held in CI/gateway), verification needs only the public key (safe to ship in flash). Extracting the public key from a device grants no forgery ability.

Note the design deliberately uses **two independent trust paths** — Ed25519 for gateway manifests, RSA-2048 for device packages. Compromise of one key alone does not permit arbitrary code execution. Do not conflate or unify them.

### 8.2 Threat table

| # | Threat | Impact | Mitigation | Detection | Recovery |
|---|---|---|---|---|---|
| 1 | Malicious firmware | RCE on fleet | RSA verify pre-activation | Sig failure in logs | Abort; running image intact |
| 2 | Firmware tampering | Corrupt/backdoor | SHA-256 under signature | Verify stage fails | Abort |
| 3 | MITM | Substituted image | TLS + pinned CA; sig is the real defence | Handshake/sig failure | Abort |
| 4 | Replay old firmware | Reintroduce CVE | Version score, both ends | Gateway logs refusal | No download occurs |
| 5 | Downgrade attack | Same | As #4 | Same | Same |
| 6 | Compromised GitHub repo | Malicious build | ⚠ **Gap** — no branch protection/review gate | CI logs | Revoke, rebuild, rotate |
| 7 | Compromised CI runner | Signed malware | ⚠ **Gap** — keys live in Actions secrets | Anomalous release | Rotate keys, re-sign |
| 8 | Stolen signing key | Full fleet compromise | ⚠ **Gap** — no HSM, no rotation, no revocation | — | **No recovery path today** |
| 9 | Unauthorized deployment | Unwanted rollout | Fleet API key | Dashboard audit rows | Reassign |
| 10 | Compromised device creds | Fleet impersonation | ⚠ **Gap** — one shared key, no per-device identity | — | Rotate everything |
| 11 | Fake device registration | Registry poisoning | ⚠ **Gap** — heartbeat is unauthenticated | — | Manual purge |
| 12 | Gateway compromise | Serve any firmware | Device-side RSA still blocks unsigned | Sig failures fleet-wide | Restore; device keys unaffected |
| 13 | DoS | No updates | Bounded ingestion, clamped fields | Gateway metrics | Restart; devices retry |
| 14 | Corrupted download | Failed update | Length + padding + hash checks | Verify fails | Abort, retry next poll |
| 15 | Interrupted OTA | Partial write | Inactive slot only; otadata untouched | Update fails | Running image unaffected |
| 16 | **Boot-loop after update** | **Bricked in field** | ⚠ **NONE — see §1.7** | Device stops reporting | **USB reflash only** |

Six gaps. **#16 and #8 are the most severe**: #16 because failure is unrecoverable without physical access, #8 because it has no mitigation *and* no recovery.

### 8.3 Non-negotiable rules

- Never trust firmware because the backend served it — verify signature on-device, always
- Never treat SHA-256 as a signature
- Never mark success on download or on reboot — only on attested health
- Never let the backend touch local COM ports
- Never store WiFi passwords or signing keys in git
- Never let every authenticated user deploy — deployment needs its own permission
- Never assume a GitHub Actions artifact is trustworthy without verifying its signature

---

## 9. Failure and recovery model

| # | Scenario | Current behaviour | Adequate? |
|---|---|---|---|
| 1 | WiFi drops mid-OTA | `readBytes` short → abort, slot discarded | ✅ |
| 2 | Download halts | Length mismatch → abort | ✅ |
| 3 | SHA-256 mismatch | Signature verify fails → abort, no activation | ✅ |
| 4 | Invalid signature | `mbedtls_pk_verify != 0` → abort | ✅ |
| 5 | Power loss mid-write | otadata never updated → old slot boots | ✅ |
| 6 | **New firmware crashes** | **Marked VALID before setup() → boot-loop** | ❌ **§1.7** |
| 7 | **Cannot reach gateway after reboot** | **Same — already VALID** | ❌ **§1.7** |
| 8 | **Repeated boot-loop** | **No escape; USB only** | ❌ **§1.7** |
| 9 | Gateway unavailable | Fetch fails, ASH −1, retry next poll | ✅ |
| 10 | CI build fails | `pio run` non-zero → no Release | ✅ |
| 11 | Signing fails | Warning, publishes **unsigned** | ⚠ should hard-fail in prod |
| 12 | Unsupported version | 404 per-architecture, no bytes sent | ✅ |

Scenarios 1–5, 9, 10, 12 are handled correctly and reflect genuinely careful design. **6, 7, 8 all trace to the same root cause** and are fixed by the same change.

---

## 10. Implementation roadmap

Incremental. No rewrite — the gateway's release/deployment logic is sound and should be preserved.

### Phase 1 — Close the bricking risk *(highest value per unit effort)*

1. Override `verifyRollbackLater()` → `true` in the sketch; call `esp_ota_mark_app_valid_cancel_rollback()` only after WiFi + gateway heartbeat succeed; `esp_ota_mark_app_invalid_rollback_and_reboot()` on failure. Add a watchdog for the hang case.
2. Pin **one** Arduino core version across CI and arduino-cli (§4.5).
3. Configure the CI secrets; make signing hard-fail rather than publishing unsigned.

*Exit criteria:* a deliberately broken firmware, deployed to a test device, rolls back automatically and the device reappears on the previous version.

### Phase 2 — Device identity and authenticated telemetry

4. `POST /api/devices/register`; per-device token issued at registration, stored in NVS.
5. Authenticate `POST /api/heartbeat` with that token (flagged transition to avoid stranding fielded devices).
6. Move `DEVICE_ID` from compile-time constant to chip-ID-derived at runtime.
7. Add gateway-side audit logging.

*Closes threats #10, #11, and forged deployment confirmation.*

### Phase 3 — Pipeline continuity and persistence

8. `POST /api/github/webhook` — auto-ingest a published Release; verify HMAC **and** re-verify artifact signature.
9. Extend the state machine to the full §7 set via `POST /api/devices/{id}/ota/status`.
10. Migrate to PostgreSQL per §6. Do this *after* the auth model settles.
11. Fix the unmounted `lib/db.ts` `.data` directory (§4.2).

### Phase 4 — Hardening *(only for a production fleet)*

12. Secure Boot v2 + Flash Encryption. **Irreversible; bricks on error. Never on dev boards.**
13. Hardware anti-rollback (`CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK` + eFuse secure version).
14. Signing keys into an HSM or cloud KMS; define rotation and revocation — closes threat #8.
15. Consider a `factory` partition for guaranteed recovery (§1.1), accepting the flash cost.
16. Staged/canary rollout using the existing evidence-based deployment records.

### Explicitly not recommended

- Rewriting `release.py` / `deployment.py` — the evidence-based model is correct
- Replacing the shared-secret model before per-device identity exists — sequencing matters
- Integrating `SecureOTA-IDE` into the OTA path (§4.6)
- Immediate PostgreSQL migration — JSON state is adequate at current scale

---

## Summary of verified defects

| # | Defect | Severity | Phase |
|---|---|---|---|
| 1 | Rollback auto-disarmed before `setup()` — boot-loop unrecoverable | **Critical** | 1 |
| 2 | CI and IDE build with different Arduino cores | High | 1 |
| 3 | `POST /api/heartbeat` unauthenticated — forgeable telemetry and deployment confirmation | High | 2 |
| 4 | No per-device identity; one shared fleet key | High | 2 |
| 5 | Signing keys in CI secrets, no rotation/revocation | High | 4 |
| 6 | GitHub Release → gateway delivery is manual | Medium | 3 |
| 7 | `lib/db.ts` writes to an unmounted directory — data loss on recreate | Medium | 3 |
| 8 | Secure-OTA failure falls back to unauthenticated plain OTA | Medium | 2 |
| 9 | CI publishes unsigned binaries when secrets absent | Medium | 1 |
| 10 | No factory partition — no guaranteed recovery image | Low | 4 |
