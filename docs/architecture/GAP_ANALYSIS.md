# SecureOTA — Gap Analysis

**Method:** every row below was verified by reading source or running a search against it. Where a README, a type declaration, or a config flag claims a capability that the code does not deliver, the row says so explicitly and names the evidence. No row is marked present on documentation alone.

**Repositories inspected**
- `Rithik-sharma12/Secure_OTA_Update_Security_Mechanism` — gateway, dashboard, firmware, CI
- `riteshvijaykumar/SecureOTA-IDE` — Arduino IDE fork scaffold

**Priority key:** P0 device-bricking / safety · P1 security · P2 functional completeness · P3 scale & hardening

---

## 1. Verification notes — claims that did not survive inspection

Four capabilities appear to exist from documentation, type declarations, or config flags, but do not function. These are the reason this document exists.

| Apparent claim | Evidence it appears present | Verified reality |
|---|---|---|
| **Rollback / recovery** | `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y` in shipped sdkconfig | `esp32-hal-misc.c:222-239` calls `esp_ota_mark_app_valid_cancel_rollback()` inside `initArduino()`, before `setup()`. Sketch overrides neither weak hook (`verifyOta`, `verifyRollbackLater`) — grep returns nothing. **Rollback window closes before app code runs.** |
| **Authorization / RBAC** | `role: 'admin' \| 'operator' \| 'viewer'` typed in `lib/local-database.ts:16` and `lib/client-auth.ts:7` | Searched every `.ts`/`.tsx` for a role comparison (`===`, `!==`, `includes`, `requireRole`). **Zero matches.** `withSecureApi` exposes only `requireAuth?: boolean`. Any authenticated user can deploy firmware. |
| **Device registration** | README language; `/api/devices/register` in the architecture brief | No such route in gateway (16 endpoints enumerated) or dashboard (14 route files enumerated). Devices materialise as a side effect of first heartbeat, `routes/heartbeat.py:59-66`. |
| **GitHub integration in backend** | Listed as a platform capability | `grep -ri 'github\|webhook' src/implementation/gateway/` returns **zero matches**. The dashboard has `webhooks` routes, but they are unrelated to GitHub releases. |

---

## 2. Feature-by-feature gap table

### Identity, authentication, authorization

| Feature | Current implementation | Required implementation | Files involved | Gap | Priority |
|---|---|---|---|---|---|
| Operator authentication | **Working.** scrypt password hash, sha256 token hash, expiry + revocation, session cookie | Keep as-is | `CODE/OTA_IDE/lib/auth.ts`, `lib/local-database.ts` | None | — |
| Operator authorization (RBAC) | **Absent.** `role` field stored and typed but never read; no comparison anywhere in codebase | Enforce role at route level; deployment and firmware publish restricted to `admin`/`operator` | `lib/api-security.ts` (add `requiredRole`), all `app/api/**/route.ts` | Declared but never enforced | **P1** |
| Device identity | **Weak.** `DEVICE_ID` is a compile-time `#define`; every device flashed from one build shares one identity | Derive from chip ID / eFuse MAC at runtime; unique per device | `CODE/frimware_code/esp32_ota_main/ota_config.h:33`, `esp32_ota_main.ino:392` | Not unique per device | **P1** |
| Device registration | **Absent.** No endpoint; devices appear implicitly on first heartbeat | `POST /api/devices/register` issuing a per-device token; bootstrap credential validated | New `gateway/routes/devices.py`, `gateway/state.py` | Entirely missing | **P1** |
| Device credentials | **Absent.** One shared fleet key `OTA_GATEWAY_API_KEY` for all devices and the dashboard | Per-device token, hashed at rest, revocable | New `device_credentials` store; `gateway/auth.py` | No per-device secret | **P1** |
| Telemetry authentication | **Absent.** `POST /api/heartbeat` has no auth dependency — verified by enumerating guards per route file (`heartbeat.py`: 0, `releases.py`: 2, `operations.py`: 2, `deployments.py`: 1) | Require per-device token; flagged transition so fielded devices are not stranded | `gateway/routes/heartbeat.py:36`, `gateway/auth.py` | Anyone reachable can forge any device's telemetry **and falsely confirm deployments** | **P1** |

### Firmware delivery and verification

| Feature | Current implementation | Required implementation | Files involved | Gap | Priority |
|---|---|---|---|---|---|
| Firmware download | **Working.** Manifest poll every 30 s, HTTP/HTTPS with pinned-CA support and NTP sentinel | Keep | `esp32_ota_main.ino:319-366`, `:210-227`, `:173-200` | None | — |
| Firmware integrity | **Working.** SHA-256 over plaintext accumulated during streaming decrypt | Keep | `esp32_ota_main.ino:589` | None | — |
| Firmware authenticity | **Working.** RSA-2048 verify before activation; gateway signs manifests Ed25519 | Keep. Two independent trust paths — do not unify | `esp32_ota_main.ino:624-634`, `gateway/crypto.py` | None | — |
| Write to inactive partition | **Working.** `Update.begin/write/end`; `Updater.cpp:231` refuses the running partition | Keep | `esp32_ota_main.ino:530-641` | None | — |
| Deferred boot activation | **Working.** `Update.end(true)` only after signature verifies; `abort()` otherwise | Keep | `esp32_ota_main.ino:638`, `:646` | None | — |
| Plain-OTA fallback | **Present but unsafe.** Falls back to unauthenticated plain OTA when secure path fails | Gate behind a build flag; disabled in production | `esp32_ota_main.ino:417-432` | Silent downgrade of security posture | **P1** |
| Version management | **Working.** `major*10000+minor*100+patch`, normalised, version uniqueness enforced at publish | Keep | `gateway/utils.py:72-97`, `esp32_ota_main.ino:782-808` | None | — |
| Anti-rollback (application) | **Working and symmetric.** Gateway advertises only strictly-newer; device refuses downgrade before download | Keep | `gateway/utils.py:95`, `gateway/routes/heartbeat.py:114-123`, `esp32_ota_main.ino:298` | None | — |
| Anti-rollback (hardware) | **Absent.** `# CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK is not set` | eFuse secure version — production fleet only, irreversible | sdkconfig; requires Secure Boot v2 | Bypassable via USB | P3 |
| **Rollback / recovery** | **Absent in practice.** Bootloader capable, but image auto-marked valid before `setup()` | Override `verifyRollbackLater()`; validate only after health check; `esp_ota_mark_app_invalid_rollback_and_reboot()` on failure; watchdog backing | `esp32_ota_main.ino` (setup/loop), `+#include "esp_ota_ops.h"` | **Failed update bricks device — USB reflash only** | **P0** |
| Post-update health check | **Absent.** No gate between boot and "declared good" | WiFi associated + heartbeat accepted + ASH above threshold, within a deadline | `esp32_ota_main.ino` setup path | Nothing distinguishes "booted" from "working" | **P0** |
| Recovery partition | **Absent.** `default.csv` has no `factory` partition; `app0` is an OTA slot | Optional factory image for guaranteed recovery | partition CSV, `platformio.ini` | No image OTA cannot overwrite | P3 |

### Provisioning and local tooling

| Feature | Current implementation | Required implementation | Files involved | Gap | Priority |
|---|---|---|---|---|---|
| COM port detection | **Working.** Enumerates local ports, validates against connected set before flashing | Keep | `CODE/OTA_IDE/lib/serial-port-detection.ts`, `app/api/serial-ports/route.ts` | None | — |
| Serial flashing | **Working.** Async job `queued→compiling→uploading→success/failed`, progress scraped, logs polled | Keep | `lib/serial-upload-jobs.ts`, `app/api/serial/upload/**` | Non-functional in Docker (no serial HW) — expected | — |
| WiFi provisioning at flash | **Working, uncommitted.** Credentials injected into a temp copy of `ota_config.h`; workspace deleted in `finally` | Commit it | `lib/serial-upload-jobs.ts`, `components/devices/DeviceConnectionCard.tsx`, `app/api/serial/upload/route.ts` | Not yet committed | **P2** |
| Backend/COM separation | **Correct.** Gateway contains no serial code; flashing runs in the operator's process | Keep — architectural invariant | — | None | — |

### Release pipeline

| Feature | Current implementation | Required implementation | Files involved | Gap | Priority |
|---|---|---|---|---|---|
| CI build | **Working, inert.** Builds 3 boards; compile is a hard gate. Zero secrets configured | Configure secrets | `.github/workflows/firmware-release.yml` | Inert until secrets set | **P2** |
| Automated firmware tests | **Absent.** `pio check` is advisory (`continue-on-error: true`); no unit tests | Host-side unit tests for version arithmetic, padding, manifest parsing | New `test/` under `frimware_code` | Compile is the only real gate | P2 |
| Firmware signing in CI | **Present, fails open.** Publishes **unsigned** binaries with a warning when keys absent | Hard-fail on missing keys for release tags | `.github/workflows/firmware-release.yml` | Unsigned release possible | **P1** |
| Toolchain consistency | **Broken.** CI uses core **2.0.17**; IDE uses arduino-cli core **3.3.8** | Pin one version in both | `platformio.ini`, arduino-cli config | CI does not validate what ships | **P0** |
| Release → gateway delivery | **Absent.** Operator downloads from GitHub and re-uploads manually | `POST /api/github/webhook`; verify HMAC **and** re-verify artifact signature | New `gateway/routes/github.py` | Pipeline stops at GitHub | P2 |
| Firmware publish (manual) | **Working.** Multipart upload; dashboard attaches gateway key server-side; browser never sees it | Keep | `gateway/routes/releases.py:70`, `app/api/firmware/publish/route.ts` | None | — |
| Release integrity | **Working.** Measured 4-stage pipeline; read-back verify aborts publish on mismatch | Keep | `gateway/release.py:180-346` | None | — |

### Deployment, monitoring, audit

| Feature | Current implementation | Required implementation | Files involved | Gap | Priority |
|---|---|---|---|---|---|
| Deployment tracking | **Working.** Evidence-based: `pending→confirmed` only on heartbeat reporting target version; never writes `device['fw']`; lazy expiry | Keep — do not rewrite | `gateway/deployment.py` | None | — |
| OTA state granularity | **3 states** (`pending`/`confirmed`/`failed`) — gateway sees only heartbeats | 11-state machine via `POST /api/devices/{id}/ota/status` | `gateway/deployment.py`, new route, firmware reporting | No download/verify/install visibility | P2 |
| Automatic deployment | **Absent.** Deployments are created manually | Policy-driven auto-assign on release publish | `gateway/deployment.py` | Manual step | P2 |
| Device monitoring | **Partial.** Latest state only — heartbeat *replaces* the device record wholesale | Retain history | `gateway/routes/heartbeat.py:82-96` | No historical view | P2 |
| Telemetry storage | **Partial.** Last value + 50-entry rolling log per device. No time-series | Append-only telemetry table | `gateway/state.py`, `config.py:34` | Cannot chart trends or investigate past incidents | P2 |
| Events / alerts | **Working but volatile.** FIFO-capped at 500 / 200 | Durable retention | `gateway/state.py:77,84`, `config.py:35-36` | Silently discards history | P2 |
| Audit logs | **Partial.** Dashboard writes one row per API request; **gateway writes none** | Gateway-side audit with actor identity | `lib/api-security.ts:69`; new gateway audit store | Gateway writes are unaudited | **P1** |
| Persistence | **JSON.** Single lock-guarded dict, atomic whole-file dump | PostgreSQL once schema stabilises | `gateway/state.py` | Breaks at ~10³ devices / multi-replica | P3 |
| Dashboard `.data` durability | **Broken.** `lib/db.ts` hardcodes `process.cwd()/.data`, not volume-mounted | Point at the mounted dir | `CODE/OTA_IDE/lib/db.ts` | Webhook/dead-letter data lost on container recreate | P2 |

### SecureOTA-IDE repository

| Feature | Current implementation | Required implementation | Files involved | Gap | Priority |
|---|---|---|---|---|---|
| Repository state | **Scaffold + uncommitted modules.** One commit (`3c4cd45`); working tree has implemented GitHub client, packet crypto, device registry, UDP listener, 42 passing tests | Commit the work | `arduino-ide-extension/src/**` | Uncommitted | P2 |
| IDE build | **Impossible here.** Upstream requires Node `>=18.17.0 <21`; machine has Node 24 | Install Node 20 (user decision) | `upstream/arduino-ide-2.3.9/package.json` | Cannot build or run | P3 |
| OTA participation | **None.** Its "Secure OTA" feature is explicitly marked future scope; shares no code with this platform | Keep out of the OTA critical path | — | Not a gap — a scoping decision | — |

---

## 3. Summary

| Priority | Count | Theme |
|---|---|---|
| **P0** | 3 | A failed update bricks the device, and CI does not validate what ships |
| **P1** | 8 | No device identity, no telemetry auth, no authorization, unsigned-release path |
| **P2** | 11 | Pipeline continuity, observability depth, uncommitted work |
| **P3** | 5 | Scale and irreversible hardening |

**What is genuinely solid and must not be rewritten:** the streaming secure installer with deferred activation, the evidence-based deployment model, manifest re-signing over cached bytes, the read-back verification stage, symmetric version arithmetic, and the write-auth dependency pattern in `gateway/auth.py`.

---

## 4. Implementation plan — dependency order

Ordered by *dependency*, not by severity. Where the two conflict, the dependency wins — a fix you cannot verify is not a fix.

```
STAGE 0 ─ Pin the toolchain
             │  (blocks verification of everything below)
             ▼
STAGE 1 ─ Rollback + health gate           ◄── P0, the bricking risk
             │
             ├──────────────────────────────┐
             ▼                              ▼
STAGE 2 ─ Device identity              STAGE 3 ─ Authorization
          → registration                        + gateway audit
          → per-device token                    (independent of 2)
          → heartbeat auth
             │                              │
             └──────────────┬───────────────┘
                            ▼
STAGE 4 ─ CI secrets → hard-fail signing → webhook ingestion
                            │
                            ▼
STAGE 5 ─ Device OTA status reporting → full 11-state machine
                            │
                            ▼
STAGE 6 ─ PostgreSQL migration    (schema must be stable first)
                            │
                            ▼
STAGE 7 ─ Secure Boot v2 · eFuse anti-rollback · HSM   (irreversible)
```

### Stage 0 — Pin the toolchain · P0 · ~1 hour

Pin `platform_packages` in `platformio.ini` and the arduino-cli core to a single Arduino-ESP32 version.

**Why first:** Stage 1 changes rollback behaviour, which differs between core 2.0.17 and 3.3.8. Testing the fix on one core and shipping the other means the test proves nothing. **This blocks meaningful verification of every later stage.**

*Done when:* `pio run` and `arduino-cli compile` report the same core version.

### Stage 1 — Rollback and health gate · P0 · ~1 day

1. Override `verifyRollbackLater()` → `true` in the sketch.
2. Define the health check: WiFi associated **and** heartbeat returned 2xx **and** ASH above quarantine, within a deadline.
3. On pass → `esp_ota_mark_app_valid_cancel_rollback()`. On fail → `esp_ota_mark_app_invalid_rollback_and_reboot()`.
4. Arm a hardware watchdog so a hang forces the reset that triggers bootloader fallback.

**Depends on:** Stage 0.
**Blocks:** nothing — deliberately independent so it can ship immediately.

*Done when:* firmware with a deliberately broken WiFi path, deployed to a test device, returns to the previous version unattended. **Until this passes, no OTA should go to any device you cannot physically reach.**

### Stage 2 — Device identity and authenticated telemetry · P1 · ~3 days

1. `DEVICE_ID` derived from eFuse MAC at runtime, replacing the `#define`.
2. `POST /api/devices/register` → issues a per-device token; store `token_hash` only.
3. Persist the token in NVS alongside the ASH score.
4. Guard `POST /api/heartbeat` with the token, behind `OTA_REQUIRE_DEVICE_AUTH` so fielded devices are not stranded mid-migration.
5. Gate the plain-OTA fallback behind a build flag.

**Depends on:** Stage 1 (do not change the boot path twice; identity changes affect first-boot behaviour).
**Closes:** forged telemetry, false deployment confirmation, fleet impersonation.

### Stage 3 — Authorization and gateway audit · P1 · ~2 days · *parallel with Stage 2*

1. Add `requiredRole` to `withSecureApi`; enforce on publish, deploy and command routes.
2. Add a gateway-side audit store; write one row per state-mutating request.

**Depends on:** nothing. Genuinely parallelisable — different files, different repo areas.

### Stage 4 — Pipeline continuity · P2 · ~2 days

1. Set the nine CI secrets (**your action** — I will not enter credentials).
2. Make signing hard-fail on release tags.
3. `POST /api/github/webhook` — verify HMAC **and** re-verify the artifact signature before ingest.

**Depends on:** Stages 2–3 (the webhook is a write endpoint; it needs auth and audit to already exist).

### Stage 5 — Full OTA state machine · P2 · ~3 days

`POST /api/devices/{id}/ota/status`; firmware reports `DOWNLOADING → VERIFYING → INSTALLING → REBOOTING → HEALTH_CHECK`; extend `deployment.py` to consume it.

**Depends on:** Stage 2 — without per-device auth, progress reports are forgeable and the richer state machine would be *less* trustworthy than the current three-state one.

### Stage 6 — PostgreSQL · P3 · ~5 days

Schema per the architecture doc; migrate gateway state and dashboard NeDB. Also fix `lib/db.ts`'s unmounted `.data` path.

**Depends on:** Stages 2–5 — every one of them adds or changes tables. Migrating earlier means migrating twice.

### Stage 7 — Irreversible hardening · P3 · production only

Secure Boot v2, Flash Encryption, eFuse anti-rollback, signing keys to HSM/KMS, optional factory partition.

**Depends on:** everything above, proven in the field. **eFuse burns cannot be undone and brick the device on error. Never on development boards.**

---

## 5. Recommended first move

**Stages 0 and 1 together.** Roughly one day, no API changes, no database changes, no coordination with other work — and it converts "a bad release bricks the fleet" into "a bad release rolls itself back".

Everything else is a security or completeness improvement on a platform whose worst failure mode is currently unrecoverable without physical access.

**Awaiting approval before implementing.**
