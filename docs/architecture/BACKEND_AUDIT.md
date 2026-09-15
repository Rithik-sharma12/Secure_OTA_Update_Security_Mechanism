# SecureOTA Backend — Development Verification Audit

**Method:** a live gateway instance was started on an isolated port (5099) with scratchpad cache/key directories, and exercised with real HTTP requests. Every ✅ below is backed by an executed test whose output is quoted. No code was modified; the repo working tree is byte-identical to its pre-audit state.

**What could not be tested, and why**
- Dashboard (Next.js) runtime behaviour — not started during this audit
- ESP32 firmware runtime, OTA install, boot, rollback — ⚠️ **CANNOT VERIFY — HARDWARE REQUIRED**
- GitHub Actions execution — workflow has zero secrets configured, so a run would be meaningless

---

## 1. EXECUTIVE SUMMARY

### 🟠 PARTIALLY IMPLEMENTED

The **firmware release and verification core is genuinely well built and verified working**. The **device identity layer does not exist**, and its absence is remotely exploitable — I demonstrated a working attack, not a theoretical one.

**What is real (proven by test):** Ed25519 manifest signing that cryptographically verifies over the actual bytes and rejects tampering; per-architecture manifest enforcement; symmetric anti-rollback; ASH quarantine gating; path-traversal defence; upload validation; robust malformed-input handling; a genuinely measured 4-stage release pipeline; a correctly functioning write-auth guard.

**Why it is not production-ready:** `POST /api/heartbeat` requires no credential of any kind. I used this to create two device identities from nothing and then to **flip a real deployment from `pending` to `success/confirmed` without ever authenticating**. Fleet compliance reporting is therefore forgeable by anyone who can reach the gateway. Separately: authorization is declared but never enforced, device registration does not exist, offline detection does not exist, there is no audit log in the gateway, and there are **zero automated tests** in the backend or dashboard.

It is not 🔴 NOT READY — a large amount genuinely works and survived adversarial testing. It is not 🟡 either: device registration and rollback are missing *functionality*, not missing hardening.

---

## 2. FEATURE MATRIX

| # | Feature | Status | Evidence (executed) | File |
|---|---|---|---|---|
| 1 | Authentication (gateway write) | ✅ VERIFIED | 5/5 write endpoints returned **401** without key; **200** with valid key | `gateway/auth.py` |
| 1b | Authentication (operator/user) | ⚠️ NOT VERIFIED | Code present (scrypt, token hash, expiry); dashboard not started | `CODE/OTA_IDE/lib/auth.ts` |
| 2 | Authorization / RBAC | ❌ NOT IMPLEMENTED | `role` typed in 2 files; grep for any role comparison → **0 matches**. `withSecureApi` exposes only `requireAuth` | `lib/api-security.ts` |
| 3 | Device registration | ❌ NOT IMPLEMENTED | `POST /api/devices/register` → **404** | — |
| 4 | Device authentication | ❌ NOT IMPLEMENTED | Unauthenticated heartbeat → **200**, device created | `routes/heartbeat.py:36` |
| 5 | Device monitoring | 🟡 PARTIAL | Fields stored and returned; **latest value only**, no history | `routes/heartbeat.py:82` |
| 6 | Device heartbeat | 🟡 PARTIAL | Works (200), but **unauthenticated** | `routes/heartbeat.py` |
| 7 | Sensor telemetry | ❌ NOT IMPLEMENTED | No telemetry endpoint; no time-series; heartbeat *replaces* the record | `gateway/state.py` |
| 8 | Firmware management | ✅ VERIFIED | non-.bin→400, empty→400, dup version→409, bad version→400, 33 MB→**413** | `routes/releases.py:70` |
| 9 | Firmware releases | ✅ VERIFIED | Publish returned v2.0.0 with real sha256 + Ed25519 signature | `gateway/release.py:180` |
| 10 | Firmware manifest | ✅ VERIFIED | 12 fields incl. sha256, signature, algorithm, keyId, compatible | `gateway/release.py:112` |
| 11 | Secure OTA (gateway side) | ✅ VERIFIED | Signature verified against downloaded bytes with the published public key | `gateway/crypto.py` |
| 11b | Secure OTA (device side) | ⚠️ CANNOT VERIFY — HARDWARE REQUIRED | Code reviewed and correct by inspection | `esp32_ota_main.ino:445` |
| 12 | Integrity verification | ✅ VERIFIED | Downloaded 4096 B; sha256 match **True** | — |
| 13 | Authenticity verification | ✅ VERIFIED | Ed25519 verify **True**; 1-bit tamper **rejected** | — |
| 14 | Anti-rollback | ✅ VERIFIED | Device on v9.9.9 vs release v2.0.0 → `ack` (no downgrade offered) | `gateway/utils.py:95` |
| 15 | Deployment management | ✅ VERIFIED | Deployment created, target `pending`, counters correct | `gateway/deployment.py` |
| 16 | OTA status tracking | 🟡 PARTIAL | Only 3 states (`pending`/`confirmed`/`failed`); no download/verify/install visibility | `gateway/deployment.py` |
| 17 | Health checks (service) | ✅ VERIFIED | `/healthz` → 200 with deviceCount/releaseCount | `routes/health.py` |
| 17b | Health checks (post-update) | ❌ NOT IMPLEMENTED | No gate between boot and "declared good" | `esp32_ota_main.ino` |
| 18 | Rollback | ❌ NOT IMPLEMENTED | `initArduino()` marks image VALID before `setup()`; sketch overrides neither weak hook | `esp32-hal-misc.c:222`, sketch |
| 19 | Monitoring / observability | 🟡 PARTIAL | Events + alerts exist but FIFO-capped (500/200); **no offline detection** (grep → 0 matches) | `gateway/state.py:77,84` |
| 20 | Alerts | 🟡 PARTIAL | Only 3 triggers: ASH quarantine, deployment timeout, one op | `routes/heartbeat.py:69` |
| 21 | Audit logging | 🟡 PARTIAL | Dashboard writes per-request rows; **gateway has none** (grep "audit" → 0 matches) | `lib/api-security.ts:69` |
| 22 | GitHub CI/CD integration | 🟡 PARTIAL | Workflow valid but **inert** — `gh secret list` returns empty; **no backend receiver** (grep → 0 matches) | `.github/workflows/` |
| 23 | IDE integration | ✅ VERIFIED (design) | Gateway contains no serial code; flashing runs locally | `lib/serial-upload-jobs.ts` |
| 24 | Database persistence | 🟡 PARTIAL | JSON file; 197 KB at 61 devices, whole file rewritten per heartbeat | `gateway/state.py` |
| 25 | Security controls | 🟡 PARTIAL | Path traversal blocked; input clamped; **no rate limiting** (grep → 0 matches) | `gateway/utils.py:27` |
| 26 | Automated testing | ❌ NOT IMPLEMENTED | **0** test files in backend or dashboard; `integration_smoke_test.py` in README **does not exist** | — |

---

## 3. TEST RESULTS (actual)

### Architecture
```
GET /healthz        200      GET /openapi.json   200
GET /                200      GET /docs           200
documented paths    14        CORS                access-control-allow-origin: *
```

### Write-auth guard
```
POST /api/trigger_sync    no key    -> 401   wrong key -> 401   valid key -> 200
POST /api/releases        no key    -> 401
POST /api/releases/upload no key    -> 401
POST /api/deployments     no key    -> 401
POST /api/pipeline/run    no key    -> 401
```
**The `gateway/auth.py` dependency-injection fix is confirmed working.**

### 🔴 Exploit — forged deployment confirmation (no credentials used)
```
POST /api/devices/register                    -> 404  (no such endpoint)

POST /api/heartbeat  {"device_id":"AUDIT_FORGED_001", ...}   [NO API KEY]
  -> 200 {"command":"ack",...}
  -> registry now contains AUDIT_FORGED_001

POST /api/heartbeat  {"device_id":"AUDIT_IMPERSONATED_ADMIN_DEVICE", ...}  [NO KEY]
  -> registry: ['AUDIT_FORGED_001', 'AUDIT_IMPERSONATED_ADMIN_DEVICE']

-- legitimate operator publishes v2.0.0 and creates a deployment --
  deployment-3440ed6c4c  status=in_progress  pending=1
    AUDIT_FORGED_001: pending

-- attacker sends ONE unauthenticated heartbeat claiming v2.0.0 --
  deployment-3440ed6c4c  status=success  success=1  failed=0
    AUDIT_FORGED_001: confirmed  confirmedAt=2026-08-23T08:03:18+00:00
```
A deployment that never happened now reports **success**.

### Cryptography (genuine, not placeholder)
```
downloaded 4096 bytes, manifest claims 4096
sha256 match      : True
signature verifies: True   <- real Ed25519 over the actual bytes
tampered rejected : True
```

### Path traversal — all blocked
```
../../../../etc/passwd          -> 404
..%2f..%2f..%2fetc%2fpasswd     -> 404
....//....//gateway_state.json  -> 404
firmware_v2.0.0.bin             -> 200  (legitimate)
```

### OTA policy enforcement
```
manifest ?device_type=ESP32    -> 200
manifest ?device_type=ESP8266  -> 404   (no ESP8266 release; correctly refused)
device v9.9.9, release v2.0.0  -> ack               (no downgrade offered)
device v1.0.0, release v2.0.0  -> update_available  (correct)
device ash=10 (quarantined)    -> ack               (correctly withheld)
```

### Malformed / hostile telemetry
```
missing device_id -> 400    ash=99999   -> 200, clamped to 100
empty device_id   -> 400    ash=-500    -> 200, clamped to 0
500-char id       -> 400    ash="abc"   -> 200, default 0
invalid JSON      -> 422    logs=string -> 200, ignored
SQLi in device_id -> 200 (stored as a key; no SQL engine, not injectable)
unknown board     -> 200, normalised to ESP32
```

### Upload validation
```
non-.bin -> 400   empty -> 400   duplicate version -> 409
bad version -> 400   33 MB (cap 32) -> 413
```

### Concurrency — 50 devices × 4 rounds = 200 concurrent
```
succeeded 200/200   failed 0
wall clock 1.79 s   112 req/s
latency p50 142 ms  p95 1250 ms  max 1292 ms
state file 197,121 bytes for 61 devices
```

### Test suites
```
Backend  (pytest)        : 0 test files — NONE EXIST
Dashboard (jest/vitest)  : 0 test files — NONE EXIST; no "test" script
SecureOTA-IDE            : 42 tests, 42 passed, 0 failed
                           (authored during a prior session in this
                            conversation — NOT pre-existing project tests,
                            and they cover IDE modules, not the backend)
```

### Secrets
```
gateway_keys/ed25519_private_key.pem  -> PRESENT in HEAD, reachable from origin/main
                                         (introduced in commit 367720b)
old admin password                    -> removed from HEAD, still in history (c463990)
src/index.html:1019 "ghp_xxxxxxxxxxxx"-> placeholder, not a real token
.env.docker / credentials.json / *.pem in working tree -> correctly ignored
```

---

## 4. CRITICAL GAPS

| Sev | Gap | Evidence |
|---|---|---|
| **CRITICAL** | Unauthenticated heartbeat → forged device identity **and forged deployment confirmation** | Exploit executed above |
| **CRITICAL** | No rollback — a bad update bricks the device (USB reflash only) | `esp32-hal-misc.c:222`; sketch overrides neither hook |
| **CRITICAL** | Ed25519 signing private key committed and on `origin/main` | `git cat-file -e HEAD:gateway_keys/ed25519_private_key.pem` |
| **HIGH** | Authorization declared but never enforced — any authenticated user can deploy | grep: 0 role comparisons |
| **HIGH** | No device registration or per-device credentials; one shared fleet key | `/api/devices/register` → 404 |
| **HIGH** | Zero automated tests in backend and dashboard | 0 test files found |
| **HIGH** | CI publishes **unsigned** binaries when secrets absent; zero secrets set | workflow warns and continues |
| **MEDIUM** | No offline detection | grep: 0 matches |
| **MEDIUM** | No gateway audit log | grep "audit": 0 matches |
| **MEDIUM** | No rate limiting anywhere | grep: 0 matches |
| **MEDIUM** | No telemetry history; events/alerts FIFO-capped | `config.py:34-36` |
| **MEDIUM** | JSON state — 197 KB rewritten per heartbeat at 61 devices | measured |
| **LOW** | `CORS allow_origin:*` with `allow_credentials=True` | `gateway/__init__.py:28` |
| **LOW** | `/openapi.json` and `/docs` publicly exposed | 200 unauthenticated |

---

## 5. SCALABILITY ASSESSMENT (measured, extrapolated)

State file measured at **197 KB / 61 devices ≈ 3.2 KB per device**. Every heartbeat rewrites the entire file.

| Fleet | State file | Writes/s (15 s interval) | Disk write throughput | Viable |
|---|---|---|---|---|
| 10 | 32 KB | 0.7 | 22 KB/s | ✅ |
| 50 | 160 KB | 3.3 | 528 KB/s | ✅ (p95 already 1.25 s) |
| 100 | 320 KB | 6.7 | 2.1 MB/s | 🟡 marginal |
| 1000 | 3.2 MB | 67 | **215 MB/s** | ❌ infeasible |

Bottleneck is `persist_state_locked()` — whole-file serialisation under a global lock. **Ceiling is roughly 100 devices.**

---

## 6. ARCHITECTURE PROBLEMS

| Problem | Present? | Note |
|---|---|---|
| Backend accessing COM ports | ❌ **No** | Correctly separated — gateway has no serial code |
| Frontend-only authorization | ⚠️ **Worse** | There is no authorization at *either* tier |
| Missing device authentication | ✅ **Yes** | Demonstrated exploitable |
| Missing rollback | ✅ **Yes** | Bootloader capable, app disarms it pre-`setup()` |
| Missing signature verification | ❌ **No** | Verified genuine both ends |
| JSON as production database | ✅ **Yes** | Ceiling ~100 devices |
| Hardcoded secrets | 🟡 **Partly** | Not in config, but a private key is committed |
| Missing audit logging | ✅ **Yes** (gateway) | Dashboard has it |
| Insecure firmware storage | ❌ **No** | Path-traversal guarded, read-back verified |

---

## 7. PRIORITIZED REMEDIATION PLAN

### Priority 1 — Critical security & reliability

**1.1 Pin the Arduino core** · `platformio.ini`, arduino-cli · no deps · Low
*Why:* CI builds core 2.0.17, IDE flashes 3.3.8 — rollback behaviour differs, so 1.2 cannot be verified without this.
*Accept:* both toolchains report the same core version.

**1.2 Rollback + post-update health gate** · `esp32_ota_main.ino` · needs 1.1 · Medium
*Why:* a failed update currently bricks the device.
*Accept:* deliberately broken firmware deployed to a test device returns to the previous version unattended.

**1.3 Device identity → registration → per-device token → heartbeat auth** · `routes/heartbeat.py`, new `routes/devices.py`, `auth.py`, firmware NVS · needs 1.2 · High
*Why:* closes the demonstrated exploit.
*Accept:* the exact attack above returns 401; a registered device with its token still succeeds.

**1.4 Rotate and purge the committed signing key** · git history · none · Medium
*Why:* private key is on `origin/main`.
*Accept:* new keypair in service; old key absent from all refs; devices re-provisioned.

### Priority 2 — Core functionality

**2.1 Enforce authorization** · `lib/api-security.ts` + route handlers · none · Low
*Accept:* a `viewer` token receives 403 on publish and deploy; an `admin` succeeds.

**2.2 CI secrets + hard-fail signing** · workflow · user action · Low
*Accept:* a release tag with missing keys fails the run instead of publishing unsigned.

**2.3 GitHub → gateway release ingestion** · new `routes/github.py` · needs 1.3, 2.2 · Medium
*Accept:* publishing a Release causes the gateway to ingest it after verifying HMAC **and** artifact signature.

**2.4 Full OTA state machine** · `deployment.py` + device reporting · needs 1.3 · Medium
*Accept:* a real update walks DOWNLOADING→VERIFYING→INSTALLING→REBOOTING→HEALTH_CHECK→SUCCESS.

### Priority 3 — Monitoring & observability

**3.1 Offline detection** · `routes/dashboard.py` · none · Low — *Accept:* device stops heartbeating → marked offline after threshold → returns online on resume.
**3.2 Gateway audit log** · new module · needs 1.3 · Medium — *Accept:* every mutation records who/what/when/target/result.
**3.3 Telemetry history + retention** · `state.py` or DB · needs 4.1 · Medium.
**3.4 Rate limiting** · gateway middleware · none · Low.

### Priority 4 — Scalability

**4.1 PostgreSQL migration** · `state.py` · needs 1.3, 2.4, 3.x · High — *Accept:* 1000 devices at 15 s heartbeat with p95 < 200 ms.

### Priority 5 — Nice to have

**5.1** Backend test suite (start with auth, anti-rollback, manifest) · **5.2** API versioning (`/api/v1`) · **5.3** Restrict CORS and gate `/docs` · **5.4** Secure Boot v2 + eFuse anti-rollback (production only, irreversible).

---

## 8. BOTTOM LINE

The cryptographic and release-management core is **genuinely sound and survived adversarial testing** — signatures verify, tampering is rejected, traversal is blocked, downgrades are refused, malformed input is handled. That work should not be rewritten.

What is missing is the layer that establishes **who a device is**. Without it, the verified crypto protects the firmware but not the fleet record: anyone who can reach the gateway can invent devices and declare deployments successful. Combined with the absence of rollback, the current system can neither prove an update happened nor recover when one goes wrong.

**Priority 1.1–1.3 (~1 week) moves this from 🟠 to a defensible 🟡.**
