# Backend Operations & Implementation Checklist

Scope: the gateway (FastAPI, `src/implementation/gateway/`) and the dashboard's
server-side API (`CODE/OTA_IDE/app/api/`). This is a working checklist — tick
items as they are verified against a running instance, not just read in source.

Legend: `[x]` done/verified · `[~]` partial · `[ ]` open · 🔴 critical · 🟠 important · 🟢 nice-to-have

---

## 1. Gateway endpoints — does each one work?

Exercise these with curl against a running gateway (local: `http://localhost:5000`).
Write endpoints need `x-api-key: <OTA_GATEWAY_API_KEY>`.

### Read paths (no auth)
- [ ] `GET /` — root banner, returns `releaseCount`, `deviceCount`, mode URL
- [ ] `GET /healthz` — 200 with `status: ok` (this is the container healthcheck)
- [ ] `GET /api/dashboard` — full snapshot: devices, events, alerts, releases, pipeline
- [ ] `GET /api/events?limit=N` — event log, newest first, honours `limit`
- [ ] `GET /api/deployments` — lists assignments; **lazily expires stale ones** on read
- [ ] `GET /api/releases` — release list
- [ ] `GET /api/releases/latest` — newest release record
- [ ] `GET /releases/latest/manifest` — signed manifest; **404 on a fresh gateway** (normal)
- [ ] `GET /releases/latest/manifest?device_type=ESP32` — per-architecture filtering returns the right build or 404
- [ ] `GET /releases/latest/public-key` — Ed25519 verify key for the manifest
- [ ] `GET /releases/download/{filename}` — serves the `.bin`; reject path traversal (`../`)

### Write paths (require API key)
- [ ] `POST /api/heartbeat` — **401 without key** (F-1 fix), 200 with key; updates device state
- [ ] `POST /api/deployments` — creates an assignment; **never writes `device['fw']`**
- [ ] `POST /api/releases` (JSON) — reads `.bin` from gateway filesystem path (CLI only)
- [ ] `POST /api/releases/upload` (multipart) — dashboard path; needs `python-multipart`
- [ ] `POST /api/pipeline/run` — runs artifact → store → sign → **verify** (SHA-256 re-read)
- [ ] `POST /api/trigger_sync` — 401 without key, 200 with

### Auth guard — must stay true
- [ ] Every write route imports `require_write_auth` from `gateway.auth` directly
- [ ] No route module reassigns `_require_write_auth` from `create_app()` (the silent-noop trap)
- [ ] Confirm: unauth `POST /api/trigger_sync` and `POST /api/releases/upload` → 401

---

## 2. State, persistence, integrity

- [ ] `STATE` mutations happen under `STATE_LOCK`; `*_locked` helpers only called with the lock held
- [ ] `persist_state_locked()` writes atomically to `gateway_firmware_cache/gateway_state.json`
- [ ] Boot `load_state()` rebuilds and **re-signs** the manifest from the cached binary
- [ ] Signing keys (`gateway_keys/`) + cache dir survive a container recreate (named volumes)
- [ ] Pipeline `verify` stage aborts the release on SHA-256 mismatch (don't fabricate stages)
- [ ] Deployment target moves `pending → confirmed` only on a heartbeat reporting the target version
- [ ] Deployment `→ failed` on arch mismatch / ASH quarantine / rollback attempt / 30-min deadline
- [ ] Per-arch `compatible` list enforced; empty list = universal (back-compat)
- [ ] `update_available` fires only for a **strictly newer** compatible build

---

## 3. Dashboard server API (`CODE/OTA_IDE/app/api/`)

- [ ] `withSecureApi(...)` wraps every internal route (DB init, admin bootstrap, audit row)
- [ ] `POST /api/auth/login` — scrypt verify, issues token; `logout` revokes; `session` reflects state
- [ ] `POST /api/firmware/publish` — authenticates session, forwards `.bin` to gateway with shared key (key never reaches browser)
- [ ] `GET /api/runtime/snapshot` — merges gateway `/api/dashboard` + manifest into one `RuntimeSnapshot`
- [ ] `POST /api/serial/upload` + `GET /api/serial/upload/[jobId]` — job lifecycle (non-functional inside Docker, no serial HW)
- [ ] `/api/runtime/command` — **stays disabled** unless `OTA_RUNTIME_COMMANDS_ENABLED=true`; allowlist + destructive blocklist both intact
- [ ] `POST /api/ota/check` — OTA check path returns correct manifest/no-update signal
- [ ] Webhook routes (`/api/webhooks`, `[eventId]/retry`, `cron/webhooks`) — retry worker runs only in production build (disabled in `NODE_ENV=development`)

### Host access & network discovery (added 2026-08-27)
- [ ] `GET /api/host/access` — reports detected COM ports + local IPv4 networks, each flagged granted/not-granted, plus the account's active grants
- [ ] `POST /api/host/access` — records a grant for `serial:<COMx>` or `network:<cidr>`; re-granting refreshes, never duplicates
- [ ] `DELETE /api/host/access` — revokes a grant by id (scoped to the owning user)
- [ ] `POST /api/serial/upload` — **403 with `requiresGrant`** when the target COM port has no active grant (consent gate)
- [ ] `POST /api/network/scan` — **403** without a network grant on that subnet; otherwise bounded TCP sweep (/24 max) returns responding hosts
- [ ] Grants expire (`OTA_ACCESS_GRANT_TTL_HOURS`, default 12) and are stored in `access-grants.db` (mounted `sentinel_ota_ide_db` volume)
- [ ] UI: `HostAccessCard` on the Devices page grants/revokes and runs discovery; discovered host → "Deploy via OTA" preloads the OTA target

---

## 4. Configuration & deployment sanity

- [ ] `EDGE_GATEWAY_API_KEY` (dashboard) == `OTA_GATEWAY_API_KEY` (gateway)
- [ ] No value in `.env.docker` contains a literal `$` (compose interpolates it)
- [ ] Mode URL (`OTA_LOCAL_URL` / `OTA_PUBLIC_URL`) is **routable from the device network** — never `localhost` in a manifest
- [ ] Firmware build mode matches server mode (local HTTP vs cloud HTTPS + pinned CA)
- [ ] Authoritative mode check: `docker exec secure_ota_gateway python -c "from gateway.config import PUBLIC_BASE_URL; print(PUBLIC_BASE_URL)"`
- [ ] cloud → local switch uses `--remove-orphans` (else cloudflared stays up, still public)
- [ ] Stop the gateway before editing anything in its persistent volume (it re-persists on next write)
- [ ] Never `docker compose down -v` (destroys signing keys + dashboard DB)

---

## 5. Known open issues (must-fix before this is "done")

- [ ] 🔴 **F-2 — no working rollback.** Config enabled but disarmed before `setup()`; a bad OTA bricks the device (USB recovery only). See GAP_ANALYSIS Stage 1.
- [ ] 🔴 **F-3 — Ed25519 private key committed in git history** (`origin/main`, commit `367720b`). Rotate the key and purge history; the exposed key can forge manifests.
- [ ] 🟠 **F-1 fix not committed.** The heartbeat-auth fix runs in the built image only. Commit `gateway/routes/heartbeat.py` so a clean rebuild keeps it.
- [ ] 🟠 **`lib/db.ts` uses unmounted `.data`** — webhook/dead-letter records are lost on container recreate. Point it at a mounted volume.
- [ ] 🟠 **No test suite anywhere.** No pytest/jest/CI test job. `pnpm lint` fails (no eslint installed). Only `pnpm build` + `tsc` gate the dashboard.
- [ ] 🟢 **Scaling ceiling ~100 devices** — whole-file JSON rewrite per heartbeat. Fine for the demo, not for scale.

---

## 6. Further implementation — roadmap

Ordered so each stage unblocks the next.

### Stage 0 — lock it down (do first)
- [ ] Commit the F-1 heartbeat-auth fix
- [ ] Rotate the leaked Ed25519 key; purge `367720b` from history; re-sign manifests with the new key
- [ ] Set Docker Desktop to start on login + restart policy so the stack survives a reboot

### Stage 1 — device safety
- [ ] Fix rollback (F-2): arm `esp_ota_mark_app_valid_cancel_rollback` correctly, verify a bad image auto-reverts on next boot
- [ ] Health-gate confirmation: only mark a deployment confirmed after N good heartbeats post-flash

### Stage 2 — durability & correctness
- [ ] Move gateway `STATE` off whole-file JSON to SQLite (keep the lock semantics, drop the rewrite cost)
- [ ] Mount `lib/db.ts` data dir; verify webhook retries survive a recreate
- [ ] Add a real healthcheck that fails when the manifest can't be signed (not just process-up)

### Stage 3 — testing & CI
- [ ] pytest for the gateway: auth (401/200 matrix), deployment state machine, manifest per-arch filtering, pipeline verify-abort
- [ ] Wire eslint config + install it, or drop the dead `lint` script
- [ ] CI job that runs the gateway tests + `pnpm build` + `tsc` on PRs
- [ ] Convert `docs/architecture/acceptance-test.ps1` into the CI smoke stage

### Stage 4 — operability
- [ ] Structured logging + request IDs on the gateway
- [ ] Metrics endpoint (device count, heartbeat rate, deployment outcomes) for a real dashboard graph
- [ ] Rate-limit `POST /api/heartbeat` to blunt a key-leak abuse
- [ ] Role enforcement in `withSecureApi` (today it only checks *authenticated*, not *authorized*)

### Stage 5 — the tunnel
- [ ] Apply cloudflared `--protocol http2` and confirm large `/api/dashboard` responses stop dropping
- [ ] Or move off Cloudflare Tunnel to a reverse proxy with a real cert

---

_Keep this file updated as items are verified. When a 🔴/🟠 closes, move it to the
PROJECT_LOG timeline with how it was verified.
