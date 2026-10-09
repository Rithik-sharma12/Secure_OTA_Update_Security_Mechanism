# Remote OTA control and USB provisioning

How the website reaches a board in two ways: through the **COM port** of the
computer viewing the dashboard, and over the **internet** through the gateway.

```
                      ┌──────────── operator's computer ────────────┐
 Dashboard (cloud) ──▶│ browser ──▶ SecureOTA agent (127.0.0.1) ──▶ │──USB──▶ ESP32
        │             └─────────────────────────────────────────────┘          │
        │ fleet key (server side only)                                         │ Wi-Fi / internet
        ▼                                                                      ▼
   Edge gateway  ◀──────── heartbeat every 15 s (device token) ─────────────  ESP32
                 ────────▶ response carries queued commands
                 ◀──────── manifest ?device_id=… → assigned release, signed
                 ◀──────── /ota/status and /commands/{id}/result reports
```

The gateway never opens a connection to a device (boards sit behind NAT and
firewalls). Everything it wants a device to do is handed over in the answer to
the device's own heartbeat, so it works on any network the board can reach the
gateway from.

## 1. Flash and provision over the COM port

1. Start the agent on the computer the board is plugged into:
   `python secureota_agent.py` (download it from the dashboard at
   `/agent/secureota_agent.py`; v1.1.0 or newer is needed for provisioning).
2. **Devices → Flash over USB**: pick the COM port and flash the published
   release (or a `.bin`). esptool runs on your computer through the agent.
3. **Devices → Provision over USB**:
   * *Read board* asks the firmware for its id (`SOTA:INFO`). Release builds
     use `DEVICE_ID "auto"`, so the id is derived from the chip MAC, e.g.
     `esp32-a1b2c3d4e5f6`.
   * *Provision board* asks the gateway (through the dashboard server) for a
     token that only this board can use, then writes Wi-Fi, the gateway URL and
     the token into the board's NVS (`SOTA:PROVISION`). The board reboots.
4. Within ~20 s the board heartbeats with its own token and appears in the
   device table.

Provisioned values live in NVS and survive OTA updates. They override the
`ota_config.h` defaults, so **one CI-built binary can be flashed to every
board**. A board with no Wi-Fi configured waits for provisioning instead of
boot-looping. To wipe provisioned settings send `SOTA:RESET-CONFIG`.

### Agent endpoints (loopback only)

| Method | Path | Purpose |
|---|---|---|
| GET | `/device-info?port=COM7` | Board identity, firmware version, Wi-Fi and gateway state |
| POST | `/provision` | `{"port":"COM7","config":{"ssid","password","backend_url","device_token","device_id","hostname","api_key","reset_health"}}` |
| POST | `/flash`, GET `/jobs/{id}`, GET `/monitor` | unchanged |

The Wi-Fi password and token go browser → 127.0.0.1 → USB cable. They are never
sent to the dashboard server, and the agent never echoes them back.

## 2. Update and control a board over the internet

From the device table (⋮ menu):

| Action | What happens |
|---|---|
| **Deploy latest via OTA** | `POST /api/deployments` assigns the newest compatible release to that board. The gateway refuses wrong architecture, quarantined boards and downgrades, then queues an `update` command. |
| **Check for update now** | Queues `check_update`. |
| **Identify (blink LED)** | Queues `identify`. |
| **Restart Device** | Queues `reboot`. |
| **Remove Device** | Deletes the record, its queued commands and its token. |

On the next heartbeat the device receives the command, fetches
`/releases/latest/manifest?device_id=…&device_type=…` (which returns the
release *assigned to it*, not merely the newest one), downloads, verifies
(SHA-256 and, with secure keys, AES-256 + RSA-2048), writes the inactive
partition and reboots. It reports each phase to
`POST /api/devices/{id}/ota/status`; the Status column shows it.

### Post-update health gate and rollback

The firmware now overrides `verifyRollbackLater()`, so a new image boots in
`PENDING_VERIFY`. It must join Wi-Fi and get one heartbeat accepted within
`OTA_HEALTH_GATE_TIMEOUT_SECONDS` (default 120 s):

* **passes** → image marked valid, `succeeded` reported, the dashboard command
  acknowledged;
* **fails or resets** → the bootloader restores the previous image, which
  reports `rolled_back`; the deployment target is failed with the reason
  instead of waiting 30 minutes to time out.

While on probation the device does not start another update.

## 3. Gateway API added

| Method | Path | Auth |
|---|---|---|
| GET | `/api/devices`, `/api/devices/{id}`, `/api/devices/{id}/commands` | open (like `/api/dashboard`) |
| POST | `/api/devices/register` → `{token}` (shown once; re-register rotates) | fleet key |
| POST | `/api/devices/{id}/revoke-token` | fleet key |
| DELETE | `/api/devices/{id}` | fleet key |
| POST | `/api/devices/{id}/commands` `{type, params}` | fleet key |
| POST | `/api/devices/{id}/commands/{cid}/cancel` | fleet key |
| POST | `/api/devices/{id}/commands/{cid}/result` | device token (or fleet key) |
| POST | `/api/devices/{id}/ota/status` `{phase, version, progress, detail}` | device token (or fleet key) |
| POST | `/api/heartbeat` | device token (or fleet key); response now has `commands` and `target_version` |

Command types: `update`, `check_update`, `reboot`, `identify`. Lifecycle:
`queued → delivered → succeeded | failed`, or `expired` after
`OTA_COMMAND_TTL_MINUTES`. A delivered command with no result is re-offered
after 90 s, up to 3 times.

A device token only authorises requests about its own device id. Only its
SHA-256 is stored, and it is never returned by any read endpoint.

## 4. Settings

| Variable | Where | Default | Meaning |
|---|---|---|---|
| `OTA_AUTO_UPDATE` | gateway | `true` | `false` = devices install only what a deployment assigns |
| `OTA_REQUIRE_DEVICE_TOKEN` | gateway | `false` | `true` = a board that has a token can no longer use the fleet key |
| `OTA_COMMAND_TTL_MINUTES` | gateway | `30` | queued command lifetime |
| `OTA_DEVICE_GATEWAY_URL` | dashboard | `OTA_GATEWAY_PUBLIC_URL` | gateway URL written into boards at provisioning |
| `OTA_HEALTH_GATE_TIMEOUT_SECONDS` | firmware | `120` | probation window after an OTA reboot |
| `DEVICE_ID` / `DEVICE_HOSTNAME` | firmware | `"auto"` | MAC-derived unique id |
| `DEVICE_TOKEN` | firmware | `""` | compile-time token (normally provisioned over USB instead) |

Recommended rollout: provision every board with its own token, then set
`OTA_REQUIRE_DEVICE_TOKEN=true` so a fleet key pulled from one board's flash no
longer speaks for the others.

## 5. Verifying

```bash
cd src/implementation && python -m pytest -q        # 146 tests, incl. tests/test_device_control.py
cd CODE/OTA_IDE && npx tsc --noEmit && npx vitest run
```

On hardware: flash v2.5.0 over USB, provision, publish a v2.5.1 build, use
**Deploy latest via OTA** and watch the Status column go
`downloading → rebooting → succeeded`. To see rollback, deploy a build with a
wrong Wi-Fi password provisioned out of reach (or a gateway URL that does not
answer): after 120 s the board returns to v2.5.0 and the deployment shows the
reason.
