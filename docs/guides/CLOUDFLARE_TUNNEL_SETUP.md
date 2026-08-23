# Publishing SentinelOTA on nyx-ctf.tech via Cloudflare Tunnel

Puts the dashboard and the OTA gateway on the public internet with HTTPS,
without opening a single inbound port.

---

## Why a tunnel rather than DNS + port forwarding

`cloudflared` runs beside the stack and makes an **outbound** connection to
Cloudflare. Traffic for your hostnames is delivered back down that connection:

- No port forwarding, no public IP — works behind NAT and CGNAT.
- Your home/college IP never appears in DNS.
- TLS is terminated by Cloudflare; you don't manage certificates.
- Ports 3000/5000 stay unreachable from the internet directly.

```
  Browser ──https──▶ ota.nyx-ctf.tech ─┐
                                       ├─▶ Cloudflare ◀═══ outbound tunnel ═══ cloudflared
  ESP32   ──https──▶ gw.nyx-ctf.tech  ─┘                                            │
                                                                    ┌───────────────┴────────┐
                                                                    ▼                        ▼
                                                              ota_ide:3000            gateway:5000
```

## Hostname plan

| Hostname | Service | Cloudflare Access | Notes |
|---|---|---|---|
| `ota.nyx-ctf.tech` | `ota_ide:3000` | **Yes** | Human dashboard. |
| `gw.nyx-ctf.tech` | `gateway:5000` | **No — must stay open** | Devices call this. |

> **Never put Access in front of `gw.nyx-ctf.tech`.** Access requires an
> interactive browser login. An ESP32 cannot complete that flow — it would
> receive an HTML login page instead of the manifest and every device would
> stop updating. Access goes on the dashboard hostname only.

---

## Part 1 — Cloudflare setup

### Step 1 — Point the domain at Cloudflare

Cloudflare dashboard → **Add a site** → `nyx-ctf.tech`, then change the
nameservers at your registrar to the pair Cloudflare gives you. Wait until the
site reads **Active**. Nothing below works until it does.

### Step 2 — Create the tunnel

**Zero Trust** → **Networks** → **Tunnels** → **Create a tunnel**:

1. Type: **Cloudflared**
2. Name: e.g. `sentinel-ota`
3. On the install screen choose **Docker**, and copy the **token** out of the
   command shown (the long string after `--token`). You don't need to run it.

### Step 3 — Add the token

In `.env.docker` (git-ignored):

```bash
CLOUDFLARE_TUNNEL_TOKEN=eyJhIjoi...
```

### Step 4 — Add both public hostnames

In the tunnel's **Public Hostnames** tab, add two entries:

| Subdomain | Domain | Type | URL |
|---|---|---|---|
| `ota` | `nyx-ctf.tech` | HTTP | `ota_ide:3000` |
| `gw` | `nyx-ctf.tech` | HTTP | `gateway:5000` |

The URL uses the **container name** on the shared Docker network — not
`localhost`, which from `cloudflared`'s perspective is its own container. Type
is `HTTP` because the tunnel's hop to your container is internal; the public
side is HTTPS either way. DNS records are created automatically.

### Step 5 — Start the tunnel

```bash
docker compose -f docker-compose.cloud.yml \
  --env-file Secure_OTA_Update_Security_Mechanism/.env.docker up -d

docker logs -f secure_ota_cloudflared
```

Look for `Registered tunnel connection` (usually four). Verify both hostnames:

```bash
curl -sI  https://ota.nyx-ctf.tech          # expect 307 -> /login
curl -s   https://gw.nyx-ctf.tech/healthz   # expect {"ok":true,...}
```

### Step 6 — Protect the dashboard with Access

**Zero Trust** → **Access** → **Applications** → **Add an application** →
**Self-hosted**:

- Application domain: `ota.nyx-ctf.tech` — **this hostname only**
- Policy: **Allow**, rule **Emails ending in** → your chosen domain

Unauthenticated traffic is then rejected at Cloudflare's edge and never reaches
your machine. You get a Cloudflare identity check *plus* the dashboard's own
login — two independent layers.

Re-check afterwards that the gateway is still open to devices:

```bash
curl -s https://gw.nyx-ctf.tech/healthz     # must still return JSON, not HTML
```

If that returns an HTML login page, Access was applied too broadly (e.g. to
`*.nyx-ctf.tech`). Narrow it to the exact dashboard hostname.

---

## Part 2 — Point the gateway and devices at the public URL

### Step 7 — Update the gateway's advertised URL

The manifest tells devices where to fetch firmware, built from
`OTA_PUBLIC_URL`, which cloud mode maps onto the gateway. In `.env.docker`:

```bash
OTA_PUBLIC_URL=https://gw.nyx-ctf.tech
```

Note there is no `:5000` — Cloudflare serves on 443 and the tunnel maps it.

Recreate the gateway and confirm what devices will be handed:

```bash
docker compose -f docker-compose.cloud.yml --env-file Secure_OTA_Update_Security_Mechanism/.env.docker up -d gateway
curl -s https://gw.nyx-ctf.tech/releases/latest/manifest
```

`downloadUrl` must read `https://gw.nyx-ctf.tech/releases/download/...`.

### Step 8 — Firmware: TLS configuration

The firmware now selects its transport from the URL scheme
(`beginRequest()` in `esp32_ota_main.ino`), so HTTPS works — but it needs two
things configured in `ota_config.h`.

**a) Point it at the public gateway**

```c
#define BACKEND_URL "https://gw.nyx-ctf.tech"
```

**b) Pin the root CA**

Do not guess this: Cloudflare issues from different roots per zone (GlobalSign,
Let's Encrypt, Google Trust Services). Read it off your live hostname:

```bash
pip install cryptography certifi
python CODE/frimware_code/tools/fetch_root_ca.py gw.nyx-ctf.tech
```

It prints the leaf and root subjects to stderr and a ready-to-paste block to
stdout. Replace the `OTA_ROOT_CA` declaration in `ota_config.h` with it.

Leaving `OTA_ROOT_CA` empty still connects, but skips server verification —
the firmware logs a warning. Since the plain-OTA path does no signature check,
that would let anyone able to intercept traffic serve arbitrary firmware. Pin
the root for anything real.

NTP is already wired (`OTA_NTP_SERVER_PRIMARY`/`SECONDARY`) and mandatory: the
ESP32 boots at epoch 0 and would reject every certificate as "not yet valid".
The device must be able to reach UDP 123 outbound.

**c) Reflash over USB once**

The device must be running TLS-capable firmware before it can fetch over HTTPS,
so this transition cannot be done over the air:

```bash
cd CODE/frimware_code
pio run -e esp32dev --target upload
pio device monitor
```

Expected on boot:

```
[TLS] Syncing clock via NTP....
[TLS] Clock synced: Thu Aug 21 09:14:22 2026
[Backend] Checking for firmware update...
```

After this one cable flash, every later update goes over the air from anywhere.

---

## Hardening

**Lock down CORS.** `gateway/__init__.py` sends `allow_origins=['*']`. Once
public, restrict it:

```python
allow_origins=['https://ota.nyx-ctf.tech'],
```

**Keep the runtime command endpoint off.** `OTA_RUNTIME_COMMANDS_ENABLED` must
stay `false` — it executes commands on the host.

**Know what is now world-reachable on `gw.nyx-ctf.tech`:**

| Endpoint | Auth | Exposure |
|---|---|---|
| `POST /api/heartbeat` | none by design | Anyone can inject fake devices/telemetry. |
| `GET /releases/download/{file}` | none | Your firmware binaries are downloadable. |
| `GET /releases/latest/manifest` | none | Version metadata is public. |
| `POST /api/releases/upload` | API key | Protected. |
| `POST /api/releases`, `/api/deployments`, `/api/trigger_sync` | API key | Protected. |

The write paths are safe. The first two are not access-controlled, so treat
device telemetry as untrusted input and don't ship secrets inside firmware
images. A Cloudflare WAF rate-limit rule on `/api/heartbeat` is worth adding.

**Firmware secrets.** `BACKEND_API_KEY` is compiled into the image. Anyone with
physical access can extract it, and the binary is now publicly downloadable —
so keep the *gateway* key out of firmware where possible, and rotate it if a
device is lost.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `502 Bad Gateway` | Wrong service URL — must be `ota_ide:3000` / `gateway:5000`, not `localhost`. |
| Tunnel `DOWN` | Bad/empty `CLOUDFLARE_TUNNEL_TOKEN`, or no outbound access. |
| `530` / `1033` | Tunnel not running, or hostname not routed to it. |
| Devices stopped after going public | Access was applied to `gw.` — remove it. |
| `[TLS] NTP sync failed` | Device can't reach UDP 123 outbound. |
| TLS handshake fails, clock is fine | Wrong root pinned. Re-run `fetch_root_ca.py`. |
| Devices worked, then all stopped months later | Pinned root expired, or Cloudflare changed issuer. Re-run the tool and reflash. |
| Dashboard 200 but devices 404 on manifest | No release published yet — normal on a fresh gateway. |

```bash
docker logs --tail 50 secure_ota_cloudflared
docker run --rm --network sentinel_network curlimages/curl -sI http://ota_ide:3000
docker run --rm --network sentinel_network curlimages/curl -s  http://gateway:5000/healthz
```
