# Deployment Modes — Local vs Cloud

SentinelOTA ships two deployment modes. They share the same images, the same
volumes, and the same credentials — the difference is **where devices reach the
gateway**, and whether anything is published to the internet.

| | Local | Cloud |
|---|---|---|
| Compose file | `docker-compose.local.yml` | `docker-compose.cloud.yml` |
| Containers | `gateway`, `ota_ide` | `gateway`, `ota_ide`, `cloudflared` |
| Dashboard | `http://localhost:3000` | `https://ota.nyx-ctf.tech` |
| Device endpoint | `OTA_LOCAL_URL` (LAN IP) | `OTA_PUBLIC_URL` (HTTPS) |
| Transport to device | plain HTTP | HTTPS via Cloudflare |
| Firmware TLS setup | not needed | `OTA_ROOT_CA` must be pinned |
| Exposed to internet | nothing | dashboard + gateway |
| Devices must be | on your LAN | anywhere |

Both use the compose project name `secure_ota`, so they share the same named
volumes. **Switching modes preserves your signing keys, releases, device
registry, and users** — only the advertised download URL changes.

---

## Local mode

```bash
docker compose -f docker-compose.local.yml \
  --env-file Secure_OTA_Update_Security_Mechanism/.env.docker up -d
```

Nothing is published. Devices must share the network with this machine and
reach it at `OTA_LOCAL_URL`. Firmware talks plain HTTP — no certificate
pinning, no NTP requirement.

Use it for development, offline demos, and any lab where devices sit on the
same Wi-Fi.

Set in `.env.docker`:

```bash
OTA_LOCAL_URL=http://192.168.1.20:5000     # this machine's LAN IP
```

Find the IP with `ipconfig` (IPv4 Address). Never `localhost` — on an ESP32
that resolves to the ESP32 itself. Your firewall must allow inbound TCP 5000.

---

## Cloud mode

```bash
docker compose -f docker-compose.cloud.yml \
  --env-file Secure_OTA_Update_Security_Mechanism/.env.docker up -d
```

Adds `cloudflared`, which dials **outbound** to Cloudflare — no inbound ports
are opened and no public IP is needed. Devices can update from anywhere.

Requires:

- `CLOUDFLARE_TUNNEL_TOKEN` — not used at runtime in config mode, but kept for
  reference; the tunnel authenticates with `cloudflared/credentials.json`
- `cloudflared/config.yml` — ingress rules (committed)
- `cloudflared/credentials.json` — **git-ignored secret**
- `OTA_PUBLIC_URL=https://gw.nyx-ctf.tech`

Setup is in `CLOUDFLARE_TUNNEL_SETUP.md`.

### Firmware must be rebuilt for cloud mode

Manifests advertise `https://`, and the ESP32 needs TLS configured:

```c
#define BACKEND_URL "https://gw.nyx-ctf.tech"
```

plus a pinned root CA — read it off the live host, don't guess:

```bash
python CODE/frimware_code/tools/fetch_root_ca.py gw.nyx-ctf.tech
```

A device running local-mode firmware **cannot** fetch over HTTPS, so the
switch needs one USB flash per device. After that, updates are remote.

---

## Switching modes

Local → Cloud:

```bash
docker compose -f docker-compose.cloud.yml \
  --env-file Secure_OTA_Update_Security_Mechanism/.env.docker up -d
```

Cloud → Local — `--remove-orphans` is what stops the tunnel:

```bash
docker compose -f docker-compose.local.yml \
  --env-file Secure_OTA_Update_Security_Mechanism/.env.docker up -d --remove-orphans
```

Without it, `cloudflared` keeps running and your deployment stays public even
though you deployed "local".

Confirm which mode is actually live — this is the authoritative check, since it
reads the value baked into every manifest:

```bash
docker exec secure_ota_gateway python -c "from gateway.config import PUBLIC_BASE_URL; print(PUBLIC_BASE_URL)"
docker ps --filter name=secure_ota --format "{{.Names}}"
```

---

## The bare `docker compose` command

`docker-compose.yml` at the repo root includes `docker-compose.local.yml`, so:

```bash
docker compose ps
docker compose logs -f gateway
docker compose restart gateway
docker compose down
```

work from the root with no `-f`. A bare `docker compose up -d` deploys **local**
mode — the safe default, since it publishes nothing. Cloud mode always requires
an explicit `-f docker-compose.cloud.yml`.

`--env-file` is only needed for commands that create containers (`up`).
Read-only and lifecycle commands don't need it.

> Always pass `--env-file` on `up`. Without it, the `${...}` defaults in the
> base compose file win over `.env.docker`, silently reverting the gateway API
> key and admin password to their old placeholder values.

---

## Why the mode is a compose file, not an env var

`OTA_LOCAL_URL` and `OTA_PUBLIC_URL` both live in `.env.docker` at the same
time. Which one reaches the gateway is decided entirely by the compose file you
deploy with.

Previously a single `OTA_GATEWAY_PUBLIC_URL` was edited by hand to switch
modes. That made the deployment's behaviour invisible: nothing in the command
told you whether devices were being pointed at a LAN address or a public one,
and an un-reverted edit would silently break every device. Now the mode is
stated in the command that deploys it.
