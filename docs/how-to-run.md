# How to Run SentinelOTA

Two ways to run the platform:

- **Local** — everything on your own network. Nothing published to the internet.
- **Online** — dashboard and gateway reachable from anywhere over HTTPS.

Both use the same images, volumes, and credentials. The only difference is
where devices reach the gateway, and whether anything is exposed publicly.

> Every command below is run from the **repository root**
> (`E:\9.College_prj\OTA_IOT`), not from inside a subfolder.

---

## 0. Prerequisites

- **Docker Desktop** running (`docker compose version` should print v2+)
- **~2 GB free disk** for images
- For firmware work only: PlatformIO or Arduino IDE, and a USB cable

Check Docker is alive:

```bash
docker compose version
```

---

## 1. First-time setup

The stack reads its secrets from `Secure_OTA_Update_Security_Mechanism/.env.docker`.
If that file does not exist yet, create it from the template:

```bash
cp Secure_OTA_Update_Security_Mechanism/.env.docker.example \
   Secure_OTA_Update_Security_Mechanism/.env.docker
```

Then open it and set, at minimum:

| Variable | What to put |
|---|---|
| `OTA_ADMIN_PASSWORD` | A long passphrase. **≥ 12 chars**, or the dashboard refuses to start. |
| `OTA_GATEWAY_API_KEY` | A random URL-safe key. Generate: `python -c "import secrets; print(secrets.token_urlsafe(36))"` |
| `OTA_LOCAL_URL` | `http://<your-LAN-IP>:5000` — used by **local** mode |
| `OTA_PUBLIC_URL` | `https://<your-domain>` — used by **online** mode |

Find your LAN IP with `ipconfig` (look for **IPv4 Address**).

Two rules that cause silent failures if broken:

- **Never use `localhost`** in `OTA_LOCAL_URL`. That value is baked into every
  firmware manifest, and on an ESP32 `localhost` means the ESP32 itself.
- **No literal `$`** in any value — docker compose interprets it.

> `.env.docker` is git-ignored and holds live secrets. Never commit it, and
> never copy real values into `.env.docker.example`.

---

## 2. Run locally

```bash
docker compose -f docker-compose.local.yml \
  --env-file Secure_OTA_Update_Security_Mechanism/.env.docker up -d
```

First run builds the images (a few minutes). Later runs start in seconds.

### Verify

```bash
docker compose ps
```

Expect two services, both `healthy`:

```
gateway   Up (healthy)   0.0.0.0:5000->5000/tcp
ota_ide   Up (healthy)   0.0.0.0:3000->3000/tcp
```

Then:

```bash
curl http://localhost:5000/healthz          # {"ok":true,...}
curl -I http://localhost:3000               # 307 -> /login
```

Open <http://localhost:3000> and log in with `OTA_ADMIN_USERNAME` /
`OTA_ADMIN_PASSWORD` from `.env.docker`.

Other machines and devices on your Wi-Fi reach it at
`http://<your-LAN-IP>:3000`. If they can't, your firewall is blocking inbound
TCP 3000/5000 — allow it or the ESP32 downloads will time out.

---

## 3. Run online

This publishes the platform through a Cloudflare Tunnel. No ports are opened;
`cloudflared` dials outbound to Cloudflare.

**Requires a one-time Cloudflare setup** — domain on Cloudflare nameservers, a
tunnel created, `cloudflared/credentials.json` present, and ingress rules in
`cloudflared/config.yml`. Full walkthrough:
[guides/CLOUDFLARE_TUNNEL_SETUP.md](guides/CLOUDFLARE_TUNNEL_SETUP.md).

Once that exists:

```bash
docker compose -f docker-compose.cloud.yml \
  --env-file Secure_OTA_Update_Security_Mechanism/.env.docker up -d
```

### Verify

```bash
docker compose ps
```

Expect **three** services — `gateway`, `ota_ide`, and `cloudflared`.

```bash
docker logs secure_ota_cloudflared | grep "Registered tunnel connection"
```

Four connections is normal. Then check the public endpoints:

```bash
curl -sI https://ota.nyx-ctf.tech           # 307 -> /login
curl -s  https://gw.nyx-ctf.tech/healthz    # {"ok":true,...}
```

The second one matters: it must return **JSON, not an HTML page**. HTML means
Cloudflare Access is wrongly applied to the gateway hostname, which blocks
every device (an ESP32 can't complete a browser login). Access belongs on the
dashboard hostname only.

---

## 4. Switching between modes

Local → Online:

```bash
docker compose -f docker-compose.cloud.yml \
  --env-file Secure_OTA_Update_Security_Mechanism/.env.docker up -d
```

Online → Local — **`--remove-orphans` is required**:

```bash
docker compose -f docker-compose.local.yml \
  --env-file Secure_OTA_Update_Security_Mechanism/.env.docker up -d --remove-orphans
```

Without it, `cloudflared` keeps running and your deployment stays public even
though you deployed "local".

Both modes share the project name `secure_ota`, so **your signing keys,
releases, device registry, and users survive the switch.**

To confirm which mode is actually live — this reads the value baked into every
manifest, so it's authoritative:

```bash
docker exec secure_ota_gateway python -c "from gateway.config import PUBLIC_BASE_URL; print(PUBLIC_BASE_URL)"
```

An `http://<LAN-IP>` result means local; `https://<domain>` means online.

---

## 5. Everyday commands

These work from the repo root with **no `-f` and no `--env-file`**:

```bash
docker compose ps                    # status
docker compose logs -f gateway       # follow gateway logs
docker compose logs -f ota_ide       # follow dashboard logs
docker compose restart gateway       # restart one service
docker compose down                  # stop everything (volumes survive)
```

> **`--env-file` is required for `up`.** Leave it off and the `${...}`
> fallbacks win over `.env.docker`, reverting the gateway API key and admin
> password to placeholder values and setting the device URL to the sentinel
> `OTA-LOCAL-URL-NOT-SET-PASS-ENV-FILE`. That sentinel exists so the mistake
> is obvious in the manifest rather than silently falling back to `localhost`.
>
> To avoid typing it every time, export it once per shell:
>
> ```bash
> export COMPOSE_ENV_FILES=Secure_OTA_Update_Security_Mechanism/.env.docker   # bash
> $env:COMPOSE_ENV_FILES="Secure_OTA_Update_Security_Mechanism\.env.docker"   # PowerShell
> ```

> **Never run `docker compose down -v`.** The `-v` deletes the named volumes,
> destroying your Ed25519 signing keys, published firmware, and user accounts.

---

## 6. Publishing a firmware update

Once running, the actual workflow:

1. Bump **both** version lines in `esp32_ota_main.ino`
   (`FIRMWARE_VERSION` and `FIRMWARE_VERSION_N`) — devices reject anything not
   strictly newer.
2. Build: `pio run -e esp32dev` → `.pio/build/esp32dev/firmware.bin`
3. Open the dashboard → **Releases** → **Publish Firmware Update**
4. Choose the `.bin`, set the version, press **Publish Release**
5. Devices pick it up on their next check (default 30 s)

Full details, including the first USB flash and TLS setup for online mode:
[guides/WEB_OTA_UPDATE_GUIDE.md](guides/WEB_OTA_UPDATE_GUIDE.md).

Firmware must match the mode it runs against: local mode serves plain HTTP,
online mode serves HTTPS and needs `BACKEND_URL` plus a pinned `OTA_ROOT_CA`
in `ota_config.h`. A device flashed for one cannot talk to the other, and
switching requires a USB reflash.

---

## 7. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `port is already allocated` | Something else uses 3000/5000. Stop it, or change the published port. |
| `container name already in use` | Stale container from an old run: `docker compose down`, then `up` again. |
| Login shows `Unexpected token '<'` | The origin was restarting and an HTML error page came back. Wait a few seconds and retry. |
| Login rejects a correct password | The admin is bootstrapped **once**. Editing `OTA_ADMIN_PASSWORD` later does nothing unless `users.db` in the `sentinel_ota_ide_db` volume is cleared. |
| Dashboard loads, devices never update | Check the advertised URL (section 4). A `localhost` value is the usual cause. |
| `Failed to check manifest: 404` | No release published yet. Normal on a fresh gateway. |
| Public hostname returns **503** | Tunnel is up but has no ingress rules. See the tunnel guide. |
| Public hostname returns **1033** / **530** | Tunnel isn't running. `docker compose ps`. |
| Gateway edits keep reverting | Stop the gateway before editing its volume — it re-persists in-memory state on the next write. |

---

## Related documents

- [guides/DEPLOYMENT_MODES.md](guides/DEPLOYMENT_MODES.md) — local vs online in depth
- [guides/CLOUDFLARE_TUNNEL_SETUP.md](guides/CLOUDFLARE_TUNNEL_SETUP.md) — one-time online setup
- [guides/WEB_OTA_UPDATE_GUIDE.md](guides/WEB_OTA_UPDATE_GUIDE.md) — pushing firmware to devices
- [../DEPLOYMENT.md](../DEPLOYMENT.md) — cloud VPS / production notes
