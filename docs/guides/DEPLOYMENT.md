# SentinelOTA — Cloud Deployment & Containerization Guide

This guide provides end-to-end instructions for deploying the **SentinelOTA** platform to cloud platforms (AWS EC2, DigitalOcean, Hetzner, GCP Compute Engine, Azure VM, or any Linux VPS) using **Docker Compose** with persistent data storage.

---

## 1. Multi-Container System Architecture

```
                                Cloud Server / VPS
+-------------------------------------------------------------------------------+
|                                                                               |
|   +-----------------------+      HTTP        +----------------------------+   |
|   |      ota_ide          | ---------------> |          gateway           |   |
|   |  (Next.js Control)    |                  |      (FastAPI Gateway)     |   |
|   |   Port 3000:3000      |                  |       Port 5000:5000       |   |
|   +-----------+-----------+                  +--------------+-------------+   |
|               |                                             |                 |
|               v                                             v                 |
|     (sentinel_ota_ide_db)                    +--------------+-------------+   |
|      [Persistent Volume]                     | (sentinel_gateway_cache)   |   |
|                                              | (sentinel_gateway_keys)    |   |
|                                              +--------------+-------------+   |
+---------------------------------------------------------------|---------------+
                                                                 | HTTP
                                                    manifest poll | + firmware
                                                                 v
                                                    +----------------------------+
                                                    |   Real ESP32 devices       |
                                                    |   on the device network    |
                                                    +----------------------------+
```

### Managed Microservices
1. **`gateway`**: FastAPI backend service handling device heartbeats, manifest signing (Ed25519), telemetry logging, and firmware download streaming.
2. **`ota_ide`**: Next.js 16 control plane dashboard for administrative access, analytics, serial flashing APIs, and pipeline orchestration.

> **Production deployment — no simulator.** The stack runs exactly two services.
> Firmware telemetry comes from real hardware polling the gateway. For devices
> to reach it, `OTA_LOCAL_URL` / `OTA_PUBLIC_URL` must be a routable address (LAN IP or
> domain), never `localhost`.

---

## 2. Server Requirements

- **Operating System**: Ubuntu 22.04 LTS / Debian 12 / RHEL 9
- **Recommended Hardware**:
  - CPU: 2 vCPU
  - RAM: 2 GB minimum (4 GB recommended)
  - Disk: 20 GB SSD
- **Network Ports**:
  - `80` / `443` (HTTP/HTTPS for Reverse Proxy / SSL)
  - `3000` (OTA IDE Dashboard)
  - `5000` (FastAPI Gateway)

---

## 3. Quick Start Deployment

### Step 1: Install Docker & Docker Compose on Cloud VPS

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add current user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Verify installation
docker compose version
```

### Step 2: Clone Project & Configure Environment

```bash
git clone https://github.com/Rithik-sharma12/OTA_IOT.git
cd OTA_IOT/Secure_OTA_Update_Security_Mechanism

# Create production environment config
cp .env.docker.example .env.docker
```

Edit `.env.docker` to set secure credentials:
```bash
nano .env.docker
```
Important settings to customize:
- `OTA_ADMIN_USERNAME`: Admin login username
- `OTA_ADMIN_PASSWORD`: Strong password (min 12 characters)
- `OTA_GATEWAY_API_KEY`: Secret key for protecting write endpoints

### Step 3: Build & Launch Containers

```bash
# Build images and start all services in detached mode
docker compose --env-file .env.docker up --build -d
```

### Step 4: Verify Container Status & Health

```bash
# Check running containers
docker compose ps

# View container health and logs
docker compose logs -f gateway
docker compose logs -f ota_ide
```

Test HTTP endpoints:
```bash
# Gateway health check
curl http://localhost:5000/healthz

# Dashboard health check
curl -I http://localhost:3000
```

---

## 4. Persistent Storage Management

All sensitive data and firmware assets persist across container restarts and builds using named Docker volumes:

| Volume Name | Target Path inside Container | Data Stored |
|---|---|---|
| `sentinel_ota_ide_db` | `/app/.local-db` | NeDB database (users, sessions, release records, logs) |
| `sentinel_gateway_cache` | `/app/gateway_firmware_cache` | Cached binary firmware packages and manifests |
| `sentinel_gateway_keys` | `/app/gateway_keys` | Ed25519 signing keypairs for gateway signatures |

### Backup Volume Data

To create a tar backup of all persistent volumes:
```bash
# Backup NeDB database
docker run --rm -v sentinel_ota_ide_db:/data -v $(pwd):/backup ubuntu tar cvzf /backup/ota_ide_db_backup.tar.gz -C /data .

# Backup Gateway keys
docker run --rm -v sentinel_gateway_keys:/data -v $(pwd):/backup ubuntu tar cvzf /backup/gateway_keys_backup.tar.gz -C /data .
```

### Restore Volume Data

```bash
# Restore NeDB database from backup archive
docker run --rm -v sentinel_ota_ide_db:/data -v $(pwd):/backup ubuntu tar xvzf /backup/ota_ide_db_backup.tar.gz -C /data
```

---

## 5. Nginx Reverse Proxy & SSL (HTTPS) Setup

For production cloud deployments, it is recommended to run Nginx as a reverse proxy with Let's Encrypt TLS certs.

### Sample Nginx Site Configuration (`/etc/nginx/sites-available/sentinel.conf`)

```nginx
server {
    server_name ota.yourdomain.com;

    # Dashboard Control Plane
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Gateway APIs for IoT Devices
    location /gateway/ {
        proxy_pass http://127.0.0.1:5000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Enable SSL with Certbot:
```bash
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d ota.yourdomain.com
```

---

## 6. Container Commands Cheat Sheet

| Action | Command |
|---|---|
| **Start platform** | `docker compose up -d` |
| **Rebuild & start** | `docker compose up --build -d` |
| **Stop platform** | `docker compose down` |
| **Stop & remove volumes** | `docker compose down -v` |
| **View combined logs** | `docker compose logs -f --tail=100` |
| **Restart a service** | `docker compose restart gateway` |
| **Check container resources** | `docker stats` |
