/*
 * ota_config.h  –  SECRETS FILE (TEMPLATE)
 * ──────────────────────────────────────────────────
 * ⚠  This file is git-ignored. Never commit real credentials.
 * ──────────────────────────────────────────────────
 * Copy this template, fill in your values, and save as
 * ota_config.h in the same folder as the .ino file.
 *
 * If you see this file tracked in git, run:
 *   git rm --cached ota_config.h
 */

#pragma once

// ── Wi-Fi ─────────────────────────────────────────
#define WIFI_SSID       "YOUR_WIFI_SSID"
#define WIFI_PASSWORD   "YOUR_WIFI_PASSWORD"

// ── ArduinoOTA ────────────────────────────────────
#define OTA_PASSWORD    "YOUR_OTA_PASSWORD"
#define DEVICE_HOSTNAME "esp32-ota-device-01"

// ── Custom OTA Backend ────────────────────────────
// Where the device reaches the gateway. Two supported shapes:
//
//   LAN  : "http://192.168.1.20:5000"   plain HTTP, device on the same network
//   WAN  : "https://gw.nyx-ctf.tech"    via Cloudflare Tunnel, no port
//
// For the https form you MUST also set OTA_ROOT_CA below, and the device needs
// working NTP (see below) or every TLS handshake fails as "not yet valid".
// Never localhost/127.0.0.1 — that resolves to the ESP32 itself.
#define BACKEND_URL     "http://YOUR_GATEWAY_IP:5000"
#define DEVICE_ID       "ESP32_DEVICE_001"
#define DEVICE_TYPE     "ESP32"
#define BACKEND_API_KEY "YOUR_GATEWAY_API_KEY"

// ── TLS (only needed when BACKEND_URL is https://) ─
// NTP is mandatory for HTTPS: the ESP32 boots at epoch 0 and certificate
// validity checks reject every certificate as "not yet valid" until synced.
#define OTA_NTP_SERVER_PRIMARY   "pool.ntp.org"
#define OTA_NTP_SERVER_SECONDARY "time.nist.gov"

// Root CA that your gateway's certificate chains to. Leave EMPTY for plain
// http:// deployments.
//
// Do not guess this value — Cloudflare issues from different roots per zone
// (GlobalSign, Let's Encrypt, Google Trust Services). Read it off your own
// live hostname once DNS is up:
//
//     pip install cryptography certifi
//     python ../tools/fetch_root_ca.py gw.nyx-ctf.tech
//
// Paste the emitted block here, replacing this declaration. If left empty the
// firmware still connects over TLS but does NOT verify the server, which means
// an attacker who can intercept traffic can serve arbitrary firmware on the
// plain-OTA path. Acceptable for a lab; not for deployment.
//
// Root certificates expire (often years out). When yours does, re-run the tool
// and reflash, or devices will silently stop updating.
static const char OTA_ROOT_CA[] PROGMEM = "";

// ── Update check cadence ──────────────────────────
// How often the device polls the gateway for a newer manifest. 30 s gives a
// near-immediate pickup after publishing from the dashboard. Raise it for
// battery-powered deployments where responsiveness matters less.
#define OTA_CHECK_INTERVAL_SECONDS 30

// ── Firmware Encryption ────────────────────────────────
// AES-256 key for decrypting secure firmware packages. MUST be 32 bytes long.
// Leave empty to disable secure package mode and use plain OTA package flow.
#define FIRMWARE_ENC_KEY ""

// ── Firmware Digital Signature ─────────────────────────
// RSA-2048 Public Key for verifying firmware integrity.
// Leave empty to disable secure package mode and use plain OTA package flow.
static const char FIRMWARE_PUB_KEY[] = R"KEY(
)KEY";
