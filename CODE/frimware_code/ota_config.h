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
// Password used when pushing firmware from Arduino IDE / OTA IDE
#define OTA_PASSWORD    "YOUR_OTA_PASSWORD"

// Hostname shown in Arduino IDE network ports list
#define DEVICE_HOSTNAME "esp32-ota-device-01"

// ── Custom OTA Backend ────────────────────────────
// Backend gateway URL (use your computer's local IP on the network)
#define BACKEND_URL     "http://YOUR_GATEWAY_IP:5000"

// Device Identity for Telemetry / Dashboard
#define DEVICE_ID       "ESP32_DEVICE_001"
#define DEVICE_TYPE     "ESP32"

// API Key for authenticating with the backend
#define BACKEND_API_KEY "YOUR_GATEWAY_API_KEY"

// ── Firmware Encryption ────────────────────────────────
// AES-256 key for decrypting secure firmware packages. MUST be 32 bytes long.
// Leave empty to disable secure package mode and use plain OTA package flow.
#define FIRMWARE_ENC_KEY ""

// ── Firmware Digital Signature ─────────────────────────
// RSA-2048 Public Key for verifying firmware integrity.
// Leave empty to disable secure package mode and use plain OTA package flow.
static const char FIRMWARE_PUB_KEY[] = R"KEY(
)KEY";
