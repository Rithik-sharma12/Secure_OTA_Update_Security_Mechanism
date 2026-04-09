/*
 * ota_config.h  –  SECRETS FILE
 * ──────────────────────────────────────────────────
 * ⚠  Add "ota_config.h" to .gitignore
 *    NEVER commit this file to GitHub
 * ──────────────────────────────────────────────────
 * Copy this template, fill in your values, save as
 * ota_config.h in the same folder as the .ino file.
 */

#pragma once

// ── Wi-Fi ─────────────────────────────────────────
#define WIFI_SSID       "YOUR_WIFI_SSID"
#define WIFI_PASSWORD   "YOUR_WIFI_PASSWORD"

// ── ArduinoOTA ────────────────────────────────────
// Password used when pushing firmware from Arduino IDE / OTA IDE
#define OTA_PASSWORD    "your_ota_password_here"

// Hostname shown in Arduino IDE network ports list
#define DEVICE_HOSTNAME "esp32-ota-device-01"

// ── Custom OTA Backend ────────────────────────────
// Backend gateway URL (use your computer's local IP on the network)
#define BACKEND_URL     "http://192.168.1.100:5000"

// Device Identity for Telemetry / Dashboard
#define DEVICE_ID       "ESP32_INTEGRATION_001"
#define DEVICE_TYPE     "ESP32"

// API Key for authenticating with the backend
#define BACKEND_API_KEY "your_gateway_api_key_here"

// ── Firmware Encryption ────────────────────────────────
// AES-256 key for decrypting secure firmware packages. MUST be 32 bytes long.
// If this stays as placeholder, firmware uses plain OTA package fallback mode.
// This key must match the FIRMWARE_ENC_KEY secret in your GitHub repository.
#define FIRMWARE_ENC_KEY "your_32_byte_firmware_enc_key_here"

// ── Firmware Digital Signature ─────────────────────────
// RSA-2048 Public Key for verifying firmware integrity.
// If this stays as placeholder, firmware uses plain OTA package fallback mode.
// This key must match the FIRMWARE_PRIV_KEY secret in your GitHub repository.
static const char FIRMWARE_PUB_KEY[] = \
"-----BEGIN PUBLIC KEY-----\n" \
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...your_public_key_here...\n" \
"-----END PUBLIC KEY-----\n";
