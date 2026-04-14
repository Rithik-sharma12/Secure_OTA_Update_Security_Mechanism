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
#define WIFI_SSID       "Redmi Note 12 5G"
#define WIFI_PASSWORD   "12345678"

// ── ArduinoOTA ────────────────────────────────────
// Password used when pushing firmware from Arduino IDE / OTA IDE
#define OTA_PASSWORD    "KCG_OTA_2026$Secure"

// Hostname shown in Arduino IDE network ports list
#define DEVICE_HOSTNAME "esp32-ota-device-01"

// ── Custom OTA Backend ────────────────────────────
// Backend gateway URL (use your computer's local IP on the network)
#define BACKEND_URL     "http://10.161.249.69:5000"

// Device Identity for Telemetry / Dashboard
#define DEVICE_ID       "ESP32_INTEGRATION_001"
#define DEVICE_TYPE     "ESP32"

// API Key for authenticating with the backend
#define BACKEND_API_KEY "KCG_GATEWAY_2026_9f5e7a"

// ── Firmware Encryption ────────────────────────────────
// AES-256 key for decrypting secure firmware packages. MUST be 32 bytes long.
// Leave empty to disable secure package mode and use plain OTA package flow.
#define FIRMWARE_ENC_KEY "GdUw5PMGlonBkwD1AFEjX6aqYHQjPq6X"

// ── Firmware Digital Signature ─────────────────────────
// RSA-2048 Public Key for verifying firmware integrity.
// Leave empty to disable secure package mode and use plain OTA package flow.
static const char FIRMWARE_PUB_KEY[] = R"KEY(
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwyKGjC0UXpTDgqwq9sxn
+NXzLvJ4eyJEvjm3B7/QasuBjHhomSrbYs7+n56aPoyPYwPWaS8Ra+m4bEQaPC4U
CYiVcDT9Y2C/FeJG5sVUrEcVUyrCmDuKkzFPo2avWaxbB30rZzGxlz3TwqyFFQ3f
4P78RIVgL6Oqpx7KX4dJzSdTiNFII2eLUHjFq9aEhQFcxFS16VHt9BdlmGE7my32
+viiZXIwHSeiT4+N1f32tyV6YRwyvvYoY6NOVejplD5LsxMApvKUrnCoMhFkkckC
u8bdhK47W2RUesoI7vqwG8LD3Zb88ZLaq4+B0a4bYS6oO9Cfa0NAqKZffqadhvoC
NQIDAQAB
-----END PUBLIC KEY-----
)KEY";
