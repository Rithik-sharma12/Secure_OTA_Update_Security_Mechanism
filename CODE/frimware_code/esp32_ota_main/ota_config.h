/*
 * ota_config.h  -  SECRETS FILE
 * --------------------------------------------------
 * Keep this file local and do NOT commit real secrets.
 */

#pragma once

// -- Wi-Fi --
#define WIFI_SSID       "Redmi Note 12 5G"
#define WIFI_PASSWORD   "12345678"

// -- ArduinoOTA --
#define OTA_PASSWORD    "KCG_OTA_2026$Secure"
#define DEVICE_HOSTNAME "esp32-ota-device-01"

// -- Backend --
#define BACKEND_URL     "http://10.161.249.69:5000"
#define DEVICE_ID       "ESP32_INTEGRATION_001"
#define DEVICE_TYPE     "ESP32"
#define BACKEND_API_KEY "KCG_GATEWAY_2026_9f5e7a"

// -- Secure OTA keys (leave empty to use plain OTA package mode) --
#define FIRMWARE_ENC_KEY "GdUw5PMGlonBkwD1AFEjX6aqYHQjPq6X"

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
