/*
 * ESP32 Multi-Method OTA Firmware
 * --------------------------------------------------
 * Supports:
 *   1) ArduinoOTA push updates (IDE / OTA tools)
 *   2) Backend manifest pull and self-update
 *   3) Secure package mode (AES-256-CBC + RSA signature)
 *   4) Plain package fallback (for development)
 */

#include <Arduino.h>
#include <WiFi.h>
#include <ArduinoOTA.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <Update.h>

#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"

#include "ota_config.h"

#define FIRMWARE_VERSION    "2.4.0"
#define FIRMWARE_VERSION_N  20400  // major*10000 + minor*100 + patch

#define HEALTH_QUARANTINE 40
#define HEALTH_MAX       100

#define BACKEND_CHECK_INTERVAL_MS (15UL * 60UL * 1000UL)
#define HEARTBEAT_INTERVAL_MS     (15UL * 1000UL)
#define ARDUINO_OTA_PORT          3232

#define LED_STATUS 2
#define BTN_OTA    0

#define SECURE_IV_BYTES        16U
#define SECURE_SIGNATURE_BYTES 256U
#define SECURE_AES_BLOCK_SIZE  16U

Preferences prefs;

struct AppState {
  int healthScore = HEALTH_MAX;
  bool inQuarantine = false;
  int failedAttempts24h = 0;
  unsigned long lastBackendCheck = 0;
  unsigned long lastHeartbeat = 0;
};

struct ManifestInfo {
  String version;
  String filename;
  String downloadUrl;
};

AppState state;

void setupWiFi();
void setupArduinoOTA();
void checkBackendOTA();
void sendHeartbeat();

bool fetchLatestRelease(ManifestInfo &manifestOut);
bool performHttpUpdate(const String &url);
bool performSecurePackageUpdate(const String &url);
bool performPlainPackageUpdate(const String &url);
bool isSecureOtaConfigured();

void adjustHealth(int delta, const char *reason);
void loadHealth();
void saveHealth();

void blinkLED(int times, int ms = 100);
bool isBtnHeld(int ms);
int parseVersion(String ver);

void setup() {
  Serial.begin(115200);
  delay(500);

  pinMode(LED_STATUS, OUTPUT);
  pinMode(BTN_OTA, INPUT_PULLUP);

  Serial.printf("\n[OTA] Firmware v%s starting...\n", FIRMWARE_VERSION);

  loadHealth();
  setupWiFi();

  setupArduinoOTA();
  if (state.inQuarantine) {
    Serial.println("[OTA] Device in quarantine. OTA recovery mode enabled.");
    blinkLED(5, 180);
  }

  blinkLED(2, 120);
  Serial.println("[OTA] Setup complete");
}

void loop() {
  ArduinoOTA.handle();

  if (isBtnHeld(3000)) {
    Serial.println("[OTA] Manual backend OTA trigger from button");
    checkBackendOTA();
  }

  const unsigned long now = millis();

  if (now - state.lastBackendCheck >= BACKEND_CHECK_INTERVAL_MS) {
    state.lastBackendCheck = now;
    if (state.inQuarantine) {
      Serial.println("[OTA] Skipping backend check. Device quarantined.");
    } else {
      checkBackendOTA();
    }
  }

  if (now - state.lastHeartbeat >= HEARTBEAT_INTERVAL_MS) {
    state.lastHeartbeat = now;
    adjustHealth(+1, "poll success");
    sendHeartbeat();
  }

  delay(10);
}

void setupWiFi() {
  Serial.printf("[WiFi] Connecting to %s", WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  WiFi.setHostname(DEVICE_HOSTNAME);

  int tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 30) {
    delay(500);
    Serial.print('.');
    tries++;
  }

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("\n[WiFi] Failed. Rebooting in 10s.");
    adjustHealth(-1, "network error");
    delay(10000);
    ESP.restart();
  }

  Serial.printf("\n[WiFi] Connected. IP: %s\n", WiFi.localIP().toString().c_str());
}

void setupArduinoOTA() {
  ArduinoOTA.setPort(ARDUINO_OTA_PORT);
  ArduinoOTA.setHostname(DEVICE_HOSTNAME);
  ArduinoOTA.setPassword(OTA_PASSWORD);

  ArduinoOTA.onStart([]() {
    const String type = (ArduinoOTA.getCommand() == U_FLASH) ? "firmware" : "filesystem";
    Serial.printf("[ArduinoOTA] Start: %s\n", type.c_str());
    digitalWrite(LED_STATUS, HIGH);
  });

  ArduinoOTA.onEnd([]() {
    Serial.println("[ArduinoOTA] Complete. Rebooting.");
    adjustHealth(+10, "ota success");
    blinkLED(5, 80);
  });

  ArduinoOTA.onProgress([](unsigned int progress, unsigned int total) {
    static int lastPct = -1;
    const int pct = static_cast<int>((progress * 100U) / total);
    if (pct != lastPct) {
      Serial.printf("[ArduinoOTA] %u%%\r", pct);
      lastPct = pct;
    }
    digitalWrite(LED_STATUS, (progress / 1200U) % 2U);
  });

  ArduinoOTA.onError([](ota_error_t error) {
    const char *msg = "Unknown";
    switch (error) {
      case OTA_AUTH_ERROR: msg = "Auth failed"; break;
      case OTA_BEGIN_ERROR: msg = "Begin failed"; break;
      case OTA_CONNECT_ERROR: msg = "Connect failed"; break;
      case OTA_RECEIVE_ERROR: msg = "Receive failed"; break;
      case OTA_END_ERROR: msg = "End failed"; break;
      default: break;
    }
    Serial.printf("[ArduinoOTA] Error[%u]: %s\n", error, msg);
    adjustHealth(-10, "ota error");
  });

  ArduinoOTA.begin();
  Serial.printf("[ArduinoOTA] Listening on port %d\n", ARDUINO_OTA_PORT);
}

void checkBackendOTA() {
  Serial.println("[Backend] Checking for firmware update...");

  ManifestInfo manifest;
  if (!fetchLatestRelease(manifest)) {
    Serial.println("[Backend] Could not fetch release info");
    adjustHealth(-1, "network error");
    return;
  }

  const int remoteVerN = parseVersion(manifest.version);

  Serial.printf("[Backend] Current v%s (%d), Remote %s (%d)\n",
                FIRMWARE_VERSION,
                FIRMWARE_VERSION_N,
                manifest.version.c_str(),
                remoteVerN);

  if (remoteVerN == FIRMWARE_VERSION_N) {
    Serial.println("[Backend] Device is up to date");
    adjustHealth(+1, "poll success");
    return;
  }

  if (remoteVerN < FIRMWARE_VERSION_N) {
    Serial.println("[Backend] Anti-rollback blocked downgrade package");
    return;
  }

  Serial.printf("[Backend] Update available: %s\n", manifest.downloadUrl.c_str());
  Serial.println("[Backend] Downloading and flashing...");

  if (performHttpUpdate(manifest.downloadUrl)) {
    adjustHealth(+10, "update success");
    Serial.println("[Backend] Update successful. Rebooting.");
    blinkLED(10, 50);
    delay(500);
    ESP.restart();
  } else {
    Serial.println("[Backend] Update failed");
    state.failedAttempts24h++;
    adjustHealth(-25, "update failed");
  }
}

bool fetchLatestRelease(ManifestInfo &manifestOut) {
  if (WiFi.status() != WL_CONNECTED) {
    return false;
  }

  HTTPClient http;
  const String apiUrl = String(BACKEND_URL) + "/releases/latest/manifest";
  if (!http.begin(apiUrl)) {
    Serial.println("[Backend] Could not open manifest endpoint");
    return false;
  }

  if (strlen(BACKEND_API_KEY) > 0) {
    http.addHeader("x-api-key", BACKEND_API_KEY);
  }

  http.setTimeout(10000);
  const int code = http.GET();
  if (code != HTTP_CODE_OK) {
    Serial.printf("[Backend] Manifest API error %d\n", code);
    http.end();
    return false;
  }

  JsonDocument doc;
  const DeserializationError err = deserializeJson(doc, http.getStream());
  http.end();

  if (err) {
    Serial.printf("[Backend] Manifest parse error: %s\n", err.c_str());
    return false;
  }

  manifestOut.version = doc["version"] | "";
  manifestOut.filename = doc["filename"] | "firmware.bin";
  if (doc["downloadUrl"].is<const char*>()) {
    manifestOut.downloadUrl = doc["downloadUrl"].as<String>();
  } else {
    manifestOut.downloadUrl = String(BACKEND_URL) + "/releases/download/" + manifestOut.filename;
  }

  if (manifestOut.version.length() == 0 || manifestOut.downloadUrl.length() == 0) {
    Serial.println("[Backend] Manifest missing required fields");
    return false;
  }

  return true;
}

void sendHeartbeat() {
  if (WiFi.status() != WL_CONNECTED) {
    return;
  }

  const unsigned long uptimeSeconds = millis() / 1000UL;
  const int freeHeap = ESP.getFreeHeap();
  const int heapSize = ESP.getHeapSize();
  const int memoryUsedPct =
    (heapSize > 0)
      ? static_cast<int>(100 - ((static_cast<long>(freeHeap) * 100L) / heapSize))
      : 0;

  HTTPClient http;
  if (!http.begin(String(BACKEND_URL) + "/api/heartbeat")) {
    return;
  }

  http.addHeader("Content-Type", "application/json");
  if (strlen(BACKEND_API_KEY) > 0) {
    http.addHeader("x-api-key", BACKEND_API_KEY);
  }

  JsonDocument doc;
  doc["device_id"] = DEVICE_ID;
  doc["device_type"] = DEVICE_TYPE;
  doc["current_version"] = FIRMWARE_VERSION;
  doc["ash_score"] = state.healthScore;
  doc["status"] = state.inQuarantine ? "Quarantined" : "Healthy";
  doc["memoryUsage"] = memoryUsedPct;
  doc["uptime"] = uptimeSeconds;
  doc["location"] = DEVICE_HOSTNAME;
  doc["signalStrength"] = WiFi.RSSI();

  JsonArray logs = doc["logs"].to<JsonArray>();
  logs.add(String("[HB] device=") + DEVICE_ID + " fw=" + FIRMWARE_VERSION + " ash=" + state.healthScore);
  logs.add(String("[NET] ip=") + WiFi.localIP().toString() + " rssi=" + WiFi.RSSI() + "dBm");
  logs.add(String("[SYS] uptime=") + uptimeSeconds + "s freeHeap=" + freeHeap + "B mem=" + memoryUsedPct + "% status=" + (state.inQuarantine ? "Quarantined" : "Healthy"));

  String payload;
  serializeJson(doc, payload);
  http.POST(payload);
  http.end();
}

bool performHttpUpdate(const String &url) {
  digitalWrite(LED_STATUS, HIGH);

  bool success = false;
  if (isSecureOtaConfigured()) {
    Serial.println("[Update] Secure OTA configuration detected");
    success = performSecurePackageUpdate(url);
    if (!success) {
      Serial.println("[Update] Secure OTA failed. Trying plain OTA fallback.");
    }
  } else {
    Serial.println("[Update] Secure OTA not configured. Using plain package mode.");
  }

  if (!success) {
    success = performPlainPackageUpdate(url);
  }

  digitalWrite(LED_STATUS, LOW);
  return success;
}

bool isSecureOtaConfigured() {
  const bool hasAesKey = strlen(FIRMWARE_ENC_KEY) == 32;

  const bool hasPubKey =
    strstr(FIRMWARE_PUB_KEY, "-----BEGIN PUBLIC KEY-----") != nullptr &&
    strstr(FIRMWARE_PUB_KEY, "-----END PUBLIC KEY-----") != nullptr;

  return hasAesKey && hasPubKey;
}

bool performSecurePackageUpdate(const String &url) {
  Serial.println("[Update] Starting secure OTA package flow...");

  HTTPClient http;
  if (!http.begin(url)) {
    Serial.println("[Update] ERROR: Could not open secure package URL");
    return false;
  }

  if (strlen(BACKEND_API_KEY) > 0) {
    http.addHeader("x-api-key", BACKEND_API_KEY);
  }

  http.setTimeout(15000);
  const int httpCode = http.GET();
  if (httpCode != HTTP_CODE_OK) {
    Serial.printf("[Update] ERROR: Secure package GET failed (%d)\n", httpCode);
    http.end();
    return false;
  }

  const int contentLength = http.getSize();
  if (contentLength <= static_cast<int>(SECURE_IV_BYTES + SECURE_SIGNATURE_BYTES)) {
    Serial.println("[Update] ERROR: Secure package too small");
    http.end();
    return false;
  }

  const size_t encryptedSize =
    static_cast<size_t>(contentLength - static_cast<int>(SECURE_IV_BYTES + SECURE_SIGNATURE_BYTES));

  if ((encryptedSize % SECURE_AES_BLOCK_SIZE) != 0U) {
    Serial.printf("[Update] ERROR: Encrypted payload size invalid (%u bytes)\n", static_cast<unsigned int>(encryptedSize));
    http.end();
    return false;
  }

  WiFiClient *stream = http.getStreamPtr();

  uint8_t iv[SECURE_IV_BYTES];
  uint8_t signature[SECURE_SIGNATURE_BYTES];

  const size_t ivRead = stream->readBytes(reinterpret_cast<char *>(iv), sizeof(iv));
  const size_t sigRead = stream->readBytes(reinterpret_cast<char *>(signature), sizeof(signature));
  if (ivRead != sizeof(iv) || sigRead != sizeof(signature)) {
    Serial.println("[Update] ERROR: Could not read secure package header");
    http.end();
    return false;
  }

  mbedtls_pk_context pk;
  mbedtls_md_context_t mdCtx;
  mbedtls_aes_context aes;
  mbedtls_pk_init(&pk);
  mbedtls_md_init(&mdCtx);
  mbedtls_aes_init(&aes);

  bool success = false;
  bool updateBegun = false;

  do {
    const int pkResult = mbedtls_pk_parse_public_key(
      &pk,
      reinterpret_cast<const unsigned char *>(FIRMWARE_PUB_KEY),
      strlen(FIRMWARE_PUB_KEY) + 1);
    if (pkResult != 0) {
      Serial.printf("[Update] ERROR: Public key parse failed (%d)\n", pkResult);
      break;
    }

    if (mbedtls_md_setup(&mdCtx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0) != 0 ||
        mbedtls_md_starts(&mdCtx) != 0) {
      Serial.println("[Update] ERROR: SHA-256 context init failed");
      break;
    }

    const int aesResult = mbedtls_aes_setkey_dec(
      &aes,
      reinterpret_cast<const unsigned char *>(FIRMWARE_ENC_KEY),
      256);
    if (aesResult != 0) {
      Serial.printf("[Update] ERROR: AES key init failed (%d)\n", aesResult);
      break;
    }

    if (!Update.begin(encryptedSize, U_FLASH)) {
      Serial.printf("[Update] ERROR: Not enough space for update (%u)\n", Update.getError());
      break;
    }
    updateBegun = true;

    uint8_t cipherBlock[SECURE_AES_BLOCK_SIZE];
    uint8_t plainBlock[SECURE_AES_BLOCK_SIZE];

    size_t totalRead = 0;
    size_t totalWritten = 0;
    int lastPct = -1;
    bool streamFailed = false;

    while (totalRead < encryptedSize) {
      const size_t got = stream->readBytes(reinterpret_cast<char *>(cipherBlock), sizeof(cipherBlock));
      if (got != sizeof(cipherBlock)) {
        Serial.println("[Update] ERROR: Truncated secure payload");
        streamFailed = true;
        break;
      }

      const int cryptResult = mbedtls_aes_crypt_cbc(
        &aes,
        MBEDTLS_AES_DECRYPT,
        sizeof(cipherBlock),
        iv,
        cipherBlock,
        plainBlock);
      if (cryptResult != 0) {
        Serial.printf("[Update] ERROR: AES decrypt failed (%d)\n", cryptResult);
        streamFailed = true;
        break;
      }

      size_t bytesToWrite = sizeof(plainBlock);
      const bool isFinalBlock = (totalRead + sizeof(cipherBlock) == encryptedSize);

      if (isFinalBlock) {
        const uint8_t pad = plainBlock[SECURE_AES_BLOCK_SIZE - 1U];
        if (pad == 0U || pad > SECURE_AES_BLOCK_SIZE) {
          Serial.println("[Update] ERROR: Invalid PKCS7 padding");
          streamFailed = true;
          break;
        }
        for (size_t i = 0; i < pad; ++i) {
          if (plainBlock[SECURE_AES_BLOCK_SIZE - 1U - i] != pad) {
            Serial.println("[Update] ERROR: Corrupted PKCS7 padding bytes");
            streamFailed = true;
            break;
          }
        }
        if (streamFailed) {
          break;
        }
        bytesToWrite = SECURE_AES_BLOCK_SIZE - pad;
      }

      if (bytesToWrite > 0U) {
        if (mbedtls_md_update(&mdCtx, plainBlock, bytesToWrite) != 0) {
          Serial.println("[Update] ERROR: Hash update failed");
          streamFailed = true;
          break;
        }

        if (Update.write(plainBlock, bytesToWrite) != bytesToWrite) {
          Serial.println("[Update] ERROR: Flash write failed in secure flow");
          streamFailed = true;
          break;
        }

        totalWritten += bytesToWrite;
      }

      totalRead += sizeof(cipherBlock);

      const int pct = static_cast<int>((totalRead * 100UL) / encryptedSize);
      if (pct != lastPct && pct % 10 == 0) {
        Serial.printf("[Update] Secure OTA %d%%\n", pct);
        lastPct = pct;
      }
    }

    if (streamFailed || totalRead != encryptedSize) {
      break;
    }

    uint8_t hash[32];
    if (mbedtls_md_finish(&mdCtx, hash) != 0) {
      Serial.println("[Update] ERROR: Hash finalize failed");
      break;
    }

    Serial.println("[Update] Verifying firmware signature...");
    const int verifyResult = mbedtls_pk_verify(
      &pk,
      MBEDTLS_MD_SHA256,
      hash,
      sizeof(hash),
      signature,
      sizeof(signature));
    if (verifyResult != 0) {
      Serial.printf("[Update] ERROR: Signature verification failed (%d)\n", verifyResult);
      break;
    }

    Serial.printf("[Update] Signature verified. Writing %u bytes to flash.\n", static_cast<unsigned int>(totalWritten));

    if (!Update.end(true)) {
      Serial.printf("[Update] ERROR: Update finalize failed (%u)\n", Update.getError());
      break;
    }

    success = true;
  } while (false);

  if (!success && updateBegun) {
    Update.abort();
  }

  mbedtls_aes_free(&aes);
  mbedtls_md_free(&mdCtx);
  mbedtls_pk_free(&pk);
  http.end();

  return success;
}

bool performPlainPackageUpdate(const String &url) {
  Serial.println("[Update] Starting plain OTA package flow...");

  HTTPClient http;
  if (!http.begin(url)) {
    Serial.println("[Update] ERROR: Could not open plain package URL");
    return false;
  }

  if (strlen(BACKEND_API_KEY) > 0) {
    http.addHeader("x-api-key", BACKEND_API_KEY);
  }

  http.setTimeout(15000);
  const int httpCode = http.GET();
  if (httpCode != HTTP_CODE_OK) {
    Serial.printf("[Update] ERROR: Plain package GET failed (%d)\n", httpCode);
    http.end();
    return false;
  }

  const int contentLength = http.getSize();
  const bool hasKnownLength = contentLength > 0;

  if (hasKnownLength) {
    if (!Update.begin(static_cast<size_t>(contentLength), U_FLASH)) {
      Serial.printf("[Update] ERROR: Not enough space for plain update (%u)\n", Update.getError());
      http.end();
      return false;
    }
    Serial.printf("[Update] Plain package size: %d bytes\n", contentLength);
  } else {
    if (!Update.begin(UPDATE_SIZE_UNKNOWN, U_FLASH)) {
      Serial.printf("[Update] ERROR: Could not start unknown-size plain update (%u)\n", Update.getError());
      http.end();
      return false;
    }
    Serial.println("[Update] Plain package length unknown. Streaming until disconnect.");
  }

  WiFiClient *stream = http.getStreamPtr();
  const size_t written = Update.writeStream(*stream);

  bool success = true;
  if (written == 0U) {
    Serial.println("[Update] ERROR: Plain OTA stream returned zero bytes");
    success = false;
  }

  if (hasKnownLength && written != static_cast<size_t>(contentLength)) {
    Serial.printf("[Update] ERROR: Plain OTA size mismatch wrote=%u expected=%u\n",
                  static_cast<unsigned int>(written),
                  static_cast<unsigned int>(contentLength));
    success = false;
  }

  if (!success) {
    Update.abort();
  } else if (!Update.end(true)) {
    Serial.printf("[Update] ERROR: Plain OTA finalize failed (%u)\n", Update.getError());
    Update.abort();
    success = false;
  }

  http.end();
  return success;
}

void adjustHealth(int delta, const char *reason) {
  const int previous = state.healthScore;
  state.healthScore = constrain(state.healthScore + delta, 0, HEALTH_MAX);

  Serial.printf("[Health] %s: %d %+d -> %d\n", reason, previous, delta, state.healthScore);

  if (state.healthScore < HEALTH_QUARANTINE && !state.inQuarantine) {
    state.inQuarantine = true;
    Serial.println("[Health] QUARANTINE enabled");
    blinkLED(10, 150);
  }

  if (state.inQuarantine && state.healthScore >= HEALTH_MAX) {
    state.inQuarantine = false;
    Serial.println("[Health] Quarantine lifted");
    setupArduinoOTA();
  }

  saveHealth();
}

void loadHealth() {
  prefs.begin("ota-health", false);
  state.healthScore = prefs.getInt("health", HEALTH_MAX);
  state.inQuarantine = prefs.getBool("quarantine", false);
  state.failedAttempts24h = prefs.getInt("fails24h", 0);
  prefs.end();

  Serial.printf("[Health] Loaded: score=%d quarantine=%d\n", state.healthScore, state.inQuarantine);
}

void saveHealth() {
  prefs.begin("ota-health", false);
  prefs.putInt("health", state.healthScore);
  prefs.putBool("quarantine", state.inQuarantine);
  prefs.putInt("fails24h", state.failedAttempts24h);
  prefs.end();
}

void blinkLED(int times, int ms) {
  for (int i = 0; i < times; i++) {
    digitalWrite(LED_STATUS, HIGH);
    delay(ms);
    digitalWrite(LED_STATUS, LOW);
    delay(ms);
  }
}

bool isBtnHeld(int ms) {
  if (digitalRead(BTN_OTA) == HIGH) {
    return false;
  }
  delay(ms);
  return digitalRead(BTN_OTA) == LOW;
}

int parseVersion(String ver) {
  int major = 0;
  int minor = 0;
  int patch = 0;

  if (ver.startsWith("v") || ver.startsWith("V")) {
    ver = ver.substring(1);
  }

  const int firstDot = ver.indexOf('.');
  const int secondDot = ver.indexOf('.', firstDot + 1);

  if (firstDot > 0) {
    major = ver.substring(0, firstDot).toInt();
  } else {
    major = ver.toInt();
  }

  if (firstDot > 0 && secondDot > firstDot) {
    minor = ver.substring(firstDot + 1, secondDot).toInt();
    patch = ver.substring(secondDot + 1).toInt();
  } else if (firstDot > 0) {
    minor = ver.substring(firstDot + 1).toInt();
  }

  return major * 10000 + minor * 100 + patch;
}
