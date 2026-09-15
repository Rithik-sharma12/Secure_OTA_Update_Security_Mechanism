/*
 * ESP32 Multi-Method OTA Firmware
 * --------------------------------------------------
 * Supports:
 *   1) ArduinoOTA push updates (IDE / OTA tools)
 *   2) Backend manifest pull and self-update
 *   3) Secure package mode (AES-256-CBC + RSA-2048 signature)
 *   4) Plain package mode, bound to the manifest sha256 (for development)
 *
 * Update paths are mutually exclusive and fail closed. A device built with
 * secure keys never falls back to an unverified flash; a device without them
 * still refuses any image the manifest cannot vouch for by digest. See
 * OTA_ALLOW_INSECURE_TLS / OTA_ALLOW_UNVERIFIED_OTA for the bench escapes.
 */

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <ArduinoOTA.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <Update.h>
#include <time.h>

#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"

#include "ota_config.h"

#define FIRMWARE_VERSION    "2.4.1"
#define FIRMWARE_VERSION_N  20401  // major*10000 + minor*100 + patch

#define HEALTH_QUARANTINE 40
#define HEALTH_MAX       100

// Poll cadence for the backend manifest. Overridable from ota_config.h so a
// dashboard publish is picked up quickly without editing this file.
#ifndef OTA_CHECK_INTERVAL_SECONDS
#define OTA_CHECK_INTERVAL_SECONDS 30
#endif

#define BACKEND_CHECK_INTERVAL_MS (static_cast<unsigned long>(OTA_CHECK_INTERVAL_SECONDS) * 1000UL)
#define HEARTBEAT_INTERVAL_MS     (15UL * 1000UL)
#define ARDUINO_OTA_PORT          3232

#define LED_STATUS 2
#define BTN_OTA    0

#define SECURE_IV_BYTES        16U
#define SECURE_SIGNATURE_BYTES 256U
#define SECURE_AES_BLOCK_SIZE  16U
#define SHA256_DIGEST_BYTES    32U

/* Secure package framing. Defined once on the gateway side in
 * src/implementation/gateway/package.py — keep the two in step.
 *
 *   v2  magic(6) | sig_alg(1) | cipher_alg(1) | sig_len(2) | IV(16) | sig | ct
 *   v1  IV(16) | sig(256) | ct
 *
 * SECURE_HEADER_BYTES must stay <= SECURE_IV_BYTES: the v1 branch reads a
 * header-sized block speculatively and reuses it as the front of the IV.
 */
#define SECURE_MAGIC_V2    "SOTAv2"
#define SECURE_MAGIC_BYTES 6U
#define SECURE_HEADER_BYTES 10U

#define SECURE_SIG_ALG_RSA2048_SHA256 1U
#define SECURE_SIG_ALG_ED25519        2U  // reserved; not verifiable in this build
#define SECURE_CIPHER_ALG_AES256_CBC  1U

/* ── Security policy ───────────────────────────────────────────────────────
 * Both switches default to the safe value and may be overridden in
 * ota_config.h for bench work only. A build with either set to 1 must never
 * be flashed onto a deployed device.
 *
 * OTA_ALLOW_INSECURE_TLS   1 = contact an https:// gateway without validating
 *                              its certificate (WiFiClientSecure::setInsecure).
 * OTA_ALLOW_UNVERIFIED_OTA 1 = flash a package whose integrity could not be
 *                              proven, i.e. no secure keys configured AND no
 *                              sha256 published in the manifest.
 */
#ifndef OTA_ALLOW_INSECURE_TLS
#define OTA_ALLOW_INSECURE_TLS 0
#endif

#ifndef OTA_ALLOW_UNVERIFIED_OTA
#define OTA_ALLOW_UNVERIFIED_OTA 0
#endif

Preferences prefs;

// Reused across requests. Requests are strictly sequential, so a single client
// of each kind is enough; a WiFiClientSecure costs ~40 KB of heap while a TLS
// session is open, so we avoid allocating one per call.
WiFiClient plainClient;
WiFiClientSecure secureClient;

// TLS certificate validation compares the certificate's validity window against
// the clock. An ESP32 boots at epoch 0, so every handshake fails as
// "not yet valid" until the time is synced. Tracked here so we only sync once.
bool tlsTimeReady = false;

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
  // Lowercase hex SHA-256 of the PLAINTEXT firmware image, as published by the
  // gateway. The manifest arrives over the authenticated control channel
  // (TLS + x-api-key), so this digest is what binds the version the device
  // agreed to install to the bytes it actually flashes. Empty when the
  // gateway did not publish one.
  String sha256;
};

AppState state;

void setupWiFi();
void setupArduinoOTA();
void checkBackendOTA();
void sendHeartbeat();

bool beginRequest(HTTPClient &http, const String &url);
bool syncTimeForTls();

bool fetchLatestRelease(ManifestInfo &manifestOut);
bool performHttpUpdate(const String &url, const String &expectedSha256);
bool performSecurePackageUpdate(const String &url, const String &expectedSha256);
bool performPlainPackageUpdate(const String &url, const String &expectedSha256);
bool isSecureOtaConfigured();
bool digestMatchesExpected(const uint8_t *digest, const String &expectedHex);
String digestToHex(const uint8_t *digest);

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

bool syncTimeForTls() {
  if (tlsTimeReady) {
    return true;
  }

  Serial.print("[TLS] Syncing clock via NTP");
  configTime(0, 0, OTA_NTP_SERVER_PRIMARY, OTA_NTP_SERVER_SECONDARY);

  // Anything past 2021-01-01 means NTP has actually replied; the epoch-0
  // starting value would otherwise sail through a naive "is it non-zero" check.
  const time_t minimumValidEpoch = 1609459200UL;
  time_t now = time(nullptr);

  for (int attempt = 0; attempt < 40 && now < minimumValidEpoch; ++attempt) {
    delay(250);
    Serial.print('.');
    now = time(nullptr);
  }

  if (now < minimumValidEpoch) {
    Serial.println("\n[TLS] ERROR: NTP sync failed. HTTPS certificate checks cannot pass.");
    return false;
  }

  Serial.printf("\n[TLS] Clock synced: %s", ctime(&now));
  tlsTimeReady = true;
  return true;
}

/*
 * Open `url` on `http`, selecting the transport from the scheme.
 *
 * https:// requires a synced clock and a trusted root. OTA_ROOT_CA must hold
 * the PEM root that the gateway's certificate chains to (see ota_config.h).
 *
 * An empty OTA_ROOT_CA used to silently downgrade to setInsecure(), which
 * authenticates nothing: any host that can answer the DNS name serves the
 * manifest and the image. The request is now refused instead, so a
 * misconfigured build fails loudly at the first poll rather than trusting
 * whoever answers. Set OTA_ALLOW_INSECURE_TLS to 1 in ota_config.h to get the
 * old behaviour back on a bench.
 */
bool beginRequest(HTTPClient &http, const String &url) {
  if (!url.startsWith("https://")) {
    return http.begin(plainClient, url);
  }

  if (!syncTimeForTls()) {
    return false;
  }

  if (strlen(OTA_ROOT_CA) > 0) {
    secureClient.setCACert(OTA_ROOT_CA);
  } else {
#if OTA_ALLOW_INSECURE_TLS
    Serial.println("[TLS] WARNING: OTA_ROOT_CA is empty and OTA_ALLOW_INSECURE_TLS=1 —");
    Serial.println("[TLS] WARNING: the server certificate is NOT verified. Bench builds only.");
    secureClient.setInsecure();
#else
    Serial.println("[TLS] ERROR: https:// gateway configured but OTA_ROOT_CA is empty.");
    Serial.println("[TLS] ERROR: refusing to connect without a trusted root. Run");
    Serial.println("[TLS] ERROR:   python tools/fetch_root_ca.py <host> --out esp32_ota_main/root_ca.h");
    return false;
#endif
  }

  return http.begin(secureClient, url);
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

  if (performHttpUpdate(manifest.downloadUrl, manifest.sha256)) {
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
  if (!beginRequest(http, apiUrl)) {
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
  manifestOut.sha256 = doc["sha256"] | "";
  manifestOut.sha256.trim();
  manifestOut.sha256.toLowerCase();
  if (manifestOut.sha256.length() != SHA256_DIGEST_BYTES * 2U) {
    if (manifestOut.sha256.length() > 0) {
      Serial.printf("[Backend] Ignoring malformed manifest sha256 (%u chars)\n",
                    static_cast<unsigned int>(manifestOut.sha256.length()));
    }
    manifestOut.sha256 = "";
  }
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
  if (!beginRequest(http, String(BACKEND_URL) + "/api/heartbeat")) {
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

/*
 * Route one update to the correct package handler.
 *
 * This function used to fall back to the plain (unauthenticated) path whenever
 * the secure path returned false — including when the signature check itself
 * failed. That turned every verification failure into an unverified flash:
 * flipping one byte of the signature was enough to make the device install
 * the attacker's image. A device configured for secure OTA now stays on the
 * secure path and fails the update instead.
 */
bool performHttpUpdate(const String &url, const String &expectedSha256) {
  digitalWrite(LED_STATUS, HIGH);

  bool success = false;

  if (isSecureOtaConfigured()) {
    Serial.println("[Update] Secure OTA configuration detected");
    success = performSecurePackageUpdate(url, expectedSha256);
    if (!success) {
      Serial.println("[Update] ERROR: Secure OTA failed. No fallback — the device");
      Serial.println("[Update] ERROR: keeps its current firmware.");
    }
  } else if (expectedSha256.length() == 64) {
    Serial.println("[Update] Secure keys not configured. Using plain package mode");
    Serial.println("[Update] with the manifest sha256 as the integrity check.");
    success = performPlainPackageUpdate(url, expectedSha256);
  } else {
#if OTA_ALLOW_UNVERIFIED_OTA
    Serial.println("[Update] WARNING: no secure keys and no manifest sha256.");
    Serial.println("[Update] WARNING: flashing an UNVERIFIED image (bench build).");
    success = performPlainPackageUpdate(url, String());
#else
    Serial.println("[Update] ERROR: no secure keys configured and the manifest");
    Serial.println("[Update] ERROR: published no sha256. Nothing can vouch for this");
    Serial.println("[Update] ERROR: image, so the update is refused.");
    success = false;
#endif
  }

  digitalWrite(LED_STATUS, LOW);
  return success;
}

String digestToHex(const uint8_t *digest) {
  static const char kHexDigits[] = "0123456789abcdef";
  String out;
  out.reserve(SHA256_DIGEST_BYTES * 2U);
  for (size_t i = 0; i < SHA256_DIGEST_BYTES; ++i) {
    out += kHexDigits[(digest[i] >> 4) & 0x0F];
    out += kHexDigits[digest[i] & 0x0F];
  }
  return out;
}

/*
 * Constant-time-ish comparison of a computed digest against the hex digest the
 * manifest published. Returns false for a malformed or absent expectation, so
 * callers must decide separately whether an absent digest is acceptable.
 */
bool digestMatchesExpected(const uint8_t *digest, const String &expectedHex) {
  if (expectedHex.length() != SHA256_DIGEST_BYTES * 2U) {
    return false;
  }

  const String actualHex = digestToHex(digest);

  uint8_t diff = 0;
  for (size_t i = 0; i < actualHex.length(); ++i) {
    diff |= static_cast<uint8_t>(actualHex[i]) ^
            static_cast<uint8_t>(tolower(expectedHex[i]));
  }

  return diff == 0;
}

bool isSecureOtaConfigured() {
  const bool hasAesKey = strlen(FIRMWARE_ENC_KEY) == 32;

  const bool hasPubKey =
    strstr(FIRMWARE_PUB_KEY, "-----BEGIN PUBLIC KEY-----") != nullptr &&
    strstr(FIRMWARE_PUB_KEY, "-----END PUBLIC KEY-----") != nullptr;

  return hasAesKey && hasPubKey;
}

bool performSecurePackageUpdate(const String &url, const String &expectedSha256) {
  Serial.println("[Update] Starting secure OTA package flow...");

  HTTPClient http;
  if (!beginRequest(http, url)) {
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

  WiFiClient *stream = http.getStreamPtr();

  /*
   * Two package layouts are accepted, distinguished by a magic prefix:
   *
   *   v2  "SOTAv2" | sig_alg | cipher_alg | sig_len(be16) | IV | sig | ct
   *   v1  IV | sig | ct                      (no header; the original format)
   *
   * v2 states its algorithms rather than leaving the device to assume them,
   * so a package signed with something this build cannot verify is rejected
   * outright instead of being fed to the wrong verifier. v1 is still parsed
   * so packages built by older tooling keep working.
   *
   * Both layouts are defined once, on the gateway side, in
   * src/implementation/gateway/package.py.
   */
  uint8_t header[SECURE_HEADER_BYTES];
  const size_t headerRead = stream->readBytes(reinterpret_cast<char *>(header), sizeof(header));
  if (headerRead != sizeof(header)) {
    Serial.println("[Update] ERROR: Could not read secure package header");
    http.end();
    return false;
  }

  const bool isV2 = (memcmp(header, SECURE_MAGIC_V2, SECURE_MAGIC_BYTES) == 0);

  size_t signatureLength = SECURE_SIGNATURE_BYTES;
  size_t consumedHeader = 0;

  uint8_t iv[SECURE_IV_BYTES];
  uint8_t signature[SECURE_SIGNATURE_BYTES];

  if (isV2) {
    const uint8_t signatureAlg = header[SECURE_MAGIC_BYTES];
    const uint8_t cipherAlg = header[SECURE_MAGIC_BYTES + 1U];
    signatureLength = (static_cast<size_t>(header[SECURE_MAGIC_BYTES + 2U]) << 8) |
                      static_cast<size_t>(header[SECURE_MAGIC_BYTES + 3U]);

    Serial.printf("[Update] Package format v2 (sig_alg=%u cipher_alg=%u sig_len=%u)\n",
                  static_cast<unsigned int>(signatureAlg),
                  static_cast<unsigned int>(cipherAlg),
                  static_cast<unsigned int>(signatureLength));

    if (signatureAlg != SECURE_SIG_ALG_RSA2048_SHA256) {
      Serial.println("[Update] ERROR: Package signed with an algorithm this build");
      Serial.println("[Update] ERROR: cannot verify. Refusing the update.");
      http.end();
      return false;
    }

    if (cipherAlg != SECURE_CIPHER_ALG_AES256_CBC) {
      Serial.println("[Update] ERROR: Unsupported package cipher. Refusing the update.");
      http.end();
      return false;
    }

    if (signatureLength != SECURE_SIGNATURE_BYTES) {
      Serial.printf("[Update] ERROR: Declared signature length %u, expected %u\n",
                    static_cast<unsigned int>(signatureLength),
                    static_cast<unsigned int>(SECURE_SIGNATURE_BYTES));
      http.end();
      return false;
    }

    consumedHeader = SECURE_HEADER_BYTES;

    const size_t ivRead = stream->readBytes(reinterpret_cast<char *>(iv), sizeof(iv));
    const size_t sigRead = stream->readBytes(reinterpret_cast<char *>(signature), signatureLength);
    if (ivRead != sizeof(iv) || sigRead != signatureLength) {
      Serial.println("[Update] ERROR: Truncated secure package header");
      http.end();
      return false;
    }
  } else {
    // v1: the bytes already read are the start of the IV, not a header.
    Serial.println("[Update] Package format v1 (legacy, no algorithm header)");

    memcpy(iv, header, SECURE_HEADER_BYTES);
    const size_t ivRemaining = SECURE_IV_BYTES - SECURE_HEADER_BYTES;
    const size_t ivRead = stream->readBytes(
      reinterpret_cast<char *>(iv) + SECURE_HEADER_BYTES, ivRemaining);
    const size_t sigRead = stream->readBytes(
      reinterpret_cast<char *>(signature), SECURE_SIGNATURE_BYTES);
    if (ivRead != ivRemaining || sigRead != SECURE_SIGNATURE_BYTES) {
      Serial.println("[Update] ERROR: Truncated secure package header");
      http.end();
      return false;
    }
  }

  const size_t framingBytes = consumedHeader + SECURE_IV_BYTES + signatureLength;
  if (static_cast<size_t>(contentLength) <= framingBytes) {
    Serial.println("[Update] ERROR: Secure package has no payload after its header");
    http.end();
    return false;
  }

  const size_t encryptedSize = static_cast<size_t>(contentLength) - framingBytes;

  if ((encryptedSize % SECURE_AES_BLOCK_SIZE) != 0U) {
    Serial.printf("[Update] ERROR: Encrypted payload size invalid (%u bytes)\n", static_cast<unsigned int>(encryptedSize));
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

    /*
     * The signature proves the image was produced by the holder of the signing
     * key. It does NOT prove this is the image the manifest promised: a valid
     * package from an older release is signed just as correctly, so an
     * attacker who can serve the download URL could answer a v2.5.0 manifest
     * with a genuinely signed v2.0.0 package and roll the fleet back past the
     * version check. Binding the flash to the digest the manifest published
     * over the authenticated channel closes that gap.
     */
    if (expectedSha256.length() > 0) {
      if (!digestMatchesExpected(hash, expectedSha256)) {
        Serial.println("[Update] ERROR: Image does not match the manifest sha256.");
        Serial.printf("[Update] ERROR:   expected %s\n", expectedSha256.c_str());
        Serial.printf("[Update] ERROR:   computed %s\n", digestToHex(hash).c_str());
        break;
      }
      Serial.println("[Update] Manifest sha256 matches the decrypted image.");
    } else {
      Serial.println("[Update] NOTE: manifest published no sha256; relying on the");
      Serial.println("[Update] NOTE: signature alone (no rollback binding).");
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

/*
 * Plain (unencrypted) image download.
 *
 * The stream is now read in chunks and hashed as it goes, rather than handed
 * wholesale to Update.writeStream(), so the image can be checked against the
 * manifest digest before the boot partition is switched. `expectedSha256`
 * empty means the caller has already decided an unverified flash is
 * acceptable (OTA_ALLOW_UNVERIFIED_OTA); every other caller passes a digest.
 */
bool performPlainPackageUpdate(const String &url, const String &expectedSha256) {
  Serial.println("[Update] Starting plain OTA package flow...");

  HTTPClient http;
  if (!beginRequest(http, url)) {
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

  mbedtls_md_context_t mdCtx;
  mbedtls_md_init(&mdCtx);

  bool success = true;
  size_t written = 0;

  if (mbedtls_md_setup(&mdCtx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0) != 0 ||
      mbedtls_md_starts(&mdCtx) != 0) {
    Serial.println("[Update] ERROR: SHA-256 context init failed");
    success = false;
  }

  if (success) {
    uint8_t buffer[1024];
    unsigned long lastDataMs = millis();

    while (http.connected() && (!hasKnownLength || written < static_cast<size_t>(contentLength))) {
      const size_t available = stream->available();

      if (available == 0U) {
        if (millis() - lastDataMs > 15000UL) {
          Serial.println("[Update] ERROR: Plain OTA stream stalled");
          success = false;
          break;
        }
        delay(1);
        continue;
      }

      const size_t toRead = available > sizeof(buffer) ? sizeof(buffer) : available;
      const size_t got = stream->readBytes(buffer, toRead);
      if (got == 0U) {
        continue;
      }
      lastDataMs = millis();

      if (mbedtls_md_update(&mdCtx, buffer, got) != 0) {
        Serial.println("[Update] ERROR: Hash update failed");
        success = false;
        break;
      }

      if (Update.write(buffer, got) != got) {
        Serial.printf("[Update] ERROR: Flash write failed in plain flow (%u)\n", Update.getError());
        success = false;
        break;
      }

      written += got;
    }
  }

  if (success && written == 0U) {
    Serial.println("[Update] ERROR: Plain OTA stream returned zero bytes");
    success = false;
  }

  if (success && hasKnownLength && written != static_cast<size_t>(contentLength)) {
    Serial.printf("[Update] ERROR: Plain OTA size mismatch wrote=%u expected=%u\n",
                  static_cast<unsigned int>(written),
                  static_cast<unsigned int>(contentLength));
    success = false;
  }

  if (success) {
    uint8_t digest[SHA256_DIGEST_BYTES];
    if (mbedtls_md_finish(&mdCtx, digest) != 0) {
      Serial.println("[Update] ERROR: Hash finalize failed");
      success = false;
    } else if (expectedSha256.length() > 0) {
      if (!digestMatchesExpected(digest, expectedSha256)) {
        Serial.println("[Update] ERROR: Image does not match the manifest sha256.");
        Serial.printf("[Update] ERROR:   expected %s\n", expectedSha256.c_str());
        Serial.printf("[Update] ERROR:   computed %s\n", digestToHex(digest).c_str());
        success = false;
      } else {
        Serial.println("[Update] Manifest sha256 matches the downloaded image.");
      }
    }
  }

  mbedtls_md_free(&mdCtx);

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
