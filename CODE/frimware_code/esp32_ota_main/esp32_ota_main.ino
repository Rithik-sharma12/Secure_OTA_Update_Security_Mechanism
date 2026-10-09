/*
 * ESP32 Multi-Method OTA Firmware
 * --------------------------------------------------
 * Supports:
 *   1) ArduinoOTA push updates (IDE / OTA tools)
 *   2) Backend manifest pull and self-update
 *   3) Secure package mode (AES-256-CBC + RSA-2048 signature)
 *   4) Plain package mode, bound to the manifest sha256 (for development)
 *   5) Remote control from the dashboard over the internet: commands
 *      (update / check_update / reboot / identify) arrive in heartbeat
 *      responses, progress is reported to /api/devices/{id}/ota/status
 *   6) Post-update health gate with automatic bootloader rollback
 *   7) USB provisioning: Wi-Fi, gateway URL and device token are written
 *      over the COM port (SOTA:PROVISION) and kept in NVS, so one released
 *      binary can be flashed to any board and configured afterwards
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

#include "esp_ota_ops.h"

#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"

#include "ota_config.h"

// Older ota_config.h files predate these; keep them compiling.
#ifndef DEVICE_ID
#define DEVICE_ID "auto"
#endif
#ifndef DEVICE_HOSTNAME
#define DEVICE_HOSTNAME "auto"
#endif
#ifndef DEVICE_TOKEN
#define DEVICE_TOKEN ""
#endif
#ifndef BACKEND_API_KEY
#define BACKEND_API_KEY ""
#endif

#define FIRMWARE_VERSION    "2.5.0"
#define FIRMWARE_VERSION_N  20500  // major*10000 + minor*100 + patch

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

// After an OTA reboot the new image must prove itself within this window —
// Wi-Fi up and one heartbeat accepted by the gateway — or the bootloader is
// told to go back to the previous image.
#ifndef OTA_HEALTH_GATE_TIMEOUT_SECONDS
#define OTA_HEALTH_GATE_TIMEOUT_SECONDS 120
#endif
#define HEALTH_GATE_TIMEOUT_MS (static_cast<unsigned long>(OTA_HEALTH_GATE_TIMEOUT_SECONDS) * 1000UL)

#define REPORT_TIMEOUT_MS   6000
#define MAX_PENDING_COMMANDS 4
#define SERIAL_LINE_MAX      1024

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

  // Post-update health gate (see confirmHealthyBoot / enforceHealthGate).
  bool rollbackPending = false;
  unsigned long bootMillis = 0;
};

/*
 * Settings that used to be compile-time only. Each is read from NVS
 * (namespace "sota-cfg", written by SOTA:PROVISION over USB) and falls back to
 * the ota_config.h macro, so an existing build behaves exactly as before and a
 * CI-built release can be configured per board after flashing.
 */
struct RuntimeConfig {
  String wifiSsid;
  String wifiPassword;
  String backendUrl;
  String apiKey;       // fleet key (legacy, shared)
  String deviceToken;  // per-device token from POST /api/devices/register
  String deviceId;
  String hostname;
};

struct PendingCommand {
  String id;
  String type;
  String version;
};

RuntimeConfig cfg;
PendingCommand pendingCommands[MAX_PENDING_COMMANDS];
int pendingCommandCount = 0;
String serialLine;
String rolledBackVersion;   // set when a newer image gave up and the bootloader brought us back
String rolledBackCommand;
bool bootReportsDone = false;

enum UpdateOutcome { UPDATE_NOT_NEEDED, UPDATE_INSTALLED, UPDATE_FAILED, UPDATE_CHECK_FAILED };

struct ManifestInfo {
  String version;
  String filename;
  String downloadUrl;
  /*
   * Two different digests, because in secure mode the bytes on the wire are
   * not the bytes that get flashed.
   *
   *   sha256       digest of the artifact exactly as served. For a plain
   *                release that IS the firmware image. For a secure release
   *                it covers the whole package (header, IV, signature and
   *                ciphertext), so it must never be compared against the
   *                decrypted image.
   *
   *   imageSha256  digest of the PLAINTEXT firmware image. Equal to sha256
   *                for a plain release; the only one meaningful to the secure
   *                path. Published by whoever built the package, so it may be
   *                absent on older releases.
   *
   * Both arrive over the authenticated control channel (TLS + x-api-key),
   * which is what lets either bind an agreed version to specific bytes.
   * Empty when the gateway published nothing usable.
   */
  String sha256;
  String imageSha256;

  /*
   * True when the gateway says the artifact is an encrypted package. A device
   * without secure keys must refuse it: the plain path would happily flash
   * ciphertext, and only the ESP32 Update library's 0xE9 image-magic check
   * stands in the way — which a v1 package's random first IV byte passes once
   * in 256, bricking the board.
   */
  bool securePackage = false;
};

AppState state;

void setupWiFi();
void setupArduinoOTA();
UpdateOutcome checkBackendOTA();
bool sendHeartbeat();

void loadRuntimeConfig();
bool isPlaceholder(const String &value);
void addAuthHeaders(HTTPClient &http);
void reportOtaStatus(const char *phase, const String &version, int progress, const String &detail);
void reportCommandResult(const String &commandId, bool ok, const String &detail);
void processPendingCommands();
void serviceSerial();
void handleSerialLine(const String &line);
void detectPendingVerification();
// Declared up front with C linkage: the .ino preprocessor (arduino-cli and
// PlatformIO) otherwise generates a C++ prototype for it, which conflicts with
// the core's weak C symbol this overrides.
extern "C" bool verifyRollbackLater();
void confirmHealthyBoot();
void enforceHealthGate();
String urlEncode(const String &value);

bool beginRequest(HTTPClient &http, const String &url);
bool syncTimeForTls();

bool fetchLatestRelease(ManifestInfo &manifestOut);
bool performHttpUpdate(const ManifestInfo &manifest);
bool performSecurePackageUpdate(const String &url, const String &expectedSha256);
bool performPlainPackageUpdate(const String &url, const String &expectedSha256);
bool isSecureOtaConfigured();
bool digestMatchesExpected(const uint8_t *digest, const String &expectedHex);
String digestToHex(const uint8_t *digest);
void normalizeDigestField(String &value, const char *fieldName);

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

  state.bootMillis = millis();
  loadRuntimeConfig();
  detectPendingVerification();
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
  serviceSerial();
  enforceHealthGate();

  if (isBtnHeld(3000)) {
    Serial.println("[OTA] Manual backend OTA trigger from button");
    checkBackendOTA();
  }

  const unsigned long now = millis();

  if (now - state.lastBackendCheck >= BACKEND_CHECK_INTERVAL_MS) {
    state.lastBackendCheck = now;
    if (state.rollbackPending) {
      // Never stack a second update on an image that has not proven itself.
      Serial.println("[OTA] Skipping backend check until this image passes its health gate.");
    } else if (state.inQuarantine) {
      Serial.println("[OTA] Skipping backend check. Device quarantined.");
    } else {
      checkBackendOTA();
    }
  }

  if (now - state.lastHeartbeat >= HEARTBEAT_INTERVAL_MS) {
    state.lastHeartbeat = now;
    if (sendHeartbeat()) {
      adjustHealth(+1, "poll success");
      confirmHealthyBoot();
    }
  }

  processPendingCommands();

  delay(10);
}

void setupWiFi() {
  // A release binary built in CI may carry placeholder credentials. Instead
  // of boot-looping on a network that does not exist, wait here for the
  // dashboard to provision the board over USB (SOTA:PROVISION).
  if (isPlaceholder(cfg.wifiSsid)) {
    Serial.println("[WiFi] No Wi-Fi configured. Waiting for USB provisioning");
    Serial.println("[WiFi] (dashboard -> Devices -> Provision, or send SOTA:PROVISION {...}).");
    Serial.printf("SOTA:READY {\"device_id\":\"%s\",\"version\":\"%s\"}\n", cfg.deviceId.c_str(), FIRMWARE_VERSION);
    for (;;) {
      serviceSerial();  // restarts the board once provisioned
      digitalWrite(LED_STATUS, (millis() / 500UL) % 2UL);
      delay(10);
    }
  }

  Serial.printf("[WiFi] Connecting to %s", cfg.wifiSsid.c_str());
  WiFi.setHostname(cfg.hostname.c_str());
  WiFi.begin(cfg.wifiSsid.c_str(), cfg.wifiPassword.c_str());

  int tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 30) {
    for (int i = 0; i < 50; ++i) {
      serviceSerial();
      delay(10);
    }
    Serial.print('.');
    tries++;
  }

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("\n[WiFi] Failed. Rebooting in 10s (send SOTA:PROVISION to change Wi-Fi).");
    adjustHealth(-1, "network error");
    const unsigned long until = millis() + 10000UL;
    while (millis() < until) {
      serviceSerial();
      delay(10);
    }
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
  ArduinoOTA.setHostname(cfg.hostname.c_str());
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

UpdateOutcome checkBackendOTA() {
  Serial.println("[Backend] Checking for firmware update...");

  ManifestInfo manifest;
  if (!fetchLatestRelease(manifest)) {
    Serial.println("[Backend] Could not fetch release info");
    adjustHealth(-1, "network error");
    return UPDATE_CHECK_FAILED;
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
    return UPDATE_NOT_NEEDED;
  }

  if (remoteVerN < FIRMWARE_VERSION_N) {
    Serial.println("[Backend] Anti-rollback blocked downgrade package");
    return UPDATE_NOT_NEEDED;
  }

  Serial.printf("[Backend] Update available: %s\n", manifest.downloadUrl.c_str());
  Serial.println("[Backend] Downloading and flashing...");
  reportOtaStatus("downloading", manifest.version, 0, "Download started");

  if (performHttpUpdate(manifest)) {
    adjustHealth(+10, "update success");
    reportOtaStatus("rebooting", manifest.version, 100, "Image verified and written; rebooting into it");

    // The new image reads these after boot: which version it is expected to
    // be, and which dashboard command (if any) to acknowledge once healthy.
    prefs.begin("ota-health", false);
    prefs.putString("expectver", manifest.version);
    if (pendingCommandCount > 0 && (pendingCommands[0].type == "update" || pendingCommands[0].type == "check_update")) {
      prefs.putString("ackcmd", pendingCommands[0].id);
    }
    prefs.end();

    Serial.println("[Backend] Update successful. Rebooting.");
    blinkLED(10, 50);
    delay(500);
    ESP.restart();
    return UPDATE_INSTALLED;  // not reached
  }

  Serial.println("[Backend] Update failed");
  state.failedAttempts24h++;
  adjustHealth(-25, "update failed");
  reportOtaStatus("failed", manifest.version, -1, "Download, verification or flash write failed (see serial log)");
  return UPDATE_FAILED;
}

bool fetchLatestRelease(ManifestInfo &manifestOut) {
  if (WiFi.status() != WL_CONNECTED) {
    return false;
  }

  HTTPClient http;
  // Identify ourselves so the gateway can answer with the build a dashboard
  // deployment assigned to *this* board, for *this* architecture.
  const String apiUrl = cfg.backendUrl + "/releases/latest/manifest?device_id=" + urlEncode(cfg.deviceId) +
                        "&device_type=" + urlEncode(DEVICE_TYPE);
  if (!beginRequest(http, apiUrl)) {
    Serial.println("[Backend] Could not open manifest endpoint");
    return false;
  }

  addAuthHeaders(http);

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

  // Gateway with OTA_AUTO_UPDATE off and nothing assigned to this board.
  if (doc["updateAvailable"].is<bool>() && !doc["updateAvailable"].as<bool>()) {
    manifestOut.version = FIRMWARE_VERSION;
    manifestOut.downloadUrl = "-";
    return true;
  }

  manifestOut.filename = doc["filename"] | "firmware.bin";
  manifestOut.sha256 = doc["sha256"] | "";
  normalizeDigestField(manifestOut.sha256, "sha256");

  manifestOut.imageSha256 = doc["imageSha256"] | "";
  normalizeDigestField(manifestOut.imageSha256, "imageSha256");

  manifestOut.securePackage = doc["securePackage"] | false;
  if (doc["downloadUrl"].is<const char*>()) {
    manifestOut.downloadUrl = doc["downloadUrl"].as<String>();
  } else {
    manifestOut.downloadUrl = cfg.backendUrl + "/releases/download/" + manifestOut.filename;
  }

  if (manifestOut.version.length() == 0 || manifestOut.downloadUrl.length() == 0) {
    Serial.println("[Backend] Manifest missing required fields");
    return false;
  }

  return true;
}

bool sendHeartbeat() {
  if (WiFi.status() != WL_CONNECTED) {
    return false;
  }

  const unsigned long uptimeSeconds = millis() / 1000UL;
  const int freeHeap = ESP.getFreeHeap();
  const int heapSize = ESP.getHeapSize();
  const int memoryUsedPct =
    (heapSize > 0)
      ? static_cast<int>(100 - ((static_cast<long>(freeHeap) * 100L) / heapSize))
      : 0;

  HTTPClient http;
  if (!beginRequest(http, cfg.backendUrl + "/api/heartbeat")) {
    return false;
  }

  http.addHeader("Content-Type", "application/json");
  addAuthHeaders(http);
  http.setTimeout(10000);

  JsonDocument doc;
  doc["device_id"] = cfg.deviceId;
  doc["device_type"] = DEVICE_TYPE;
  doc["current_version"] = FIRMWARE_VERSION;
  doc["ash_score"] = state.healthScore;
  doc["status"] = state.inQuarantine ? "Quarantined" : "Healthy";
  doc["memoryUsage"] = memoryUsedPct;
  doc["uptime"] = uptimeSeconds;
  doc["location"] = cfg.hostname;
  doc["signalStrength"] = WiFi.RSSI();
  doc["ip"] = WiFi.localIP().toString();
  doc["rollback_pending"] = state.rollbackPending;

  JsonArray logs = doc["logs"].to<JsonArray>();
  logs.add(String("[HB] device=") + cfg.deviceId + " fw=" + FIRMWARE_VERSION + " ash=" + state.healthScore);
  logs.add(String("[NET] ip=") + WiFi.localIP().toString() + " rssi=" + WiFi.RSSI() + "dBm");
  logs.add(String("[SYS] uptime=") + uptimeSeconds + "s freeHeap=" + freeHeap + "B mem=" + memoryUsedPct + "% status=" + (state.inQuarantine ? "Quarantined" : "Healthy"));

  String payload;
  serializeJson(doc, payload);
  const int code = http.POST(payload);
  if (code < 200 || code >= 300) {
    Serial.printf("[HB] Gateway answered %d\n", code);
    if (code == 401) {
      Serial.println("[HB] Credentials refused. Re-provision this board from the dashboard.");
    }
    http.end();
    return false;
  }

  /*
   * The gateway cannot connect to us (NAT, firewalls), so it answers our
   * heartbeat with whatever the dashboard queued. Commands are only recorded
   * here and executed from loop(), outside the HTTP client's lifetime.
   */
  JsonDocument reply;
  const DeserializationError err = deserializeJson(reply, http.getStream());
  http.end();
  if (err) {
    return true;  // accepted; an unreadable body is not a health failure
  }

  JsonArray commands = reply["commands"].as<JsonArray>();
  for (JsonObject command : commands) {
    const String id = command["id"] | "";
    if (id.length() == 0) {
      continue;
    }
    bool known = false;
    for (int i = 0; i < pendingCommandCount; ++i) {
      if (pendingCommands[i].id == id) known = true;
    }
    if (known || pendingCommandCount >= MAX_PENDING_COMMANDS) {
      continue;
    }
    pendingCommands[pendingCommandCount].id = id;
    pendingCommands[pendingCommandCount].type = command["type"] | "";
    pendingCommands[pendingCommandCount].version = command["params"]["version"] | "";
    pendingCommandCount++;
    Serial.printf("[CMD] Received '%s' (%s)\n", pendingCommands[pendingCommandCount - 1].type.c_str(), id.c_str());
  }

  // Legacy signal: the gateway has something newer for us. Act on it now
  // rather than waiting out the poll timer.
  const String hint = reply["command"] | "";
  if (hint == "update_available" && pendingCommandCount == 0 && !state.inQuarantine && !state.rollbackPending) {
    state.lastBackendCheck = millis() - BACKEND_CHECK_INTERVAL_MS;
  }
  return true;
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
bool performHttpUpdate(const ManifestInfo &manifest) {
  digitalWrite(LED_STATUS, HIGH);

  bool success = false;

  if (isSecureOtaConfigured()) {
    /*
     * The secure path decrypts before it checks, so it must be given the
     * digest of the PLAINTEXT image. `sha256` describes the package as
     * served and would never match — passing it here would fail every secure
     * update and quarantine the device after three tries.
     */
    Serial.println("[Update] Secure OTA configuration detected");
    success = performSecurePackageUpdate(manifest.downloadUrl, manifest.imageSha256);
    if (!success) {
      Serial.println("[Update] ERROR: Secure OTA failed. No fallback — the device");
      Serial.println("[Update] ERROR: keeps its current firmware.");
    }
  } else if (manifest.securePackage) {
    Serial.println("[Update] ERROR: The release is an encrypted package but this");
    Serial.println("[Update] ERROR: device has no FIRMWARE_ENC_KEY/FIRMWARE_PUB_KEY.");
    Serial.println("[Update] ERROR: Flashing it would write ciphertext to flash.");
    success = false;
  } else if (manifest.sha256.length() == SHA256_DIGEST_BYTES * 2U) {
    // Plain path: the downloaded bytes are the image, so `sha256` is correct.
    Serial.println("[Update] Secure keys not configured. Using plain package mode");
    Serial.println("[Update] with the manifest sha256 as the integrity check.");
    success = performPlainPackageUpdate(manifest.downloadUrl, manifest.sha256);
  } else {
#if OTA_ALLOW_UNVERIFIED_OTA
    Serial.println("[Update] WARNING: no secure keys and no manifest sha256.");
    Serial.println("[Update] WARNING: flashing an UNVERIFIED image (bench build).");
    success = performPlainPackageUpdate(manifest.downloadUrl, String());
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

/*
 * Reduce a manifest digest field to either a valid 64-character lowercase hex
 * string or an empty one, so callers only ever see "usable" or "absent".
 */
void normalizeDigestField(String &value, const char *fieldName) {
  value.trim();
  value.toLowerCase();

  if (value.length() == 0) {
    return;
  }

  if (value.length() != SHA256_DIGEST_BYTES * 2U) {
    Serial.printf("[Backend] Ignoring malformed manifest %s (%u chars)\n",
                  fieldName,
                  static_cast<unsigned int>(value.length()));
    value = "";
  }
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

  /*
   * Must be checked before the loop. digestToHex builds its result with 64
   * String concatenations, and the ESP32 core's String::concat calls
   * invalidate() when a reallocation fails, leaving length() == 0. Heap
   * pressure here is not hypothetical: a WiFiClientSecure session and the
   * Update write buffer are both live during an OTA. Looping to
   * actualHex.length() would then run zero iterations, leave diff at 0, and
   * return true for ANY expected digest — a fail-open on the one check the
   * plain path relies on.
   */
  if (actualHex.length() != SHA256_DIGEST_BYTES * 2U) {
    Serial.println("[Update] ERROR: Could not format digest for comparison (out of memory).");
    return false;
  }

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

  addAuthHeaders(http);

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

  addAuthHeaders(http);

  http.setTimeout(15000);
  const int httpCode = http.GET();
  if (httpCode != HTTP_CODE_OK) {
    Serial.printf("[Update] ERROR: Plain package GET failed (%d)\n", httpCode);
    http.end();
    return false;
  }

  const int contentLength = http.getSize();

  /*
   * A known Content-Length is required now, where the old writeStream() path
   * tolerated its absence. Two reasons, both introduced by hashing the stream
   * ourselves:
   *
   *  - Without a length the loop below can only stop when the peer closes or
   *    the stall timer fires, and the stall timer means failure. HTTPClient
   *    sends `Connection: keep-alive` by default, so against a keep-alive
   *    server a completed download would still be aborted.
   *
   *  - A response with no Content-Length is almost always chunked, and
   *    getStreamPtr() hands back the raw socket with the chunk-size lines
   *    still in it. Those bytes would be hashed and flashed as if they were
   *    firmware.
   *
   * The gateway always sends a length (server.py serves a file from disk), so
   * this is a clear error rather than a limitation in practice.
   */
  if (contentLength <= 0) {
    Serial.println("[Update] ERROR: Plain package response has no Content-Length.");
    Serial.println("[Update] ERROR: Refusing to flash a stream of unknown length.");
    http.end();
    return false;
  }

  const size_t expectedBytes = static_cast<size_t>(contentLength);

  if (!Update.begin(expectedBytes, U_FLASH)) {
    Serial.printf("[Update] ERROR: Not enough space for plain update (%u)\n", Update.getError());
    http.end();
    return false;
  }
  Serial.printf("[Update] Plain package size: %d bytes\n", contentLength);

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

    // Bounded by the declared length, so the loop always terminates on a
    // complete download rather than waiting for a close that keep-alive will
    // never send.
    while (written < expectedBytes) {
      // Checked inside the loop, not in the condition: a peer that closes
      // after sending everything must still count as success.
      const bool peerGone = !http.connected();

      const size_t available = stream->available();

      if (available == 0U) {
        if (peerGone) {
          Serial.println("[Update] ERROR: Connection closed before the full image arrived");
          success = false;
          break;
        }
        if (millis() - lastDataMs > 15000UL) {
          Serial.println("[Update] ERROR: Plain OTA stream stalled");
          success = false;
          break;
        }
        delay(1);
        continue;
      }

      size_t toRead = available > sizeof(buffer) ? sizeof(buffer) : available;
      const size_t remaining = expectedBytes - written;
      if (toRead > remaining) {
        toRead = remaining;  // never read past the declared body
      }

      const size_t got = stream->readBytes(buffer, toRead);
      if (got == 0U) {
        // available() claimed data that could not be read. Without this the
        // stall timer is unreachable here and the loop could spin forever.
        if (millis() - lastDataMs > 15000UL) {
          Serial.println("[Update] ERROR: Plain OTA stream stalled (no readable bytes)");
          success = false;
          break;
        }
        delay(1);
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

  if (success && written != expectedBytes) {
    Serial.printf("[Update] ERROR: Plain OTA size mismatch wrote=%u expected=%u\n",
                  static_cast<unsigned int>(written),
                  static_cast<unsigned int>(expectedBytes));
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


/* ══════════════════════════════════════════════════════════════════════════
 *  Runtime configuration (NVS "sota-cfg", falls back to ota_config.h)
 * ══════════════════════════════════════════════════════════════════════════ */

bool isPlaceholder(const String &value) {
  return value.length() == 0 || value.startsWith("CHANGE_ME") || value.startsWith("YOUR_");
}

static String macDeviceId() {
  const uint64_t mac = ESP.getEfuseMac();
  char id[24];
  // getEfuseMac() packs the first MAC byte into the lowest bits.
  snprintf(id, sizeof(id), "esp32-%02x%02x%02x%02x%02x%02x",
           static_cast<unsigned>(mac & 0xFF), static_cast<unsigned>((mac >> 8) & 0xFF),
           static_cast<unsigned>((mac >> 16) & 0xFF), static_cast<unsigned>((mac >> 24) & 0xFF),
           static_cast<unsigned>((mac >> 32) & 0xFF), static_cast<unsigned>((mac >> 40) & 0xFF));
  return String(id);
}

void loadRuntimeConfig() {
  prefs.begin("sota-cfg", false);
  cfg.wifiSsid = prefs.getString("ssid", WIFI_SSID);
  cfg.wifiPassword = prefs.getString("pass", WIFI_PASSWORD);
  cfg.backendUrl = prefs.getString("url", BACKEND_URL);
  cfg.apiKey = prefs.getString("apikey", BACKEND_API_KEY);
  cfg.deviceToken = prefs.getString("token", DEVICE_TOKEN);
  cfg.deviceId = prefs.getString("devid", DEVICE_ID);
  cfg.hostname = prefs.getString("host", DEVICE_HOSTNAME);
  prefs.end();

  while (cfg.backendUrl.endsWith("/")) {
    cfg.backendUrl.remove(cfg.backendUrl.length() - 1);
  }

  // One CI build is flashed onto many boards, so a shared compile-time id
  // would make them all report as the same device. "auto" derives a stable,
  // unique id from the factory-programmed MAC instead.
  if (cfg.deviceId.length() == 0 || cfg.deviceId == "auto" || isPlaceholder(cfg.deviceId)) {
    cfg.deviceId = macDeviceId();
  }
  if (cfg.hostname.length() == 0 || cfg.hostname == "auto" || isPlaceholder(cfg.hostname)) {
    cfg.hostname = cfg.deviceId;
  }

  Serial.printf("[CFG] device=%s gateway=%s auth=%s\n", cfg.deviceId.c_str(), cfg.backendUrl.c_str(),
                cfg.deviceToken.length() ? "device-token" : (cfg.apiKey.length() ? "fleet-key" : "none"));
}

/*
 * Prefer the per-device token: it only lets this board speak for itself,
 * whereas the fleet key extracted from any one board speaks for all of them.
 */
void addAuthHeaders(HTTPClient &http) {
  if (cfg.deviceToken.length() > 0) {
    http.addHeader("x-device-token", cfg.deviceToken);
  } else if (cfg.apiKey.length() > 0 && !isPlaceholder(cfg.apiKey)) {
    http.addHeader("x-api-key", cfg.apiKey);
  }
}

String urlEncode(const String &value) {
  static const char *hex = "0123456789ABCDEF";
  String out;
  out.reserve(value.length() * 3);
  for (size_t i = 0; i < value.length(); ++i) {
    const char c = value.charAt(i);
    if (isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' || c == '~') {
      out += c;
    } else {
      out += '%';
      out += hex[(static_cast<unsigned char>(c) >> 4) & 0x0F];
      out += hex[static_cast<unsigned char>(c) & 0x0F];
    }
  }
  return out;
}

/* ══════════════════════════════════════════════════════════════════════════
 *  Reports to the gateway
 * ══════════════════════════════════════════════════════════════════════════ */

static bool postJson(const String &path, const String &body) {
  if (WiFi.status() != WL_CONNECTED) {
    return false;
  }
  HTTPClient http;
  if (!beginRequest(http, cfg.backendUrl + path)) {
    return false;
  }
  http.addHeader("Content-Type", "application/json");
  addAuthHeaders(http);
  http.setTimeout(REPORT_TIMEOUT_MS);
  const int code = http.POST(body);
  http.end();
  return code >= 200 && code < 300;
}

void reportOtaStatus(const char *phase, const String &version, int progress, const String &detail) {
  JsonDocument doc;
  doc["phase"] = phase;
  doc["version"] = version;
  if (progress >= 0) {
    doc["progress"] = progress;
  }
  doc["detail"] = detail;
  String body;
  serializeJson(doc, body);
  const bool ok = postJson("/api/devices/" + urlEncode(cfg.deviceId) + "/ota/status", body);
  Serial.printf("[Report] ota/status %s v%s %s\n", phase, version.c_str(), ok ? "sent" : "NOT delivered");
}

void reportCommandResult(const String &commandId, bool ok, const String &detail) {
  if (commandId.length() == 0) {
    return;
  }
  JsonDocument doc;
  doc["ok"] = ok;
  doc["detail"] = detail;
  String body;
  serializeJson(doc, body);
  const bool sent = postJson("/api/devices/" + urlEncode(cfg.deviceId) + "/commands/" + urlEncode(commandId) + "/result", body);
  Serial.printf("[CMD] %s -> %s (%s)%s\n", commandId.c_str(), ok ? "ok" : "failed", detail.c_str(), sent ? "" : " [report not delivered]");
}

/* ══════════════════════════════════════════════════════════════════════════
 *  Dashboard commands (delivered in heartbeat responses)
 * ══════════════════════════════════════════════════════════════════════════ */

static void dropFirstCommand() {
  for (int i = 1; i < pendingCommandCount; ++i) {
    pendingCommands[i - 1] = pendingCommands[i];
  }
  if (pendingCommandCount > 0) {
    pendingCommandCount--;
    pendingCommands[pendingCommandCount] = PendingCommand();
  }
}

void processPendingCommands() {
  if (pendingCommandCount == 0) {
    return;
  }

  // Index 0 stays in the queue while an update runs, so checkBackendOTA() can
  // hand its id to the next image to acknowledge after the health gate.
  const PendingCommand command = pendingCommands[0];
  Serial.printf("[CMD] Executing '%s'\n", command.type.c_str());

  if (command.type == "reboot") {
    reportCommandResult(command.id, true, "Rebooting now");
    dropFirstCommand();
    delay(300);
    ESP.restart();
    return;
  }

  if (command.type == "identify") {
    blinkLED(15, 120);
    reportCommandResult(command.id, true, String("Blinked LED on GPIO ") + LED_STATUS);
    dropFirstCommand();
    return;
  }

  if (command.type == "update" || command.type == "check_update") {
    if (state.inQuarantine) {
      reportCommandResult(command.id, false, "Device is quarantined; updates are disabled");
    } else if (state.rollbackPending) {
      reportCommandResult(command.id, false, "Current image has not passed its health gate yet");
    } else {
      const UpdateOutcome outcome = checkBackendOTA();  // restarts on success
      state.lastBackendCheck = millis();
      if (outcome == UPDATE_NOT_NEEDED) {
        String detail = String("Already on v") + FIRMWARE_VERSION;
        if (command.version.length() && parseVersion(command.version) > FIRMWARE_VERSION_N) {
          detail += String("; gateway did not offer v") + command.version + " to this device";
        }
        reportCommandResult(command.id, true, detail);
      } else if (outcome == UPDATE_CHECK_FAILED) {
        reportCommandResult(command.id, false, "Could not fetch the manifest from the gateway");
      } else {
        reportCommandResult(command.id, false, "Update failed; device kept its current firmware");
      }
    }
    dropFirstCommand();
    return;
  }

  reportCommandResult(command.id, false, String("Unsupported command '") + command.type + "'");
  dropFirstCommand();
}

/* ══════════════════════════════════════════════════════════════════════════
 *  Post-update health gate and rollback
 *
 *  The Arduino core marks every image valid inside initArduino(), before
 *  setup() runs, unless the sketch defers that decision. Returning true here
 *  defers it: a freshly installed image boots in PENDING_VERIFY and must prove
 *  itself (Wi-Fi + an accepted heartbeat) within OTA_HEALTH_GATE_TIMEOUT_SECONDS.
 *  If it cannot, the bootloader is told to boot the previous image. A hard
 *  crash/reset loop before validation also lands back on the previous image,
 *  because the bootloader aborts a PENDING_VERIFY image that resets.
 * ══════════════════════════════════════════════════════════════════════════ */

extern "C" bool verifyRollbackLater() {
  return true;
}

void detectPendingVerification() {
  const esp_partition_t *running = esp_ota_get_running_partition();
  esp_ota_img_states_t imageState;
  if (running && esp_ota_get_state_partition(running, &imageState) == ESP_OK &&
      imageState == ESP_OTA_IMG_PENDING_VERIFY) {
    state.rollbackPending = true;
    Serial.printf("[Gate] New image v%s is on probation: %u s to reach the gateway.\n",
                  FIRMWARE_VERSION, static_cast<unsigned>(OTA_HEALTH_GATE_TIMEOUT_SECONDS));
  }

  // Left behind by a newer image that failed its gate and rolled back to us.
  prefs.begin("ota-health", false);
  rolledBackVersion = prefs.getString("rbver", "");
  rolledBackCommand = prefs.getString("rbcmd", "");
  prefs.end();
  if (rolledBackVersion.length()) {
    Serial.printf("[Gate] v%s failed its health check; running v%s again.\n", rolledBackVersion.c_str(), FIRMWARE_VERSION);
  }
}

void confirmHealthyBoot() {
  if (state.rollbackPending) {
    const esp_err_t err = esp_ota_mark_app_valid_cancel_rollback();
    state.rollbackPending = false;
    Serial.printf("[Gate] Health check passed; image v%s marked valid (%s).\n", FIRMWARE_VERSION, esp_err_to_name(err));
  }

  if (bootReportsDone) {
    return;
  }
  bootReportsDone = true;

  prefs.begin("ota-health", false);
  const String expected = prefs.getString("expectver", "");
  const String ackCommand = prefs.getString("ackcmd", "");
  prefs.remove("expectver");
  prefs.remove("ackcmd");
  prefs.remove("rbver");
  prefs.remove("rbcmd");
  prefs.end();

  if (expected.length() && parseVersion(expected) == FIRMWARE_VERSION_N) {
    reportOtaStatus("succeeded", FIRMWARE_VERSION, 100, "Booted, joined Wi-Fi and reached the gateway");
    reportCommandResult(ackCommand, true, String("Updated to v") + FIRMWARE_VERSION);
  }

  if (rolledBackVersion.length()) {
    reportOtaStatus("rolled_back", rolledBackVersion, -1,
                    String("v") + rolledBackVersion + " could not reach the gateway within " +
                    OTA_HEALTH_GATE_TIMEOUT_SECONDS + " s; restored v" + FIRMWARE_VERSION);
    reportCommandResult(rolledBackCommand, false, String("v") + rolledBackVersion + " rolled back after failing its health check");
    rolledBackVersion = "";
    rolledBackCommand = "";
  }
}

void enforceHealthGate() {
  if (!state.rollbackPending || millis() - state.bootMillis < HEALTH_GATE_TIMEOUT_MS) {
    return;
  }

  Serial.println("[Gate] Health check FAILED: no accepted heartbeat in time. Rolling back.");
  prefs.begin("ota-health", false);
  prefs.putString("rbver", FIRMWARE_VERSION);
  prefs.putString("rbcmd", prefs.getString("ackcmd", ""));
  prefs.remove("expectver");
  prefs.remove("ackcmd");
  prefs.end();
  adjustHealth(-25, "rollback");

  // Reboots into the previous image when one exists; returns only on error.
  const esp_err_t err = esp_ota_mark_app_invalid_rollback_and_reboot();
  Serial.printf("[Gate] Rollback not possible (%s); keeping this image.\n", esp_err_to_name(err));
  state.rollbackPending = false;
  esp_ota_mark_app_valid_cancel_rollback();
}

/* ══════════════════════════════════════════════════════════════════════════
 *  USB provisioning protocol (one line per message, 115200 baud)
 *
 *    SOTA:PING                     -> SOTA:PONG
 *    SOTA:INFO                     -> SOTA:INFO {"device_id":...,"version":...}
 *    SOTA:PROVISION {"ssid":"..","password":"..","backend_url":"..",
 *                    "device_token":"..","device_id":"..","api_key":".."}
 *                                  -> SOTA:OK ... then reboot | SOTA:ERR <why>
 *    SOTA:RESET-CONFIG             -> SOTA:OK ... then reboot
 *
 *  Driven by the SecureOTA local agent (POST /provision, GET /device-info).
 *  Anyone at the USB port can reflash the board anyway, so this adds no new
 *  exposure; nothing here is reachable over the network.
 * ══════════════════════════════════════════════════════════════════════════ */

void serviceSerial() {
  while (Serial.available() > 0) {
    const char c = static_cast<char>(Serial.read());
    if (c == '\n' || c == '\r') {
      if (serialLine.length() > 0) {
        const String line = serialLine;
        serialLine = "";
        handleSerialLine(line);
      }
    } else if (serialLine.length() < SERIAL_LINE_MAX) {
      serialLine += c;
    } else {
      serialLine = "";  // overlong line: drop it rather than act on a fragment
    }
  }
}

static bool validDeviceId(const String &id) {
  if (id.length() == 0 || id.length() > 64) return false;
  for (size_t i = 0; i < id.length(); ++i) {
    const char c = id.charAt(i);
    if (!isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_' && c != '.' && c != ':') return false;
  }
  return true;
}

void handleSerialLine(const String &rawLine) {
  String line = rawLine;
  line.trim();
  if (!line.startsWith("SOTA:")) {
    return;
  }

  if (line == "SOTA:PING") {
    Serial.println("SOTA:PONG");
    return;
  }

  if (line == "SOTA:INFO") {
    JsonDocument info;
    info["device_id"] = cfg.deviceId;
    info["device_type"] = DEVICE_TYPE;
    info["version"] = FIRMWARE_VERSION;
    info["mac"] = WiFi.macAddress();
    info["chip"] = ESP.getChipModel();
    info["wifi_configured"] = !isPlaceholder(cfg.wifiSsid);
    info["wifi_ssid"] = isPlaceholder(cfg.wifiSsid) ? "" : cfg.wifiSsid;
    info["wifi_connected"] = WiFi.status() == WL_CONNECTED;
    info["ip"] = WiFi.status() == WL_CONNECTED ? WiFi.localIP().toString() : "";
    info["backend_url"] = cfg.backendUrl;
    info["has_device_token"] = cfg.deviceToken.length() > 0;
    info["health"] = state.healthScore;
    info["quarantined"] = state.inQuarantine;
    String out;
    serializeJson(info, out);
    Serial.print("SOTA:INFO ");
    Serial.println(out);
    return;
  }

  if (line == "SOTA:RESET-CONFIG") {
    prefs.begin("sota-cfg", false);
    prefs.clear();
    prefs.end();
    Serial.println("SOTA:OK config cleared; rebooting");
    delay(300);
    ESP.restart();
    return;
  }

  if (line.startsWith("SOTA:PROVISION ")) {
    JsonDocument doc;
    const DeserializationError err = deserializeJson(doc, line.substring(15));
    if (err) {
      Serial.printf("SOTA:ERR invalid JSON (%s)\n", err.c_str());
      return;
    }

    const String ssid = doc["ssid"] | "";
    const String url = doc["backend_url"] | "";
    const String devid = doc["device_id"] | "";
    if (doc["ssid"].is<const char *>() && (ssid.length() == 0 || ssid.length() > 32)) {
      Serial.println("SOTA:ERR ssid must be 1-32 characters");
      return;
    }
    if (doc["backend_url"].is<const char *>() && !(url.startsWith("http://") || url.startsWith("https://"))) {
      Serial.println("SOTA:ERR backend_url must start with http:// or https://");
      return;
    }
    if (url.startsWith("https://") && strlen(OTA_ROOT_CA) == 0 && !OTA_ALLOW_INSECURE_TLS) {
      Serial.println("SOTA:ERR this build has no OTA_ROOT_CA, so it cannot verify an https:// gateway");
      return;
    }
    if (doc["device_id"].is<const char *>() && devid.length() && !validDeviceId(devid)) {
      Serial.println("SOTA:ERR device_id may only contain A-Z a-z 0-9 _ . : -");
      return;
    }

    prefs.begin("sota-cfg", false);
    if (doc["ssid"].is<const char *>()) prefs.putString("ssid", ssid);
    if (doc["password"].is<const char *>()) prefs.putString("pass", doc["password"].as<String>());
    if (doc["backend_url"].is<const char *>()) prefs.putString("url", url);
    if (doc["device_token"].is<const char *>()) prefs.putString("token", doc["device_token"].as<String>());
    if (doc["api_key"].is<const char *>()) prefs.putString("apikey", doc["api_key"].as<String>());
    if (doc["device_id"].is<const char *>()) prefs.putString("devid", devid);
    if (doc["hostname"].is<const char *>()) prefs.putString("host", doc["hostname"].as<String>());
    prefs.end();

    // A board moved to a new network starts with a clean health record.
    if (doc["reset_health"] | false) {
      state.healthScore = HEALTH_MAX;
      state.inQuarantine = false;
      state.failedAttempts24h = 0;
      saveHealth();
    }

    Serial.println("SOTA:OK provisioned; rebooting");
    Serial.flush();
    delay(300);
    ESP.restart();
    return;
  }

  Serial.println("SOTA:ERR unknown command");
}
