/*
 * SecureOTA update agent for the ESP8266 (Arduino core 3.x).
 *
 * The same five stages as the ESP32 firmware, on 80 KB of RAM:
 *   S1 connectivity and health   Wi-Fi + heartbeat; quarantine at H <= 40
 *   S2 manifest validation       fields, strictly newer, fits the free sketch space,
 *                                plain image only (no encrypted packages on this board)
 *   S3 chunk-based download      512-byte chunks streamed into the OTA area
 *   S4 SHA-256 integrity         recomputed from what was written to flash
 *   S5 Ed25519 signature         gateway-signed manifest statement (sota_core / Monocypher)
 *
 * S4 and S5 run inside Update.end() through the core's verifier hook, so the
 * boot command that makes eboot copy the new image is written only when both
 * pass. A failed check leaves the running firmware untouched.
 *
 * Rollback: the ESP8266 bootloader copies the new image over the old one, so
 * there is no previous image to return to. A failed post-boot self-test is
 * recorded (H - 25), reported, and that version is skipped from then on.
 *
 * Status: written against ESP8266 Arduino core 3.1.2; not yet run on hardware.
 */
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <WiFiClientSecureBearSSL.h>
#include <ArduinoJson.h>
#include <EEPROM.h>
#include <Updater.h>

#include "sota_core.h"
#include "ota_config.h"

#define FIRMWARE_VERSION "1.0.0"
#define DEVICE_TYPE "ESP8266"
#define CHECK_INTERVAL_MS 60000UL
#define HEARTBEAT_INTERVAL_MS 15000UL
#define CHUNK_BYTES 512

#ifndef GATEWAY_TLS_FINGERPRINT
#define GATEWAY_TLS_FINGERPRINT ""
#endif

// ── health record in EEPROM: 'S' 'O' health pending expected[32] ─────────
struct Health {
  int score = SOTA_HEALTH_MAX;
  uint8_t pending = 0;  // 0 none, 1 awaiting self-test, 2 `expected` failed: skip it
  char expected[33] = {0};
} health;

static void saveHealth() {
  EEPROM.write(0, 'S');
  EEPROM.write(1, 'O');
  EEPROM.write(2, static_cast<uint8_t>(health.score));
  EEPROM.write(3, health.pending);
  for (int i = 0; i < 32; ++i) EEPROM.write(4 + i, static_cast<uint8_t>(health.expected[i]));
  EEPROM.commit();
}

static void loadHealth() {
  EEPROM.begin(64);
  if (EEPROM.read(0) != 'S' || EEPROM.read(1) != 'O') {
    saveHealth();
    return;
  }
  health.score = min<int>(EEPROM.read(2), SOTA_HEALTH_MAX);
  health.pending = EEPROM.read(3) <= 2 ? EEPROM.read(3) : 0;
  for (int i = 0; i < 32; ++i) health.expected[i] = static_cast<char>(EEPROM.read(4 + i));
  health.expected[32] = '\0';
}

// Write-ahead: every change is committed before the next step.
static void applyHealth(sota_health_event event, const char *reason) {
  health.score = sota_health_apply(health.score, event);
  saveHealth();
  Serial.printf("[ASH] %+d (%s) -> %d\n", sota_health_delta(event), reason, health.score);
}

// ── HTTP ─────────────────────────────────────────────────────────────────
static std::unique_ptr<WiFiClient> makeClient() {
  if (strncmp(BACKEND_URL, "https://", 8) == 0) {
    auto *tls = new BearSSL::WiFiClientSecure();
    if (strlen(GATEWAY_TLS_FINGERPRINT) > 0) {
      tls->setFingerprint(GATEWAY_TLS_FINGERPRINT);
    } else {
      tls->setInsecure();  // transport only; stages 4 and 5 still authenticate the image
    }
    tls->setBufferSizes(1024, 512);
    return std::unique_ptr<WiFiClient>(tls);
  }
  return std::unique_ptr<WiFiClient>(new WiFiClient());
}

static void addAuth(HTTPClient &http) {
  if (strlen(DEVICE_TOKEN) > 0) http.addHeader("x-device-token", DEVICE_TOKEN);
}

static int postJson(const String &path, const String &body) {
  auto client = makeClient();
  HTTPClient http;
  if (!http.begin(*client, String(BACKEND_URL) + path)) return -1;
  http.addHeader("Content-Type", "application/json");
  addAuth(http);
  const int code = http.POST(body);
  http.end();
  return code;
}

static bool heartbeat() {
  JsonDocument doc;
  doc["device_id"] = DEVICE_ID;
  doc["device_type"] = DEVICE_TYPE;
  doc["current_version"] = FIRMWARE_VERSION;
  doc["ash_score"] = health.score;
  doc["status"] = sota_health_quarantined(health.score) ? "Quarantined" : "Healthy";
  doc["ip"] = WiFi.localIP().toString();
  doc["signalStrength"] = WiFi.RSSI();
  doc["uptime"] = millis() / 1000UL;
  String body;
  serializeJson(doc, body);
  const int code = postJson("/api/heartbeat", body);
  return code >= 200 && code < 300;
}

static void reportStatus(const char *phase, const char *version, const char *detail) {
  JsonDocument doc;
  doc["phase"] = phase;
  doc["version"] = version;
  doc["detail"] = detail;
  String body;
  serializeJson(doc, body);
  postJson(String("/api/devices/") + DEVICE_ID + "/ota/status", body);
}

// ── S4 + S5 inside Update.end() ──────────────────────────────────────────
class Sha256OverFlash : public UpdaterHashClass {
 public:
  void begin() override { sota_sha256_init(&ctx_); }
  void add(const void *data, uint32_t len) override { sota_sha256_update(&ctx_, static_cast<const uint8_t *>(data), len); }
  void end() override { sota_sha256_final(&ctx_, digest_); }
  int len() override { return 32; }
  const void *hash() override { return digest_; }
  const unsigned char *oid() override { return nullptr; }

 private:
  sota_sha256_ctx ctx_;
  uint8_t digest_[32];
};

struct ManifestFields {
  String version, sha256, imageSha256, signature, url;
  unsigned long size = 0;
};

class StageFourAndFive : public UpdaterVerifyClass {
 public:
  explicit StageFourAndFive(const ManifestFields &m) : m_(m) {}
  uint32_t length() override { return 0; }  // nothing appended to the image
  bool verify(UpdaterHashClass *hash, const void *, uint32_t) override {
    char hex[65];
    sota_digest_hex(static_cast<const uint8_t *>(hash->hash()), hex);
    if (m_.sha256 != hex) {  // S4, over the bytes actually in flash
      failedStage = 4;
      Serial.printf("[S4] REJECTED: flash holds %s, manifest says %s\n", hex, m_.sha256.c_str());
      return false;
    }
    Serial.println("[S4] SHA-256 matches the manifest");
    const unsigned long started = millis();
    const sota_sig_result r = sota_verify_manifest(GATEWAY_ED25519_PUBKEY, m_.signature.c_str(), m_.version.c_str(),
                                                   hex, m_.imageSha256.c_str(), m_.size);
    if (r != SOTA_SIG_OK) {  // S5
      failedStage = 5;
      Serial.printf("[S5] REJECTED: %s\n", sota_sig_result_text(r));
      return false;
    }
    Serial.printf("[S5] Ed25519 manifest signature valid (%lu ms)\n", millis() - started);
    return true;
  }
  int failedStage = 0;

 private:
  const ManifestFields &m_;
};

// ── one update cycle ─────────────────────────────────────────────────────
static void updateCycle() {
  // S1: connectivity and health
  if (sota_health_quarantined(health.score)) {
    Serial.println("[S1] Quarantined: no updates until an administrator resets the score");
    return;
  }
  if (WiFi.status() != WL_CONNECTED || !heartbeat()) {
    applyHealth(SOTA_EV_SERVER_UNREACHABLE, "gateway unreachable");
    return;
  }

  auto client = makeClient();
  HTTPClient http;
  const String url = String(BACKEND_URL) + "/releases/latest/manifest?device_id=" + DEVICE_ID + "&device_type=" + DEVICE_TYPE;
  if (!http.begin(*client, url)) return;
  addAuth(http);
  const int code = http.GET();
  if (code == 404) {
    http.end();
    applyHealth(SOTA_EV_POLL_NO_UPDATE, "nothing published");
    return;
  }
  if (code != 200) {
    http.end();
    applyHealth(SOTA_EV_SERVER_UNREACHABLE, "manifest request failed");
    return;
  }
  JsonDocument doc;
  const DeserializationError err = deserializeJson(doc, http.getStream());
  http.end();

  // S2: manifest validation
  if (err) {
    applyHealth(SOTA_EV_MANIFEST_FIELD_MISSING, "manifest unreadable");
    return;
  }
  if (doc["updateAvailable"].is<bool>() && !doc["updateAvailable"].as<bool>()) {
    applyHealth(SOTA_EV_POLL_NO_UPDATE, "up to date");
    return;
  }
  ManifestFields m;
  m.version = doc["version"] | "";
  m.sha256 = doc["sha256"] | "";
  m.imageSha256 = doc["imageSha256"] | "";
  m.signature = doc["manifestSignature"] | "";
  m.size = doc["size"] | 0UL;
  m.url = doc["downloadUrl"] | (doc["url"] | "");
  m.sha256.toLowerCase();
  m.imageSha256.toLowerCase();
  if (m.version.isEmpty() || m.sha256.length() != 64 || m.signature.isEmpty() || m.size == 0 || m.url.isEmpty()) {
    applyHealth(SOTA_EV_MANIFEST_FIELD_MISSING, "manifest field missing");
    return;
  }
  const int order = sota_version_compare(m.version.c_str(), FIRMWARE_VERSION);
  if (order == 0) {
    applyHealth(SOTA_EV_POLL_NO_UPDATE, "up to date");
    return;
  }
  if (order < 0) {
    applyHealth(SOTA_EV_DOWNGRADE_OFFERED, "older version offered");
    return;
  }
  if (health.pending == 2 && sota_version_compare(m.version.c_str(), health.expected) == 0) {
    Serial.printf("[S2] v%s already failed here; waiting for a newer release\n", m.version.c_str());
    return;
  }
  if (doc["securePackage"] | false || (m.imageSha256.length() && m.imageSha256 != m.sha256)) {
    applyHealth(SOTA_EV_MANIFEST_FIELD_MISSING, "encrypted package; this board takes plain images");
    return;
  }
  if (m.size > ESP.getFreeSketchSpace()) {
    applyHealth(SOTA_EV_SIZE_MISMATCH, "image larger than the free sketch space");
    return;
  }

  // S3: chunk-based download into the OTA area
  Serial.printf("[S3] Downloading v%s (%lu bytes)\n", m.version.c_str(), m.size);
  reportStatus("downloading", m.version.c_str(), "Download started");
  if (m.url.startsWith("/")) m.url = String(BACKEND_URL) + m.url;
  auto dl = makeClient();
  HTTPClient get;
  if (!get.begin(*dl, m.url)) return;
  addAuth(get);
  if (get.GET() != 200 || get.getSize() != static_cast<int>(m.size)) {
    get.end();
    applyHealth(SOTA_EV_SIZE_MISMATCH, "download size differs from the manifest");
    reportStatus("failed", m.version.c_str(), "Download size differs from the manifest");
    return;
  }
  Sha256OverFlash hash;
  StageFourAndFive verifier(m);
  Update.installSignature(&hash, &verifier);
  if (!Update.begin(m.size)) {
    get.end();
    reportStatus("failed", m.version.c_str(), "Not enough space for the update");
    return;
  }
  WiFiClient *stream = get.getStreamPtr();
  uint8_t chunk[CHUNK_BYTES];
  size_t written = 0;
  unsigned long lastByte = millis();
  while (written < m.size && millis() - lastByte < 15000UL) {
    const size_t want = min<size_t>(sizeof(chunk), m.size - written);
    const size_t got = stream->readBytes(chunk, min<size_t>(want, stream->available() ? stream->available() : 1));
    if (got == 0) {
      delay(1);
      continue;
    }
    if (Update.write(chunk, got) != got) break;
    written += got;
    lastByte = millis();
  }
  get.end();

  // S4 + S5 run inside end(); the copy command is written only if both pass.
  if (!Update.end() ) {
    if (verifier.failedStage == 5) {
      applyHealth(SOTA_EV_SIGNATURE_INVALID, "manifest signature invalid");
      reportStatus("failed", m.version.c_str(), "Rejected at stage 5: Ed25519 signature");
    } else if (verifier.failedStage == 4) {
      applyHealth(SOTA_EV_SHA256_MISMATCH, "SHA-256 mismatch");
      reportStatus("failed", m.version.c_str(), "Rejected at stage 4: SHA-256 mismatch");
    } else {
      applyHealth(SOTA_EV_SIZE_MISMATCH, "incomplete download");
      reportStatus("failed", m.version.c_str(), "Download incomplete");
    }
    return;
  }

  health.pending = 1;
  strncpy(health.expected, m.version.c_str(), sizeof(health.expected) - 1);
  saveHealth();
  reportStatus("rebooting", m.version.c_str(), "Image verified (SHA-256 + Ed25519); rebooting into it");
  delay(200);
  ESP.restart();
}

// Post-boot self-test of a newly installed image.
static void selfTest() {
  if (health.pending != 1) return;
  const unsigned long deadline = millis() + 60000UL;
  while (WiFi.status() != WL_CONNECTED && millis() < deadline) delay(250);
  const bool ok = WiFi.status() == WL_CONNECTED && sota_version_compare(FIRMWARE_VERSION, health.expected) == 0 && heartbeat();
  if (ok) {
    health.pending = 0;
    health.expected[0] = '\0';
    applyHealth(SOTA_EV_UPDATE_OK, "update confirmed");
    reportStatus("succeeded", FIRMWARE_VERSION, "Booted, joined Wi-Fi and reached the gateway");
  } else {
    health.pending = 2;
    applyHealth(SOTA_EV_SELF_TEST_FAILED, "self-test failed");
    reportStatus("failed", health.expected, "Post-boot self-test failed");
  }
}

unsigned long lastCheck = 0;
unsigned long lastBeat = 0;

void setup() {
  Serial.begin(115200);
  Serial.printf("\n[OTA] ESP8266 SecureOTA v%s\n", FIRMWARE_VERSION);
  loadHealth();
  if (strlen(GATEWAY_ED25519_PUBKEY) != 64) {
    Serial.println("[OTA] GATEWAY_ED25519_PUBKEY is not set: updates are refused (stage 5 cannot run).");
  }
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  selfTest();
  lastCheck = millis() - CHECK_INTERVAL_MS + 10000UL;
}

void loop() {
  if (millis() - lastBeat >= HEARTBEAT_INTERVAL_MS && WiFi.status() == WL_CONNECTED) {
    lastBeat = millis();
    heartbeat();
  }
  if (millis() - lastCheck >= CHECK_INTERVAL_MS) {
    lastCheck = millis();
    if (strlen(GATEWAY_ED25519_PUBKEY) == 64) updateCycle();
  }
}
