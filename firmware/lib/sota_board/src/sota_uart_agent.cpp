#include "sota_uart_agent.h"

#include <EEPROM.h>

// EEPROM layout: 'S' 'O' health pending expected_version[33]
static const int EE_MAGIC = 0;
static const int EE_HEALTH = 2;
static const int EE_PENDING = 3;
static const int EE_EXPECTED = 4;

void SotaUartAgent::loadState() {
  if (EEPROM.read(EE_MAGIC) != 'S' || EEPROM.read(EE_MAGIC + 1) != 'O') {
    health_ = SOTA_HEALTH_MAX;
    pending_ = 0;
    expected_[0] = '\0';
    saveState();
    return;
  }
  health_ = EEPROM.read(EE_HEALTH);
  if (health_ > SOTA_HEALTH_MAX) health_ = SOTA_HEALTH_MAX;
  pending_ = EEPROM.read(EE_PENDING);
  if (pending_ > 2) pending_ = 0;
  for (int i = 0; i < 32; ++i) expected_[i] = static_cast<char>(EEPROM.read(EE_EXPECTED + i));
  expected_[32] = '\0';
}

void SotaUartAgent::saveState() {
  // update() only writes cells that change, sparing the EEPROM.
  EEPROM.update(EE_MAGIC, 'S');
  EEPROM.update(EE_MAGIC + 1, 'O');
  EEPROM.update(EE_HEALTH, static_cast<uint8_t>(health_));
  EEPROM.update(EE_PENDING, pending_);
  for (int i = 0; i < 32; ++i) EEPROM.update(EE_EXPECTED + i, static_cast<uint8_t>(expected_[i]));
}

// Every change is written before the next step (write-ahead), so a power cut
// cannot erase a pattern of failures.
void SotaUartAgent::applyHealth(sota_health_event event) {
  health_ = sota_health_apply(health_, event);
  saveState();
}

bool SotaUartAgent::hello() {
  snprintf(line_, sizeof(line_), "SOTA:HELLO id=%s t=%s v=%s h=%d q=%d", cfg_.device_id, cfg_.device_type,
           cfg_.firmware_version, health_, sota_health_quarantined(health_) ? 1 : 0);
  return link_.request(line_, line_, sizeof(line_), cfg_.link_timeout_ms) && strncmp(line_, "SOTA:ACK", 8) == 0;
}

void SotaUartAgent::status(const char *phase) {
  snprintf(line_, sizeof(line_), "SOTA:STATUS %s %s", phase, manifest_.version[0] ? manifest_.version : cfg_.firmware_version);
  link_.request(line_, line_, sizeof(line_), cfg_.link_timeout_ms);
}

void SotaUartAgent::begin() {
  loadState();
  if (pending_ != 1) return;

  // Post-boot self-test of the newly installed image: it must be the version
  // that was verified, and it must reach the gateway through the link.
  pending_ = 0;
  strncpy(manifest_.version, expected_, sizeof(manifest_.version));
  bool linked = false;
  for (int attempt = 0; attempt < 5 && !linked; ++attempt) linked = hello();
  if (linked && sota_version_compare(cfg_.firmware_version, expected_) == 0) {
    link_.log("self-test passed; update confirmed");
    expected_[0] = '\0';
    applyHealth(SOTA_EV_UPDATE_OK);
    status("confirmed");
  } else {
    // No second image to boot on these boards: record the failure, skip this
    // version from now on, and let the dashboard see it.
    link_.log("self-test failed");
    pending_ = 2;
    applyHealth(SOTA_EV_SELF_TEST_FAILED);
    status("self_test_failed");
  }
}

bool SotaUartAgent::stage3Download() {
  uint8_t chunk[SOTA_MAX_CHUNK];
  const uint16_t step = cfg_.chunk_bytes > sizeof(chunk) ? sizeof(chunk) : cfg_.chunk_bytes;
  sota_sha256_ctx sha;
  sota_sha256_init(&sha);

  // Erase only what the image needs, 4 KB at a time.
  const uint32_t first = cfg_.image_offset & ~0xFFFUL;
  const uint32_t last = cfg_.image_offset + manifest_.size;
  for (uint32_t sector = first; sector < last; sector += 4096UL) flash_.eraseSector(sector);

  for (uint32_t offset = 0; offset < manifest_.size; offset += step) {
    const uint16_t want = (manifest_.size - offset) < step ? static_cast<uint16_t>(manifest_.size - offset) : step;
    int got = -1;
    for (int attempt = 0; attempt < 3 && got != want; ++attempt) {
      snprintf(line_, sizeof(line_), "SOTA:CHUNK %lu %u", static_cast<unsigned long>(offset), want);
      if (link_.request(line_, line_, sizeof(line_), cfg_.link_timeout_ms)) {
        got = sota_parse_data_line(line_, offset, chunk, want);
      }
    }
    if (got != want) return false;
    flash_.write(cfg_.image_offset + offset, chunk, want);
    sota_sha256_update(&sha, chunk, want);
  }

  uint8_t digest[32];
  sota_sha256_final(&sha, digest);
  sota_digest_hex(digest, digest_hex_);
  return true;
}

bool SotaUartAgent::stage5Signature() {
#if !defined(__AVR__)
  // Ed25519 on an 8-bit AVR would not fit next to the application (about 30 KB
  // of code and its tables in RAM), so it is compiled only for 32-bit boards.
  if (cfg_.gateway_public_key != nullptr) {
    // On the board: Monocypher Ed25519 over the manifest statement, using the
    // digest this board computed rather than the one it was told.
    const sota_sig_result result = sota_verify_manifest(cfg_.gateway_public_key, manifest_.signature, manifest_.version,
                                                        digest_hex_, manifest_.image_sha256, manifest_.size);
    if (result != SOTA_SIG_OK) link_.log(sota_sig_result_text(result));
    return result == SOTA_SIG_OK;
  }
#endif
  // Gateway-assisted: send the fields (with the computed digest) and the
  // signature; the answer is one bit. The image never leaves the board.
  snprintf(line_, sizeof(line_), "SOTA:VERIFY v=%s s=%s i=%s n=%lu g=%s", manifest_.version, digest_hex_,
           manifest_.image_sha256[0] ? manifest_.image_sha256 : "-", manifest_.size, manifest_.signature);
  if (!link_.request(line_, line_, sizeof(line_), cfg_.link_timeout_ms)) return false;
  return strcmp(line_, "SOTA:VERDICT 1") == 0;
}

SotaCycleResult SotaUartAgent::runCycle() {
  manifest_.version[0] = '\0';

  // ── S1: connectivity and health ─────────────────────────────────────
  if (sota_health_quarantined(health_)) {
    hello();  // still report, so the dashboard shows the quarantine
    return SOTA_QUARANTINED;
  }
  if (!hello()) {
    applyHealth(SOTA_EV_SERVER_UNREACHABLE);
    return SOTA_LINK_ERROR;
  }
  if (!link_.request("SOTA:MANIFEST?", line_, sizeof(line_), cfg_.link_timeout_ms) || strncmp(line_, "SOTA:ERR", 8) == 0) {
    applyHealth(SOTA_EV_SERVER_UNREACHABLE);
    return SOTA_LINK_ERROR;
  }
  if (strcmp(line_, "SOTA:NONE") == 0) {
    applyHealth(SOTA_EV_POLL_NO_UPDATE);
    return SOTA_NO_UPDATE;
  }

  // ── S2: manifest validation ─────────────────────────────────────────
  if (!sota_parse_manifest_line(line_, &manifest_)) {
    applyHealth(SOTA_EV_MANIFEST_FIELD_MISSING);
    return SOTA_REJECTED;
  }
  const int order = sota_version_compare(manifest_.version, cfg_.firmware_version);
  if (order == 0) {
    applyHealth(SOTA_EV_POLL_NO_UPDATE);
    return SOTA_NO_UPDATE;
  }
  if (pending_ == 2 && sota_version_compare(manifest_.version, expected_) == 0) {
    link_.log("this version already failed here; waiting for a newer release");
    return SOTA_NO_UPDATE;
  }
  if (order < 0) {
    applyHealth(SOTA_EV_DOWNGRADE_OFFERED);
    status("rejected_downgrade");
    return SOTA_REJECTED;
  }
  if (manifest_.size == 0 || manifest_.size > cfg_.staging_capacity) {
    applyHealth(SOTA_EV_SIZE_MISMATCH);
    status("rejected_size");
    return SOTA_REJECTED;
  }
  // These boards take plain images only; an encrypted package publishes a
  // different imageSha256 and would be ciphertext in flash.
  if (manifest_.image_sha256[0] && strcmp(manifest_.image_sha256, manifest_.sha256) != 0) {
    applyHealth(SOTA_EV_MANIFEST_FIELD_MISSING);
    status("rejected_package");
    return SOTA_REJECTED;
  }

  // ── S3: chunk-based download into SPI flash ─────────────────────────
  status("downloading");
  if (!stage3Download()) {
    applyHealth(SOTA_EV_SERVER_UNREACHABLE);
    status("failed");
    return SOTA_LINK_ERROR;
  }

  // ── S4: SHA-256 integrity ───────────────────────────────────────────
  if (strcmp(digest_hex_, manifest_.sha256) != 0) {
    applyHealth(SOTA_EV_SHA256_MISMATCH);
    status("rejected_sha256");
    return SOTA_REJECTED;
  }

  // ── S5: Ed25519 signature ───────────────────────────────────────────
  if (!stage5Signature()) {
    applyHealth(SOTA_EV_SIGNATURE_INVALID);
    status("rejected_signature");
    return SOTA_REJECTED;
  }

  // ── Install: the bootloader copies the verified image ───────────────
  status("installing");
  pending_ = 1;
  strncpy(expected_, manifest_.version, sizeof(expected_) - 1);
  saveState();
  cfg_.install(flash_, manifest_);  // resets on success
  pending_ = 2;  // do not download the same version again every cycle
  saveState();
  status("failed");
  return SOTA_INSTALL_FAILED;
}
