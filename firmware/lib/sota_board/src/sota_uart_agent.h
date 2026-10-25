/*
 * SotaUartAgent: the five-stage update agent for boards that reach the
 * gateway through a UART link host (apps/agent/sota_link.py).
 *
 *   S1 connectivity and health   HELLO to the link host; quarantine at H <= 40
 *   S2 manifest validation       fields, strictly newer version, size fits staging
 *   S3 chunk-based download      SOTA:CHUNK requests, written to SPI flash, hashed as it arrives
 *   S4 SHA-256 integrity         computed digest == manifest sha256
 *   S5 Ed25519 signature         on the board (STM32F103) or gateway-assisted (ATmega328P)
 *
 * The image is staged in external SPI flash. Installing it (copying it into
 * the MCU's own flash) is the bootloader's job; the sketch supplies that step
 * through `install`.
 */
#ifndef SOTA_UART_AGENT_H
#define SOTA_UART_AGENT_H

#include <Arduino.h>

#include "sota_board.h"
#include "sota_core.h"

// RAM is the limit on the ATmega328P (2 KB): a 64-byte chunk travels as a
// 128-character hex line. The STM32F103 (20 KB) takes 256-byte chunks.
#if defined(__AVR__)
#define SOTA_LINE_BYTES 320
#define SOTA_MAX_CHUNK 64
#else
#define SOTA_LINE_BYTES 600
#define SOTA_MAX_CHUNK 256
#endif

struct SotaAgentConfig {
  const char *device_id;
  const char *device_type;        // "ATmega328P" or "STM32F103"
  const char *firmware_version;   // running version, MAJOR.MINOR.PATCH
  const char *gateway_public_key; // 64 hex; nullptr = ask the gateway (gateway-assisted S5)
  uint16_t chunk_bytes;           // S3 chunk size (64 on the ATmega328P, 256 on the STM32F103)
  uint32_t image_offset;          // where the image starts in SPI flash
  uint32_t staging_capacity;      // largest image that fits
  unsigned long link_timeout_ms;
  // Called after S5 passed with the verified image in SPI flash. Writes
  // whatever the bootloader needs and resets; returns only on failure.
  bool (*install)(SotaSpiFlash &flash, const sota_manifest &manifest);
};

enum SotaCycleResult { SOTA_NO_UPDATE, SOTA_REJECTED, SOTA_LINK_ERROR, SOTA_QUARANTINED, SOTA_INSTALL_FAILED };

class SotaUartAgent {
 public:
  SotaUartAgent(Stream &io, SotaSpiFlash &flash, const SotaAgentConfig &config)
      : link_(io), flash_(flash), cfg_(config) {}

  // Load the health record and, after an install, run the post-boot self-test.
  void begin();
  // One update cycle: S1 to S5 and, when everything passes, install.
  SotaCycleResult runCycle();
  int health() const { return health_; }

 private:
  bool hello();
  bool stage3Download();
  bool stage5Signature();
  void status(const char *phase);
  void applyHealth(sota_health_event event);
  void loadState();
  void saveState();

  SotaLink link_;
  SotaSpiFlash &flash_;
  SotaAgentConfig cfg_;
  sota_manifest manifest_;
  char line_[SOTA_LINE_BYTES];
  char digest_hex_[65];
  int health_ = SOTA_HEALTH_MAX;
  // 0 nothing, 1 an install is pending its self-test, 2 `expected_` failed
  // (self-test or install) and is skipped until a newer release appears.
  uint8_t pending_ = 0;
  char expected_[33] = {0};
};

#endif
