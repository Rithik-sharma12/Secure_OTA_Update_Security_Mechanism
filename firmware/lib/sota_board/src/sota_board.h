/*
 * sota_board: Arduino helpers for the boards that reach the gateway through
 * a UART link host (ATmega328P, STM32F103).
 *
 *   SotaLink      line-based request/response over a Stream (firmware/UART_LINK.md)
 *   SotaSpiFlash  minimal W25Qxx driver used to stage the downloaded image
 */
#ifndef SOTA_BOARD_H
#define SOTA_BOARD_H

#include <Arduino.h>
#include <SPI.h>

class SotaLink {
 public:
  explicit SotaLink(Stream &io) : io_(io) {}

  /*
   * Send `request` and wait for a reply line starting with "SOTA:". Lines
   * that do not start with "SOTA:" are ignored. Returns false on timeout or
   * when the reply does not fit in `cap`.
   */
  bool request(const char *request, char *reply, size_t cap, unsigned long timeout_ms);

  /* One log line for the link host (prefixed "# ", never parsed). */
  void log(const char *text);

 private:
  Stream &io_;
};

/* W25Q16/32/64/128-style SPI NOR flash, 4 KB sectors, 256-byte pages. */
class SotaSpiFlash {
 public:
  explicit SotaSpiFlash(uint8_t cs_pin) : cs_(cs_pin) {}
  bool begin();                       // false when no flash answers (JEDEC id 0x00/0xFF)
  void eraseSector(uint32_t address); // 4 KB at a 4 KB boundary
  void write(uint32_t address, const uint8_t *data, size_t length);  // crosses pages as needed
  void read(uint32_t address, uint8_t *data, size_t length);

 private:
  void select();
  void deselect();
  void waitReady();
  void writeEnable();
  uint8_t cs_;
};

#endif
