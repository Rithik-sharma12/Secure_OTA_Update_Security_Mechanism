// In-memory W25Q-style SPI NOR flash behind the Arduino SPI API (native test only).
#pragma once
#include <vector>
#include "Arduino.h"

struct SPISettings {
  SPISettings(uint32_t, int, int) {}
};

class SPIClass {
 public:
  std::vector<uint8_t> memory = std::vector<uint8_t>(1 << 20, 0xFF);  // 1 MB, erased
  void begin() {}
  void beginTransaction(SPISettings) { phase_ = 0; command_ = 0; address_ = 0; pageOffset_ = 0; }
  void endTransaction() {
    if (command_ == 0x06) writeEnabled_ = true;
    if (command_ == 0x02 || command_ == 0x20) writeEnabled_ = false;  // WEL clears after program/erase
  }
  uint8_t transfer(uint8_t b) {
    if (phase_ == 0) {
      command_ = b;
      phase_ = 1;
      return 0;
    }
    switch (command_) {
      case 0x9F: return phase_++ == 1 ? 0xEF : 0x40;  // Winbond
      case 0x05: return 0x00;                         // never busy
      case 0x03:
      case 0x02:
      case 0x20:
        if (phase_ <= 3) {
          address_ = (address_ << 8) | b;
          if (++phase_ == 4 && command_ == 0x20 && writeEnabled_) {
            std::fill(memory.begin() + (address_ & ~0xFFFu), memory.begin() + (address_ & ~0xFFFu) + 4096, 0xFF);
            writeEnabled_ = false;
          }
          return 0;
        }
        if (command_ == 0x03) return memory[address_++ % memory.size()];
        if (command_ == 0x02 && writeEnabled_) {
          // NOR flash can only clear bits; a page program wraps inside its page.
          const uint32_t at = (address_ & ~0xFFu) | ((address_ + pageOffset_) & 0xFFu);
          memory[at] &= b;
          ++pageOffset_;
        }
        return 0;
    }
    return 0;
  }

 private:
  int phase_ = 0;
  uint8_t command_ = 0;
  uint32_t address_ = 0;
  uint32_t pageOffset_ = 0;
  bool writeEnabled_ = false;
};

extern SPIClass SPI;
