#include "sota_board.h"

bool SotaLink::request(const char *request, char *reply, size_t cap, unsigned long timeout_ms) {
  while (io_.available()) io_.read();  // drop anything stale before asking
  io_.print(request);
  io_.print('\n');
  const unsigned long start = millis();
  size_t n = 0;
  bool overflow = false;
  while (millis() - start < timeout_ms) {
    if (!io_.available()) continue;
    const char c = static_cast<char>(io_.read());
    if (c == '\r') continue;
    if (c != '\n') {
      if (n + 1 < cap) {
        reply[n++] = c;
      } else {
        overflow = true;
      }
      continue;
    }
    reply[n] = '\0';
    if (!overflow && n >= 5 && strncmp(reply, "SOTA:", 5) == 0) return true;
    n = 0;  // not ours (or too long): keep waiting
    overflow = false;
  }
  return false;
}

void SotaLink::log(const char *text) {
  io_.print("# ");
  io_.println(text);
}

void SotaSpiFlash::select() {
  SPI.beginTransaction(SPISettings(8000000, MSBFIRST, SPI_MODE0));
  digitalWrite(cs_, LOW);
}

void SotaSpiFlash::deselect() {
  digitalWrite(cs_, HIGH);
  SPI.endTransaction();
}

bool SotaSpiFlash::begin() {
  pinMode(cs_, OUTPUT);
  digitalWrite(cs_, HIGH);
  SPI.begin();
  select();
  SPI.transfer(0x9F);  // JEDEC ID
  const uint8_t maker = SPI.transfer(0);
  SPI.transfer(0);
  SPI.transfer(0);
  deselect();
  return maker != 0x00 && maker != 0xFF;
}

void SotaSpiFlash::waitReady() {
  select();
  SPI.transfer(0x05);  // read status register 1
  while (SPI.transfer(0) & 0x01) {
  }
  deselect();
}

void SotaSpiFlash::writeEnable() {
  select();
  SPI.transfer(0x06);
  deselect();
}

void SotaSpiFlash::eraseSector(uint32_t address) {
  writeEnable();
  select();
  SPI.transfer(0x20);
  SPI.transfer(static_cast<uint8_t>(address >> 16));
  SPI.transfer(static_cast<uint8_t>(address >> 8));
  SPI.transfer(static_cast<uint8_t>(address));
  deselect();
  waitReady();
}

void SotaSpiFlash::write(uint32_t address, const uint8_t *data, size_t length) {
  while (length > 0) {
    const size_t room = 256U - (address & 0xFFU);  // never cross a page in one program
    const size_t n = length < room ? length : room;
    writeEnable();
    select();
    SPI.transfer(0x02);
    SPI.transfer(static_cast<uint8_t>(address >> 16));
    SPI.transfer(static_cast<uint8_t>(address >> 8));
    SPI.transfer(static_cast<uint8_t>(address));
    for (size_t i = 0; i < n; ++i) SPI.transfer(data[i]);
    deselect();
    waitReady();
    address += n;
    data += n;
    length -= n;
  }
}

void SotaSpiFlash::read(uint32_t address, uint8_t *data, size_t length) {
  select();
  SPI.transfer(0x03);
  SPI.transfer(static_cast<uint8_t>(address >> 16));
  SPI.transfer(static_cast<uint8_t>(address >> 8));
  SPI.transfer(static_cast<uint8_t>(address));
  for (size_t i = 0; i < length; ++i) data[i] = SPI.transfer(0);
  deselect();
}
