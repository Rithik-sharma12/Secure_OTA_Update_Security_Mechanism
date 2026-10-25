// EEPROM backed by a file, so a "reboot" (a second process) keeps the health record.
#pragma once
#include <cstdio>
#include <cstdint>

class EEPROMClass {
 public:
  uint8_t cells[64];
  const char *path = nullptr;
  void load(const char *file) {
    path = file;
    for (auto &c : cells) c = 0xFF;
    if (FILE *f = fopen(path, "rb")) { size_t n = fread(cells, 1, sizeof cells, f); (void)n; fclose(f); }
  }
  uint8_t read(int i) { return cells[i]; }
  void update(int i, uint8_t v) {
    cells[i] = v;
    if (path) if (FILE *f = fopen(path, "wb")) { fwrite(cells, 1, sizeof cells, f); fclose(f); }
  }
};
extern EEPROMClass EEPROM;
