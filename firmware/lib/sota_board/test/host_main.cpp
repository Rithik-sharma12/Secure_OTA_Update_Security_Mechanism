/*
 * Runs SotaUartAgent on a PC: stdin/stdout is the board's serial port.
 * Driven by apps/agent/tests/test_uart_agent_e2e.py through the real link
 * host and the real gateway.
 *
 *   sota_agent_host <version> <device_id> <eeprom file> <staged image out> [gateway public key hex]
 *
 * One process is one boot: begin() (post-install self-test), then one
 * runCycle(). install() writes the staged image to a file and exits with
 * code 42, standing in for the reset into the bootloader.
 */
#include <cstdlib>
#include <deque>
#include <mutex>
#include <thread>

#include "Arduino.h"
#include "EEPROM.h"
#include "SPI.h"
#include "sota_uart_agent.h"

SPIClass SPI;
EEPROMClass EEPROM;

class StdioSerial : public Stream {
 public:
  StdioSerial() {
    std::thread([this] {
      int c;
      while ((c = getchar()) != EOF) {
        std::lock_guard<std::mutex> lock(mu_);
        queue_.push_back((uint8_t)c);
      }
    }).detach();
  }
  int available() override {
    std::lock_guard<std::mutex> lock(mu_);
    return (int)queue_.size();
  }
  int read() override {
    std::lock_guard<std::mutex> lock(mu_);
    if (queue_.empty()) return -1;
    const int c = queue_.front();
    queue_.pop_front();
    return c;
  }
  size_t write(uint8_t c) override {
    putchar(c);
    if (c == '\n') fflush(stdout);
    return 1;
  }

 private:
  std::mutex mu_;
  std::deque<uint8_t> queue_;
};

static const char *g_staged_path;
static uint32_t g_image_offset;

static bool installToFile(SotaSpiFlash &flash, const sota_manifest &manifest) {
  std::vector<uint8_t> image(manifest.size);
  flash.read(g_image_offset, image.data(), image.size());
  FILE *f = fopen(g_staged_path, "wb");
  fwrite(image.data(), 1, image.size(), f);
  fclose(f);
  fflush(stdout);
  std::_Exit(42);  // like a reset: no destructors, no waiting on the stdin thread
  return false;
}

int main(int argc, char **argv) {
  if (argc < 5) {
    fprintf(stderr, "usage: %s version device_id eeprom staged [pubkey]\n", argv[0]);
    return 2;
  }
  EEPROM.load(argv[3]);
  g_staged_path = argv[4];
  g_image_offset = 10;
  static StdioSerial serial;
  static SotaSpiFlash flash(8);
  const SotaAgentConfig config = {
    argv[2], argc > 5 ? "STM32F103" : "ATmega328P", argv[1], argc > 5 ? argv[5] : nullptr,
    SOTA_MAX_CHUNK, g_image_offset, 512UL * 1024UL, 5000UL, installToFile,
  };
  if (!flash.begin()) return 3;
  static SotaUartAgent agent(serial, flash, config);
  agent.begin();
  const int result = agent.runCycle();
  printf("# result %d health %d\n", result, agent.health());
  fflush(stdout);
  std::_Exit(result);
}
