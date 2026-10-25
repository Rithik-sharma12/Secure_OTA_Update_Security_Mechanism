// Minimal Arduino API for running SotaUartAgent on a PC (native test only).
#pragma once
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>

#define F(s) (s)
#define OUTPUT 1
#define LOW 0
#define HIGH 1
#define MSBFIRST 1
#define SPI_MODE0 0

inline unsigned long millis() {
  using namespace std::chrono;
  static const auto start = steady_clock::now();
  return (unsigned long)duration_cast<milliseconds>(steady_clock::now() - start).count();
}
inline void delay(unsigned long ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }
inline void pinMode(int, int) {}
inline void digitalWrite(int, int) {}

// The serial link is stdin/stdout. stdin is read on a background thread so
// available() can be non-blocking, as on a real UART.
class Stream {
 public:
  virtual int available() = 0;
  virtual int read() = 0;
  virtual size_t write(uint8_t c) = 0;
  size_t print(const char *s) { size_t n = 0; while (*s) n += write((uint8_t)*s++); return n; }
  size_t print(char c) { return write((uint8_t)c); }
  size_t println(const char *s) { size_t n = print(s); return n + write('\n'); }
  virtual ~Stream() {}
};
