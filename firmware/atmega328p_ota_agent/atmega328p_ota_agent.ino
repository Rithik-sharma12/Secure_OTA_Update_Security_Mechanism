/*
 * SecureOTA update agent for the ATmega328P (Arduino Uno / Nano / Moteino).
 *
 * The ATmega has no network and 2 KB of RAM, so:
 *   - it reaches the gateway through a link host on its serial port
 *     (apps/agent/sota_link.py, protocol in firmware/UART_LINK.md);
 *   - it runs S1 to S4 itself (health, manifest, chunked download, SHA-256)
 *     and asks the gateway to check the Ed25519 signature (gateway-assisted
 *     S5): it sends the fields and the digest it computed, and installs only
 *     on "SOTA:VERDICT 1";
 *   - the image is staged in an external SPI flash chip (W25Qxx) and copied
 *     into the ATmega by the DualOptiboot bootloader (LowPowerLab) on the
 *     next reset. Without DualOptiboot the image stays staged, the self-test
 *     after the reset fails, and the version is skipped.
 *
 * Wiring: SPI flash CS on D8 (Moteino layout), MOSI/MISO/SCK on D11/D12/D13.
 * The serial port is the link: do not print to Serial except through
 * agent link logging ("# ..." lines).
 *
 * Status: compiles for atmega328p; not yet run on hardware.
 */
#include <avr/wdt.h>
#include <sota_board.h>
#include <sota_uart_agent.h>

#define FIRMWARE_VERSION "1.0.0"
#define DEVICE_ID "atmega328p-01"
#define FLASH_CS_PIN 8
#define CHECK_INTERVAL_MS 60000UL

SotaSpiFlash spiFlash(FLASH_CS_PIN);

/*
 * DualOptiboot reads this header at address 0 of the SPI flash on every
 * reset: "FLXIMG:" + image length (2 bytes, MSB first) + ":" and then the
 * image from address 10. It copies the image into the ATmega's flash and
 * erases the header. The header is written only now, after S4 and S5
 * passed, so the bootloader never sees an unverified image.
 */
static bool installWithDualOptiboot(SotaSpiFlash &flash, const sota_manifest &manifest) {
  if (manifest.size > 0xFFFFUL) return false;
  const uint8_t header[10] = {'F', 'L', 'X', 'I', 'M', 'G', ':', static_cast<uint8_t>(manifest.size >> 8),
                              static_cast<uint8_t>(manifest.size & 0xFF), ':'};
  flash.write(0, header, sizeof(header));
  delay(20);
  wdt_enable(WDTO_15MS);  // reset into the bootloader
  for (;;) {
  }
  return false;
}

static const SotaAgentConfig config = {
  DEVICE_ID,
  "ATmega328P",
  FIRMWARE_VERSION,
  nullptr,      // no key on the board: S5 is gateway-assisted
  SOTA_MAX_CHUNK,
  10,           // image after the 10-byte DualOptiboot header
  31744UL,      // 32 KB flash minus the 1 KB bootloader section
  4000UL,
  installWithDualOptiboot,
};

SotaUartAgent agent(Serial, spiFlash, config);
unsigned long lastCheck = 0;

void setup() {
  MCUSR = 0;
  wdt_disable();
  Serial.begin(115200);
  if (!spiFlash.begin()) {
    Serial.println(F("# no SPI flash found on D8; updates cannot be staged"));
  }
  agent.begin();
  lastCheck = millis() - CHECK_INTERVAL_MS + 5000UL;  // first check shortly after boot
}

void loop() {
  if (millis() - lastCheck >= CHECK_INTERVAL_MS) {
    lastCheck = millis();
    agent.runCycle();
  }
  // Application code goes here; keep it non-blocking.
}
