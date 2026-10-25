/*
 * SecureOTA update agent for the STM32F103 (Blue Pill, STM32duino core).
 *
 *   - Reaches the gateway through a link host on USART1 (PA9/PA10)
 *     (apps/agent/sota_link.py, protocol in firmware/UART_LINK.md).
 *   - Runs all five stages itself, including Ed25519 (Monocypher, about
 *     1.5 KB of RAM), with the gateway public key below.
 *   - Stages the verified image in an external SPI flash chip (W25Qxx, CS on
 *     PA4) behind a "SOTAIMG1" header.
 *
 * Installing the staged image needs a bootloader that copies it into the
 * STM32's own flash on reset. That bootloader is not part of this
 * repository yet, so with SOTA_STM32_BOOTLOADER 0 (default) the agent stops
 * after verification, reports "staged" and skips the version afterwards.
 *
 * Status: written against the STM32duino API; not yet run on hardware.
 */
#include <sota_board.h>
#include <sota_uart_agent.h>

#define FIRMWARE_VERSION "1.0.0"
#define DEVICE_ID "stm32f103-01"
#define FLASH_CS_PIN PA4
#define CHECK_INTERVAL_MS 60000UL

// The gateway's raw Ed25519 public key, 64 hex characters:
// GET <gateway>/releases/latest/public-key -> publicKeyHex
#define GATEWAY_ED25519_PUBKEY "0000000000000000000000000000000000000000000000000000000000000000"

#ifndef SOTA_STM32_BOOTLOADER
#define SOTA_STM32_BOOTLOADER 0
#endif

HardwareSerial LinkSerial(PA10, PA9);  // RX, TX
SotaSpiFlash spiFlash(FLASH_CS_PIN);

/*
 * Header at address 0, image from 4096:
 *   "SOTAIMG1" | size (4 bytes, little endian) | sha256 (32 bytes)
 * Written only after S4 and S5 passed.
 */
static bool installStaged(SotaSpiFlash &flash, const sota_manifest &manifest) {
  uint8_t header[44] = {'S', 'O', 'T', 'A', 'I', 'M', 'G', '1'};
  header[8] = static_cast<uint8_t>(manifest.size);
  header[9] = static_cast<uint8_t>(manifest.size >> 8);
  header[10] = static_cast<uint8_t>(manifest.size >> 16);
  header[11] = static_cast<uint8_t>(manifest.size >> 24);
  if (sota_hex_decode(manifest.sha256, header + 12, 32) != 0) return false;
  flash.write(0, header, sizeof(header));
#if SOTA_STM32_BOOTLOADER
  delay(20);
  NVIC_SystemReset();  // the bootloader copies the image
#endif
  LinkSerial.println("# image verified and staged; no bootloader configured to install it");
  return false;
}

static const SotaAgentConfig config = {
  DEVICE_ID,
  "STM32F103",
  FIRMWARE_VERSION,
  GATEWAY_ED25519_PUBKEY,  // S5 on the board
  SOTA_MAX_CHUNK,
  4096,
  60UL * 1024UL,           // up to the 64 KB part's flash, minus a bootloader
  4000UL,
  installStaged,
};

SotaUartAgent *agent = nullptr;
unsigned long lastCheck = 0;

void setup() {
  LinkSerial.begin(115200);
  if (!spiFlash.begin()) {
    LinkSerial.println("# no SPI flash found on PA4; updates cannot be staged");
  }
  static SotaUartAgent instance(LinkSerial, spiFlash, config);
  agent = &instance;
  agent->begin();
  lastCheck = millis() - CHECK_INTERVAL_MS + 5000UL;
}

void loop() {
  if (millis() - lastCheck >= CHECK_INTERVAL_MS) {
    lastCheck = millis();
    agent->runCycle();
  }
}
