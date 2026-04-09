#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <ArduinoJson.h>

// ── INJECTED BY SecureOTA IDE ──────────────────
#define TRACKING_SSID      "Redmi Note 12 5G"   // from IDE settings
#define TRACKING_PASSWORD  "12345678"           // from IDE settings
#define FIRMWARE_VERSION   "v3"            // auto-incremented
#define SKETCH_NAME        "BlinkLED"      // from project name
// ──────────────────────────────────────────────

void setup();
void loop();

// === User's sketch pasted here (untouched) ===
void setup() { pinMode(LED, OUTPUT); }
void loop()  { digitalWrite(LED, HIGH); delay(1000); }
// ==============================================

// ── INJECTED AGENT ─────────────────────────────
void trackingAgentTask(void* param) {
    WiFi.begin(TRACKING_SSID, TRACKING_PASSWORD);
    while (WiFi.status() != WL_CONNECTED) {
        vTaskDelay(500 / portTICK_PERIOD_MS);
    }
    WiFiUDP udp;
    while (true) {
        // build + send JSON broadcast
        udp.beginPacket("255.255.255.255", 5007);
        udp.printf("{\"mac\":\"%s\",\"version\":\"%s\","
                   "\"sketch\":\"%s\",\"ip\":\"%s\"}",
            WiFi.macAddress().c_str(), FIRMWARE_VERSION,
            SKETCH_NAME, WiFi.localIP().toString().c_str());
        udp.endPacket();
        vTaskDelay(30000 / portTICK_PERIOD_MS);
    }
}
// ───────────────────────────────────────────────

int main() {
    init();
    
    // ── INJECTED ──
    xTaskCreatePinnedToCore(trackingAgentTask,
        "Agent", 8192, NULL, 1, NULL, 0);
    // ──────────────
    
    setup();
    while(1) {
        loop();
        if (serialEventRun) serialEventRun();
    }
}