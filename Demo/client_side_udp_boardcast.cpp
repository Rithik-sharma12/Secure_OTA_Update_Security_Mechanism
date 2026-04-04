#include <WiFiUdp.h>
#include <ArduinoJson.h>

WiFiUDP udp;
#define BROADCAST_PORT 5007

void sendUDPBroadcast() {
    // Build JSON payload
    StaticJsonDocument<256> doc;
    doc["mac"]     = WiFi.macAddress();
    doc["version"] = FIRMWARE_VERSION;   // injected by IDE e.g. "v3"
    doc["sketch"]  = SKETCH_NAME;        // injected by IDE e.g. "BlinkLED"
    doc["board"]   = "ESP32";
    doc["ip"]      = WiFi.localIP().toString();
    doc["status"]  = "online";
    
    char buffer[256];
    serializeJson(doc, buffer);
    
    // Send to broadcast address
    udp.beginPacket("255.255.255.255", BROADCAST_PORT);
    udp.print(buffer);
    udp.endPacket();
}