// This is what gets injected into generated main()

void trackingAgentTask(void* parameter) {
    // This function runs forever on Core 0
    
    // Step 1: Connect to Wi-Fi
    WiFi.begin(TRACKING_SSID, TRACKING_PASSWORD);
    while (WiFi.status() != WL_CONNECTED) {
        vTaskDelay(500 / portTICK_PERIOD_MS);
    }
    
    // Step 2: Loop forever — broadcast every 30 seconds
    while (true) {
        sendUDPBroadcast();                        // explained in section 2
        vTaskDelay(30000 / portTICK_PERIOD_MS);    // wait 30 seconds
    }
    
    vTaskDelete(NULL); // never reaches here
}

// This gets injected into generated main():
xTaskCreatePinnedToCore(
    trackingAgentTask,  // function to run
    "TrackingAgent",    // task name (for debugging)
    8192,               // stack size in bytes
    NULL,               // parameters passed to task
    1,                  // priority (1 = low, fine for background)
    NULL,               // task handle (not needed)
    0                   // ← Core 0 pinned here
);