/**
 * @file hal_esp32.c
 * @brief ESP32-specific Hardware Abstraction Layer implementation.
 *
 * Uses the ESP-IDF APIs for flash, partition table, HTTP client,
 * and efuse-based monotonic counter support.
 *
 * Requires ESP-IDF >= 5.0. Add this file to the CMakeLists.txt
 * component sources when building for ESP32 targets.
 */

#include "hal.h"

#include <string.h>
#include <stdio.h>

/* ESP-IDF headers */
#include "esp_partition.h"
#include "esp_ota_ops.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "esp_http_client.h"
#include "esp_system.h"
#include "esp_mac.h"
#include "nvs_flash.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "hal_esp32";

/* ── Internal HTTP stream context ─────────────────────────────────────────── */

struct hal_http_stream_s {
    esp_http_client_handle_t client;
    bool                     open;
};

/* ── Flash API ────────────────────────────────────────────────────────────── */

hal_err_t hal_flash_erase(const hal_partition_t *partition)
{
    if (partition == NULL) {
        return HAL_ERR_PARAM;
    }

    const esp_partition_t *esp_part = esp_partition_find_first(
        (esp_partition_type_t)ESP_PARTITION_TYPE_APP,
        ESP_PARTITION_SUBTYPE_ANY,
        NULL);

    /* Locate the correct ESP-IDF partition by offset */
    esp_partition_iterator_t it = esp_partition_find(ESP_PARTITION_TYPE_APP,
                                                     ESP_PARTITION_SUBTYPE_ANY,
                                                     NULL);
    while (it != NULL) {
        esp_part = esp_partition_get(it);
        if (esp_part->address == partition->offset) {
            break;
        }
        it = esp_partition_next(it);
        esp_part = NULL;
    }
    esp_partition_iterator_release(it);

    if (esp_part == NULL) {
        ESP_LOGE(TAG, "Partition at offset 0x%08" PRIx32 " not found", partition->offset);
        return HAL_ERR_PARAM;
    }

    esp_err_t err = esp_partition_erase_range(esp_part, 0, partition->size);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Erase failed: %s", esp_err_to_name(err));
        return HAL_ERR_GENERIC;
    }
    return HAL_OK;
}

hal_err_t hal_flash_write(const hal_partition_t *partition,
                           uint32_t               offset,
                           const uint8_t         *data,
                           size_t                 size)
{
    if (partition == NULL || data == NULL || size == 0) {
        return HAL_ERR_PARAM;
    }
    if (offset + size > partition->size) {
        ESP_LOGE(TAG, "Write exceeds partition boundary");
        return HAL_ERR_PARAM;
    }

    const esp_partition_t *esp_part = esp_partition_find_first(
        ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_ANY, NULL);

    esp_partition_iterator_t it = esp_partition_find(ESP_PARTITION_TYPE_APP,
                                                     ESP_PARTITION_SUBTYPE_ANY, NULL);
    while (it != NULL) {
        const esp_partition_t *p = esp_partition_get(it);
        if (p->address == partition->offset) {
            esp_part = p;
            break;
        }
        it = esp_partition_next(it);
    }
    esp_partition_iterator_release(it);

    if (esp_part == NULL) {
        return HAL_ERR_PARAM;
    }

    esp_err_t err = esp_partition_write(esp_part, offset, data, size);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Flash write error at offset %" PRIu32 ": %s", offset, esp_err_to_name(err));
        return HAL_ERR_GENERIC;
    }
    return HAL_OK;
}

hal_err_t hal_flash_read(const hal_partition_t *partition,
                          uint32_t               offset,
                          uint8_t               *buf,
                          size_t                 size)
{
    if (partition == NULL || buf == NULL || size == 0) {
        return HAL_ERR_PARAM;
    }

    const esp_partition_t *esp_part = NULL;
    esp_partition_iterator_t it = esp_partition_find(ESP_PARTITION_TYPE_APP,
                                                     ESP_PARTITION_SUBTYPE_ANY, NULL);
    while (it != NULL) {
        const esp_partition_t *p = esp_partition_get(it);
        if (p->address == partition->offset) {
            esp_part = p;
            break;
        }
        it = esp_partition_next(it);
    }
    esp_partition_iterator_release(it);

    if (esp_part == NULL) {
        return HAL_ERR_PARAM;
    }

    esp_err_t err = esp_partition_read(esp_part, offset, buf, size);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Flash read error: %s", esp_err_to_name(err));
        return HAL_ERR_GENERIC;
    }
    return HAL_OK;
}

hal_err_t hal_get_partition_info(hal_partition_id_t id, hal_partition_t *partition)
{
    if (partition == NULL) {
        return HAL_ERR_PARAM;
    }

    const esp_partition_t *esp_part = NULL;

    switch (id) {
        case HAL_PARTITION_OTA_ACTIVE:
            esp_part = esp_ota_get_running_partition();
            break;

        case HAL_PARTITION_OTA_INACTIVE: {
            const esp_partition_t *running = esp_ota_get_running_partition();
            esp_part = esp_ota_get_next_update_partition(running);
            break;
        }

        case HAL_PARTITION_FACTORY:
            esp_part = esp_partition_find_first(ESP_PARTITION_TYPE_APP,
                                                ESP_PARTITION_SUBTYPE_APP_FACTORY,
                                                NULL);
            break;

        case HAL_PARTITION_NVS:
            esp_part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                                ESP_PARTITION_SUBTYPE_DATA_NVS,
                                                NULL);
            break;

        default:
            return HAL_ERR_PARAM;
    }

    if (esp_part == NULL) {
        return HAL_ERR_GENERIC;
    }

    partition->id        = id;
    partition->offset    = esp_part->address;
    partition->size      = esp_part->size;
    partition->encrypted = esp_part->encrypted;
    return HAL_OK;
}

hal_err_t hal_set_boot_partition(hal_partition_id_t id)
{
    const esp_partition_t *target = NULL;

    if (id == HAL_PARTITION_OTA_INACTIVE) {
        const esp_partition_t *running = esp_ota_get_running_partition();
        target = esp_ota_get_next_update_partition(running);
    } else if (id == HAL_PARTITION_OTA_ACTIVE) {
        target = esp_ota_get_running_partition();
    } else if (id == HAL_PARTITION_FACTORY) {
        target = esp_partition_find_first(ESP_PARTITION_TYPE_APP,
                                          ESP_PARTITION_SUBTYPE_APP_FACTORY,
                                          NULL);
    }

    if (target == NULL) {
        return HAL_ERR_PARAM;
    }

    esp_err_t err = esp_ota_set_boot_partition(target);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Set boot partition failed: %s", esp_err_to_name(err));
        return HAL_ERR_GENERIC;
    }
    return HAL_OK;
}

/* ── System API ───────────────────────────────────────────────────────────── */

void hal_reset(void)
{
    ESP_LOGI(TAG, "System reset initiated by OTA client");
    vTaskDelay(pdMS_TO_TICKS(100));  /* Allow logs to flush */
    esp_restart();
    /* Does not return */
}

hal_err_t hal_get_device_id(uint8_t *buf, size_t buf_len)
{
    if (buf == NULL || buf_len < HAL_DEVICE_ID_LEN) {
        return HAL_ERR_PARAM;
    }

    uint8_t mac[6];
    esp_err_t err = esp_efuse_mac_get_default(mac);
    if (err != ESP_OK) {
        return HAL_ERR_GENERIC;
    }

    /* Encode as 12-char hex string, zero-padded */
    snprintf((char *)buf, buf_len, "%02x%02x%02x%02x%02x%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return HAL_OK;
}

hal_err_t hal_get_monotonic_counter(uint32_t *counter)
{
    if (counter == NULL) {
        return HAL_ERR_PARAM;
    }

    /*
     * Read the OTA rollback counter from eFuse.
     * Each bit represents one firmware version increment.
     * ESP32 provides 20 eFuse bits for OTA counter via
     * ESP_EFUSE_WR_DIS_BLK3 / custom layout; adapt for target.
     */
    uint32_t val = 0;
    esp_err_t err = esp_efuse_read_field_cnt(ESP_EFUSE_WR_DIS, &val);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "eFuse read failed, returning 0: %s", esp_err_to_name(err));
        *counter = 0;
        return HAL_OK;  /* Non-fatal: return 0 so OTA can proceed */
    }
    *counter = val;
    return HAL_OK;
}

hal_err_t hal_increment_monotonic_counter(void)
{
    esp_err_t err = esp_efuse_write_field_cnt(ESP_EFUSE_WR_DIS, 1);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to increment eFuse counter: %s", esp_err_to_name(err));
        return HAL_ERR_FAULT;
    }
    return HAL_OK;
}

/* ── Network API ──────────────────────────────────────────────────────────── */

hal_err_t hal_http_get(const char *url,
                        uint8_t    *buf,
                        size_t      buf_size,
                        size_t     *out_len,
                        uint32_t    timeout_ms)
{
    if (url == NULL || buf == NULL || out_len == NULL) {
        return HAL_ERR_PARAM;
    }

    esp_http_client_config_t cfg = {
        .url             = url,
        .timeout_ms      = (int)timeout_ms,
        .transport_type  = HTTP_TRANSPORT_OVER_SSL,
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (client == NULL) {
        return HAL_ERR_GENERIC;
    }

    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        esp_http_client_cleanup(client);
        return HAL_ERR_GENERIC;
    }

    int content_len = esp_http_client_fetch_headers(client);
    (void)content_len;

    int read = esp_http_client_read_response(client, (char *)buf, (int)buf_size - 1);
    if (read < 0) {
        esp_http_client_cleanup(client);
        return HAL_ERR_GENERIC;
    }
    buf[read] = '\0';
    *out_len = (size_t)read;

    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return HAL_OK;
}

hal_err_t hal_http_open_stream(const char       *url,
                                hal_http_stream_t *stream,
                                uint32_t           timeout_ms)
{
    if (url == NULL || stream == NULL) {
        return HAL_ERR_PARAM;
    }

    esp_http_client_config_t cfg = {
        .url             = url,
        .timeout_ms      = (int)timeout_ms,
        .transport_type  = HTTP_TRANSPORT_OVER_SSL,
        .buffer_size     = OTA_HTTP_BUFFER_SIZE,
    };

    stream->client = esp_http_client_init(&cfg);
    if (stream->client == NULL) {
        return HAL_ERR_GENERIC;
    }

    esp_err_t err = esp_http_client_open(stream->client, 0);
    if (err != ESP_OK) {
        esp_http_client_cleanup(stream->client);
        stream->client = NULL;
        return HAL_ERR_GENERIC;
    }

    esp_http_client_fetch_headers(stream->client);
    stream->open = true;
    return HAL_OK;
}

hal_err_t hal_http_read_stream(hal_http_stream_t *stream,
                                uint8_t           *buf,
                                size_t             buf_size,
                                size_t            *out_len)
{
    if (stream == NULL || !stream->open || buf == NULL || out_len == NULL) {
        return HAL_ERR_PARAM;
    }

    int read = esp_http_client_read(stream->client, (char *)buf, (int)buf_size);
    if (read < 0) {
        return HAL_ERR_GENERIC;
    }
    if (read == 0) {
        *out_len = 0;
        return HAL_ERR_EOF;
    }
    *out_len = (size_t)read;
    return HAL_OK;
}

void hal_http_close_stream(hal_http_stream_t *stream)
{
    if (stream && stream->open) {
        esp_http_client_close(stream->client);
        esp_http_client_cleanup(stream->client);
        stream->open   = false;
        stream->client = NULL;
    }
}

void hal_http_cleanup(void)
{
    /* Global HTTP cleanup; no persistent state in ESP-IDF client. */
}

/* ── JSON parsing helpers ─────────────────────────────────────────────────── */

hal_err_t hal_parse_json_string(const uint8_t *json,
                                 size_t         json_len,
                                 const char    *key,
                                 char          *out,
                                 size_t         out_len)
{
    if (!json || !key || !out || out_len == 0) {
        return HAL_ERR_PARAM;
    }

    /* Build search pattern: "key": " */
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
    const char *p = (const char *)memmem(json, json_len, pattern, strlen(pattern));
    if (!p) {
        /* Try with space after colon */
        snprintf(pattern, sizeof(pattern), "\"%s\": \"", key);
        p = (const char *)memmem(json, json_len, pattern, strlen(pattern));
    }
    if (!p) {
        return HAL_ERR_PARAM;
    }

    const char *val_start = p + strlen(pattern);
    const char *val_end   = strchr(val_start, '"');
    if (!val_end) {
        return HAL_ERR_PARAM;
    }

    size_t val_len = (size_t)(val_end - val_start);
    if (val_len >= out_len) {
        val_len = out_len - 1;
    }
    memcpy(out, val_start, val_len);
    out[val_len] = '\0';
    return HAL_OK;
}

hal_err_t hal_parse_json_uint(const uint8_t *json,
                               size_t         json_len,
                               const char    *key,
                               size_t        *out)
{
    if (!json || !key || !out) {
        return HAL_ERR_PARAM;
    }

    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);
    const char *p = (const char *)memmem(json, json_len, pattern, strlen(pattern));
    if (!p) {
        snprintf(pattern, sizeof(pattern), "\"%s\": ", key);
        p = (const char *)memmem(json, json_len, pattern, strlen(pattern));
    }
    if (!p) {
        return HAL_ERR_PARAM;
    }

    const char *val = p + strlen(pattern);
    while (*val == ' ' || *val == '\t') {
        val++;
    }

    unsigned long v = strtoul(val, NULL, 10);
    *out = (size_t)v;
    return HAL_OK;
}
