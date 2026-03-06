/**
 * @file rollback.c
 * @brief Rollback protection implementation using monotonic hardware counters.
 *
 * Reads the current counter value from the HAL and compares it against
 * the minimum counter embedded in the staged firmware image header.
 * The firmware header format is:
 *
 *   Offset 0x00: uint32_t magic (0x4F544148 = "OTAH")
 *   Offset 0x04: uint32_t min_counter
 *   Offset 0x08: char     version[32]
 *   (remaining bytes: firmware payload)
 */

#include "rollback.h"
#include "hal.h"

#include <string.h>
#include <stdio.h>

/** Magic value that identifies a valid OTA firmware header. */
#define OTA_HEADER_MAGIC    0x4F544148u

/** Byte offset of min_counter within the firmware header. */
#define HEADER_COUNTER_OFFSET  4u

/** Total header size read for inspection. */
#define HEADER_READ_SIZE       64u

/* ── Internal helpers ──────────────────────────────────────────────────────── */

/**
 * @brief Read the firmware header from the inactive partition.
 *
 * @param magic        Output: header magic value.
 * @param min_counter  Output: minimum counter value.
 * @return             0 on success, -1 on error.
 */
static int read_firmware_header(uint32_t *magic, uint32_t *min_counter)
{
    hal_partition_t inactive;
    if (hal_get_partition_info(HAL_PARTITION_OTA_INACTIVE, &inactive) != HAL_OK) {
        return -1;
    }

    uint8_t header[HEADER_READ_SIZE];
    if (hal_flash_read(&inactive, 0, header, HEADER_READ_SIZE) != HAL_OK) {
        return -1;
    }

    /* Read little-endian uint32 values from the header bytes */
    *magic        = (uint32_t)header[0]
                  | ((uint32_t)header[1] << 8)
                  | ((uint32_t)header[2] << 16)
                  | ((uint32_t)header[3] << 24);

    *min_counter  = (uint32_t)header[HEADER_COUNTER_OFFSET]
                  | ((uint32_t)header[HEADER_COUNTER_OFFSET + 1] << 8)
                  | ((uint32_t)header[HEADER_COUNTER_OFFSET + 2] << 16)
                  | ((uint32_t)header[HEADER_COUNTER_OFFSET + 3] << 24);

    return 0;
}

/* ── Public API ────────────────────────────────────────────────────────────── */

bool rollback_can_update(void)
{
    uint32_t hw_counter = 0;
    if (hal_get_monotonic_counter(&hw_counter) != HAL_OK) {
        /* Conservative: deny update if counter cannot be read. */
        return false;
    }

    uint32_t magic       = 0;
    uint32_t min_counter = 0;
    if (read_firmware_header(&magic, &min_counter) != 0) {
        /* Cannot read firmware header: deny update. */
        return false;
    }

    if (magic != OTA_HEADER_MAGIC) {
        /* Invalid firmware header: deny update. */
        return false;
    }

    /*
     * Allow update only if the firmware's minimum counter is >= the
     * hardware counter. A strict downgrade (min_counter < hw_counter)
     * is rejected.
     */
    return (min_counter >= hw_counter);
}

int rollback_commit_update(void)
{
    /*
     * Increment the hardware monotonic counter to lock out the previous
     * firmware version. This is a one-way operation.
     */
    if (hal_increment_monotonic_counter() != HAL_OK) {
        return -1;
    }
    return 0;
}

int rollback_request_rollback(void)
{
    /*
     * Nothing to do with the hardware counter on rollback – we simply
     * flag the intent and let the caller switch the boot partition.
     *
     * On platforms with watchdog-based rollback (e.g. ESP-IDF OTA), you
     * would call esp_ota_mark_app_invalid_rollback_and_reboot() here.
     */
    return 0;
}

int rollback_get_firmware_min_counter(uint32_t *min_counter)
{
    if (min_counter == NULL) {
        return -1;
    }

    uint32_t magic = 0;
    return read_firmware_header(&magic, min_counter);
}
