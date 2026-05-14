/**
 * @file rollback.h
 * @brief Rollback protection interface using monotonic hardware counters.
 *
 * Provides version-locking semantics: each firmware image embeds a minimum
 * required counter value. The device refuses to downgrade to a firmware
 * whose counter value is less than the current hardware counter.
 */

#ifndef ROLLBACK_H
#define ROLLBACK_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Check whether a firmware update is permitted by rollback protection.
 *
 * Reads the hardware monotonic counter and compares it against the
 * counter embedded in the pending firmware image. Returns false if the
 * firmware would constitute a downgrade.
 *
 * @return true  if the update is allowed.
 * @return false if the update would violate rollback protection.
 */
bool rollback_can_update(void);

/**
 * @brief Commit a successfully applied update by incrementing the counter.
 *
 * Must be called after ota_apply_update() succeeds and the device has
 * booted into the new firmware without error. Increments the hardware
 * monotonic counter so the old firmware cannot be reinstalled.
 *
 * @return 0 on success, -1 on hardware counter write failure.
 */
int rollback_commit_update(void);

/**
 * @brief Request a rollback to the previous partition.
 *
 * Marks the current boot attempt as failed. Does NOT decrement the
 * hardware counter (counters are one-way). The caller is responsible
 * for resetting the boot partition via hal_set_boot_partition().
 *
 * @return 0 on success, -1 on failure.
 */
int rollback_request_rollback(void);

/**
 * @brief Retrieve the minimum counter value embedded in the staged firmware.
 *
 * The value is read from a fixed metadata offset within the inactive
 * partition (e.g., a header field written by the firmware builder).
 *
 * @param min_counter  Output: minimum counter required by the firmware.
 * @return             0 on success, -1 if the metadata cannot be read.
 */
int rollback_get_firmware_min_counter(uint32_t *min_counter);

#ifdef __cplusplus
}
#endif

#endif /* ROLLBACK_H */
