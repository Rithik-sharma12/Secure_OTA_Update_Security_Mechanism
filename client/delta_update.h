/**
 * @file delta_update.h
 * @brief Delta (differential) firmware update interface.
 *
 * Provides an API for applying binary patch files to reduce the
 * over-the-air transfer size. Patches are generated offline with a
 * tool such as bsdiff or JojoDiff and applied here on the device.
 */

#ifndef DELTA_UPDATE_H
#define DELTA_UPDATE_H

#include <stddef.h>
#include <stdint.h>
#include "hal.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Magic number at the start of a valid OTA delta patch file. */
#define DELTA_PATCH_MAGIC  0x44454C54u  /* "DELT" */

/** @brief Maximum size of the delta patch header. */
#define DELTA_HEADER_SIZE  64u

/**
 * @brief Delta patch context.
 *
 * Populated by delta_open_patch() and passed to delta_apply() and
 * delta_close_patch().
 */
typedef struct {
    uint32_t  magic;            /**< Must equal DELTA_PATCH_MAGIC          */
    uint32_t  source_crc32;     /**< CRC32 of the source (current) image   */
    uint32_t  target_crc32;     /**< CRC32 of the expected output image    */
    size_t    source_size;      /**< Size of the source partition image    */
    size_t    target_size;      /**< Expected size of the patched output   */
    size_t    patch_size;       /**< Total size of the patch payload       */
    uint32_t  patch_offset;     /**< Flash offset of patch data            */
} delta_patch_ctx_t;

/**
 * @brief Open and validate a delta patch from a flash partition.
 *
 * Reads the patch header from @p patch_partition and populates @p ctx.
 * Verifies the magic value and that the source CRC matches the active
 * partition.
 *
 * @param patch_partition  Partition containing the patch binary.
 * @param ctx              Output context.
 * @return                 HAL_OK on success, error code on failure.
 */
hal_err_t delta_open_patch(const hal_partition_t *patch_partition,
                            delta_patch_ctx_t     *ctx);

/**
 * @brief Apply a validated delta patch to produce new firmware.
 *
 * Reads the source firmware from the active partition, applies the patch
 * from @p ctx, and writes the result to @p target_partition. Progress is
 * reported via the optional @p progress_cb callback.
 *
 * @param ctx               Populated patch context from delta_open_patch().
 * @param target_partition  Partition to write the patched firmware into.
 * @param progress_cb       Optional progress callback (may be NULL).
 * @param user_data         Opaque pointer forwarded to @p progress_cb.
 * @return                  HAL_OK on success, error code on failure.
 */
hal_err_t delta_apply(const delta_patch_ctx_t *ctx,
                       const hal_partition_t   *target_partition,
                       void (*progress_cb)(size_t done, size_t total, void *ud),
                       void                    *user_data);

/**
 * @brief Verify the CRC32 of the patched output partition.
 *
 * @param ctx               Patch context containing the expected CRC.
 * @param target_partition  Partition written by delta_apply().
 * @return                  HAL_OK if the CRC matches, HAL_ERR_FAULT otherwise.
 */
hal_err_t delta_verify_output(const delta_patch_ctx_t *ctx,
                               const hal_partition_t   *target_partition);

/**
 * @brief Release resources held by a delta patch context.
 *
 * @param ctx  Context to clean up.
 */
void delta_close_patch(delta_patch_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* DELTA_UPDATE_H */
