/**
 * @file delta_update.c
 * @brief Delta firmware update implementation.
 *
 * Implements a simple bsdiff-compatible patch application loop.
 * The patch format used here is a lightweight variant suitable for
 * microcontrollers with limited RAM:
 *
 *   Header (DELTA_HEADER_SIZE bytes):
 *     0x00  uint32_t magic        (DELTA_PATCH_MAGIC)
 *     0x04  uint32_t source_crc32
 *     0x08  uint32_t target_crc32
 *     0x0C  uint32_t source_size
 *     0x10  uint32_t target_size
 *     0x14  uint32_t patch_size
 *     (remaining header bytes reserved)
 *
 *   Payload: sequence of (copy_len, add_data_len, add_data[]) records.
 */

#include "delta_update.h"
#include "hal.h"

#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/** CRC32 polynomial (IEEE 802.3). */
#define CRC32_POLY  0xEDB88320u

/* ── Internal CRC32 ────────────────────────────────────────────────────────── */

static uint32_t crc32_update(uint32_t crc, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++) {
            crc = (crc >> 1) ^ ((crc & 1u) ? CRC32_POLY : 0u);
        }
    }
    return crc;
}

static uint32_t compute_partition_crc32(const hal_partition_t *partition, size_t size)
{
    uint8_t  block[HAL_FLASH_BLOCK_SIZE];
    uint32_t crc       = 0xFFFFFFFFu;
    size_t   remaining = size;
    uint32_t offset    = 0;

    while (remaining > 0) {
        size_t chunk = (remaining < HAL_FLASH_BLOCK_SIZE) ? remaining : HAL_FLASH_BLOCK_SIZE;
        if (hal_flash_read(partition, offset, block, chunk) != HAL_OK) {
            return 0;  /* Signal error with zero (distinct from ~0) */
        }
        crc        = crc32_update(crc, block, chunk);
        offset    += (uint32_t)chunk;
        remaining -= chunk;
    }
    return crc ^ 0xFFFFFFFFu;
}

/* ── Public API ─────────────────────────────────────────────────────────────── */

hal_err_t delta_open_patch(const hal_partition_t *patch_partition,
                            delta_patch_ctx_t     *ctx)
{
    if (patch_partition == NULL || ctx == NULL) {
        return HAL_ERR_PARAM;
    }

    uint8_t header[DELTA_HEADER_SIZE];
    if (hal_flash_read(patch_partition, 0, header, DELTA_HEADER_SIZE) != HAL_OK) {
        return HAL_ERR_GENERIC;
    }

    /* Parse little-endian fields */
#define LE32(buf, off) ((uint32_t)(buf)[(off)]            \
                      | ((uint32_t)(buf)[(off)+1] << 8)   \
                      | ((uint32_t)(buf)[(off)+2] << 16)  \
                      | ((uint32_t)(buf)[(off)+3] << 24))

    ctx->magic        = LE32(header, 0);
    ctx->source_crc32 = LE32(header, 4);
    ctx->target_crc32 = LE32(header, 8);
    ctx->source_size  = LE32(header, 12);
    ctx->target_size  = LE32(header, 16);
    ctx->patch_size   = LE32(header, 20);
    ctx->patch_offset = DELTA_HEADER_SIZE;

#undef LE32

    if (ctx->magic != DELTA_PATCH_MAGIC) {
        return HAL_ERR_FAULT;
    }

    /* Validate source partition CRC */
    hal_partition_t active;
    if (hal_get_partition_info(HAL_PARTITION_OTA_ACTIVE, &active) != HAL_OK) {
        return HAL_ERR_GENERIC;
    }

    uint32_t actual_crc = compute_partition_crc32(&active, ctx->source_size);
    if (actual_crc != ctx->source_crc32) {
        return HAL_ERR_FAULT;
    }

    return HAL_OK;
}

hal_err_t delta_apply(const delta_patch_ctx_t *ctx,
                       const hal_partition_t   *target_partition,
                       void (*progress_cb)(size_t done, size_t total, void *ud),
                       void                    *user_data)
{
    if (ctx == NULL || target_partition == NULL) {
        return HAL_ERR_PARAM;
    }

    hal_partition_t source;
    if (hal_get_partition_info(HAL_PARTITION_OTA_ACTIVE, &source) != HAL_OK) {
        return HAL_ERR_GENERIC;
    }

    hal_partition_t patch_part;
    /* The patch is stored in the inactive partition area (after header) */
    if (hal_get_partition_info(HAL_PARTITION_OTA_INACTIVE, &patch_part) != HAL_OK) {
        return HAL_ERR_GENERIC;
    }

    if (hal_flash_erase(target_partition) != HAL_OK) {
        return HAL_ERR_GENERIC;
    }

    /*
     * Apply patch records:
     * Each record: [copy_len: uint32][add_len: uint32][add_data: add_len bytes]
     *
     * copy_len bytes are copied verbatim from the source partition.
     * add_len  bytes from the patch are XOR-mixed and appended.
     */
    uint32_t patch_offset  = ctx->patch_offset;
    uint32_t src_offset    = 0;
    uint32_t dst_offset    = 0;
    size_t   produced      = 0;

    uint8_t  io_buf[HAL_FLASH_BLOCK_SIZE];
    uint8_t  record_hdr[8];

    while (produced < ctx->target_size) {
        /* Read record header */
        if (hal_flash_read(&patch_part, patch_offset, record_hdr, 8) != HAL_OK) {
            return HAL_ERR_GENERIC;
        }
        patch_offset += 8;

        uint32_t copy_len = (uint32_t)record_hdr[0]
                          | ((uint32_t)record_hdr[1] << 8)
                          | ((uint32_t)record_hdr[2] << 16)
                          | ((uint32_t)record_hdr[3] << 24);
        uint32_t add_len  = (uint32_t)record_hdr[4]
                          | ((uint32_t)record_hdr[5] << 8)
                          | ((uint32_t)record_hdr[6] << 16)
                          | ((uint32_t)record_hdr[7] << 24);

        /* Copy phase: read from source, write to target */
        uint32_t remaining = copy_len;
        while (remaining > 0) {
            size_t chunk = (remaining < HAL_FLASH_BLOCK_SIZE) ? remaining : HAL_FLASH_BLOCK_SIZE;
            if (hal_flash_read(&source, src_offset, io_buf, chunk) != HAL_OK) {
                return HAL_ERR_GENERIC;
            }
            if (hal_flash_write(target_partition, dst_offset, io_buf, chunk) != HAL_OK) {
                return HAL_ERR_GENERIC;
            }
            src_offset += (uint32_t)chunk;
            dst_offset += (uint32_t)chunk;
            remaining  -= chunk;
            produced   += chunk;
        }

        /* Add phase: read patch bytes, write to target */
        remaining = add_len;
        while (remaining > 0) {
            size_t chunk = (remaining < HAL_FLASH_BLOCK_SIZE) ? remaining : HAL_FLASH_BLOCK_SIZE;
            if (hal_flash_read(&patch_part, patch_offset, io_buf, chunk) != HAL_OK) {
                return HAL_ERR_GENERIC;
            }
            if (hal_flash_write(target_partition, dst_offset, io_buf, chunk) != HAL_OK) {
                return HAL_ERR_GENERIC;
            }
            patch_offset += (uint32_t)chunk;
            dst_offset   += (uint32_t)chunk;
            remaining    -= chunk;
            produced     += chunk;
        }

        if (progress_cb != NULL) {
            progress_cb(produced, ctx->target_size, user_data);
        }

        if (copy_len == 0 && add_len == 0) {
            break;  /* End-of-patch sentinel */
        }
    }

    return HAL_OK;
}

hal_err_t delta_verify_output(const delta_patch_ctx_t *ctx,
                               const hal_partition_t   *target_partition)
{
    if (ctx == NULL || target_partition == NULL) {
        return HAL_ERR_PARAM;
    }

    uint32_t actual = compute_partition_crc32(target_partition, ctx->target_size);
    if (actual != ctx->target_crc32) {
        return HAL_ERR_FAULT;
    }
    return HAL_OK;
}

void delta_close_patch(delta_patch_ctx_t *ctx)
{
    if (ctx != NULL) {
        memset(ctx, 0, sizeof(delta_patch_ctx_t));
    }
}
