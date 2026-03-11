/**
 * @file ota_client.c
 * @brief Secure OTA update client implementation.
 *
 * Implements the public API declared in ota_client.h. Relies on the HAL
 * (hal.h) for all hardware-specific operations and uses mbedTLS SHA-256
 * and RSA primitives for cryptographic verification.
 *
 * Build note: Link with mbedTLS (-lmbedcrypto) and an HTTP client.
 */

#include "ota_client.h"
#include "hal.h"
#include "rollback.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* mbedTLS headers for SHA-256 and RSA */
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/md.h"

/* ── Internal state ────────────────────────────────────────────────────────── */

/** Sentinel value for the initialised flag. */
#define OTA_INIT_MAGIC  0xDEADBEEFu

typedef struct {
    uint32_t       magic;
    ota_config_t   config;
    bool           update_pending;
    hal_partition_t inactive_partition;
} ota_ctx_t;

static ota_ctx_t s_ctx;

/* ── Internal helpers ─────────────────────────────────────────────────────── */

/**
 * @brief Compute SHA-256 digest of data in the inactive partition.
 *
 * Reads the partition in HAL_FLASH_BLOCK_SIZE chunks to avoid large
 * stack allocations.
 *
 * @param size    Number of bytes to hash.
 * @param digest  Output 32-byte buffer.
 * @return        0 on success, -1 on HAL or mbedTLS error.
 */
static int compute_partition_sha256(size_t size, uint8_t digest[OTA_SHA256_LEN])
{
    mbedtls_sha256_context sha_ctx;
    uint8_t  block[HAL_FLASH_BLOCK_SIZE];
    size_t   remaining = size;
    uint32_t offset    = 0;
    int      ret       = -1;

    mbedtls_sha256_init(&sha_ctx);
    if (mbedtls_sha256_starts(&sha_ctx, 0 /* SHA-256, not SHA-224 */) != 0) {
        goto cleanup;
    }

    while (remaining > 0) {
        size_t chunk = (remaining < HAL_FLASH_BLOCK_SIZE) ? remaining : HAL_FLASH_BLOCK_SIZE;
        if (hal_flash_read(&s_ctx.inactive_partition, offset, block, chunk) != HAL_OK) {
            goto cleanup;
        }
        if (mbedtls_sha256_update(&sha_ctx, block, chunk) != 0) {
            goto cleanup;
        }
        offset    += (uint32_t)chunk;
        remaining -= chunk;
    }

    if (mbedtls_sha256_finish(&sha_ctx, digest) != 0) {
        goto cleanup;
    }
    ret = 0;

cleanup:
    mbedtls_sha256_free(&sha_ctx);
    return ret;
}

/**
 * @brief Verify an RSA-SHA256 PKCS#1 v1.5 signature.
 *
 * @param digest     32-byte SHA-256 digest of the message.
 * @param signature  Signature bytes.
 * @param sig_len    Length of the signature.
 * @return           0 if valid, non-zero otherwise.
 */
static int verify_rsa_signature(const uint8_t  digest[OTA_SHA256_LEN],
                                 const uint8_t *signature,
                                 size_t         sig_len)
{
    mbedtls_pk_context pk;
    int ret;

    mbedtls_pk_init(&pk);

    ret = mbedtls_pk_parse_public_key(&pk,
                                      s_ctx.config.public_key_der,
                                      s_ctx.config.public_key_len);
    if (ret != 0) {
        mbedtls_pk_free(&pk);
        return ret;
    }

    ret = mbedtls_pk_verify(&pk,
                             MBEDTLS_MD_SHA256,
                             digest,
                             OTA_SHA256_LEN,
                             signature,
                             sig_len);
    mbedtls_pk_free(&pk);
    return ret;
}

/* ── Public API implementation ─────────────────────────────────────────────── */

ota_err_t ota_init(const ota_config_t *config)
{
    if (config == NULL) {
        return OTA_ERR_INVALID_ARG;
    }
    if (config->public_key_len == 0 || config->public_key_len > sizeof(config->public_key_der)) {
        return OTA_ERR_INVALID_ARG;
    }
    if (strnlen(config->server_url, OTA_URL_MAX_LEN) == 0) {
        return OTA_ERR_INVALID_ARG;
    }

    memset(&s_ctx, 0, sizeof(s_ctx));
    memcpy(&s_ctx.config, config, sizeof(ota_config_t));

    /* Query the HAL for the inactive (update target) partition */
    hal_err_t hal_ret = hal_get_partition_info(HAL_PARTITION_OTA_INACTIVE,
                                               &s_ctx.inactive_partition);
    if (hal_ret != HAL_OK) {
        return OTA_ERR_PARTITION;
    }

    s_ctx.magic = OTA_INIT_MAGIC;
    return OTA_OK;
}

ota_err_t ota_check_update(ota_update_info_t *info)
{
    if (s_ctx.magic != OTA_INIT_MAGIC) {
        return OTA_ERR_NOT_INITIALIZED;
    }
    if (info == NULL) {
        return OTA_ERR_INVALID_ARG;
    }

    memset(info, 0, sizeof(ota_update_info_t));

    /*
     * Build the update-check URL:
     *   GET {server_url}/api/v1/devices/{device_id}/updates
     */
    char url[OTA_URL_MAX_LEN];
    int n = snprintf(url, sizeof(url), "%s/api/v1/devices/%s/updates",
                     s_ctx.config.server_url,
                     s_ctx.config.device_id);
    if (n < 0 || (size_t)n >= sizeof(url)) {
        return OTA_ERR_INVALID_ARG;
    }

    /*
     * Perform the HTTP GET. The HAL http helper populates a caller-supplied
     * buffer with the JSON response body.
     */
    uint8_t  resp_buf[2048];
    size_t   resp_len = 0;
    hal_err_t hr = hal_http_get(url,
                                resp_buf, sizeof(resp_buf),
                                &resp_len,
                                s_ctx.config.http_timeout_ms);
    if (hr == HAL_ERR_TIMEOUT) {
        return OTA_ERR_TIMEOUT;
    }
    if (hr != HAL_OK) {
        return OTA_ERR_NETWORK;
    }

    /*
     * Minimal JSON parsing: look for "update_available": true
     * A production implementation should use a proper JSON library (cJSON).
     */
    if (memmem(resp_buf, resp_len, "\"update_available\":true", 23) == NULL &&
        memmem(resp_buf, resp_len, "\"update_available\": true", 24) == NULL) {
        return OTA_ERR_NO_UPDATE;
    }

    /* Parse version, firmware_id, hash_sha256, size from JSON.
     * Using sscanf with field-width limits to avoid buffer overflows. */
    char hash_hex[65] = {0};
    hal_parse_json_string(resp_buf, resp_len, "version",     info->version,     OTA_VERSION_MAX_LEN);
    hal_parse_json_string(resp_buf, resp_len, "firmware_id", info->firmware_id, 64);
    hal_parse_json_string(resp_buf, resp_len, "hash_sha256", hash_hex,          65);

    /* Decode hex digest to binary */
    for (int i = 0; i < OTA_SHA256_LEN; i++) {
        unsigned int byte;
        sscanf(&hash_hex[i * 2], "%02x", &byte);
        info->expected_sha256[i] = (uint8_t)byte;
    }

    hal_parse_json_uint(resp_buf, resp_len, "size", &info->firmware_size);

    /* Construct download URL */
    snprintf(info->download_url, OTA_URL_MAX_LEN,
             "%s/api/v1/firmware/%s/download",
             s_ctx.config.server_url, info->firmware_id);

    info->update_available = true;
    return OTA_OK;
}

ota_err_t ota_download_firmware(const ota_update_info_t *info,
                                 ota_progress_cb_t        progress_cb,
                                 void                    *user_data)
{
    if (s_ctx.magic != OTA_INIT_MAGIC) {
        return OTA_ERR_NOT_INITIALIZED;
    }
    if (info == NULL || !info->update_available) {
        return OTA_ERR_INVALID_ARG;
    }

    /* Erase the inactive partition before writing */
    if (hal_flash_erase(&s_ctx.inactive_partition) != HAL_OK) {
        return OTA_ERR_FLASH_ERASE;
    }

    uint8_t   buf[OTA_HTTP_BUFFER_SIZE];
    size_t    bytes_written = 0;
    uint32_t  flash_offset  = 0;
    int       attempt;

    for (attempt = 0; attempt < OTA_MAX_RETRIES; attempt++) {
        hal_http_stream_t stream;
        hal_err_t hr = hal_http_open_stream(info->download_url,
                                            &stream,
                                            s_ctx.config.http_timeout_ms);
        if (hr != HAL_OK) {
            continue;  /* retry */
        }

        bytes_written = 0;
        flash_offset  = 0;
        bool stream_ok = true;

        while (bytes_written < info->firmware_size) {
            size_t chunk_size = 0;
            hr = hal_http_read_stream(&stream, buf, sizeof(buf), &chunk_size);
            if (hr == HAL_ERR_EOF || chunk_size == 0) {
                break;
            }
            if (hr != HAL_OK) {
                stream_ok = false;
                break;
            }

            if (hal_flash_write(&s_ctx.inactive_partition, flash_offset, buf, chunk_size) != HAL_OK) {
                hal_http_close_stream(&stream);
                return OTA_ERR_FLASH_WRITE;
            }

            flash_offset  += (uint32_t)chunk_size;
            bytes_written += chunk_size;

            if (progress_cb != NULL) {
                progress_cb(bytes_written, info->firmware_size, user_data);
            }
        }

        hal_http_close_stream(&stream);

        if (stream_ok && bytes_written == info->firmware_size) {
            return OTA_OK;  /* success */
        }
        /* partial download – erase and retry */
        hal_flash_erase(&s_ctx.inactive_partition);
    }

    return OTA_ERR_NETWORK;
}

ota_err_t ota_verify_checksum(const uint8_t expected_sha256[OTA_SHA256_LEN])
{
    if (s_ctx.magic != OTA_INIT_MAGIC) {
        return OTA_ERR_NOT_INITIALIZED;
    }
    if (expected_sha256 == NULL) {
        return OTA_ERR_INVALID_ARG;
    }

    uint8_t actual[OTA_SHA256_LEN];
    if (compute_partition_sha256(s_ctx.inactive_partition.size, actual) != 0) {
        return OTA_ERR_FLASH_WRITE;
    }

    if (memcmp(actual, expected_sha256, OTA_SHA256_LEN) != 0) {
        return OTA_ERR_CHECKSUM;
    }
    return OTA_OK;
}

ota_err_t ota_verify_signature(const ota_update_info_t *info)
{
    if (s_ctx.magic != OTA_INIT_MAGIC) {
        return OTA_ERR_NOT_INITIALIZED;
    }
    if (info == NULL || info->signature_len == 0) {
        return OTA_ERR_INVALID_ARG;
    }

    /* First verify the checksum to detect bit-flips before RSA. */
    ota_err_t err = ota_verify_checksum(info->expected_sha256);
    if (err != OTA_OK) {
        return err;
    }

    if (verify_rsa_signature(info->expected_sha256,
                              info->signature,
                              info->signature_len) != 0) {
        return OTA_ERR_SIGNATURE;
    }
    return OTA_OK;
}

ota_err_t ota_apply_update(void)
{
    if (s_ctx.magic != OTA_INIT_MAGIC) {
        return OTA_ERR_NOT_INITIALIZED;
    }

    /* Rollback protection: verify we are allowed to update. */
    if (!rollback_can_update()) {
        return OTA_ERR_ROLLBACK;
    }

    /* Atomically set boot partition to the inactive slot. */
    if (hal_set_boot_partition(HAL_PARTITION_OTA_INACTIVE) != HAL_OK) {
        return OTA_ERR_PARTITION;
    }

    /* Commit the update to the monotonic counter. */
    if (rollback_commit_update() != 0) {
        /* Non-fatal: partition is already set; log and continue. */
    }

    s_ctx.update_pending = true;
    return OTA_OK;
}

ota_err_t ota_rollback(void)
{
    if (s_ctx.magic != OTA_INIT_MAGIC) {
        return OTA_ERR_NOT_INITIALIZED;
    }

    if (rollback_request_rollback() != 0) {
        return OTA_ERR_ROLLBACK;
    }

    if (hal_set_boot_partition(HAL_PARTITION_OTA_ACTIVE) != HAL_OK) {
        return OTA_ERR_PARTITION;
    }

    return OTA_OK;
}

void ota_cleanup(void)
{
    if (s_ctx.magic == OTA_INIT_MAGIC) {
        /* Close any open HTTP handles via HAL */
        hal_http_cleanup();
    }
    memset(&s_ctx, 0, sizeof(s_ctx));
}

const char *ota_err_to_str(ota_err_t err)
{
    switch (err) {
        case OTA_OK:                  return "OTA_OK";
        case OTA_ERR_INVALID_ARG:     return "OTA_ERR_INVALID_ARG";
        case OTA_ERR_NOT_INITIALIZED: return "OTA_ERR_NOT_INITIALIZED";
        case OTA_ERR_NETWORK:         return "OTA_ERR_NETWORK";
        case OTA_ERR_SERVER:          return "OTA_ERR_SERVER";
        case OTA_ERR_FLASH_WRITE:     return "OTA_ERR_FLASH_WRITE";
        case OTA_ERR_FLASH_ERASE:     return "OTA_ERR_FLASH_ERASE";
        case OTA_ERR_SIGNATURE:       return "OTA_ERR_SIGNATURE";
        case OTA_ERR_CHECKSUM:        return "OTA_ERR_CHECKSUM";
        case OTA_ERR_NO_UPDATE:       return "OTA_ERR_NO_UPDATE";
        case OTA_ERR_ROLLBACK:        return "OTA_ERR_ROLLBACK";
        case OTA_ERR_PARTITION:       return "OTA_ERR_PARTITION";
        case OTA_ERR_OUT_OF_MEMORY:   return "OTA_ERR_OUT_OF_MEMORY";
        case OTA_ERR_TIMEOUT:         return "OTA_ERR_TIMEOUT";
        case OTA_ERR_DELTA:           return "OTA_ERR_DELTA";
        default:                      return "OTA_ERR_UNKNOWN";
    }
}
