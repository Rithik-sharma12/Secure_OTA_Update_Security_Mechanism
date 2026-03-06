/**
 * @file hal.h
 * @brief Hardware Abstraction Layer (HAL) interface for OTA flash and network operations.
 *
 * All hardware-specific operations are accessed through this interface,
 * allowing the OTA client logic to be platform-independent. Implement
 * the functions declared here for each target platform (e.g. ESP32, STM32).
 */

#ifndef HAL_H
#define HAL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── HAL return codes ─────────────────────────────────────────────────────── */

typedef enum {
    HAL_OK           =  0,  /**< Operation succeeded          */
    HAL_ERR_GENERIC  = -1,  /**< Unspecified hardware error   */
    HAL_ERR_TIMEOUT  = -2,  /**< Operation timed out          */
    HAL_ERR_BUSY     = -3,  /**< Hardware resource is busy    */
    HAL_ERR_FAULT    = -4,  /**< Hardware fault / ECC error   */
    HAL_ERR_EOF      = -5,  /**< End of stream                */
    HAL_ERR_PARAM    = -6,  /**< Invalid parameter            */
} hal_err_t;

/* ── Partition identifiers ────────────────────────────────────────────────── */

typedef enum {
    HAL_PARTITION_OTA_ACTIVE    = 0,  /**< Currently running firmware partition */
    HAL_PARTITION_OTA_INACTIVE  = 1,  /**< Partition to write update into        */
    HAL_PARTITION_FACTORY       = 2,  /**< Factory/recovery partition            */
    HAL_PARTITION_NVS           = 3,  /**< Non-volatile storage partition        */
} hal_partition_id_t;

/** @brief Flash block size used for read/write operations (4 KiB). */
#define HAL_FLASH_BLOCK_SIZE  4096u

/** @brief Maximum device ID length. */
#define HAL_DEVICE_ID_LEN     32

/**
 * @brief Partition descriptor populated by hal_get_partition_info().
 */
typedef struct {
    hal_partition_id_t id;           /**< Logical partition identifier      */
    uint32_t           offset;       /**< Flash offset in bytes             */
    size_t             size;         /**< Partition size in bytes           */
    bool               encrypted;   /**< True if flash encryption enabled  */
} hal_partition_t;

/**
 * @brief Opaque handle for an HTTP streaming connection.
 */
typedef struct hal_http_stream_s hal_http_stream_t;

/* ── Flash API ────────────────────────────────────────────────────────────── */

/**
 * @brief Erase a flash partition before writing new firmware.
 *
 * @param partition  Partition to erase.
 * @return           HAL_OK on success.
 */
hal_err_t hal_flash_erase(const hal_partition_t *partition);

/**
 * @brief Write bytes to a flash partition at a given offset.
 *
 * The write must be aligned to HAL_FLASH_BLOCK_SIZE boundaries on platforms
 * that require sector-aligned writes.
 *
 * @param partition  Target partition.
 * @param offset     Byte offset within the partition.
 * @param data       Data buffer to write.
 * @param size       Number of bytes to write.
 * @return           HAL_OK on success.
 */
hal_err_t hal_flash_write(const hal_partition_t *partition,
                           uint32_t               offset,
                           const uint8_t         *data,
                           size_t                 size);

/**
 * @brief Read bytes from a flash partition at a given offset.
 *
 * @param partition  Source partition.
 * @param offset     Byte offset within the partition.
 * @param buf        Output buffer.
 * @param size       Number of bytes to read.
 * @return           HAL_OK on success.
 */
hal_err_t hal_flash_read(const hal_partition_t *partition,
                          uint32_t               offset,
                          uint8_t               *buf,
                          size_t                 size);

/**
 * @brief Retrieve partition metadata from the partition table.
 *
 * @param id         Logical partition identifier.
 * @param partition  Output partition descriptor.
 * @return           HAL_OK if the partition exists, HAL_ERR_PARAM otherwise.
 */
hal_err_t hal_get_partition_info(hal_partition_id_t id, hal_partition_t *partition);

/**
 * @brief Set the boot partition for the next reset.
 *
 * @param id  Partition to boot from.
 * @return    HAL_OK on success.
 */
hal_err_t hal_set_boot_partition(hal_partition_id_t id);

/* ── System API ───────────────────────────────────────────────────────────── */

/**
 * @brief Trigger a system reset.
 *
 * This function does not return.
 */
void hal_reset(void);

/**
 * @brief Read the hardware unique device identifier.
 *
 * @param buf      Output buffer of at least HAL_DEVICE_ID_LEN bytes.
 * @param buf_len  Size of @p buf.
 * @return         HAL_OK on success.
 */
hal_err_t hal_get_device_id(uint8_t *buf, size_t buf_len);

/**
 * @brief Read the current value of the monotonic rollback counter.
 *
 * @param counter  Output counter value.
 * @return         HAL_OK on success.
 */
hal_err_t hal_get_monotonic_counter(uint32_t *counter);

/**
 * @brief Increment the monotonic rollback counter by one.
 *
 * This operation is irreversible on hardware anti-rollback-counter devices.
 *
 * @return HAL_OK on success.
 */
hal_err_t hal_increment_monotonic_counter(void);

/* ── Network API ──────────────────────────────────────────────────────────── */

/**
 * @brief Perform a blocking HTTP GET and return the response body.
 *
 * @param url         Null-terminated URL string.
 * @param buf         Buffer to receive the response body.
 * @param buf_size    Size of @p buf.
 * @param out_len     Number of bytes written to @p buf.
 * @param timeout_ms  Timeout in milliseconds.
 * @return            HAL_OK on success, HAL_ERR_TIMEOUT or HAL_ERR_GENERIC on error.
 */
hal_err_t hal_http_get(const char *url,
                        uint8_t    *buf,
                        size_t      buf_size,
                        size_t     *out_len,
                        uint32_t    timeout_ms);

/**
 * @brief Open a streaming HTTP connection for firmware download.
 *
 * @param url         Download URL.
 * @param stream      Output handle for the stream.
 * @param timeout_ms  Connection timeout.
 * @return            HAL_OK on success.
 */
hal_err_t hal_http_open_stream(const char       *url,
                                hal_http_stream_t *stream,
                                uint32_t           timeout_ms);

/**
 * @brief Read the next chunk from an open HTTP stream.
 *
 * @param stream      Open stream handle.
 * @param buf         Output buffer.
 * @param buf_size    Size of @p buf.
 * @param out_len     Bytes written to @p buf.
 * @return            HAL_OK, HAL_ERR_EOF at end-of-body, or error.
 */
hal_err_t hal_http_read_stream(hal_http_stream_t *stream,
                                uint8_t           *buf,
                                size_t             buf_size,
                                size_t            *out_len);

/**
 * @brief Close an open HTTP stream and free its resources.
 *
 * @param stream  Stream to close.
 */
void hal_http_close_stream(hal_http_stream_t *stream);

/**
 * @brief Release all HTTP client resources.
 */
void hal_http_cleanup(void);

/* ── JSON parsing helpers (minimal, no dynamic allocation) ─────────────────── */

/**
 * @brief Extract a string value from a flat JSON object.
 *
 * @param json      JSON buffer (not necessarily null-terminated).
 * @param json_len  Length of @p json.
 * @param key       JSON key to look up.
 * @param out       Output string buffer.
 * @param out_len   Size of @p out (result is null-terminated).
 * @return          HAL_OK if found, HAL_ERR_PARAM otherwise.
 */
hal_err_t hal_parse_json_string(const uint8_t *json,
                                 size_t         json_len,
                                 const char    *key,
                                 char          *out,
                                 size_t         out_len);

/**
 * @brief Extract an unsigned integer value from a flat JSON object.
 *
 * @param json      JSON buffer.
 * @param json_len  Length of @p json.
 * @param key       JSON key to look up.
 * @param out       Output unsigned integer.
 * @return          HAL_OK if found, HAL_ERR_PARAM otherwise.
 */
hal_err_t hal_parse_json_uint(const uint8_t *json,
                               size_t         json_len,
                               const char    *key,
                               size_t        *out);

#ifdef __cplusplus
}
#endif

#endif /* HAL_H */
