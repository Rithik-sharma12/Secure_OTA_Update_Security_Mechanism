/**
 * @file ota_client.h
 * @brief Secure OTA (Over-The-Air) update client interface.
 *
 * Provides a portable API for checking, downloading, verifying, and
 * applying firmware updates with cryptographic integrity guarantees.
 * Designed for microcontrollers with an A/B partition scheme.
 */

#ifndef OTA_CLIENT_H
#define OTA_CLIENT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Return codes ─────────────────────────────────────────────────────────── */

/** @brief OTA operation result codes. */
typedef enum {
    OTA_OK                  =  0,  /**< Success                               */
    OTA_ERR_INVALID_ARG     = -1,  /**< NULL or out-of-range argument         */
    OTA_ERR_NOT_INITIALIZED = -2,  /**< ota_init() not called                 */
    OTA_ERR_NETWORK         = -3,  /**< HTTP / TLS network failure            */
    OTA_ERR_SERVER          = -4,  /**< Server returned an error status       */
    OTA_ERR_FLASH_WRITE     = -5,  /**< Flash write failure                   */
    OTA_ERR_FLASH_ERASE     = -6,  /**< Flash erase failure                   */
    OTA_ERR_SIGNATURE       = -7,  /**< RSA-SHA256 signature verification fail*/
    OTA_ERR_CHECKSUM        = -8,  /**< SHA-256 checksum mismatch             */
    OTA_ERR_NO_UPDATE       = -9,  /**< No new firmware available             */
    OTA_ERR_ROLLBACK        = -10, /**< Rollback protection counter violation */
    OTA_ERR_PARTITION       = -11, /**< Partition table error                 */
    OTA_ERR_OUT_OF_MEMORY   = -12, /**< Memory allocation failure             */
    OTA_ERR_TIMEOUT         = -13, /**< Operation timed out                   */
    OTA_ERR_DELTA           = -14, /**< Delta patch application failure       */
} ota_err_t;

/* ── Configuration ────────────────────────────────────────────────────────── */

/** @brief Maximum length of a URL string (including null terminator). */
#define OTA_URL_MAX_LEN        512

/** @brief Maximum length of a version string (e.g. "1.23.456"). */
#define OTA_VERSION_MAX_LEN     32

/** @brief SHA-256 digest length in bytes. */
#define OTA_SHA256_LEN          32

/** @brief RSA-4096 signature length in bytes. */
#define OTA_SIG_MAX_LEN        512

/** @brief Size of the HTTP receive buffer. */
#define OTA_HTTP_BUFFER_SIZE  4096

/** @brief Maximum number of download retry attempts. */
#define OTA_MAX_RETRIES          3

/** @brief TLS fingerprint length in bytes (SHA-256). */
#define OTA_TLS_FINGERPRINT_LEN 32

/**
 * @brief OTA client configuration supplied to ota_init().
 */
typedef struct {
    char     server_url[OTA_URL_MAX_LEN];   /**< Base URL of the OTA server   */
    char     device_id[128];                /**< Unique device identifier      */
    uint8_t  public_key_der[800];           /**< DER-encoded RSA public key    */
    size_t   public_key_len;                /**< Length of public_key_der      */
    uint8_t  tls_server_fingerprint[OTA_TLS_FINGERPRINT_LEN]; /**< Expected TLS fingerprint */
    bool     verify_tls_fingerprint;        /**< Enable TLS cert pinning       */
    uint32_t http_timeout_ms;               /**< HTTP request timeout          */
    bool     enable_delta_updates;          /**< Accept delta/diff firmware    */
} ota_config_t;

/* ── Update info ──────────────────────────────────────────────────────────── */

/**
 * @brief Describes an available firmware update returned by ota_check_update().
 */
typedef struct {
    bool     update_available;                    /**< True if a new version exists  */
    char     version[OTA_VERSION_MAX_LEN];        /**< New firmware version string   */
    char     firmware_id[64];                     /**< Server-side firmware UUID     */
    char     download_url[OTA_URL_MAX_LEN];       /**< Absolute download URL         */
    uint8_t  expected_sha256[OTA_SHA256_LEN];     /**< Expected SHA-256 digest       */
    uint8_t  signature[OTA_SIG_MAX_LEN];          /**< RSA-SHA256 signature          */
    size_t   signature_len;                       /**< Length of signature           */
    size_t   firmware_size;                       /**< Total firmware size in bytes  */
    bool     is_delta;                            /**< True if this is a delta update*/
} ota_update_info_t;

/* ── Progress callback ────────────────────────────────────────────────────── */

/**
 * @brief Prototype for the download progress callback.
 *
 * @param bytes_downloaded  Bytes received so far.
 * @param total_bytes       Total expected bytes (0 if unknown).
 * @param user_data         Opaque pointer supplied to ota_download_firmware().
 */
typedef void (*ota_progress_cb_t)(size_t bytes_downloaded,
                                  size_t total_bytes,
                                  void  *user_data);

/* ── Public API ───────────────────────────────────────────────────────────── */

/**
 * @brief Initialise the OTA client subsystem.
 *
 * Must be called once before any other OTA function. Validates the
 * configuration, initialises TLS, and prepares internal state.
 *
 * @param config  Pointer to a fully populated ota_config_t structure.
 * @return        OTA_OK on success, negative error code on failure.
 */
ota_err_t ota_init(const ota_config_t *config);

/**
 * @brief Query the OTA server for available firmware updates.
 *
 * Sends a signed GET request to /api/v1/devices/{device_id}/updates and
 * populates @p info with the result.
 *
 * @param info  Output structure to populate with update details.
 * @return      OTA_OK if the query succeeded (check info->update_available),
 *              OTA_ERR_NO_UPDATE if the server reports no new firmware, or a
 *              negative error code on failure.
 */
ota_err_t ota_check_update(ota_update_info_t *info);

/**
 * @brief Download firmware to the inactive flash partition.
 *
 * Streams the firmware binary over HTTPS directly to flash. Calls
 * @p progress_cb periodically with download progress.
 *
 * @param info         Update info obtained from ota_check_update().
 * @param progress_cb  Optional progress callback (NULL to disable).
 * @param user_data    Opaque pointer forwarded to @p progress_cb.
 * @return             OTA_OK on success, negative error code on failure.
 */
ota_err_t ota_download_firmware(const ota_update_info_t *info,
                                 ota_progress_cb_t        progress_cb,
                                 void                    *user_data);

/**
 * @brief Verify the RSA-SHA256 signature of the downloaded firmware.
 *
 * Reads the inactive partition, verifies both the SHA-256 checksum and
 * the RSA-SHA256 signature against the public key in the configuration.
 *
 * @param info  Update info containing expected digest and signature.
 * @return      OTA_OK if signature is valid, OTA_ERR_SIGNATURE otherwise.
 */
ota_err_t ota_verify_signature(const ota_update_info_t *info);

/**
 * @brief Verify the SHA-256 checksum of the downloaded firmware.
 *
 * @param expected_sha256  Expected 32-byte SHA-256 digest.
 * @return                 OTA_OK if checksums match, OTA_ERR_CHECKSUM otherwise.
 */
ota_err_t ota_verify_checksum(const uint8_t expected_sha256[OTA_SHA256_LEN]);

/**
 * @brief Atomically swap to the new firmware partition.
 *
 * Sets the boot partition to the inactive slot and writes to the
 * monotonic counter. The device must be reset afterwards.
 *
 * @return OTA_OK on success, or OTA_ERR_ROLLBACK / OTA_ERR_PARTITION on failure.
 */
ota_err_t ota_apply_update(void);

/**
 * @brief Rollback to the previously running firmware partition.
 *
 * Sets the boot partition back to the last known-good slot. Does NOT
 * decrement the monotonic counter.
 *
 * @return OTA_OK on success, negative error code on failure.
 */
ota_err_t ota_rollback(void);

/**
 * @brief Release all resources held by the OTA client.
 *
 * Closes network connections and frees any heap memory. Safe to call
 * even if ota_init() was not called or failed.
 */
void ota_cleanup(void);

/**
 * @brief Return a human-readable description of an OTA error code.
 *
 * @param err  Error code returned by an OTA function.
 * @return     Pointer to a static string; never NULL.
 */
const char *ota_err_to_str(ota_err_t err);

#ifdef __cplusplus
}
#endif

#endif /* OTA_CLIENT_H */
