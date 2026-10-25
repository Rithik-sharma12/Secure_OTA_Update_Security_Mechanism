/*
 * sota_core: the board-independent part of the SecureOTA update agent.
 *
 * Shared by every firmware in this repository (ESP32, ESP8266, STM32F103,
 * ATmega328P) and by the native unit test in firmware/lib/sota_core/test/.
 * Plain C99, no heap, no Arduino headers, so the same file compiles for an
 * 8-bit AVR and for the host.
 *
 * What lives here:
 *   - the canonical manifest statement the gateway signs with Ed25519
 *     (apps/gateway/gateway/crypto.py, manifest_signing_message), and its
 *     verification (stage 5 of the five-stage pipeline);
 *   - hex and base64 decoding for manifest fields;
 *   - semantic version comparison (anti-downgrade);
 *   - the health-score table (anomaly-scored health, ASH).
 *
 * Ed25519 comes from Monocypher 4.0.2 (src/monocypher*.c, CC0 / BSD-2,
 * see LICENCE-monocypher.md).
 */
#ifndef SOTA_CORE_H
#define SOTA_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* First line of the signed statement. Changing it invalidates every signature. */
#define SOTA_MANIFEST_PREFIX "SOTA-MANIFEST-V1"

#define SOTA_ED25519_PUBLIC_KEY_BYTES 32
#define SOTA_ED25519_SIGNATURE_BYTES  64
#define SOTA_SHA256_HEX_CHARS         64

/* Longest statement: prefix + version(32) + two digests + size, plus newlines. */
#define SOTA_MANIFEST_MESSAGE_MAX 192

/* Result of sota_verify_manifest(). Only SOTA_SIG_OK means "install". */
typedef enum {
  SOTA_SIG_OK = 0,
  SOTA_SIG_BAD_KEY = 1,        /* public key is not 64 hex characters */
  SOTA_SIG_BAD_ENCODING = 2,   /* signature is not base64 of 64 bytes */
  SOTA_SIG_BAD_FIELDS = 3,     /* version / digest / size unusable */
  SOTA_SIG_INVALID = 4         /* well formed, but the signature does not verify */
} sota_sig_result;

/*
 * Build the statement the gateway signs:
 *
 *   SOTA-MANIFEST-V1\n<version>\n<sha256>\n<imageSha256>\n<size>
 *
 * sha256 and imageSha256 are lowercase hex (imageSha256 may be "" for a plain
 * release). size is the artifact size in bytes, in decimal.
 * Returns the message length, or 0 if it does not fit in `cap` or a field is
 * unusable.
 */
size_t sota_manifest_message(char *out, size_t cap, const char *version, const char *sha256,
                             const char *image_sha256, unsigned long size);

/* Verify a raw Ed25519 signature. Returns 1 when valid, 0 otherwise. */
int sota_ed25519_verify(const uint8_t public_key[SOTA_ED25519_PUBLIC_KEY_BYTES],
                        const uint8_t signature[SOTA_ED25519_SIGNATURE_BYTES], const uint8_t *message,
                        size_t length);

/*
 * Stage 5: check the gateway's Ed25519 signature over the manifest fields.
 * public_key_hex: 64 hex characters (the gateway's raw public key).
 * signature_b64:  the manifest's "manifestSignature" field.
 */
sota_sig_result sota_verify_manifest(const char *public_key_hex, const char *signature_b64, const char *version,
                                     const char *sha256, const char *image_sha256, unsigned long size);

/* Short reason for a result, for serial logs. */
const char *sota_sig_result_text(sota_sig_result result);

/* Decode exactly `length` bytes of hex. Returns 0 on success, -1 otherwise. */
int sota_hex_decode(const char *hex, uint8_t *out, size_t length);

/* Decode standard base64 (with padding). Returns bytes written, or -1. */
int sota_base64_decode(const char *in, uint8_t *out, size_t cap);

/*
 * Compare "major.minor.patch" versions (an optional leading 'v' is ignored).
 * Returns <0, 0 or >0 like strcmp; a malformed version compares lowest.
 */
int sota_version_compare(const char *a, const char *b);

/*
 * Streaming SHA-256 for boards whose core has none (ATmega328P, STM32F103).
 * About 300 bytes of RAM including the context; the ESP32 and ESP8266 use
 * their hardware-backed mbedTLS / BearSSL instead.
 */
typedef struct {
  uint32_t state[8];
  uint64_t bit_length;
  uint8_t block[64];
  uint8_t used;
} sota_sha256_ctx;

void sota_sha256_init(sota_sha256_ctx *ctx);
void sota_sha256_update(sota_sha256_ctx *ctx, const uint8_t *data, size_t length);
void sota_sha256_final(sota_sha256_ctx *ctx, uint8_t digest[32]);

/* Lowercase hex of a 32-byte digest into out[65]. */
void sota_digest_hex(const uint8_t digest[32], char out[65]);

/*
 * UART link protocol (boards without networking: ATmega328P, STM32F103).
 * The board talks to a link host (apps/agent/sota_link.py) over its serial
 * port; the host talks HTTP to the gateway. See firmware/UART_LINK.md.
 *
 *   board -> host  SOTA:MANIFEST?
 *   host -> board  SOTA:MANIFEST v=<version> s=<sha256> i=<imageSha256|-> n=<size> g=<signature>
 *                  | SOTA:NONE | SOTA:ERR <reason>
 */
typedef struct {
  char version[33];
  char sha256[65];
  char image_sha256[65]; /* "" when the gateway published none */
  unsigned long size;
  char signature[89];    /* base64 of 64 bytes is 88 characters */
} sota_manifest;

/* Parse a SOTA:MANIFEST line. Returns 1 when every field is present and well formed. */
int sota_parse_manifest_line(const char *line, sota_manifest *out);

/*
 *   board -> host  SOTA:CHUNK <offset> <length>
 *   host -> board  SOTA:DATA <offset> <hex bytes>
 * Decodes a SOTA:DATA line for the expected offset into out (at most cap
 * bytes). Returns the byte count, or -1 if the line is not that chunk.
 */
int sota_parse_data_line(const char *line, unsigned long expected_offset, uint8_t *out, size_t cap);

/* Health-score events and their effect (report Table 4.4). */
typedef enum {
  SOTA_EV_UPDATE_OK,
  SOTA_EV_POLL_NO_UPDATE,
  SOTA_EV_SERVER_UNREACHABLE,
  SOTA_EV_MANIFEST_FIELD_MISSING,
  SOTA_EV_VERSION_MISMATCH,
  SOTA_EV_SIZE_MISMATCH,
  SOTA_EV_SHA256_MISMATCH,
  SOTA_EV_DOWNGRADE_OFFERED,
  SOTA_EV_SELF_TEST_FAILED,
  SOTA_EV_SIGNATURE_INVALID,
  SOTA_EV_REPEATED_FAILURES
} sota_health_event;

#define SOTA_HEALTH_MAX        100
#define SOTA_HEALTH_QUARANTINE 40

int sota_health_delta(sota_health_event event);

/* Apply an event to a score, clamped to 0..100. */
int sota_health_apply(int score, sota_health_event event);

/* 1 when the score means "stop updating until an administrator resets it". */
int sota_health_quarantined(int score);

#ifdef __cplusplus
}
#endif

#endif /* SOTA_CORE_H */
