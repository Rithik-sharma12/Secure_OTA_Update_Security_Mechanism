/* sota_core: see sota_core.h. */
#include "sota_core.h"

#include <string.h>

#include "monocypher-ed25519.h"

static int is_lower_hex(const char *s, size_t length) {
  size_t i;
  if (s == NULL || strlen(s) != length) return 0;
  for (i = 0; i < length; ++i) {
    const char c = s[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
  }
  return 1;
}

static int version_is_usable(const char *version) {
  size_t i;
  const size_t length = version ? strlen(version) : 0;
  if (length == 0 || length > 32) return 0;
  for (i = 0; i < length; ++i) {
    const char c = version[i];
    /* No newline may appear inside a field of the signed statement. */
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.' || c == '-' ||
          c == '+' || c == '_')) {
      return 0;
    }
  }
  return 1;
}

static size_t append(char *out, size_t cap, size_t at, const char *text) {
  const size_t length = strlen(text);
  if (at + length + 1 > cap) return (size_t)-1;
  memcpy(out + at, text, length);
  out[at + length] = '\0';
  return at + length;
}

size_t sota_manifest_message(char *out, size_t cap, const char *version, const char *sha256,
                             const char *image_sha256, unsigned long size) {
  char digits[21];
  size_t at = 0;
  int n = 0;
  unsigned long v = size;
  char reversed[21];

  if (out == NULL || cap == 0) return 0;
  if (!version_is_usable(version)) return 0;
  if (!is_lower_hex(sha256, SOTA_SHA256_HEX_CHARS)) return 0;
  if (image_sha256 == NULL) image_sha256 = "";
  if (image_sha256[0] != '\0' && !is_lower_hex(image_sha256, SOTA_SHA256_HEX_CHARS)) return 0;

  /* Decimal size without printf, which is large on AVR. */
  do {
    reversed[n++] = (char)('0' + (v % 10UL));
    v /= 10UL;
  } while (v > 0 && n < 20);
  {
    int i;
    for (i = 0; i < n; ++i) digits[i] = reversed[n - 1 - i];
    digits[n] = '\0';
  }

  out[0] = '\0';
  if ((at = append(out, cap, at, SOTA_MANIFEST_PREFIX "\n")) == (size_t)-1) return 0;
  if ((at = append(out, cap, at, version)) == (size_t)-1) return 0;
  if ((at = append(out, cap, at, "\n")) == (size_t)-1) return 0;
  if ((at = append(out, cap, at, sha256)) == (size_t)-1) return 0;
  if ((at = append(out, cap, at, "\n")) == (size_t)-1) return 0;
  if ((at = append(out, cap, at, image_sha256)) == (size_t)-1) return 0;
  if ((at = append(out, cap, at, "\n")) == (size_t)-1) return 0;
  if ((at = append(out, cap, at, digits)) == (size_t)-1) return 0;
  return at;
}

int sota_ed25519_verify(const uint8_t public_key[SOTA_ED25519_PUBLIC_KEY_BYTES],
                        const uint8_t signature[SOTA_ED25519_SIGNATURE_BYTES], const uint8_t *message,
                        size_t length) {
  /* crypto_ed25519_check: RFC 8032 Ed25519 (SHA-512), 0 when valid. */
  return crypto_ed25519_check(signature, public_key, message, length) == 0;
}

static int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

int sota_hex_decode(const char *hex, uint8_t *out, size_t length) {
  size_t i;
  if (hex == NULL || strlen(hex) != length * 2) return -1;
  for (i = 0; i < length; ++i) {
    const int hi = hex_value(hex[2 * i]);
    const int lo = hex_value(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) return -1;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return 0;
}

static int b64_value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

int sota_base64_decode(const char *in, uint8_t *out, size_t cap) {
  size_t length, i, written = 0;
  if (in == NULL) return -1;
  length = strlen(in);
  if (length == 0 || length % 4 != 0) return -1;
  for (i = 0; i < length; i += 4) {
    const int a = b64_value(in[i]);
    const int b = b64_value(in[i + 1]);
    const int pad2 = in[i + 2] == '=';
    const int pad3 = in[i + 3] == '=';
    const int c = pad2 ? 0 : b64_value(in[i + 2]);
    const int d = pad3 ? 0 : b64_value(in[i + 3]);
    unsigned long triple;
    if (a < 0 || b < 0 || c < 0 || d < 0) return -1;
    if ((pad2 && !pad3) || ((pad2 || pad3) && i + 4 != length)) return -1;
    triple = ((unsigned long)a << 18) | ((unsigned long)b << 12) | ((unsigned long)c << 6) | (unsigned long)d;
    if (written >= cap) return -1;
    out[written++] = (uint8_t)(triple >> 16);
    if (!pad2) {
      if (written >= cap) return -1;
      out[written++] = (uint8_t)(triple >> 8);
    }
    if (!pad3) {
      if (written >= cap) return -1;
      out[written++] = (uint8_t)triple;
    }
  }
  return (int)written;
}

sota_sig_result sota_verify_manifest(const char *public_key_hex, const char *signature_b64, const char *version,
                                     const char *sha256, const char *image_sha256, unsigned long size) {
  uint8_t key[SOTA_ED25519_PUBLIC_KEY_BYTES];
  uint8_t signature[SOTA_ED25519_SIGNATURE_BYTES + 3];
  char message[SOTA_MANIFEST_MESSAGE_MAX];
  size_t length;

  if (sota_hex_decode(public_key_hex, key, sizeof(key)) != 0) return SOTA_SIG_BAD_KEY;
  if (sota_base64_decode(signature_b64, signature, sizeof(signature)) != SOTA_ED25519_SIGNATURE_BYTES) {
    return SOTA_SIG_BAD_ENCODING;
  }
  length = sota_manifest_message(message, sizeof(message), version, sha256, image_sha256, size);
  if (length == 0) return SOTA_SIG_BAD_FIELDS;
  return sota_ed25519_verify(key, signature, (const uint8_t *)message, length) ? SOTA_SIG_OK : SOTA_SIG_INVALID;
}

const char *sota_sig_result_text(sota_sig_result result) {
  switch (result) {
    case SOTA_SIG_OK: return "valid";
    case SOTA_SIG_BAD_KEY: return "gateway public key is not 64 hex characters";
    case SOTA_SIG_BAD_ENCODING: return "manifestSignature is not base64 of 64 bytes";
    case SOTA_SIG_BAD_FIELDS: return "manifest version, digest or size unusable";
    case SOTA_SIG_INVALID: return "Ed25519 signature does not verify";
  }
  return "unknown";
}

static int parse_part(const char **p, long *value) {
  long v = 0;
  int digits = 0;
  while (**p >= '0' && **p <= '9') {
    v = v * 10 + (**p - '0');
    if (v > 1000000L) return 0;
    ++*p;
    ++digits;
  }
  *value = v;
  return digits > 0;
}

/* Parses "[v]major.minor.patch"; anything after the patch number is ignored. */
static int parse_version(const char *s, long parts[3]) {
  int i;
  if (s == NULL) return 0;
  if (*s == 'v' || *s == 'V') ++s;
  for (i = 0; i < 3; ++i) {
    if (!parse_part(&s, &parts[i])) return 0;
    if (i < 2) {
      if (*s != '.') return 0;
      ++s;
    }
  }
  return 1;
}

int sota_version_compare(const char *a, const char *b) {
  long pa[3], pb[3];
  int i;
  const int okA = parse_version(a, pa);
  const int okB = parse_version(b, pb);
  if (!okA || !okB) return okA - okB;
  for (i = 0; i < 3; ++i) {
    if (pa[i] != pb[i]) return pa[i] < pb[i] ? -1 : 1;
  }
  return 0;
}

int sota_health_delta(sota_health_event event) {
  switch (event) {
    case SOTA_EV_UPDATE_OK: return 10;
    case SOTA_EV_POLL_NO_UPDATE: return 1;
    case SOTA_EV_SERVER_UNREACHABLE: return -1;
    case SOTA_EV_MANIFEST_FIELD_MISSING: return -10;
    case SOTA_EV_VERSION_MISMATCH: return -15;
    case SOTA_EV_SIZE_MISMATCH: return -15;
    case SOTA_EV_SHA256_MISMATCH: return -20;
    case SOTA_EV_DOWNGRADE_OFFERED: return -20;
    case SOTA_EV_SELF_TEST_FAILED: return -25;
    case SOTA_EV_SIGNATURE_INVALID: return -30;
    case SOTA_EV_REPEATED_FAILURES: return -15;
  }
  return 0;
}

int sota_health_apply(int score, sota_health_event event) {
  int next = score + sota_health_delta(event);
  if (next < 0) next = 0;
  if (next > SOTA_HEALTH_MAX) next = SOTA_HEALTH_MAX;
  return next;
}

int sota_health_quarantined(int score) { return score <= SOTA_HEALTH_QUARANTINE; }

/* ── SHA-256 (FIPS 180-4), byte-oriented and table-light for 8-bit targets ── */

#ifdef __AVR__
/* Keep the 256-byte round-constant table in flash on the ATmega328P. */
#include <avr/pgmspace.h>
#define SOTA_K256_ATTR PROGMEM
#define SOTA_K256(i) pgm_read_dword(&K256[i])
#else
#define SOTA_K256_ATTR
#define SOTA_K256(i) K256[i]
#endif

static const uint32_t K256[64] SOTA_K256_ATTR = {
  0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
  0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
  0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL, 0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
  0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
  0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
  0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
  0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
  0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL, 0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(sota_sha256_ctx *ctx) {
  uint32_t w[16];
  uint32_t a, b, c, d, e, f, g, h;
  uint8_t i;
  for (i = 0; i < 16; ++i) {
    w[i] = ((uint32_t)ctx->block[4 * i] << 24) | ((uint32_t)ctx->block[4 * i + 1] << 16) |
           ((uint32_t)ctx->block[4 * i + 2] << 8) | (uint32_t)ctx->block[4 * i + 3];
  }
  a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
  e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
  for (i = 0; i < 64; ++i) {
    uint32_t t1, t2, wi;
    if (i < 16) {
      wi = w[i];
    } else {
      const uint32_t w15 = w[(i + 1) & 15], w2 = w[(i + 14) & 15];
      const uint32_t s0 = ROTR32(w15, 7) ^ ROTR32(w15, 18) ^ (w15 >> 3);
      const uint32_t s1 = ROTR32(w2, 17) ^ ROTR32(w2, 19) ^ (w2 >> 10);
      wi = w[i & 15] = w[i & 15] + s0 + w[(i + 9) & 15] + s1;
    }
    t1 = h + (ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25)) + ((e & f) ^ (~e & g)) + SOTA_K256(i) + wi;
    t2 = (ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
    h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
  ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void sota_sha256_init(sota_sha256_ctx *ctx) {
  ctx->state[0] = 0x6a09e667UL; ctx->state[1] = 0xbb67ae85UL; ctx->state[2] = 0x3c6ef372UL; ctx->state[3] = 0xa54ff53aUL;
  ctx->state[4] = 0x510e527fUL; ctx->state[5] = 0x9b05688cUL; ctx->state[6] = 0x1f83d9abUL; ctx->state[7] = 0x5be0cd19UL;
  ctx->bit_length = 0;
  ctx->used = 0;
}

void sota_sha256_update(sota_sha256_ctx *ctx, const uint8_t *data, size_t length) {
  while (length-- > 0) {
    ctx->block[ctx->used++] = *data++;
    ctx->bit_length += 8;
    if (ctx->used == 64) {
      sha256_block(ctx);
      ctx->used = 0;
    }
  }
}

void sota_sha256_final(sota_sha256_ctx *ctx, uint8_t digest[32]) {
  const uint64_t bits = ctx->bit_length;
  uint8_t i;
  ctx->block[ctx->used++] = 0x80;
  if (ctx->used > 56) {
    while (ctx->used < 64) ctx->block[ctx->used++] = 0;
    sha256_block(ctx);
    ctx->used = 0;
  }
  while (ctx->used < 56) ctx->block[ctx->used++] = 0;
  for (i = 0; i < 8; ++i) ctx->block[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
  sha256_block(ctx);
  for (i = 0; i < 8; ++i) {
    digest[4 * i] = (uint8_t)(ctx->state[i] >> 24);
    digest[4 * i + 1] = (uint8_t)(ctx->state[i] >> 16);
    digest[4 * i + 2] = (uint8_t)(ctx->state[i] >> 8);
    digest[4 * i + 3] = (uint8_t)ctx->state[i];
  }
}

void sota_digest_hex(const uint8_t digest[32], char out[65]) {
  static const char digits[] = "0123456789abcdef";
  uint8_t i;
  for (i = 0; i < 32; ++i) {
    out[2 * i] = digits[digest[i] >> 4];
    out[2 * i + 1] = digits[digest[i] & 0x0F];
  }
  out[64] = '\0';
}

/* ── UART link protocol parsing ─────────────────────────────────────────── */

static const char *skip_spaces(const char *p) {
  while (*p == ' ') ++p;
  return p;
}

/* Copy the token after "<key>=" up to the next space into out (cap incl. NUL). */
static int take_field(const char *line, const char *key, char *out, size_t cap) {
  const size_t key_length = strlen(key);
  const char *p = line;
  while (*p) {
    p = skip_spaces(p);
    if (strncmp(p, key, key_length) == 0 && p[key_length] == '=') {
      size_t n = 0;
      p += key_length + 1;
      while (p[n] && p[n] != ' ' && p[n] != '\r' && p[n] != '\n') {
        if (n + 1 >= cap) return 0;
        out[n] = p[n];
        ++n;
      }
      out[n] = '\0';
      return n > 0;
    }
    while (*p && *p != ' ') ++p;
  }
  return 0;
}

static int parse_ulong(const char *s, unsigned long *value) {
  unsigned long v = 0;
  if (*s == '\0') return 0;
  while (*s) {
    if (*s < '0' || *s > '9') return 0;
    if (v > 429496729UL) return 0;
    v = v * 10UL + (unsigned long)(*s - '0');
    ++s;
  }
  *value = v;
  return 1;
}

int sota_parse_manifest_line(const char *line, sota_manifest *out) {
  char size_text[12];
  static const char prefix[] = "SOTA:MANIFEST ";
  if (line == NULL || out == NULL || strncmp(line, prefix, sizeof(prefix) - 1) != 0) return 0;
  line += sizeof(prefix) - 1;
  if (!take_field(line, "v", out->version, sizeof(out->version))) return 0;
  if (!take_field(line, "s", out->sha256, sizeof(out->sha256))) return 0;
  if (!take_field(line, "i", out->image_sha256, sizeof(out->image_sha256))) return 0;
  if (!take_field(line, "n", size_text, sizeof(size_text)) || !parse_ulong(size_text, &out->size)) return 0;
  if (!take_field(line, "g", out->signature, sizeof(out->signature))) return 0;
  if (strcmp(out->image_sha256, "-") == 0) out->image_sha256[0] = '\0';
  if (!version_is_usable(out->version)) return 0;
  if (!is_lower_hex(out->sha256, SOTA_SHA256_HEX_CHARS)) return 0;
  if (out->image_sha256[0] && !is_lower_hex(out->image_sha256, SOTA_SHA256_HEX_CHARS)) return 0;
  return 1;
}

int sota_parse_data_line(const char *line, unsigned long expected_offset, uint8_t *out, size_t cap) {
  static const char prefix[] = "SOTA:DATA ";
  unsigned long offset = 0;
  size_t n = 0;
  if (line == NULL || strncmp(line, prefix, sizeof(prefix) - 1) != 0) return -1;
  line += sizeof(prefix) - 1;
  while (*line >= '0' && *line <= '9') {
    offset = offset * 10UL + (unsigned long)(*line - '0');
    ++line;
  }
  if (*line != ' ' || offset != expected_offset) return -1;
  ++line;
  while (line[0] && line[0] != '\r' && line[0] != '\n') {
    const int hi = hex_value(line[0]);
    const int lo = line[1] ? hex_value(line[1]) : -1;
    if (hi < 0 || lo < 0 || n >= cap) return -1;
    out[n++] = (uint8_t)((hi << 4) | lo);
    line += 2;
  }
  return (int)n;
}
