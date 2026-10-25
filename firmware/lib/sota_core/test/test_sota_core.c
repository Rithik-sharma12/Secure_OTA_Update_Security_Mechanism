/* Native unit test for sota_core. Build and run with test/run.sh. */
#include <stdio.h>
#include <string.h>

#include "../src/sota_core.h"
#include "vectors.h"

static int failures = 0;
#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);            \
      ++failures;                                                       \
    }                                                                   \
  } while (0)

int main(void) {
  char msg[SOTA_MANIFEST_MESSAGE_MAX];
  char tampered[96];

  /* The statement matches the gateway's byte for byte. */
  CHECK(sota_manifest_message(msg, sizeof msg, TEST0_VERSION, TEST0_SHA256, TEST0_IMAGE, TEST0_SIZE) > 0);
  CHECK(strcmp(msg, TEST0_MESSAGE) == 0);
  CHECK(sota_manifest_message(msg, sizeof msg, TEST1_VERSION, TEST1_SHA256, TEST1_IMAGE, TEST1_SIZE) > 0);
  CHECK(strcmp(msg, TEST1_MESSAGE) == 0);

  /* Genuine signatures verify. */
  CHECK(sota_verify_manifest(TEST_PUBLIC_KEY, TEST0_SIG, TEST0_VERSION, TEST0_SHA256, TEST0_IMAGE, TEST0_SIZE) == SOTA_SIG_OK);
  CHECK(sota_verify_manifest(TEST_PUBLIC_KEY, TEST1_SIG, TEST1_VERSION, TEST1_SHA256, TEST1_IMAGE, TEST1_SIZE) == SOTA_SIG_OK);

  /* Any changed field breaks it. */
  CHECK(sota_verify_manifest(TEST_PUBLIC_KEY, TEST0_SIG, "2.5.2", TEST0_SHA256, TEST0_IMAGE, TEST0_SIZE) == SOTA_SIG_INVALID);
  CHECK(sota_verify_manifest(TEST_PUBLIC_KEY, TEST0_SIG, TEST0_VERSION, TEST0_SHA256, TEST0_IMAGE, TEST0_SIZE + 1) == SOTA_SIG_INVALID);
  strcpy(tampered, TEST0_SHA256);
  tampered[0] = 'c';
  CHECK(sota_verify_manifest(TEST_PUBLIC_KEY, TEST0_SIG, TEST0_VERSION, tampered, TEST0_IMAGE, TEST0_SIZE) == SOTA_SIG_INVALID);
  strcpy(tampered, TEST0_IMAGE);
  tampered[63] = 'c';
  CHECK(sota_verify_manifest(TEST_PUBLIC_KEY, TEST0_SIG, TEST0_VERSION, TEST0_SHA256, tampered, TEST0_SIZE) == SOTA_SIG_INVALID);
  /* A signature for one manifest does not cover another. */
  CHECK(sota_verify_manifest(TEST_PUBLIC_KEY, TEST1_SIG, TEST0_VERSION, TEST0_SHA256, TEST0_IMAGE, TEST0_SIZE) == SOTA_SIG_INVALID);

  /* A flipped bit in the signature or the key. */
  strcpy(tampered, TEST0_SIG);
  tampered[5] = tampered[5] == 'A' ? 'B' : 'A';
  CHECK(sota_verify_manifest(TEST_PUBLIC_KEY, tampered, TEST0_VERSION, TEST0_SHA256, TEST0_IMAGE, TEST0_SIZE) == SOTA_SIG_INVALID);
  strcpy(tampered, TEST_PUBLIC_KEY);
  tampered[0] = tampered[0] == '0' ? '1' : '0';
  CHECK(sota_verify_manifest(tampered, TEST0_SIG, TEST0_VERSION, TEST0_SHA256, TEST0_IMAGE, TEST0_SIZE) != SOTA_SIG_OK);

  /* Malformed inputs are rejected before any crypto. */
  CHECK(sota_verify_manifest("abc", TEST0_SIG, TEST0_VERSION, TEST0_SHA256, TEST0_IMAGE, TEST0_SIZE) == SOTA_SIG_BAD_KEY);
  CHECK(sota_verify_manifest(TEST_PUBLIC_KEY, "not base64!", TEST0_VERSION, TEST0_SHA256, TEST0_IMAGE, TEST0_SIZE) == SOTA_SIG_BAD_ENCODING);
  CHECK(sota_verify_manifest(TEST_PUBLIC_KEY, "", TEST0_VERSION, TEST0_SHA256, TEST0_IMAGE, TEST0_SIZE) == SOTA_SIG_BAD_ENCODING);
  CHECK(sota_verify_manifest(TEST_PUBLIC_KEY, TEST0_SIG, "2.5.1\nx", TEST0_SHA256, TEST0_IMAGE, TEST0_SIZE) == SOTA_SIG_BAD_FIELDS);
  CHECK(sota_verify_manifest(TEST_PUBLIC_KEY, TEST0_SIG, TEST0_VERSION, "ABC", TEST0_IMAGE, TEST0_SIZE) == SOTA_SIG_BAD_FIELDS);
  CHECK(sota_manifest_message(msg, 20, TEST0_VERSION, TEST0_SHA256, TEST0_IMAGE, TEST0_SIZE) == 0);

  /* Versions. */
  CHECK(sota_version_compare("2.5.1", "2.5.0") > 0);
  CHECK(sota_version_compare("v2.10.0", "2.9.9") > 0);
  CHECK(sota_version_compare("1.0.0", "1.0.0") == 0);
  CHECK(sota_version_compare("1.0.0", "1.0.1") < 0);
  CHECK(sota_version_compare("junk", "0.0.1") < 0);

  /* Health table and clamping. */
  CHECK(sota_health_apply(100, SOTA_EV_UPDATE_OK) == 100);
  CHECK(sota_health_apply(60, SOTA_EV_SIGNATURE_INVALID) == 30);
  CHECK(sota_health_quarantined(30));
  CHECK(!sota_health_quarantined(41));
  CHECK(sota_health_apply(10, SOTA_EV_SIGNATURE_INVALID) == 0);

  /* Base64 edge cases. */
  {
    uint8_t buf[8];
    CHECK(sota_base64_decode("TWE=", buf, sizeof buf) == 2 && buf[0] == 'M' && buf[1] == 'a');
    CHECK(sota_base64_decode("TQ==", buf, sizeof buf) == 1);
    CHECK(sota_base64_decode("T===", buf, sizeof buf) == -1);
    CHECK(sota_base64_decode("TQ==TQ==", buf, sizeof buf) == -1);
  }

  /* SHA-256 against hashlib (gen_vectors.py), streamed in odd-sized pieces. */
  {
    static uint8_t data[1000];
    sota_sha256_ctx ctx;
    uint8_t digest[32];
    char hex[65];
    size_t i, at = 0;
    for (i = 0; i < sizeof data; ++i) data[i] = (uint8_t)(i * 7 + 3);
    sota_sha256_init(&ctx);
    while (at < sizeof data) {
      size_t n = (at % 13) + 1;
      if (at + n > sizeof data) n = sizeof data - at;
      sota_sha256_update(&ctx, data + at, n);
      at += n;
    }
    sota_sha256_final(&ctx, digest);
    sota_digest_hex(digest, hex);
    CHECK(strcmp(hex, TEST_SHA256_1000) == 0);
    sota_sha256_init(&ctx);
    sota_sha256_final(&ctx, digest);
    sota_digest_hex(digest, hex);
    CHECK(strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);
    sota_sha256_init(&ctx);
    sota_sha256_update(&ctx, data, 55);
    sota_sha256_final(&ctx, digest);
    sota_digest_hex(digest, hex);
    CHECK(strcmp(hex, TEST_SHA256_55) == 0);
    sota_sha256_init(&ctx);
    sota_sha256_update(&ctx, data, 64);
    sota_sha256_final(&ctx, digest);
    sota_digest_hex(digest, hex);
    CHECK(strcmp(hex, TEST_SHA256_64) == 0);
  }

  /* UART link lines. */
  {
    sota_manifest m;
    uint8_t buf[8];
    CHECK(sota_parse_manifest_line("SOTA:MANIFEST v=" TEST0_VERSION " s=" TEST0_SHA256 " i=" TEST0_IMAGE " n=1004384 g=" TEST0_SIG, &m));
    CHECK(strcmp(m.version, TEST0_VERSION) == 0 && m.size == TEST0_SIZE && strcmp(m.signature, TEST0_SIG) == 0);
    CHECK(sota_verify_manifest(TEST_PUBLIC_KEY, m.signature, m.version, m.sha256, m.image_sha256, m.size) == SOTA_SIG_OK);
    CHECK(sota_parse_manifest_line("SOTA:MANIFEST v=1.0.0 s=" TEST1_SHA256 " i=- n=14200 g=" TEST1_SIG "\r", &m));
    CHECK(m.image_sha256[0] == 0 && m.size == 14200UL);
    CHECK(!sota_parse_manifest_line("SOTA:MANIFEST v=1.0.0 s=abc i=- n=1 g=x", &m));
    CHECK(!sota_parse_manifest_line("SOTA:MANIFEST v=1.0.0 s=" TEST1_SHA256 " i=- g=" TEST1_SIG, &m));
    CHECK(!sota_parse_manifest_line("SOTA:NONE", &m));
    CHECK(sota_parse_data_line("SOTA:DATA 128 00ff10\r", 128, buf, sizeof buf) == 3 && buf[1] == 0xff);
    CHECK(sota_parse_data_line("SOTA:DATA 64 00ff10", 128, buf, sizeof buf) == -1);
    CHECK(sota_parse_data_line("SOTA:DATA 128 0g", 128, buf, sizeof buf) == -1);
    CHECK(sota_parse_data_line("SOTA:DATA 0 000102030405060708", 0, buf, sizeof buf) == -1);
  }

  if (failures == 0) printf("sota_core: all checks passed\n");
  return failures == 0 ? 0 : 1;
}
