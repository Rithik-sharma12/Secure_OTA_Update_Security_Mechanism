import sys; sys.path.insert(0, sys.argv[1]); from edit import patch
F = sys.argv[2] + '/firmware/esp32_ota_main/esp32_ota_main.ino'
patch(F, [
('#include "mbedtls/pk.h"\n', '#include "mbedtls/pk.h"\n\n// Stage 5: Ed25519 check of the gateway-signed manifest (firmware/lib/sota_core).\n#include "sota_core.h"\n'),
('#ifndef BACKEND_API_KEY\n#define BACKEND_API_KEY ""\n#endif\n',
 '#ifndef BACKEND_API_KEY\n#define BACKEND_API_KEY ""\n#endif\n'
 '// Raw Ed25519 public key of the gateway, 64 hex characters\n'
 '// (GET /releases/latest/public-key -> publicKeyHex). Usually left empty and\n'
 '// written over USB by the dashboard\'s board setup ("gateway_key"). When a key\n'
 '// is present, stage 5 is mandatory: an unsigned or badly signed manifest is\n'
 '// never installed.\n'
 '#ifndef GATEWAY_ED25519_PUBKEY\n#define GATEWAY_ED25519_PUBKEY ""\n#endif\n'),
('#define SECURE_SIG_ALG_ED25519        2U  // reserved; not verifiable in this build\n',
 '#define SECURE_SIG_ALG_ED25519        2U  // reserved package format; Ed25519 is checked on the manifest (stage 5)\n'),
('  String deviceId;\n  String hostname;\n};\n',
 '  String deviceId;\n  String hostname;\n  String gatewayKey;   // Ed25519 public key (hex) for stage 5\n};\n'),
('  String sha256;\n  String imageSha256;\n',
 '  String sha256;\n  String imageSha256;\n\n'
 '  // Artifact size in bytes and the gateway\'s Ed25519 signature over\n'
 '  // version, sha256, imageSha256 and size (stage 5, sota_verify_manifest).\n'
 '  unsigned long size = 0;\n  String manifestSignature;\n'),
('AppState state;\n',
 'AppState state;\n\n'
 '// The manifest being installed, for the stage 5 check that runs just before\n'
 '// the boot partition is switched. Set by performHttpUpdate().\n'
 'const ManifestInfo *installingManifest = nullptr;\n'
 '// Set when stage 5 rejected the update, so the health penalty is the\n'
 '// signature one (-30) rather than the generic update failure (-25).\n'
 'bool lastFailureWasSignature = false;\n'
 'bool verifyManifestSignature(const ManifestInfo &manifest);\n'),
('  state.failedAttempts24h++;\n  adjustHealth(-25, "update failed");\n',
 '  state.failedAttempts24h++;\n'
 '  if (lastFailureWasSignature) {\n'
 '    adjustHealth(sota_health_delta(SOTA_EV_SIGNATURE_INVALID), "manifest signature invalid");\n'
 '  } else {\n'
 '    adjustHealth(-25, "update failed");\n'
 '  }\n'),
('  manifestOut.securePackage = doc["securePackage"] | false;\n',
 '  manifestOut.securePackage = doc["securePackage"] | false;\n'
 '  manifestOut.size = doc["size"] | 0UL;\n'
 '  manifestOut.manifestSignature = doc["manifestSignature"] | "";\n'),
('bool performHttpUpdate(const ManifestInfo &manifest) {\n  digitalWrite(LED_STATUS, HIGH);\n',
 'bool performHttpUpdate(const ManifestInfo &manifest) {\n  digitalWrite(LED_STATUS, HIGH);\n'
 '  installingManifest = &manifest;\n  lastFailureWasSignature = false;\n'),
('  digitalWrite(LED_STATUS, LOW);\n  return success;\n}\n',
 '  installingManifest = nullptr;\n  digitalWrite(LED_STATUS, LOW);\n  return success;\n}\n\n'
 '/*\n'
 ' * Stage 5 of the five-stage pipeline. Runs after the image has been downloaded\n'
 ' * into the inactive partition (stage 3) and matched to the manifest digest\n'
 ' * (stage 4), and before the boot partition is switched.\n'
 ' *\n'
 ' * The gateway signs "SOTA-MANIFEST-V1\\nversion\\nsha256\\nimageSha256\\nsize" with\n'
 ' * its Ed25519 key. Stage 4 already proved the bytes hash to `sha256` (or\n'
 ' * `imageSha256` for a package), so a valid signature over those fields binds\n'
 ' * the flashed image to the gateway key and to the version agreed in stage 2.\n'
 ' *\n'
 ' * With no gateway key on the board (built and provisioned before this\n'
 ' * existed) the stage is skipped and logged, so existing boards keep updating;\n'
 ' * the dashboard writes the key during board setup.\n'
 ' */\n'
 'bool verifyManifestSignature(const ManifestInfo &manifest) {\n'
 '  if (cfg.gatewayKey.length() == 0) {\n'
 '    Serial.println("[Stage 5] SKIPPED: no gateway Ed25519 key on this board (set it up again from the dashboard).");\n'
 '    return true;\n'
 '  }\n'
 '  const unsigned long started = millis();\n'
 '  const sota_sig_result result = sota_verify_manifest(\n'
 '    cfg.gatewayKey.c_str(),\n'
 '    manifest.manifestSignature.c_str(),\n'
 '    manifest.version.c_str(),\n'
 '    manifest.sha256.c_str(),\n'
 '    manifest.imageSha256.c_str(),\n'
 '    manifest.size);\n'
 '  if (result != SOTA_SIG_OK) {\n'
 '    Serial.printf("[Stage 5] REJECTED: %s\\n", sota_sig_result_text(result));\n'
 '    lastFailureWasSignature = true;\n'
 '    return false;\n'
 '  }\n'
 '  Serial.printf("[Stage 5] Ed25519 manifest signature valid (%lu ms).\\n", millis() - started);\n'
 '  return true;\n'
 '}\n'),
# secure path: before Update.end
('    Serial.printf("[Update] Signature verified. Writing %u bytes to flash.\\n", static_cast<unsigned int>(totalWritten));\n\n    if (!Update.end(true)) {',
 '    if (installingManifest != nullptr && !verifyManifestSignature(*installingManifest)) {\n      break;\n    }\n\n'
 '    Serial.printf("[Update] Signature verified. Writing %u bytes to flash.\\n", static_cast<unsigned int>(totalWritten));\n\n    if (!Update.end(true)) {'),
# plain path: before Update.end
('  mbedtls_md_free(&mdCtx);\n\n  if (!success) {\n    Update.abort();\n  } else if (!Update.end(true)) {',
 '  mbedtls_md_free(&mdCtx);\n\n'
 '  if (success && installingManifest != nullptr && !verifyManifestSignature(*installingManifest)) {\n    success = false;\n  }\n\n'
 '  if (!success) {\n    Update.abort();\n  } else if (!Update.end(true)) {'),
('  cfg.hostname = nvsString("host", DEVICE_HOSTNAME);\n',
 '  cfg.hostname = nvsString("host", DEVICE_HOSTNAME);\n  cfg.gatewayKey = nvsString("gwkey", GATEWAY_ED25519_PUBKEY);\n  cfg.gatewayKey.toLowerCase();\n'),
('    info["has_device_token"] = cfg.deviceToken.length() > 0;\n',
 '    info["has_device_token"] = cfg.deviceToken.length() > 0;\n    info["has_gateway_key"] = cfg.gatewayKey.length() == 64;\n'),
('    if (doc["device_id"].is<const char *>() && devid.length() && !validDeviceId(devid)) {',
 '    const String gwkey = doc["gateway_key"] | "";\n'
 '    if (doc["gateway_key"].is<const char *>()) {\n'
 '      uint8_t keyBytes[SOTA_ED25519_PUBLIC_KEY_BYTES];\n'
 '      if (sota_hex_decode(gwkey.c_str(), keyBytes, sizeof(keyBytes)) != 0) {\n'
 '        Serial.println("SOTA:ERR gateway_key must be 64 hex characters");\n'
 '        return;\n'
 '      }\n'
 '    }\n'
 '    if (doc["device_id"].is<const char *>() && devid.length() && !validDeviceId(devid)) {'),
('    if (doc["hostname"].is<const char *>()) prefs.putString("host", doc["hostname"].as<String>());\n',
 '    if (doc["hostname"].is<const char *>()) prefs.putString("host", doc["hostname"].as<String>());\n    if (doc["gateway_key"].is<const char *>()) prefs.putString("gwkey", gwkey);\n'),
])
