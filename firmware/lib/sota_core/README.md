# sota_core

The board-independent part of the SecureOTA update agent, shared by every firmware in `firmware/`.

| Function | Used for |
|---|---|
| `sota_manifest_message`, `sota_verify_manifest` | Stage 5: Ed25519 check of the gateway-signed manifest statement |
| `sota_version_compare` | Anti-downgrade: only a strictly newer version is installed |
| `sota_health_apply`, `sota_health_quarantined` | Health score (ASH): event table, clamping, quarantine at 40 |
| `sota_hex_decode`, `sota_base64_decode` | Manifest field decoding without the heap |

The signed statement is, byte for byte:

```
SOTA-MANIFEST-V1\n<version>\n<sha256>\n<imageSha256>\n<size>
```

The gateway builds the same bytes in `apps/gateway/gateway/crypto.py` (`manifest_signing_message`).

Ed25519 is Monocypher 4.0.2 (`src/monocypher*.c`), licence in `LICENCE-monocypher.md`.

## Using it

- PlatformIO finds it automatically (it lives in the project `lib/` folder).
- arduino-cli: `--library firmware/lib/sota_core` (`firmware/tools/build_firmware.py` adds it).
- Arduino IDE: Sketch > Include Library > Add .ZIP Library, and pick this folder zipped.

## Test

```
sh firmware/lib/sota_core/test/run.sh
```

Needs a C compiler and Python with `cryptography`. It signs statements with a test key the way the gateway does and checks that the C code accepts them and rejects every altered field.
