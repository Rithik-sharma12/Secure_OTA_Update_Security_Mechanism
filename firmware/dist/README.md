# Which firmware file to flash

`scripts\build-firmware.cmd` writes one folder per board type, for example `firmware\dist\esp32dev\`.

| File | Flash address | Use it for |
|---|---|---|
| `firmware-full.bin` | `0x0` | **A new or blank board, or one stuck in download mode.** Factory image: bootloader, partition table, boot_app0 and the app in one file. This is what Devices > Set up a new board flashes. |
| `firmware.bin` | `0x10000` | Re-flashing only the app on a board that already has the SecureOTA bootloader and partition table. |
| `firmware-ota.bin` | not flashed over USB | The signed, encrypted OTA package. Devices > Flash over USB > Publish as a release uploads it (with the factory image) so boards update over the air. |
| `build-info.json`, `SHA256SUMS.txt` | | Version and SHA-256 of each file; the console checks them before flashing. |

The console lists these files under Firmware > "This computer's build", both when it runs with
`scripts\start-dev.cmd` and in Docker (`scripts\go-online.cmd` mounts this folder read-only).
