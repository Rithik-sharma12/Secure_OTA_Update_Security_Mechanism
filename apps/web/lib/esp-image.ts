/**
 * Recognises what kind of ESP firmware file the user is about to flash, so
 * the flasher can pick the right address and refuse files that would leave
 * the board unbootable.
 *
 * Layouts (ESP-IDF / Arduino-ESP32, default partition table):
 *   app image     starts with the image magic 0xE9; written at 0x10000.
 *   merged image  bootloader + partition table + boot_app0 + app, written
 *                 at 0x0. The bootloader sits at 0x1000 on the classic ESP32
 *                 and at 0x0 on S2/S3/C3; the partition table at 0x8000
 *                 starts with 0xAA 0x50; the app at 0x10000 starts with 0xE9.
 *   ESP8266       a sketch binary starts with 0xE9 and is written at 0x0.
 */

export const ESP_IMAGE_MAGIC = 0xe9;
const PARTITION_TABLE_OFFSET = 0x8000;
const APP_OFFSET = 0x10000;
const APP_DESC_OFFSET = 0x20; // esp_app_desc_t, after the 24-byte image header + first segment header
const APP_DESC_MAGIC = 0xabcd5432;
/** No real ESP32 application is this small; catches placeholder and test files. */
const MIN_APP_BYTES = 32 * 1024;

export type EspImageKind = 'merged' | 'app' | 'invalid';

export type EspImageInfo = {
  kind: EspImageKind;
  /** Where the file must be written. */
  address: number;
  /** Bootloader offset inside a merged image (0x1000 classic ESP32, 0x0 S3/C3). */
  bootloaderOffset?: number;
  /** From the app descriptor, when present (ESP-IDF and Arduino-ESP32 builds). */
  projectName?: string;
  appVersion?: string;
  idfVersion?: string;
  /** One line describing the file, or why it was refused. */
  description: string;
};

function cString(bytes: Uint8Array, start: number, length: number): string {
  const slice = bytes.subarray(start, Math.min(start + length, bytes.length));
  const end = slice.indexOf(0);
  return new TextDecoder().decode(end >= 0 ? slice.subarray(0, end) : slice).trim();
}

function readAppDescriptor(bytes: Uint8Array, appStart: number) {
  const at = appStart + APP_DESC_OFFSET;
  if (bytes.length < at + 0x60) return {};
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint32(at, true) !== APP_DESC_MAGIC) return {};
  // Arduino-ESP32 2.x stamps every sketch with the core's own builder name,
  // which says nothing about the sketch; leave it out.
  const project = cString(bytes, at + 48, 32);
  return {
    appVersion: cString(bytes, at + 16, 32) || undefined,
    projectName: project && project !== 'arduino-lib-builder' ? project : undefined,
    idfVersion: cString(bytes, at + 112, 32) || undefined,
  };
}

function formatSize(bytes: number) {
  return bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function inspectEspImage(bytes: Uint8Array): EspImageInfo {
  const size = formatSize(bytes.length);
  if (bytes.length === 0) {
    return { kind: 'invalid', address: 0, description: 'The file is empty.' };
  }

  const hasPartitionTable =
    bytes.length > PARTITION_TABLE_OFFSET + 2 &&
    bytes[PARTITION_TABLE_OFFSET] === 0xaa &&
    bytes[PARTITION_TABLE_OFFSET + 1] === 0x50;
  const hasAppAt0x10000 = bytes.length > APP_OFFSET && bytes[APP_OFFSET] === ESP_IMAGE_MAGIC;
  if (hasPartitionTable && hasAppAt0x10000) {
    const bootloaderOffset = bytes[0x1000] === ESP_IMAGE_MAGIC ? 0x1000 : bytes[0] === ESP_IMAGE_MAGIC ? 0x0 : undefined;
    if (bootloaderOffset === undefined) {
      return {
        kind: 'invalid',
        address: 0,
        description: `${size}: has a partition table and an app but no bootloader at 0x0 or 0x1000. Rebuild the merged image.`,
      };
    }
    const desc = readAppDescriptor(bytes, APP_OFFSET);
    return {
      kind: 'merged',
      address: 0x0,
      bootloaderOffset,
      ...desc,
      description:
        `Full image (${size}): bootloader at 0x${bootloaderOffset.toString(16)}, partition table, app` +
        `${desc.projectName ? ` "${desc.projectName}"` : ''}. Written at 0x0, suitable for a blank board.`,
    };
  }

  if (bytes.length >= 6 && new TextDecoder().decode(bytes.subarray(0, 6)) === 'SOTAv2') {
    return {
      kind: 'invalid',
      address: 0,
      description: `${size}: this is a signed, encrypted OTA package (firmware-ota.bin). Only a running board can open it, over the air. Over USB, flash firmware-full.bin (new board) or firmware.bin.`,
    };
  }
  if (bytes[0] !== ESP_IMAGE_MAGIC) {
    return {
      kind: 'invalid',
      address: 0,
      description: `${size}: not an ESP firmware image (it does not start with the 0xE9 image header). Use firmware.bin or firmware-full.bin from a PlatformIO or Arduino build.`,
    };
  }
  if (bytes.length < MIN_APP_BYTES) {
    return {
      kind: 'invalid',
      address: 0,
      description: `${size}: far too small to be an ESP32 application. This looks like a placeholder or test file, not firmware.`,
    };
  }
  const desc = readAppDescriptor(bytes, 0);
  return {
    kind: 'app',
    address: APP_OFFSET,
    ...desc,
    description:
      `App image (${size})${desc.projectName ? ` "${desc.projectName}"` : ''}${desc.idfVersion ? `, ${desc.idfVersion}` : ''}. ` +
      'Written at 0x10000; the board must already have a bootloader and partition table.',
  };
}
