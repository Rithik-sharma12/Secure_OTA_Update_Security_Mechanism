import { describe, expect, it } from 'vitest';
import { inspectEspImage } from '@/lib/esp-image';

function appImage(size: number, project = 'esp32_ota_main') {
  const bytes = new Uint8Array(size);
  bytes[0] = 0xe9;
  const view = new DataView(bytes.buffer);
  view.setUint32(0x20, 0xabcd5432, true);
  new TextEncoder().encodeInto('2.5.0', bytes.subarray(0x20 + 16, 0x20 + 48));
  new TextEncoder().encodeInto(project, bytes.subarray(0x20 + 48, 0x20 + 80));
  new TextEncoder().encodeInto('v4.4.7', bytes.subarray(0x20 + 112, 0x20 + 144));
  return bytes;
}

function mergedImage(bootloaderOffset: number) {
  const app = appImage(200_000);
  const bytes = new Uint8Array(0x10000 + app.length);
  bytes[bootloaderOffset] = 0xe9;
  bytes[0x8000] = 0xaa;
  bytes[0x8001] = 0x50;
  bytes.set(app, 0x10000);
  return bytes;
}

describe('inspectEspImage', () => {
  it('recognises an app image and places it at 0x10000', () => {
    const info = inspectEspImage(appImage(300_000));
    expect(info.kind).toBe('app');
    expect(info.address).toBe(0x10000);
    expect(info.projectName).toBe('esp32_ota_main');
    expect(info.appVersion).toBe('2.5.0');
    expect(info.idfVersion).toBe('v4.4.7');
  });

  it('recognises a classic ESP32 merged image and places it at 0x0', () => {
    const info = inspectEspImage(mergedImage(0x1000));
    expect(info.kind).toBe('merged');
    expect(info.address).toBe(0x0);
    expect(info.bootloaderOffset).toBe(0x1000);
  });

  it('recognises an S3/C3 merged image with the bootloader at 0x0', () => {
    const info = inspectEspImage(mergedImage(0x0));
    expect(info.kind).toBe('merged');
    expect(info.bootloaderOffset).toBe(0x0);
  });

  it('refuses a file without the image header', () => {
    const bytes = new Uint8Array(100_000).fill(0x41);
    expect(inspectEspImage(bytes).kind).toBe('invalid');
  });

  it('refuses a tiny placeholder file even with the magic byte', () => {
    const bytes = new Uint8Array(4097);
    bytes[0] = 0xe9;
    const info = inspectEspImage(bytes);
    expect(info.kind).toBe('invalid');
    expect(info.description).toMatch(/too small/);
  });

  it('refuses an empty file', () => {
    expect(inspectEspImage(new Uint8Array(0)).kind).toBe('invalid');
  });
});

describe('inspectEspImage: OTA packages and Arduino builds', () => {
  it('names an encrypted SOTAv2 package instead of calling it garbage', () => {
    const bytes = new Uint8Array(64 * 1024);
    bytes.set(new TextEncoder().encode('SOTAv2'), 0);
    const info = inspectEspImage(bytes);
    expect(info.kind).toBe('invalid');
    expect(info.description).toContain('encrypted OTA package');
  });

  it('drops the generic arduino-lib-builder project name', () => {
    const bytes = new Uint8Array(64 * 1024);
    bytes[0] = 0xe9;
    const view = new DataView(bytes.buffer);
    view.setUint32(0x20, 0xabcd5432, true);
    bytes.set(new TextEncoder().encode('arduino-lib-builder'), 0x20 + 48);
    const info = inspectEspImage(bytes);
    expect(info.kind).toBe('app');
    expect(info.projectName).toBeUndefined();
  });
});
