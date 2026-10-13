'use client';

/**
 * Browser-side USB serial detection (Web Serial API).
 *
 * The dashboard runs in a container with no USB, so the server can never list
 * the COM port a board is plugged into. Chrome/Edge can: `navigator.serial`
 * enumerates devices the user has authorized for this origin and fires
 * connect/disconnect events as they are plugged in and out. Authorization is
 * a one-time browser prompt per device (`requestSerialDevice`), after which
 * `listAuthorizedDevices` sees it without any further prompt.
 *
 * Web Serial does not expose the OS port name (COM7), only USB vendor and
 * product ids, so labels are built from a small table of the bridge chips
 * found on ESP dev boards.
 */

export type BrowserSerialDevice = {
  /** Stable within a page session: vendor:product plus the enumeration index. */
  id: string;
  /** Human label, e.g. "USB 10C4:EA60 · Silicon Labs CP210x". */
  label: string;
  vendorId: string | null;
  productId: string | null;
  description: string;
  port: SerialPort;
};

/** Marks a port path as a browser-detected device rather than an OS COM name. */
export const BROWSER_PORT_PREFIX = 'USB ';

const KNOWN_BRIDGES: Record<string, string> = {
  '10C4:EA60': 'Silicon Labs CP210x',
  '10C4:EA70': 'Silicon Labs CP2105',
  '1A86:7523': 'WCH CH340',
  '1A86:55D4': 'WCH CH9102',
  '1A86:55D3': 'WCH CH343',
  '0403:6001': 'FTDI FT232R',
  '0403:6010': 'FTDI FT2232',
  '0403:6015': 'FTDI FT231X',
  '303A:1001': 'Espressif USB-JTAG/serial',
  '303A:0002': 'Espressif ESP32-S2 USB',
  '303A:1002': 'Espressif ESP32-S3 USB',
  '2341:0043': 'Arduino Uno',
  '2341:0001': 'Arduino Uno',
  '2A03:0043': 'Arduino Uno',
};

function hex4(value: number | undefined) {
  return typeof value === 'number' ? value.toString(16).toUpperCase().padStart(4, '0') : null;
}

export function isWebSerialSupported() {
  return typeof navigator !== 'undefined' && 'serial' in navigator;
}

export function isBrowserPortPath(path: string) {
  return path.startsWith(BROWSER_PORT_PREFIX);
}

export function describeUsbDevice(vendorId: string | null, productId: string | null) {
  if (!vendorId || !productId) return 'USB serial device';
  return KNOWN_BRIDGES[`${vendorId}:${productId}`] ?? 'USB serial device';
}

function toDevice(port: SerialPort, index: number): BrowserSerialDevice {
  const info = port.getInfo();
  const vendorId = hex4(info.usbVendorId);
  const productId = hex4(info.usbProductId);
  const description = describeUsbDevice(vendorId, productId);
  const ids = vendorId && productId ? `${vendorId}:${productId}` : 'unknown';
  return {
    id: `${ids}#${index}`,
    label: `${BROWSER_PORT_PREFIX}${ids} · ${description}`,
    vendorId,
    productId,
    description,
    port,
  };
}

/** Devices the user has authorized for this origin that are currently plugged in. */
export async function listAuthorizedDevices(): Promise<BrowserSerialDevice[]> {
  if (!isWebSerialSupported()) return [];
  const ports = await navigator.serial.getPorts();
  return ports.map(toDevice);
}

/**
 * Granting or revoking permission does not fire the browser's connect /
 * disconnect events, so components on the same page are told via this
 * window event instead.
 */
const GRANTS_CHANGED_EVENT = 'secureota:serial-grants-changed';

function announceGrantsChanged() {
  window.dispatchEvent(new Event(GRANTS_CHANGED_EVENT));
}

/**
 * Open the browser's port picker. Must be called from a user gesture.
 * Resolves null when the user cancels the picker.
 */
export async function requestSerialDevice(): Promise<BrowserSerialDevice | null> {
  if (!isWebSerialSupported()) return null;
  try {
    const port = await navigator.serial.requestPort();
    const existing = await navigator.serial.getPorts();
    const index = Math.max(0, existing.indexOf(port));
    announceGrantsChanged();
    return toDevice(port, index);
  } catch (error) {
    if (error instanceof DOMException && error.name === 'NotFoundError') {
      return null; // picker dismissed
    }
    throw error;
  }
}

/** Revoke this origin's permission for a device. No-op on browsers without `forget`. */
export async function forgetSerialDevice(device: BrowserSerialDevice) {
  const port = device.port as SerialPort & { forget?: () => Promise<void> };
  if (typeof port.forget === 'function') {
    await port.forget();
    announceGrantsChanged();
  }
}

/** Re-run `callback` whenever an authorized device is plugged in, removed, granted or revoked. */
export function onSerialDevicesChanged(callback: () => void): () => void {
  if (!isWebSerialSupported()) return () => {};
  navigator.serial.addEventListener('connect', callback);
  navigator.serial.addEventListener('disconnect', callback);
  window.addEventListener(GRANTS_CHANGED_EVENT, callback);
  return () => {
    navigator.serial.removeEventListener('connect', callback);
    navigator.serial.removeEventListener('disconnect', callback);
    window.removeEventListener(GRANTS_CHANGED_EVENT, callback);
  };
}
