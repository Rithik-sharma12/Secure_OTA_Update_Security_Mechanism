'use client';

/**
 * Write a firmware image to a board on the user's machine, by either route:
 *
 *   agent   — the SecureOTA Agent on 127.0.0.1 runs esptool against the real
 *             COM port (no browser prompt, works in any browser);
 *   browser — Web Serial + esptool-js in Chrome/Edge, after the one-time port
 *             grant.
 *
 * Shared by the "Flash over USB" card and the "Set up a new board" flow so the
 * two cannot drift. Callers pass callbacks for log lines and progress.
 */

import { getAgentJob, startAgentFlash } from '@/lib/local-agent';

type Transport = import('esptool-js').Transport;

export type FlashTarget =
  | { kind: 'agent'; path: string }
  | { kind: 'browser'; port: SerialPort };

export type FlashCallbacks = {
  onLog: (line: string) => void;
  onProgress: (percent: number) => void;
  onChip?: (chip: string) => void;
  /** Called once the board is connected and bytes start moving. */
  onWriting?: () => void;
  /**
   * The automatic reset did not put the board into download mode, so the
   * flasher now waits `seconds` for the user to do it by hand
   * (hold BOOT, tap EN/RST, release BOOT). Called with null when that wait ends.
   */
  onManualBoot?: (seconds: number | null) => void;
};

export type FlashOptions = {
  /**
   * Skip the automatic reset and wait for the user to put the board into
   * download mode by hand. For boards without the auto-download circuit, or
   * USB adapters whose DTR/RTS lines do not reach EN and IO0.
   */
  manualBoot?: boolean;
};

/**
 * Tried in order. The ROM bootloader always syncs at 115200; esptool then
 * switches to the rate below. Some USB-UART bridges and long cables drop
 * bytes at 921600, so a transfer that fails part-way is retried slower.
 */
const FLASH_BAUDS = [921600, 460800, 115200];
const AGENT_POLL_MS = 700;
/** Automatic reset attempts (esptool-js alternates 50 ms and 550 ms EN delays). */
const AUTO_RESET_ATTEMPTS = 8;
/** One no-reset attempt is five sync tries, a little under a second. */
const MANUAL_WINDOW_SECONDS = 40;
const MANUAL_ATTEMPTS = 40;

/** Lowercase hex SHA-256, for checking a download before it goes to flash. */
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes.slice().buffer as ArrayBuffer);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export const MANUAL_BOOT_STEPS =
  'Press and hold BOOT (IO0), press and release EN (RST), then release BOOT.';

/** Thrown when the board never answered the ROM bootloader handshake. */
export class BoardNotInDownloadModeError extends Error {}

/** Turns esptool's low-level failures into what the user should do. */
export function explainFlashError(message: string): string {
  if (/No port selected/i.test(message)) return 'No port selected.';
  if (/already open|Failed to open serial port|could not open port|NetworkError|Access denied|PermissionError/i.test(message)) {
    return (
      'The COM port is in use by another program (Arduino IDE serial monitor, PlatformIO, PuTTY, another browser tab, ' +
      'or this page\'s serial monitor). Close it and try again.'
    );
  }
  // Already explained by the flasher itself.
  if (/^The board (never|is in download)/.test(message)) return message;
  if (/Failed to connect|Wrong boot mode|No serial data received/i.test(message)) {
    return (
      'The board did not enter download mode. Tick "Manual download mode", click Flash, then: ' + MANUAL_BOOT_STEPS
    );
  }
  if (/Timed out|timeout|Packet content transfer stopped|Invalid head of packet/i.test(message)) {
    return (
      'The board stopped answering while the firmware was being written. Use a shorter USB data cable or a port ' +
      'directly on the computer (not a hub), then try again; the flasher already retried at lower speeds.'
    );
  }
  return message;
}

/** What the ROM printed after each reset, to explain a failed connection. */
type BootObservation = { bootMode: string; downloadMode: boolean };

function diagnose(observed: BootObservation[], manualTried: boolean): string {
  const download = observed.find((entry) => entry.downloadMode);
  if (download) {
    return (
      'The board is in download mode but does not answer. Another program may be reading the port, or the ' +
      'USB adapter drops data: close other serial tools, try another USB cable or port, then retry.'
    );
  }
  const normal = observed.find((entry) => entry.bootMode);
  const manual = manualTried ? '' : ' Tick "Manual download mode" and retry.';
  if (normal) {
    return (
      `The board never entered download mode: it reset but started its normal firmware (boot mode ${normal.bootMode}), ` +
      'so IO0 was not held low. The automatic BOOT line is not working on this board or adapter. ' +
      `Put it in download mode by hand: ${MANUAL_BOOT_STEPS}${manual}`
    );
  }
  return (
    'The board never entered download mode and printed nothing after the reset. Check that this is the board\'s ' +
    'COM port, that the USB cable carries data (charge-only cables show no port or stay silent) and that the ' +
    `CP210x / CH340 driver is installed. Then put it in download mode by hand: ${MANUAL_BOOT_STEPS}${manual}`
  );
}

/**
 * Write `bytes` at `address` and reset the board. Resolves with the chip name
 * when the board has been reset into the new image.
 */
export async function flashImage(
  target: FlashTarget,
  image: { bytes: Uint8Array; address: number; filename: string; eraseAll?: boolean },
  callbacks: FlashCallbacks,
  options: FlashOptions = {}
): Promise<{ chip: string }> {
  if (image.bytes.byteLength === 0) throw new Error('The firmware image is empty.');

  if (target.kind === 'agent') {
    callbacks.onLog(`[flash] using ${target.path} via the SecureOTA Agent`);
    const jobId = await startAgentFlash({
      port: target.path,
      address: image.address,
      // TypeScript 5.9 made Uint8Array generic over its backing buffer; the
      // bytes always come from a fetch or File read, so the buffer is a plain
      // ArrayBuffer. Slicing gives one with the narrow type.
      file: new Blob([image.bytes.slice().buffer as ArrayBuffer]),
      filename: image.filename.endsWith('.bin') ? image.filename : 'firmware.bin',
      erase: Boolean(image.eraseAll),
      manualBoot: Boolean(options.manualBoot),
    });
    let seen = 0;
    let writing = false;
    let waitingManual = false;
    for (;;) {
      await new Promise((resolve) => setTimeout(resolve, AGENT_POLL_MS));
      const job = await getAgentJob(jobId, seen);
      job.log.forEach((line) => callbacks.onLog(line));
      seen = job.logLength;
      if (job.chip) callbacks.onChip?.(job.chip);
      // The agent fell back to (or was asked for) manual download mode.
      const manualNow = Boolean(job.manualBootSeconds && job.status === 'running' && job.progress === 0);
      if (manualNow !== waitingManual) {
        waitingManual = manualNow;
        callbacks.onManualBoot?.(manualNow ? Math.max(1, Math.round(job.manualBootSeconds ?? 0)) : null);
      }
      if (job.status === 'running' && job.progress > 0) {
        if (!writing) {
          writing = true;
          callbacks.onWriting?.();
        }
        callbacks.onProgress(job.progress);
      }
      if (job.status === 'success') {
        if (waitingManual) callbacks.onManualBoot?.(null);
        callbacks.onProgress(100);
        return { chip: job.chip ?? 'the board' };
      }
      if (job.status === 'failed') {
        if (waitingManual) callbacks.onManualBoot?.(null);
        throw new Error(job.error || 'Flash failed.');
      }
    }
  }

  // esptool-js writes partial lines via write(); buffer them until a newline.
  // Debug lines are swallowed except the boot-mode report, which explains a
  // failed connection (normal boot vs. download mode vs. silence).
  const observed: BootObservation[] = [];
  const emit = (line: string) => {
    if (line.startsWith('Debug: ')) {
      const match = /bootMode:(\S*) downloadMode:(true|false)/.exec(line);
      if (match && match[1]) observed.push({ bootMode: match[1], downloadMode: match[2] === 'true' });
      return;
    }
    callbacks.onLog(line);
  };
  let pending = '';
  const terminal = {
    clean: () => undefined,
    writeLine: (data: string) => {
      emit(pending + data);
      pending = '';
    },
    write: (data: string) => {
      pending += data;
      if (pending.includes('\n')) {
        const parts = pending.split('\n');
        pending = parts.pop() ?? '';
        parts.forEach((part) => emit(part));
      }
    },
  };

  // Loaded on demand: esptool-js touches navigator.serial at import time.
  const { ESPLoader, Transport } = await import('esptool-js');
  type Loader = InstanceType<typeof ESPLoader>;

  // A previous failed attempt (or a monitor) can leave the port open, and
  // Transport.connect() then fails with "The port is already open".
  try {
    await target.port.close();
  } catch {
    // not open, which is what we want
  }

  const port = target.port;
  let manualTried = false;

  /** One connection attempt with one reset strategy; the port is closed again on failure. */
  const tryConnect = async (baudrate: number, mode: 'default_reset' | 'no_reset', attempts: number) => {
    const transport = new Transport(port, false);
    const loader = new ESPLoader({ transport, baudrate, terminal, debugLogging: true });
    try {
      await loader.connect(mode, attempts);
      return { loader, transport };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (/already open|Failed to open|NetworkError|Access denied/i.test(message)) throw err;
      try {
        await transport.disconnect();
      } catch {
        // already closed
      }
      return null;
    }
  };

  /**
   * Reach the ROM bootloader: the automatic DTR/RTS reset first (esptool's
   * classic sequence, or the USB-JTAG one on native-USB chips), then a
   * window in which the user puts the board into download mode by hand.
   */
  const connectBoard = async (baudrate: number) => {
    if (!manualTried && !options.manualBoot) {
      callbacks.onLog('[web-flash] resetting the board into download mode (automatic)');
      const auto = await tryConnect(baudrate, 'default_reset', AUTO_RESET_ATTEMPTS);
      if (auto) return auto;
      callbacks.onLog('[web-flash] the automatic reset did not reach the bootloader');
    }
    manualTried = true;
    callbacks.onLog(`[web-flash] waiting ${MANUAL_WINDOW_SECONDS} s for manual download mode: ${MANUAL_BOOT_STEPS}`);
    callbacks.onManualBoot?.(MANUAL_WINDOW_SECONDS);
    try {
      const manual = await tryConnect(baudrate, 'no_reset', MANUAL_ATTEMPTS);
      if (manual) return manual;
    } finally {
      callbacks.onManualBoot?.(null);
    }
    throw new BoardNotInDownloadModeError(diagnose(observed, true));
  };

  /** What esptool-js main() does after connecting: chip info, stub, faster baud, flash check. */
  const prepare = async (loader: Loader, baudrate: number) => {
    const chip = await loader.chip.getChipDescription(loader);
    callbacks.onLog(`[web-flash] chip: ${chip}`);
    if (loader.chip.postConnect) await loader.chip.postConnect(loader);
    await loader.runStub();
    if (baudrate !== 115200) await loader.changeBaud();
    const flashId = await loader.readFlashId();
    if (flashId === 0xffffff || flashId === 0) {
      throw new Error('The ESP32 answers but its flash chip does not. Disconnect anything wired to GPIO 6-11 and retry.');
    }
    return chip;
  };

  let lastError: unknown = null;
  for (const [attempt, baudrate] of FLASH_BAUDS.entries()) {
    let transport: Transport | null = null;
    let connected = false;
    try {
      if (attempt > 0) callbacks.onLog(`[web-flash] retrying at ${baudrate} baud`);
      const link = await connectBoard(baudrate);
      transport = link.transport;
      const { loader } = link;
      connected = true;
      const chip = await prepare(loader, baudrate);
      callbacks.onChip?.(chip);
      callbacks.onLog(`[web-flash] connected: ${chip} at ${baudrate} baud`);
      callbacks.onWriting?.();

      await loader.writeFlash({
        fileArray: [{ data: image.bytes, address: image.address }],
        flashSize: 'keep',
        flashMode: 'keep',
        flashFreq: 'keep',
        eraseAll: Boolean(image.eraseAll),
        compress: true,
        reportProgress: (_fileIndex, written, total) => {
          callbacks.onProgress(total > 0 ? Math.round((written / total) * 100) : 0);
        },
      });

      await loader.after('hard_reset');
      callbacks.onProgress(100);
      callbacks.onLog(
        manualTried
          ? '[web-flash] done. If the board does not start, press EN (RST) once.'
          : '[web-flash] done, board reset'
      );
      return { chip };
    } catch (err) {
      lastError = err;
      const message = err instanceof Error ? err.message : String(err);
      callbacks.onLog(`[web-flash] ${message}`);
      // Never reached the ROM bootloader: a slower data rate will not help
      // (sync is always at 115200). Only a transfer that broke after
      // connecting is worth retrying.
      if (!connected || attempt === FLASH_BAUDS.length - 1) break;
      callbacks.onProgress(0);
    } finally {
      try {
        await transport?.disconnect();
      } catch {
        // port already closed
      }
    }
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}
