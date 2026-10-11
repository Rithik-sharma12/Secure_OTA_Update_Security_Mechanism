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
};

const FLASH_BAUD = 921600;
const AGENT_POLL_MS = 700;

/** Lowercase hex SHA-256, for checking a download before it goes to flash. */
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes.slice().buffer as ArrayBuffer);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/** Turns esptool's low-level failures into what the user should do. */
export function explainFlashError(message: string): string {
  if (/No port selected/i.test(message)) return 'No port selected.';
  if (/Failed to connect|Timed out|Invalid head of packet|Wrong boot mode/i.test(message)) {
    return (
      'The board did not enter download mode. Try again and hold the BOOT button on the board as soon as ' +
      'flashing starts; keep holding until the progress bar moves.'
    );
  }
  return message;
}

/**
 * Write `bytes` at `address` and reset the board. Resolves with the chip name
 * when the board has been reset into the new image.
 */
export async function flashImage(
  target: FlashTarget,
  image: { bytes: Uint8Array; address: number; filename: string; eraseAll?: boolean },
  callbacks: FlashCallbacks
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
    });
    let seen = 0;
    let writing = false;
    for (;;) {
      await new Promise((resolve) => setTimeout(resolve, AGENT_POLL_MS));
      const job = await getAgentJob(jobId, seen);
      job.log.forEach((line) => callbacks.onLog(line));
      seen = job.logLength;
      if (job.chip) callbacks.onChip?.(job.chip);
      if (job.status === 'running' && job.progress > 0) {
        if (!writing) {
          writing = true;
          callbacks.onWriting?.();
        }
        callbacks.onProgress(job.progress);
      }
      if (job.status === 'success') {
        callbacks.onProgress(100);
        return { chip: job.chip ?? 'the board' };
      }
      if (job.status === 'failed') {
        throw new Error(job.error || 'Flash failed.');
      }
    }
  }

  // esptool-js writes partial lines via write(); buffer them until a newline.
  let pending = '';
  const terminal = {
    clean: () => undefined,
    writeLine: (data: string) => {
      callbacks.onLog(pending + data);
      pending = '';
    },
    write: (data: string) => {
      pending += data;
      if (pending.includes('\n')) {
        const parts = pending.split('\n');
        pending = parts.pop() ?? '';
        parts.forEach((part) => callbacks.onLog(part));
      }
    },
  };

  let transport: Transport | null = null;
  try {
    // Loaded on demand: esptool-js touches navigator.serial at import time.
    const { ESPLoader, Transport } = await import('esptool-js');
    transport = new Transport(target.port, false);
    const loader = new ESPLoader({ transport, baudrate: FLASH_BAUD, terminal, debugLogging: false });

    const chip = await loader.main();
    callbacks.onChip?.(chip);
    callbacks.onLog(`[web-flash] connected: ${chip}`);
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
    callbacks.onLog('[web-flash] done, board reset');
    return { chip };
  } finally {
    try {
      await transport?.disconnect();
    } catch {
      // port already closed
    }
  }
}
