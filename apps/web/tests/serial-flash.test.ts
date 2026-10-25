import { beforeEach, describe, expect, it, vi } from 'vitest';
import { BoardNotInDownloadModeError, explainFlashError, flashImage } from '@/lib/serial-flash';

/**
 * The browser flasher's connection logic, with esptool-js replaced by a fake
 * board: whether the automatic DTR/RTS reset works, whether the person puts
 * it in download mode by hand, and what the ROM printed in between.
 */

type Behaviour = {
  autoWorks: boolean;
  manualWorks: boolean;
  bootLog?: string; // what the fake ROM reports after each reset attempt
};

const board: { behaviour: Behaviour; connects: string[]; written: number } = {
  behaviour: { autoWorks: true, manualWorks: true },
  connects: [],
  written: 0,
};

vi.mock('esptool-js', () => {
  class Transport {
    constructor(public port: unknown) {}
    async disconnect() {}
  }
  class ESPLoader {
    transport: Transport;
    terminal: { writeLine: (line: string) => void };
    chip = {
      getChipDescription: async () => 'ESP32-D0WD-V3 (revision v3.1)',
    };
    constructor(options: { transport: Transport; terminal: { writeLine: (line: string) => void } }) {
      this.transport = options.transport;
      this.terminal = options.terminal;
    }
    async connect(mode: string) {
      board.connects.push(mode);
      if (board.behaviour.bootLog) this.terminal.writeLine(`Debug: ${board.behaviour.bootLog}`);
      const ok = mode === 'default_reset' ? board.behaviour.autoWorks : board.behaviour.manualWorks;
      if (!ok) throw new Error('Failed to connect with the device');
    }
    async runStub() {}
    async changeBaud() {}
    async readFlashId() {
      return 0x164020;
    }
    async writeFlash(options: { fileArray: Array<{ data: Uint8Array }>; reportProgress: (i: number, w: number, t: number) => void }) {
      board.written = options.fileArray[0].data.byteLength;
      options.reportProgress(0, board.written, board.written);
    }
    async after() {}
  }
  return { ESPLoader, Transport };
});

const port = { close: async () => undefined } as unknown as SerialPort;
const image = { bytes: new Uint8Array(4096), address: 0x0, filename: 'firmware-full.bin' };

function callbacks() {
  const log: string[] = [];
  const manual: Array<number | null> = [];
  return {
    log,
    manual,
    cb: {
      onLog: (line: string) => log.push(line),
      onProgress: () => undefined,
      onManualBoot: (seconds: number | null) => manual.push(seconds),
    },
  };
}

describe('flashImage over Web Serial', () => {
  beforeEach(() => {
    board.connects = [];
    board.written = 0;
  });

  it('uses the automatic reset when it works, without asking for buttons', async () => {
    board.behaviour = { autoWorks: true, manualWorks: true };
    const { cb, manual } = callbacks();
    const result = await flashImage({ kind: 'browser', port }, image, cb);
    expect(result.chip).toContain('ESP32');
    expect(board.connects).toEqual(['default_reset']);
    expect(manual).toEqual([]);
    expect(board.written).toBe(4096);
  });

  it('falls back to manual download mode when the automatic reset fails', async () => {
    board.behaviour = { autoWorks: false, manualWorks: true, bootLog: 'bootMode:0x13 downloadMode:false' };
    const { cb, manual, log } = callbacks();
    await flashImage({ kind: 'browser', port }, image, cb);
    expect(board.connects).toEqual(['default_reset', 'no_reset']);
    expect(manual[0]).toBeGreaterThan(0);
    expect(manual.at(-1)).toBeNull();
    expect(board.written).toBe(4096);
    expect(log.some((line) => line.startsWith('Debug:'))).toBe(false);
  });

  it('goes straight to the manual window when asked', async () => {
    board.behaviour = { autoWorks: true, manualWorks: true };
    const { cb } = callbacks();
    await flashImage({ kind: 'browser', port }, image, cb, { manualBoot: true });
    expect(board.connects).toEqual(['no_reset']);
  });

  it('explains a board that resets into its normal firmware', async () => {
    board.behaviour = { autoWorks: false, manualWorks: false, bootLog: 'bootMode:0x13 downloadMode:false' };
    const { cb } = callbacks();
    const error = await flashImage({ kind: 'browser', port }, image, cb).catch((err: unknown) => err);
    expect(error).toBeInstanceOf(BoardNotInDownloadModeError);
    const message = (error as Error).message;
    expect(message).toContain('boot mode 0x13');
    expect(message).toContain('press and release EN');
    expect(explainFlashError(message)).toBe(message);
  });

  it('explains a board that prints nothing at all', async () => {
    board.behaviour = { autoWorks: false, manualWorks: false };
    const { cb } = callbacks();
    const error = (await flashImage({ kind: 'browser', port }, image, cb).catch((err: unknown) => err)) as Error;
    expect(error.message).toContain('printed nothing');
    expect(error.message).toContain('cable');
    // Points at the native (Arduino IDE) route when the browser cannot reach the board.
    expect(error.message).toContain('flash-board.cmd');
  });
});

describe('explainFlashError', () => {
  it('names a busy port', () => {
    expect(explainFlashError('Failed to execute open on SerialPort: Failed to open serial port.')).toContain('in use');
  });
  it('does not call a transfer timeout a download-mode problem', () => {
    expect(explainFlashError('Timed out waiting for packet header')).toContain('stopped answering');
  });
  it('points raw esptool connect failures at manual mode', () => {
    expect(explainFlashError('Failed to connect with the device')).toContain('Manual download mode');
  });
});
