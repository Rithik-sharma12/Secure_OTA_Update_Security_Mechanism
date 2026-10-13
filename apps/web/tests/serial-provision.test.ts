/**
 * Web Serial side of the USB provisioning protocol, against a simulated
 * board: it boots (noise first), answers only once it has seen a full
 * request line, and splits its reply across reads the way a UART does.
 */

import { describe, expect, it } from 'vitest';
import { cleanProvisionConfig, provisionBoard, readBoardInfo, webSerialExchange } from '@/lib/serial-provision';

type Reply = (request: string) => string | null;

function fakeBoard(reply: Reply, { bootNoise = ['ets Jun  8 2016 00:22:57', 'rst:0x1 (POWERON_RESET)'] } = {}) {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const received: string[] = [];
  let controller!: ReadableStreamDefaultController<Uint8Array>;
  let opened = 0;
  let closed = 0;
  let buffer = '';

  const port = {
    readable: null as ReadableStream<Uint8Array> | null,
    writable: null as WritableStream<Uint8Array> | null,
    async open() {
      opened += 1;
      port.readable = new ReadableStream<Uint8Array>({
        start(c) {
          controller = c;
          bootNoise.forEach((line) => c.enqueue(encoder.encode(`${line}\r\n`)));
        },
      });
      port.writable = new WritableStream<Uint8Array>({
        write(chunk) {
          buffer += decoder.decode(chunk);
          let newline = buffer.indexOf('\n');
          while (newline >= 0) {
            const line = buffer.slice(0, newline);
            buffer = buffer.slice(newline + 1);
            newline = buffer.indexOf('\n');
            received.push(line);
            const answer = reply(line);
            if (answer) {
              // Split the reply across two reads.
              const half = Math.floor(answer.length / 2);
              setTimeout(() => controller.enqueue(encoder.encode(answer.slice(0, half))), 5);
              setTimeout(() => controller.enqueue(encoder.encode(`${answer.slice(half)}\r\n`)), 15);
            }
          }
        },
      });
    },
    async setSignals() {},
    async close() {
      closed += 1;
    },
  };
  return { port: port as unknown as SerialPort, received, counts: () => ({ opened, closed }) };
}

describe('webSerialExchange', () => {
  it('skips boot noise and returns the matching line', async () => {
    const board = fakeBoard((line) => (line === 'SOTA:PING' ? 'SOTA:PONG' : null));
    const { line, seen } = await webSerialExchange(board.port, 'SOTA:PING', ['SOTA:PONG'], 3000);
    expect(line).toBe('SOTA:PONG');
    expect(seen[0]).toContain('ets Jun');
    expect(board.counts()).toEqual({ opened: 1, closed: 1 });
  });

  it('re-sends until the board answers (it may still be booting)', async () => {
    let calls = 0;
    const board = fakeBoard(() => (++calls >= 2 ? 'SOTA:PONG' : null));
    const { line } = await webSerialExchange(board.port, 'SOTA:PING', ['SOTA:PONG'], 5000);
    expect(line).toBe('SOTA:PONG');
    expect(board.received.length).toBeGreaterThanOrEqual(2);
  });

  it('gives up and still closes the port', async () => {
    const board = fakeBoard(() => null);
    const { line } = await webSerialExchange(board.port, 'SOTA:PING', ['SOTA:PONG'], 400);
    expect(line).toBeNull();
    expect(board.counts().closed).toBe(1);
  });
});

describe('browser provisioning', () => {
  it('reads SOTA:INFO', async () => {
    const board = fakeBoard((line) =>
      line === 'SOTA:INFO' ? 'SOTA:INFO {"device_id":"esp32-aabbccddeeff","version":"2.5.0"}' : null
    );
    const info = await readBoardInfo({ kind: 'browser', port: board.port });
    expect(info.device_id).toBe('esp32-aabbccddeeff');
    expect(info.version).toBe('2.5.0');
  });

  it('writes SOTA:PROVISION as one compact JSON line and reports the fields', async () => {
    const board = fakeBoard((line) => (line.startsWith('SOTA:PROVISION ') ? 'SOTA:OK provisioned; rebooting' : null));
    const written = await provisionBoard(
      { kind: 'browser', port: board.port },
      { ssid: 'lab', password: 'p@ss word', backend_url: 'https://gw.example', device_token: 'tok' }
    );
    expect(written).toEqual(['backend_url', 'device_token', 'password', 'ssid']);
    const sent = JSON.parse(board.received[0].slice('SOTA:PROVISION '.length));
    expect(sent).toEqual({ ssid: 'lab', password: 'p@ss word', backend_url: 'https://gw.example', device_token: 'tok' });
  });

  it('surfaces the board refusing the configuration', async () => {
    const board = fakeBoard((line) =>
      line.startsWith('SOTA:PROVISION ') ? 'SOTA:ERR this build has no OTA_ROOT_CA' : null
    );
    await expect(
      provisionBoard({ kind: 'browser', port: board.port }, { backend_url: 'https://gw.example' })
    ).rejects.toThrow('this build has no OTA_ROOT_CA');
  });
});

describe('cleanProvisionConfig', () => {
  it('refuses values that would break the line protocol', () => {
    expect(() => cleanProvisionConfig({ ssid: 'a\nSOTA:RESET-CONFIG' })).toThrow('single line');
    expect(() => cleanProvisionConfig({ ssid: 'x'.repeat(33) })).toThrow('at most 32');
    expect(() => cleanProvisionConfig({})).toThrow('Nothing to write');
  });
});
