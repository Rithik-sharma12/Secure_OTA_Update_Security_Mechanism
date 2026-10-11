'use client';

/**
 * Talk to SecureOTA firmware over its USB serial line protocol, from either
 * route the dashboard can reach a board by:
 *
 *   agent   — the SecureOTA Agent on 127.0.0.1 (lib/local-agent.ts);
 *   browser — Web Serial in Chrome/Edge, implemented here, so a user with no
 *             agent installed can still give a fresh board its Wi-Fi, gateway
 *             address and device token.
 *
 * Protocol (esp32_ota_main.ino, "USB provisioning protocol"), one line each:
 *
 *   SOTA:INFO                 -> SOTA:INFO {"device_id": ..., "version": ...}
 *   SOTA:PROVISION {json}     -> SOTA:OK ... (then reboots) | SOTA:ERR reason
 *
 * The request is re-sent every 1.5 s until an answer arrives, because opening
 * the port can reset the board and a freshly flashed board is still booting.
 * Secrets go from this page down the USB cable only.
 */

import {
  type AgentDeviceInfo,
  type ProvisionConfig,
  getAgentDeviceInfo,
  provisionAgentDevice,
} from '@/lib/local-agent';

export type BoardLink = { kind: 'agent'; path: string } | { kind: 'browser'; port: SerialPort };

const BAUD = 115200;
const RESEND_MS = 1500;
const INFO_TIMEOUT_MS = 12_000;
const PROVISION_TIMEOUT_MS = 15_000;

// Same limits the agent and the firmware enforce.
const PROVISION_LIMITS: Record<string, number> = {
  ssid: 32,
  password: 64,
  backend_url: 200,
  device_token: 128,
  device_id: 64,
  hostname: 32,
};

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Validate and normalise a provisioning payload before it goes to the board. */
export function cleanProvisionConfig(config: ProvisionConfig): Record<string, string | boolean> {
  const clean: Record<string, string | boolean> = {};
  for (const [key, value] of Object.entries(config)) {
    if (value === undefined) continue;
    if (key === 'reset_health') {
      clean[key] = Boolean(value);
      continue;
    }
    const limit = PROVISION_LIMITS[key];
    if (!limit) throw new Error(`Unknown provisioning field '${key}'.`);
    if (typeof value !== 'string' || value.length > limit || /[\r\n]/.test(value)) {
      throw new Error(`'${key}' must be a single line of at most ${limit} characters.`);
    }
    clean[key] = value;
  }
  if (Object.keys(clean).length === 0) throw new Error('Nothing to write to the board.');
  return clean;
}

/**
 * Send `request` until a line starting with one of `accept` arrives.
 * Opens and always closes the port, so it can be called right after a flash.
 */
export async function webSerialExchange(
  port: SerialPort,
  request: string,
  accept: string[],
  timeoutMs: number
): Promise<{ line: string | null; seen: string[] }> {
  await port.open({ baudRate: BAUD });
  const seen: string[] = [];
  try {
    // Hold EN/IO0 released where the adapter wires DTR/RTS to them, so talking
    // to the board does not put it in download mode or keep resetting it.
    try {
      await port.setSignals({ dataTerminalReady: false, requestToSend: false });
    } catch {
      // Not every adapter supports control lines.
    }
    await sleep(300);

    if (!port.readable || !port.writable) throw new Error('The serial port is not readable.');
    const reader = port.readable.getReader();
    const writer = port.writable.getWriter();
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    let pending = '';
    // One read in flight at a time: a read that lost a race against the timer
    // is kept and awaited again, so no bytes are dropped.
    let inflight: Promise<ReadableStreamReadResult<Uint8Array>> | null = null;

    try {
      const deadline = Date.now() + timeoutMs;
      let nextSend = 0;
      while (Date.now() < deadline) {
        if (Date.now() >= nextSend) {
          await writer.write(encoder.encode(`${request}\n`));
          nextSend = Date.now() + RESEND_MS;
        }
        inflight ??= reader.read();
        const result = await Promise.race([inflight, sleep(200).then(() => null)]);
        if (!result) continue;
        inflight = null;
        if (result.done) break;
        pending += decoder.decode(result.value, { stream: true });
        let newline = pending.indexOf('\n');
        while (newline >= 0) {
          const line = pending.slice(0, newline).trim();
          pending = pending.slice(newline + 1);
          newline = pending.indexOf('\n');
          if (!line) continue;
          seen.push(line);
          if (seen.length > 40) seen.shift();
          if (accept.some((prefix) => line.startsWith(prefix))) return { line, seen };
        }
      }
      return { line: null, seen };
    } finally {
      try {
        await reader.cancel();
      } catch {
        // already closed
      }
      reader.releaseLock();
      writer.releaseLock();
    }
  } finally {
    try {
      await port.close();
    } catch {
      // already closed
    }
  }
}

function tagged(line: string, tag: string): Record<string, unknown> {
  try {
    return JSON.parse(line.slice(tag.length).trim() || '{}') as Record<string, unknown>;
  } catch {
    return {};
  }
}

const NO_ANSWER =
  'No answer from the board. It needs SecureOTA firmware 2.5.0 or newer, must not be in download mode, ' +
  'and no serial monitor may hold the port.';

/** Ask the board who it is. */
export async function readBoardInfo(link: BoardLink): Promise<AgentDeviceInfo> {
  if (link.kind === 'agent') return getAgentDeviceInfo(link.path);

  const { line } = await webSerialExchange(link.port, 'SOTA:INFO', ['SOTA:INFO '], INFO_TIMEOUT_MS);
  if (!line) throw new Error(NO_ANSWER);
  const info = tagged(line, 'SOTA:INFO') as AgentDeviceInfo;
  if (!info.device_id) throw new Error('The board answered without a device id.');
  return info;
}

/** Write Wi-Fi, gateway URL and token into the board's NVS; it reboots after. */
export async function provisionBoard(link: BoardLink, config: ProvisionConfig): Promise<string[]> {
  const clean = cleanProvisionConfig(config);
  if (link.kind === 'agent') return provisionAgentDevice(link.path, config);

  const { line } = await webSerialExchange(
    link.port,
    `SOTA:PROVISION ${JSON.stringify(clean)}`,
    ['SOTA:OK', 'SOTA:ERR'],
    PROVISION_TIMEOUT_MS
  );
  if (!line) throw new Error(NO_ANSWER);
  if (line.startsWith('SOTA:ERR')) {
    throw new Error(line.slice('SOTA:ERR'.length).trim() || 'The board rejected the configuration.');
  }
  return Object.keys(clean).sort();
}
