import { networkInterfaces } from 'node:os';
import { NextResponse } from 'next/server';
import type { AuthContext } from '@/lib/auth';
import { logger } from '@/lib/logger';

/**
 * Server-side calls from the dashboard to the edge gateway.
 *
 * The gateway's fleet key lives only in this process (EDGE_GATEWAY_API_KEY);
 * the browser talks to these Next routes with its session cookie and never
 * sees the key, the same rule /api/firmware/publish follows.
 */

export const gatewayUrl = (process.env.EDGE_GATEWAY_URL || 'http://localhost:5000').replace(/\/$/, '');
const gatewayApiKey = process.env.EDGE_GATEWAY_API_KEY?.trim();

/**
 * The URL a *device* uses to reach the gateway. Often differs from
 * EDGE_GATEWAY_URL, which may be a Docker-internal name (http://gateway:5000)
 * no board on the internet can resolve.
 */
export const deviceGatewayUrl = boardReachable(
  (process.env.OTA_DEVICE_GATEWAY_URL || process.env.OTA_GATEWAY_PUBLIC_URL || process.env.EDGE_GATEWAY_URL || '').replace(
    /\/$/,
    ''
  )
);

/**
 * In local development EDGE_GATEWAY_URL is http://localhost:5000, which is
 * the board itself once it is on Wi-Fi. When the console and the gateway run
 * on the same computer, hand boards that computer's LAN address instead.
 * Docker-internal names (http://gateway:5000) are left alone: set
 * OTA_DEVICE_GATEWAY_URL for those deployments.
 */
function boardReachable(url: string): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return url;
  }
  if (!/^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\])$/i.test(parsed.hostname)) return url;
  const lan = lanIPv4();
  if (!lan) return url;
  parsed.hostname = lan;
  return parsed.toString().replace(/\/$/, '');
}

function lanIPv4(): string | null {
  const candidates: string[] = [];
  for (const entries of Object.values(networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.family === 'IPv4' && !entry.internal && !entry.address.startsWith('169.254.')) candidates.push(entry.address);
    }
  }
  // Prefer the usual private ranges a board on the same Wi-Fi can reach.
  return (
    candidates.find((ip) => ip.startsWith('192.168.')) ??
    candidates.find((ip) => ip.startsWith('10.')) ??
    candidates.find((ip) => /^172\.(1[6-9]|2\d|3[01])\./.test(ip)) ??
    candidates[0] ??
    null
  );
}

const TIMEOUT_MS = 15_000;

/**
 * Names the signed-in operator to the gateway's audit trail. The gateway only
 * believes it alongside the fleet key, which only this server holds.
 */
export function actorHeader(auth: AuthContext | null | undefined): Record<string, string> {
  if (!auth) return {};
  return { 'x-actor': `${auth.user.username} (${auth.user.role})`.replace(/[^\w .@:()/-]/g, '').slice(0, 96) };
}

export function gatewayHeaders(auth?: AuthContext | null): Record<string, string> {
  return { ...(gatewayApiKey ? { 'x-api-key': gatewayApiKey } : {}), ...actorHeader(auth) };
}

export const DEVICE_ID_PATTERN = /^[A-Za-z0-9_.:-]{1,64}$/;

function gatewayErrorMessage(parsed: unknown, text: string, status: number) {
  const detail = (parsed as { detail?: unknown } | null)?.detail;
  if (typeof detail === 'string') return detail;
  if (detail && typeof detail === 'object' && typeof (detail as { message?: unknown }).message === 'string') {
    return (detail as { message: string }).message;
  }
  const error = (parsed as { error?: unknown } | null)?.error;
  if (typeof error === 'string') return error;
  return text.slice(0, 300) || `Gateway responded ${status}`;
}

/** Forward one JSON request to the gateway and relay its answer. */
export async function proxyGatewayJson(
  scope: string,
  path: string,
  init: { method?: string; body?: unknown; auth?: AuthContext | null } = {}
): Promise<NextResponse> {
  const headers: Record<string, string> = gatewayHeaders(init.auth);
  if (init.body !== undefined) headers['Content-Type'] = 'application/json';

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const response = await fetch(`${gatewayUrl}${path}`, {
      method: init.method || 'GET',
      headers,
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      signal: controller.signal,
      cache: 'no-store',
    });
    const text = await response.text();
    let parsed: unknown = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      parsed = null;
    }

    if (!response.ok) {
      const message = gatewayErrorMessage(parsed, text, response.status);
      logger.warn(scope, `Gateway ${init.method || 'GET'} ${path} -> ${response.status}: ${message}`);
      return NextResponse.json({ ok: false, error: message }, { status: response.status });
    }
    return NextResponse.json(parsed ?? { ok: true });
  } catch (error) {
    const aborted = error instanceof Error && error.name === 'AbortError';
    const message = aborted ? 'The gateway did not answer in time.' : `Could not reach the gateway at ${gatewayUrl}.`;
    logger.error(scope, message, error);
    return NextResponse.json({ ok: false, error: message }, { status: 502 });
  } finally {
    clearTimeout(timeout);
  }
}

export function invalidDeviceId() {
  return NextResponse.json(
    { ok: false, error: 'Device id must be 1-64 characters of A-Z a-z 0-9 _ . : -' },
    { status: 400 }
  );
}
