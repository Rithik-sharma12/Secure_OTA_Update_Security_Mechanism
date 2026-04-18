import net from 'node:net';
import { NextResponse } from 'next/server';
import { z } from 'zod';
import { withSecureApi } from '@/lib/api-security';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const checkSchema = z.object({
  host: z.string().trim().min(1).max(255),
  port: z.coerce.number().int().min(1).max(65535),
  timeoutMs: z.coerce.number().int().min(500).max(10000).optional(),
});

function normalizeHost(rawHost: string) {
  const withoutProtocol = rawHost.replace(/^https?:\/\//i, '').trim();
  const withoutPath = withoutProtocol.split('/')[0] || '';
  const withoutQuery = withoutPath.split('?')[0] || '';
  const withoutHash = withoutQuery.split('#')[0] || '';
  const hostOnly = withoutHash.split(':')[0] || '';
  return hostOnly.trim();
}

async function probeTcp(host: string, port: number, timeoutMs: number) {
  return await new Promise<{ reachable: boolean; latencyMs: number; error?: string }>((resolve) => {
    const startedAt = Date.now();
    const socket = new net.Socket();
    let completed = false;

    const finish = (result: { reachable: boolean; latencyMs: number; error?: string }) => {
      if (completed) {
        return;
      }

      completed = true;
      socket.destroy();
      resolve(result);
    };

    socket.setTimeout(timeoutMs);

    socket.once('connect', () => {
      finish({ reachable: true, latencyMs: Date.now() - startedAt });
    });

    socket.once('timeout', () => {
      finish({
        reachable: false,
        latencyMs: Date.now() - startedAt,
        error: `Connection timeout after ${timeoutMs} ms.`,
      });
    });

    socket.once('error', (error) => {
      finish({
        reachable: false,
        latencyMs: Date.now() - startedAt,
        error: error.message || 'Unable to connect to target.',
      });
    });

    socket.connect(port, host);
  });
}

async function fetchLatestGatewayVersion() {
  const gatewayUrl = (process.env.EDGE_GATEWAY_URL || 'http://localhost:5000').replace(/\/$/, '');
  const gatewayApiKey = process.env.EDGE_GATEWAY_API_KEY?.trim();
  const manifestUrl = `${gatewayUrl}/releases/latest/manifest${gatewayApiKey ? `?api_key=${encodeURIComponent(gatewayApiKey)}` : ''}`;

  try {
    const response = await fetch(manifestUrl, { cache: 'no-store' });
    if (!response.ok) {
      return null;
    }

    const payload = (await response.json()) as { version?: string };
    return payload.version ? String(payload.version) : null;
  } catch {
    return null;
  }
}

export async function POST(request: Request) {
  return withSecureApi(
    request,
    '/api/ota/check',
    async () => {
      const body = await request.json().catch(() => null);
      const parsed = checkSchema.safeParse(body || {});
      if (!parsed.success) {
        return NextResponse.json(
          {
            ok: false,
            error: 'Host and port are required for OTA check.',
          },
          { status: 400 }
        );
      }

      const host = normalizeHost(parsed.data.host);
      if (!host) {
        return NextResponse.json(
          {
            ok: false,
            error: 'Host is invalid for OTA check.',
          },
          { status: 400 }
        );
      }

      const port = parsed.data.port;
      const timeoutMs = parsed.data.timeoutMs || 3000;
      const probe = await probeTcp(host, port, timeoutMs);
      const latestVersion = await fetchLatestGatewayVersion();

      return NextResponse.json({
        ok: true,
        host,
        port,
        reachable: probe.reachable,
        latencyMs: probe.latencyMs,
        error: probe.error,
        latestVersion,
        updateAvailable: Boolean(latestVersion),
        checkedAt: new Date().toISOString(),
      });
    },
    { requireAuth: true }
  );
}
