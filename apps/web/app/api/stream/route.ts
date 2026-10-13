import { NextResponse } from 'next/server';
import { withSecureApi } from '@/lib/api-security';
import { gatewayHeaders, gatewayUrl } from '@/lib/gateway-proxy';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * Live change notifications for the signed-in browser.
 *
 * Relays the gateway's /api/stream (Server-Sent Events). The events carry
 * only a revision number; pages then re-fetch through their normal
 * authenticated routes, so this stream never exposes data on its own. When
 * the browser goes away the upstream request is aborted with it.
 */
export async function GET(request: Request) {
  return withSecureApi(
    request,
    '/api/stream',
    async () => {
      let upstream: Response;
      try {
        upstream = await fetch(`${gatewayUrl}/api/stream?max_seconds=300`, {
          headers: { ...gatewayHeaders(), Accept: 'text/event-stream' },
          signal: request.signal,
          cache: 'no-store',
        });
      } catch {
        return NextResponse.json({ ok: false, error: 'Gateway stream unavailable.' }, { status: 502 });
      }
      if (!upstream.ok || !upstream.body) {
        return NextResponse.json({ ok: false, error: `Gateway stream answered ${upstream.status}.` }, { status: 502 });
      }
      return new NextResponse(upstream.body, {
        status: 200,
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-store, no-transform',
          Connection: 'keep-alive',
          'X-Accel-Buffering': 'no',
        },
      });
    },
    { requireAuth: true }
  );
}
