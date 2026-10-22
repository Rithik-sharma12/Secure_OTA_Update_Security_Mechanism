import { NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * Liveness probe for Docker and the go-online script: answers as soon as the
 * Next.js server is up, without auth, the gateway, Clerk or the database, so a
 * slow dependency cannot mark the container unhealthy and keep the tunnel down.
 */
export function GET() {
  return NextResponse.json({ ok: true, service: 'ota-ide' }, { headers: { 'Cache-Control': 'no-store' } });
}
