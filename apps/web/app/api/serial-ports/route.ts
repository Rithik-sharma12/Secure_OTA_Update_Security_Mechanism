import { NextResponse } from 'next/server';
import { withSecureApi } from '@/lib/api-security';
import { detectConnectedSerialPorts } from '@/lib/serial-port-detection';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  return withSecureApi(
    request,
    '/api/serial-ports',
    async () => {
      const detection = detectConnectedSerialPorts();

      return NextResponse.json({
        ok: true,
        supported: detection.supported,
        detected: detection.detected,
        count: detection.count,
        ports: detection.ports,
        error: detection.error,
      });
    },
    { requireAuth: true }
  );
}