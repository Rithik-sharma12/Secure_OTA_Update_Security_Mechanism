import { NextResponse } from 'next/server';
import { z } from 'zod';
import { withSecureApi } from '@/lib/api-security';
import { getLocalNetworks, isAccessGranted, toNetworkCidr } from '@/lib/host-access';
import { scanNetwork } from '@/lib/network-discovery';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const scanSchema = z.object({
  cidr: z.string().trim().min(7).max(18).optional(),
});

export async function POST(request: Request) {
  return withSecureApi(
    request,
    '/api/network/scan',
    async ({ auth }) => {
      const userId = auth!.user.id;
      const body = scanSchema.parse(await request.json().catch(() => ({})));

      const cidr = body.cidr
        ? toNetworkCidr(body.cidr)
        : getLocalNetworks()[0]?.cidr;

      if (!cidr) {
        return NextResponse.json(
          { ok: false, error: 'No local IPv4 network was detected on this host.' },
          { status: 400 }
        );
      }

      // The consent gate: scanning the LAN needs an explicit, unexpired grant on
      // exactly this subnet. Without it, no packets go out.
      const granted = await isAccessGranted(userId, 'network', cidr);
      if (!granted) {
        return NextResponse.json(
          {
            ok: false,
            error: `Local network access for ${cidr} has not been granted. Grant it under Host Access, then retry.`,
            requiresGrant: { resourceType: 'network', resourceId: cidr },
          },
          { status: 403 }
        );
      }

      const result = await scanNetwork(cidr);
      return NextResponse.json({ ok: true, ...result });
    },
    { requireAuth: true }
  );
}
