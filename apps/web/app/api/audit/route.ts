import { OPERATOR_ROLES, withSecureApi } from '@/lib/api-security';
import { proxyGatewayJson } from '@/lib/gateway-proxy';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * Gateway audit trail: who deployed, restarted, registered or removed what.
 * Operators and admins only — rows name accounts and source addresses.
 */
export async function GET(request: Request) {
  return withSecureApi(
    request,
    '/api/audit',
    async () => {
      const incoming = new URL(request.url).searchParams;
      const query = new URLSearchParams();
      for (const key of ['limit', 'before_id', 'device_id', 'actor', 'action']) {
        const value = incoming.get(key);
        if (value) query.set(key, value.slice(0, 96));
      }
      return proxyGatewayJson('Audit', `/api/audit?${query.toString()}`);
    },
    { requireRole: OPERATOR_ROLES }
  );
}
