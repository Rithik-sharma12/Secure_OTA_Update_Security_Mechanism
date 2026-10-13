import { GET as handleCronWebhook } from '@/lib/cron-webhooks';

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
	return handleCronWebhook(request);
}
