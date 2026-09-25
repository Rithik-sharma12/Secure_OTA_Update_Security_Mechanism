import { NextResponse } from 'next/server';

import { checkSupabaseConnection } from '@/lib/supabase';

export const dynamic = 'force-dynamic';

export async function GET() {
  const result = await checkSupabaseConnection();

  return NextResponse.json(result, {
    status: result.connected ? 200 : 503,
  });
}