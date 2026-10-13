import { NextResponse } from 'next/server';

import { checkSupabaseConnection } from '@/lib/supabase';
import { checkMirrorTables } from '@/lib/supabase-sync';

export const dynamic = 'force-dynamic';

/**
 * Supabase status: configured, reachable, and whether the mirror tables from
 * supabase/migrations/0001_secureota_mirror.sql exist. Reports table names
 * and error text only — never keys or row data.
 */
export async function GET() {
  const result = await checkSupabaseConnection();
  const mirror = result.connected ? await checkMirrorTables() : { enabled: false as const };

  return NextResponse.json({ ...result, mirror }, {
    status: result.connected ? 200 : 503,
  });
}
