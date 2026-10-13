import { supabaseServiceAdmin } from '@/lib/supabase';
import { logger } from '@/lib/logger';
import type { UploadRecord, UserRecord } from '@/lib/local-database';

/**
 * Optional mirror of the dashboard's own records into Supabase.
 *
 * The local store (.local-db) stays the source of truth, so sign-in and
 * uploads never depend on Supabase being reachable. When
 * NEXT_PUBLIC_SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are set, each user
 * profile and firmware-upload job is also upserted into the tables created by
 * supabase/migrations/0001_secureota_mirror.sql. Failures are logged once per
 * table and otherwise ignored.
 *
 * Only the server writes here (service role); the tables have RLS enabled and
 * no public policies, so browsers cannot read them with the anon key.
 */

const warned = new Set<string>();

function warnOnce(table: string, message: string) {
  if (warned.has(table)) return;
  warned.add(table);
  logger.warn(
    'SupabaseSync',
    `Could not write to ${table}: ${message}. Run supabase/migrations/0001_secureota_mirror.sql in the Supabase SQL editor.`
  );
}

export function isSupabaseMirrorEnabled() {
  return supabaseServiceAdmin !== null;
}

function iso(value: unknown): string | null {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(String(value));
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

async function upsert(table: string, row: Record<string, unknown>, onConflict: string) {
  const client = supabaseServiceAdmin;
  if (!client) return;
  try {
    const { error } = await client.from(table).upsert(row, { onConflict });
    if (error) warnOnce(table, error.message);
  } catch (error) {
    warnOnce(table, error instanceof Error ? error.message : String(error));
  }
}

/** Mirror one account (never its password hash). Fire-and-forget. */
export function mirrorProfile(user: UserRecord | null | undefined) {
  if (!user?._id || !isSupabaseMirrorEnabled()) return;
  void upsert(
    'ota_profiles',
    {
      local_id: String(user._id),
      clerk_id: user.clerkId ?? null,
      username: user.username,
      email: user.email || null,
      display_name: user.displayName || null,
      image_url: user.imageUrl || null,
      auth_providers: user.authProviders ?? [],
      role: user.role,
      is_active: user.isActive !== false,
      last_login_at: iso(user.lastLoginAt),
      created_at: iso(user.createdAt) ?? new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
    'local_id'
  );
}

/** Mirror a firmware-upload job's current state. Fire-and-forget. */
export function mirrorUpload(job: Partial<UploadRecord> & { jobId: string }) {
  if (!isSupabaseMirrorEnabled()) return;
  const row: Record<string, unknown> = { job_id: job.jobId, updated_at: new Date().toISOString() };
  const fields: Array<[keyof UploadRecord, string]> = [
    ['userId', 'user_local_id'],
    ['fileName', 'file_name'],
    ['fileHash', 'file_hash'],
    ['boardType', 'board_type'],
    ['fqbn', 'fqbn'],
    ['comPort', 'com_port'],
    ['status', 'status'],
    ['progress', 'progress'],
    ['errorMessage', 'error_message'],
    ['startedAt', 'started_at'],
    ['endedAt', 'ended_at'],
  ];
  for (const [from, to] of fields) {
    if (job[from] !== undefined) row[to] = job[from];
  }
  void upsert('ota_uploads', row, 'job_id');
}

/** For /api/health/supabase: are the mirror tables there and writable by the server? */
export async function checkMirrorTables() {
  const client = supabaseServiceAdmin;
  if (!client) return { enabled: false as const };
  const result: Record<string, boolean | string> = {};
  for (const table of ['ota_profiles', 'ota_uploads']) {
    const { error } = await client.from(table).select('*', { head: true, count: 'exact' }).limit(1);
    result[table] = error ? error.message : true;
  }
  return { enabled: true as const, tables: result };
}
