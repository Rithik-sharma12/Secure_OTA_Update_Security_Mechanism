import { createServerClient } from '@supabase/ssr';
import type { NextResponse } from 'next/server';

function parseRequestCookies(request: Request) {
  return (request.headers.get('cookie') || '')
    .split(';')
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const separator = entry.indexOf('=');
      return {
        name: separator >= 0 ? entry.slice(0, separator) : entry,
        value: separator >= 0 ? decodeURIComponent(entry.slice(separator + 1)) : '',
      };
    });
}

/**
 * Supabase as the *sign-in* provider. Clerk takes precedence: when Clerk keys
 * are set, accounts live in Clerk (mirrored to the local store and, through
 * lib/supabase-sync.ts, to Supabase tables), so Supabase keys must not switch
 * login, logout or Settings → Users over to Supabase Auth.
 */
export function isSupabaseAuthConfigured() {
  if (process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY && process.env.CLERK_SECRET_KEY) {
    return false;
  }
  return Boolean(
    process.env.NEXT_PUBLIC_SUPABASE_URL &&
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
  );
}

export function createSupabaseServerClient(
  request: Request,
  response?: Pick<NextResponse, 'cookies'>
) {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!url || !key) {
    throw new Error('Supabase Auth is not configured.');
  }

  return createServerClient(url, key, {
    cookies: {
      getAll() {
        return parseRequestCookies(request);
      },
      setAll(cookies) {
        if (!response) {
          return;
        }
        for (const cookie of cookies) {
          response.cookies.set(cookie.name, cookie.value, cookie.options);
        }
      },
    },
  });
}

export async function signOutSupabase(
  request: Request,
  response: Pick<NextResponse, 'cookies'>
) {
  const supabase = createSupabaseServerClient(request, response);
  await supabase.auth.signOut();
}
