/**
 * Where to send someone after they sign in.
 *
 * Two sources, both untrusted query parameters:
 *   ?next=/devices            — the landing page's deep links
 *   ?redirect_url=<absolute>  — added by Clerk when proxy.ts bounces a
 *                               signed-out visitor to /login
 *
 * Only a path on this same site is honoured, so neither parameter can be used
 * to hand a freshly signed-in user to another origin.
 */

const SAFE_PATH = /^\/(?![/\\])[\w\-./?=&%:]*$/;
const DEFAULT_PATH = '/dashboard';
const STORAGE_KEY = 'ota_post_login_path';

function sanitize(candidate: string | null | undefined): string | null {
  if (!candidate) return null;
  let value = candidate;
  if (/^https?:\/\//i.test(value)) {
    try {
      const url = new URL(value);
      if (typeof window === 'undefined' || url.origin !== window.location.origin) return null;
      value = `${url.pathname}${url.search}`;
    } catch {
      return null;
    }
  }
  if (!SAFE_PATH.test(value)) return null;
  if (value.startsWith('/login') || value.startsWith('/sso-callback')) return null;
  return value;
}

export function postLoginPath(): string {
  if (typeof window === 'undefined') return DEFAULT_PATH;
  const params = new URLSearchParams(window.location.search);
  return sanitize(params.get('next')) ?? sanitize(params.get('redirect_url')) ?? DEFAULT_PATH;
}

/** Social sign-in leaves the site; remember the destination across the round trip. */
export function rememberPostLoginPath() {
  try {
    sessionStorage.setItem(STORAGE_KEY, postLoginPath());
  } catch {
    // storage unavailable: the callback falls back to the dashboard
  }
}

export function recallPostLoginPath(): string {
  try {
    const stored = sanitize(sessionStorage.getItem(STORAGE_KEY));
    sessionStorage.removeItem(STORAGE_KEY);
    return stored ?? DEFAULT_PATH;
  } catch {
    return DEFAULT_PATH;
  }
}

/** Clerk's decorateUrl may return an absolute URL (Safari ITP refresh); follow it with a full navigation. */
export function go(url: string, push: (path: string) => void) {
  if (/^https?:\/\//i.test(url)) window.location.href = url;
  else push(url);
}

export const clerkEnabled = Boolean(process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY);
