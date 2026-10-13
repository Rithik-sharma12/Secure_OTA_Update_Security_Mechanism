'use client';

import React from 'react';
import { Github, KeyRound, Mail } from 'lucide-react';

/**
 * Shared pieces for showing who someone is: their photo (from Google, GitHub
 * or an upload) with an initials fallback, and how they sign in.
 */

export type AuthProvider = 'google' | 'github' | 'email' | 'local' | string;

export function initialsOf(name: string) {
  const parts = name
    .replace(/@.*$/, '')
    .split(/[\s._-]+/)
    .filter(Boolean);
  const letters = parts.length > 1 ? parts[0][0] + parts[1][0] : (parts[0] || '?').slice(0, 2);
  return letters.toUpperCase();
}

export function UserAvatar({
  name,
  imageUrl,
  size = 36,
  className = '',
}: {
  name: string;
  imageUrl?: string | null;
  size?: number;
  className?: string;
}) {
  const [failed, setFailed] = React.useState(false);
  React.useEffect(() => setFailed(false), [imageUrl]);
  const showImage = Boolean(imageUrl) && !failed;

  return (
    <span
      className={`relative inline-flex shrink-0 items-center justify-center overflow-hidden rounded-full ${className}`}
      style={{
        width: size,
        height: size,
        // Menus render in a portal outside .ds-root, so the brand tokens need fallbacks.
        background: showImage ? 'var(--muted)' : 'var(--gradient-cta, linear-gradient(135deg, #ff9742, #ff2803))',
        color: 'var(--carbon, #181818)',
        font: `700 ${Math.max(10, Math.round(size * 0.36))}px/1 var(--font-display, inherit)`,
      }}
      aria-hidden="true"
    >
      {showImage ? (
        // Provider photos come from several CDNs; next/image would need each
        // host allow-listed, and these are tiny.
        // eslint-disable-next-line @next/next/no-img-element
        <img
          src={imageUrl!}
          alt=""
          width={size}
          height={size}
          referrerPolicy="no-referrer"
          onError={() => setFailed(true)}
          style={{ width: '100%', height: '100%', objectFit: 'cover' }}
        />
      ) : (
        initialsOf(name)
      )}
    </span>
  );
}

function GoogleMark({ size = 14 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" aria-hidden="true">
      <path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3C33.7 32.7 29.3 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.4-.4-3.5z" />
      <path fill="#FF3D00" d="m6.3 14.7 6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z" />
      <path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.3 0-9.7-3.3-11.3-8l-6.5 5C9.5 39.6 16.2 44 24 44z" />
      <path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.2-2.2 4.2-4.1 5.6l6.2 5.2C37 39.2 44 34 44 24c0-1.3-.1-2.4-.4-3.5z" />
    </svg>
  );
}

const PROVIDERS: Record<string, { label: string; icon: (size: number) => React.ReactNode }> = {
  google: { label: 'Google', icon: (size) => <GoogleMark size={size} /> },
  github: { label: 'GitHub', icon: (size) => <Github width={size} height={size} /> },
  email: { label: 'Email', icon: (size) => <Mail width={size} height={size} /> },
  local: { label: 'Local account', icon: (size) => <KeyRound width={size} height={size} /> },
};

export function providerLabel(provider: AuthProvider) {
  return PROVIDERS[provider]?.label ?? provider.charAt(0).toUpperCase() + provider.slice(1);
}

export function ProviderIcon({ provider, size = 14 }: { provider: AuthProvider; size?: number }) {
  return <>{(PROVIDERS[provider]?.icon ?? PROVIDERS.email.icon)(size)}</>;
}

/** Small "Google" / "GitHub" / "Email" chip. */
export function ProviderChip({ provider }: { provider: AuthProvider }) {
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium"
      style={{ border: '1px solid var(--app-line)', color: 'var(--app-ink)' }}
    >
      <ProviderIcon provider={provider} size={12} />
      {providerLabel(provider)}
    </span>
  );
}
