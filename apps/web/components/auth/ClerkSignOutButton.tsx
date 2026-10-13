'use client';

import React from 'react';
import { useClerk } from '@clerk/nextjs';
import { clearAuthSession } from '@/lib/client-auth';

/**
 * Ends the Clerk session as well as the local display cache. The plain
 * /api/auth/logout call cannot do this: the Clerk session lives in Clerk's
 * cookies and the login page would find it still valid and bounce straight
 * back into the dashboard.
 */
export function ClerkSignOutButton({ className, style }: { className?: string; style?: React.CSSProperties }) {
  const { signOut } = useClerk();
  const [busy, setBusy] = React.useState(false);
  return (
    <button
      type="button"
      className={className}
      style={style}
      disabled={busy}
      onClick={async () => {
        setBusy(true);
        await clearAuthSession();
        await signOut({ redirectUrl: '/login' });
      }}
    >
      {busy ? 'Signing out…' : 'Sign Out'}
    </button>
  );
}
