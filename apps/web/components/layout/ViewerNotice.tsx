'use client';

import Link from 'next/link';
import { Eye } from 'lucide-react';
import { useCurrentUser } from '@/lib/use-current-user';

/**
 * Shown across the console to a viewer, so buttons they cannot use read as
 * a permission, not as broken features.
 */
export function ViewerNotice() {
  const { role } = useCurrentUser();
  if (role !== 'viewer') return null;
  return (
    <div
      role="status"
      className="mb-5 flex items-start gap-2.5 rounded-lg border border-chart-3/40 bg-chart-3/10 px-3.5 py-2.5 text-sm text-foreground/85"
    >
      <Eye className="mt-0.5 h-4 w-4 shrink-0 text-chart-3" />
      <span>
        You are signed in as a <strong>viewer</strong>. You can see the whole fleet, but flashing, deploying, publishing
        and device commands need an operator or admin. An admin can change your role in{' '}
        <Link href="/profile" className="underline underline-offset-2">
          Profile, User management
        </Link>
        , or add your e-mail to <code>OTA_ADMIN_EMAILS</code>.
      </span>
    </div>
  );
}
