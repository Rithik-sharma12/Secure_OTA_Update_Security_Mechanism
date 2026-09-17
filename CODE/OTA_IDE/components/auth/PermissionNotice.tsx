'use client';

import { ShieldAlert } from 'lucide-react';
import { useCurrentUser } from '@/lib/use-current-user';
import type { Capability } from '@/lib/permissions';

/**
 * Why a control on this page is unavailable to the signed-in role.
 *
 * Shown in place of the control rather than beside a dead button, so the page
 * reads as "not yours" instead of "broken".
 */
export function PermissionNotice({ capability, action }: { capability: Capability; action: string }) {
  const { reasonFor } = useCurrentUser();

  return (
    <div className="flex items-start gap-2 rounded-md border border-border/60 bg-muted/20 p-3 text-sm">
      <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-chart-3" />
      <span className="text-muted-foreground">
        {action} is not available to your account. {reasonFor(capability)}
      </span>
    </div>
  );
}
