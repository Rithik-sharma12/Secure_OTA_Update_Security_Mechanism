'use client';

import React from 'react';
import type { StoredAuthUser } from '@/lib/client-auth';
import { can as roleCan, canRunAction as roleCanRunAction, deniedReason, type Capability } from '@/lib/permissions';
import type { UserRole } from '@/lib/profile-types';

type CurrentUserValue = {
  user: StoredAuthUser | null;
  role: UserRole | null;
  can: (capability: Capability) => boolean;
  canRunAction: (action: string) => boolean;
  reasonFor: (capability: Capability) => string;
};

const CurrentUserContext = React.createContext<CurrentUserValue>({
  user: null,
  role: null,
  can: () => false,
  canRunAction: () => false,
  reasonFor: () => 'Sign in to perform this action.',
});

/**
 * Publishes the signed-in account to the tree.
 *
 * The dashboard layout already validates the session against
 * `/api/auth/session` on mount, so the user is handed straight to this
 * provider — no page pays for an extra request, and nothing reads the role
 * out of localStorage, which a viewer could edit to reveal buttons the
 * server would refuse anyway.
 */
export function CurrentUserProvider({
  user,
  children,
}: {
  user: StoredAuthUser | null;
  children: React.ReactNode;
}) {
  const value = React.useMemo<CurrentUserValue>(() => {
    const role = (user?.role as UserRole | undefined) ?? null;
    return {
      user,
      role,
      can: (capability) => roleCan(role, capability),
      canRunAction: (action) => roleCanRunAction(role, action),
      reasonFor: (capability) => deniedReason(role, capability),
    };
  }, [user]);

  return <CurrentUserContext.Provider value={value}>{children}</CurrentUserContext.Provider>;
}

export function useCurrentUser() {
  return React.useContext(CurrentUserContext);
}
