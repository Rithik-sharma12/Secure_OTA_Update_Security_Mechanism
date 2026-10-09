/**
 * Client-safe shapes for the profile and user-management screens.
 *
 * `lib/auth.ts` owns the same concepts but pulls in node:crypto and the NeDB
 * stores, so it can never be imported from a client component. These
 * declarations are the shared contract; the server remains the only place
 * the rules are enforced.
 */

export type UserRole = 'admin' | 'operator' | 'viewer';

/** A user as the API returns it — deliberately without `passwordHash`. */
export interface ManagedUser {
  id: string;
  username: string;
  role: UserRole;
  isActive: boolean;
  lastLoginAt?: string | Date;
  createdAt?: string | Date;
  updatedAt?: string | Date;
}

export interface ProfileSession {
  expiresAt: string;
  issuedAt: string | Date | null;
}

export const USER_ROLE_OPTIONS: ReadonlyArray<{
  value: UserRole;
  label: string;
  description: string;
}> = [
  {
    value: 'admin',
    label: 'Admin',
    description: 'Full access, including managing accounts and publishing firmware.',
  },
  {
    value: 'operator',
    label: 'Operator',
    description: 'Runs deployments and flashes devices, but cannot manage accounts.',
  },
  {
    value: 'viewer',
    label: 'Viewer',
    description: 'Read-only access to the fleet, releases and logs.',
  },
];
