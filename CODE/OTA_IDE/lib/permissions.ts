import type { UserRole } from '@/lib/profile-types';

/**
 * The client's copy of the server's role policy.
 *
 * This decides what the UI *offers*. It decides nothing about what the UI is
 * *allowed* to do — `withSecureApi`'s `requireRole` and the per-action check
 * in `app/api/runtime/actions/route.ts` are the enforcement points, and they
 * run again on every request no matter what renders here. Keep this file in
 * step with those two; when they disagree, the server wins and the user sees
 * a 403 instead of a hidden button.
 */

export type Capability =
  /** Create, edit and delete dashboard accounts. */
  | 'users.manage'
  /** Upload a .bin and publish it as a release. */
  | 'firmware.publish'
  /** Flash a board over USB, or from the browser. */
  | 'devices.flash'
  /** Restart, sync or otherwise act on a device or the pipeline. */
  | 'devices.control'
  /** Let the server use a COM port or sweep a subnet on your behalf. */
  | 'host.grant'
  /** Sweep the local network for devices. */
  | 'network.scan'
  /** Run an allowlisted shell command on the host. */
  | 'runtime.command'
  /** Create or inspect signing key material. */
  | 'keys.manage'
  /** Change platform settings. */
  | 'settings.write';

const CAPABILITY_ROLES: Record<Capability, readonly UserRole[]> = {
  'users.manage': ['admin'],
  'firmware.publish': ['admin', 'operator'],
  'devices.flash': ['admin', 'operator'],
  'devices.control': ['admin', 'operator'],
  'host.grant': ['admin', 'operator'],
  'network.scan': ['admin'],
  'runtime.command': ['admin'],
  'keys.manage': ['admin'],
  'settings.write': ['admin'],
};

export function can(role: UserRole | null | undefined, capability: Capability): boolean {
  return role ? CAPABILITY_ROLES[capability].includes(role) : false;
}

// ── Runtime actions ────────────────────────────────────────────────
// Mirrors `rolePermitsAction` in app/api/runtime/actions/route.ts.

const VIEWER_ACTIONS = new Set([
  'events.export',
  'releases.download',
  'reports.generate',
  'reports.download',
]);

const ADMIN_ACTIONS = new Set(['keys.create', 'keys.inspect', 'settings.save', 'settings.reset']);

export function canRunAction(role: UserRole | null | undefined, action: string): boolean {
  if (!role) return false;
  if (role === 'admin') return true;
  if (action.startsWith('danger.') || ADMIN_ACTIONS.has(action)) return false;
  return role === 'operator' || VIEWER_ACTIONS.has(action);
}

/** One line explaining why an action is unavailable, for a tooltip or notice. */
export function deniedReason(role: UserRole | null | undefined, capability: Capability): string {
  const allowed = CAPABILITY_ROLES[capability];
  const names = allowed.length === 1 ? 'an admin' : allowed.join(' or ');
  return `Requires ${names}. You are signed in as ${role ?? 'an unknown role'}.`;
}
