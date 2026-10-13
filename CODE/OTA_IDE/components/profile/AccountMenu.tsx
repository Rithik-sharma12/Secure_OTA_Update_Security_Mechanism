'use client';

import React from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useClerk, useUser } from '@clerk/nextjs';
import { ChevronDown, LogOut, Settings, UserRound } from 'lucide-react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { clearAuthSession, getStoredAuthUser } from '@/lib/client-auth';
import { clerkEnabled } from '@/lib/post-login';
import { useCurrentUser } from '@/lib/use-current-user';
import { ProviderIcon, UserAvatar, providerLabel } from '@/components/profile/identity';

/**
 * The one account control in the console header: your photo (from Google,
 * GitHub or an upload, otherwise initials), and a menu with Profile,
 * Settings and Sign out. Replaces the separate Clerk button, initials link
 * and sign-out button, which looked like two different accounts.
 */

type Identity = { name: string; email?: string; imageUrl?: string | null; providers: string[] };

function MenuBody({ identity, onSignOut, signingOut }: { identity: Identity; onSignOut: () => void; signingOut: boolean }) {
  const { role } = useCurrentUser();
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          className="ota-userchip outline-none focus-visible:ring-2 focus-visible:ring-[var(--ember)]"
          aria-label={`Account menu for ${identity.name}`}
          title={identity.name}
        >
          <UserAvatar name={identity.name} imageUrl={identity.imageUrl} size={34} />
          <span className="hidden min-w-0 text-left leading-tight lg:block">
            <span className="block max-w-[140px] truncate text-[13px] font-semibold">{identity.name}</span>
            <span className="block max-w-[140px] truncate text-[11px]" style={{ color: 'var(--app-ink2)' }}>
              {identity.email && identity.email !== identity.name ? identity.email : role ?? ''}
            </span>
          </span>
          <ChevronDown className="hidden h-4 w-4 lg:block" style={{ color: 'var(--app-ink2)' }} />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-72">
        <DropdownMenuLabel className="flex items-center gap-3 py-2 font-normal">
          <UserAvatar name={identity.name} imageUrl={identity.imageUrl} size={40} />
          <span className="min-w-0">
            <span className="block truncate text-sm font-semibold text-foreground">{identity.name}</span>
            {identity.email && identity.email !== identity.name && (
              <span className="block truncate text-xs text-muted-foreground">{identity.email}</span>
            )}
            <span className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
              {role && <span className="capitalize">{role}</span>}
              {identity.providers.map((provider) => (
                <span key={provider} className="inline-flex items-center gap-1" title={`Signs in with ${providerLabel(provider)}`}>
                  <ProviderIcon provider={provider} size={11} />
                  {providerLabel(provider)}
                </span>
              ))}
            </span>
          </span>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem asChild>
          <Link href="/profile">
            <UserRound className="mr-2 h-4 w-4" /> Profile and account
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <Link href="/settings">
            <Settings className="mr-2 h-4 w-4" /> Settings
          </Link>
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={(event) => { event.preventDefault(); onSignOut(); }} disabled={signingOut}>
          <LogOut className="mr-2 h-4 w-4" /> {signingOut ? 'Signing out…' : 'Sign out'}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

/** Providers a Clerk user can sign in with, in a stable order. */
export function clerkProviders(user: { passwordEnabled: boolean; externalAccounts: Array<{ provider: string }> }) {
  const list = user.externalAccounts.map((account) => String(account.provider).replace(/^oauth_/, ''));
  if (user.passwordEnabled || list.length === 0) list.push('email');
  return Array.from(new Set(list));
}

function ClerkAccountMenu() {
  const { user } = useUser();
  const { signOut } = useClerk();
  const [signingOut, setSigningOut] = React.useState(false);
  if (!user) return null;
  const email = user.primaryEmailAddress?.emailAddress;
  const identity: Identity = {
    name: user.fullName || user.username || email || 'Account',
    email,
    imageUrl: user.hasImage ? user.imageUrl : null,
    providers: clerkProviders(user),
  };
  return (
    <MenuBody
      identity={identity}
      signingOut={signingOut}
      onSignOut={async () => {
        setSigningOut(true);
        await clearAuthSession();
        await signOut({ redirectUrl: '/login' });
      }}
    />
  );
}

function LocalAccountMenu() {
  const router = useRouter();
  const { user } = useCurrentUser();
  const [stored, setStored] = React.useState<string>('');
  const [signingOut, setSigningOut] = React.useState(false);
  React.useEffect(() => setStored(getStoredAuthUser()?.username ?? ''), []);
  const name = user?.username || stored || 'Account';
  return (
    <MenuBody
      identity={{ name, providers: ['local'] }}
      signingOut={signingOut}
      onSignOut={async () => {
        setSigningOut(true);
        await clearAuthSession();
        router.replace('/login');
      }}
    />
  );
}

export function AccountMenu() {
  return clerkEnabled ? <ClerkAccountMenu /> : <LocalAccountMenu />;
}
