'use client';

import React from 'react';
import Link from 'next/link';
import { useClerk, useUser } from '@clerk/nextjs';
import { AlertCircle, LogOut, Settings, ShieldCheck } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { UserManagementCard } from '@/components/profile/UserManagementCard';
import { LocalCredentialsCard } from '@/components/profile/LocalCredentialsCard';
import { DevicesCard, PersonalDetailsCard, SignInMethodsCard } from '@/components/profile/ClerkAccount';
import { clerkProviders } from '@/components/profile/AccountMenu';
import { ProviderChip, UserAvatar } from '@/components/profile/identity';
import { apiFetch, clearAuthSession } from '@/lib/client-auth';
import { clerkEnabled } from '@/lib/post-login';
import { formatUtcDateTime } from '@/lib/formatters';
import { USER_ROLE_OPTIONS, type ManagedUser, type ProfileSession } from '@/lib/profile-types';

/**
 * One profile for one person. Whether they signed in with Google, GitHub,
 * email or a local account, everything about "me" lives here: who I am, how I
 * sign in, which devices are signed in, and what I am allowed to do in
 * SecureOTA. Clerk's own account screens are not used, so there is no second
 * profile to confuse with this one.
 */

type HeroIdentity = {
  name: string;
  email?: string;
  imageUrl?: string | null;
  providers: string[];
  memberSince?: string | Date | null;
  lastSignIn?: string | Date | null;
};

function DetailRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1 border-b border-border/50 py-3 last:border-0 sm:flex-row sm:items-center sm:justify-between">
      <span className="text-sm text-muted-foreground">{label}</span>
      <span className="text-sm font-medium text-foreground">{value}</span>
    </div>
  );
}

function ProfileHero({ identity, user, onSignOut }: { identity: HeroIdentity; user: ManagedUser | null; onSignOut: () => void }) {
  const [signingOut, setSigningOut] = React.useState(false);
  return (
    <Card>
      <CardContent className="flex flex-wrap items-center gap-5 py-6">
        <UserAvatar name={identity.name} imageUrl={identity.imageUrl} size={84} />
        <div className="min-w-0 flex-1 space-y-1.5">
          <h2 className="truncate text-2xl font-semibold tracking-tight text-foreground">{identity.name}</h2>
          {identity.email && identity.email !== identity.name && (
            <p className="truncate text-sm text-muted-foreground">{identity.email}</p>
          )}
          <div className="flex flex-wrap items-center gap-2 pt-1">
            {user && (
              <span
                className="rounded-md px-2.5 py-0.5 text-xs font-semibold capitalize"
                style={{ background: 'var(--app-inv-bg)', color: 'var(--app-inv-ink)' }}
              >
                {user.role}
              </span>
            )}
            {identity.providers.map((provider) => (
              <ProviderChip key={provider} provider={provider} />
            ))}
          </div>
          <p className="pt-1 text-xs text-muted-foreground">
            {identity.memberSince ? `Member since ${formatUtcDateTime(identity.memberSince)}` : null}
            {identity.memberSince && identity.lastSignIn ? ' · ' : null}
            {identity.lastSignIn ? `Last sign-in ${formatUtcDateTime(identity.lastSignIn)}` : null}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" asChild>
            <Link href="/settings">
              <Settings className="mr-2 h-4 w-4" /> Settings
            </Link>
          </Button>
          <Button
            variant="outline"
            disabled={signingOut}
            onClick={() => {
              setSigningOut(true);
              onSignOut();
            }}
          >
            <LogOut className="mr-2 h-4 w-4" /> {signingOut ? 'Signing out…' : 'Sign out'}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function AccessCard({ user, session }: { user: ManagedUser | null; session: ProfileSession | null }) {
  const role = USER_ROLE_OPTIONS.find((option) => option.value === user?.role);
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5 text-primary" />
          SecureOTA access
        </CardTitle>
        <CardDescription>What this account can do in the console. Roles are set by an admin.</CardDescription>
      </CardHeader>
      <CardContent>
        {user ? (
          <>
            <div className="mb-3 rounded-md border border-border/60 bg-muted/20 p-3">
              <p className="text-sm font-semibold text-foreground">{role?.label ?? user.role}</p>
              <p className="mt-0.5 text-xs text-muted-foreground">{role?.description}</p>
            </div>
            <DetailRow label="Status" value={user.isActive ? 'Active' : 'Disabled'} />
            <DetailRow label="Console user ID" value={<code className="text-xs">{user.id}</code>} />
            <DetailRow label="Last console sign-in" value={user.lastLoginAt ? formatUtcDateTime(user.lastLoginAt) : 'never'} />
            {!clerkEnabled && (
              <DetailRow label="Session expires" value={session ? formatUtcDateTime(session.expiresAt) : 'Not set'} />
            )}
          </>
        ) : (
          <p className="text-sm text-muted-foreground">Loading…</p>
        )}
      </CardContent>
    </Card>
  );
}

function useServerProfile() {
  const [user, setUser] = React.useState<ManagedUser | null>(null);
  const [session, setSession] = React.useState<ProfileSession | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const response = await apiFetch('/api/profile', { cache: 'no-store' });
        // An expired or revoked session goes back to the login screen rather
        // than rendering an empty profile.
        if (response.status === 401) {
          await clearAuthSession();
          window.location.href = '/login';
          return;
        }
        if (!response.ok) {
          const payload = (await response.json().catch(() => ({}))) as { error?: string };
          if (!cancelled) setError(payload?.error || `Could not load your profile (${response.status}).`);
          return;
        }
        const payload = (await response.json()) as { user: ManagedUser; session: ProfileSession };
        if (!cancelled) {
          setUser(payload.user);
          setSession(payload.session);
          setError(null);
        }
      } catch (loadError) {
        if (!cancelled) setError(loadError instanceof Error ? loadError.message : 'Could not load your profile.');
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return { user, setUser, session, error };
}

function ClerkProfile() {
  const { user: clerkUser, isLoaded } = useUser();
  const { signOut } = useClerk();
  const { user, session, error } = useServerProfile();

  const email = clerkUser?.primaryEmailAddress?.emailAddress;
  const identity: HeroIdentity = clerkUser
    ? {
        name: clerkUser.fullName || clerkUser.username || email || 'Your account',
        email,
        imageUrl: clerkUser.hasImage ? clerkUser.imageUrl : null,
        providers: clerkProviders(clerkUser),
        memberSince: clerkUser.createdAt,
        lastSignIn: clerkUser.lastSignInAt,
      }
    : { name: isLoaded ? 'Signed out' : 'Loading…', providers: [] };

  return (
    <>
      {error && <ErrorLine text={error} />}
      <ProfileHero
        identity={identity}
        user={user}
        onSignOut={async () => {
          await clearAuthSession();
          await signOut({ redirectUrl: '/login' });
        }}
      />
      {clerkUser && (
        <div className="grid gap-6 lg:grid-cols-2">
          <PersonalDetailsCard />
          <SignInMethodsCard />
          <DevicesCard />
          <AccessCard user={user} session={session} />
        </div>
      )}
      {user?.role === 'admin' && <UserManagementCard currentUserId={user.id} />}
    </>
  );
}

function LocalProfile() {
  const { user, setUser, session, error } = useServerProfile();
  const identity: HeroIdentity = {
    name: user?.username ?? 'Loading…',
    providers: ['local'],
    memberSince: user?.createdAt ?? null,
    lastSignIn: user?.lastLoginAt ?? null,
  };
  return (
    <>
      {error && <ErrorLine text={error} />}
      <ProfileHero
        identity={identity}
        user={user}
        onSignOut={async () => {
          await clearAuthSession();
          window.location.href = '/login';
        }}
      />
      <div className="grid gap-6 lg:grid-cols-2">
        {user && <LocalCredentialsCard user={user} onSaved={setUser} />}
        <AccessCard user={user} session={session} />
      </div>
      {user?.role === 'admin' && <UserManagementCard currentUserId={user.id} />}
    </>
  );
}

function ErrorLine({ text }: { text: string }) {
  return (
    <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm">
      <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
      <span>{text}</span>
    </div>
  );
}

export default function ProfilePage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-foreground">Profile</h1>
        <p className="mt-1 text-foreground/70">Your account, how you sign in, and what you can do in SecureOTA.</p>
      </div>
      {clerkEnabled ? <ClerkProfile /> : <LocalProfile />}
    </div>
  );
}
