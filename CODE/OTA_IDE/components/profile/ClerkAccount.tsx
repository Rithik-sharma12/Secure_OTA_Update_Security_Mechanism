'use client';

import React from 'react';
import { useReverification, useSession, useUser } from '@clerk/nextjs';
import { AlertCircle, Camera, CheckCircle2, KeyRound, Laptop, Loader2, LogOut, Smartphone, Trash2, UserRound } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { apiFetch } from '@/lib/client-auth';
import { ProviderIcon, UserAvatar, providerLabel } from '@/components/profile/identity';

/**
 * Account management for Clerk sign-ins, built into the SecureOTA profile
 * page so there is one place for "me": name and photo, how you sign in
 * (email and password, Google, GitHub), and which devices are signed in.
 * Clerk stays the source of truth; nothing here is stored twice.
 */

type Notice = { kind: 'ok' | 'error'; text: string } | null;

function messageOf(error: unknown, fallback: string) {
  const clerk = error as { errors?: Array<{ longMessage?: string; message?: string }>; message?: string };
  return clerk?.errors?.[0]?.longMessage || clerk?.errors?.[0]?.message || clerk?.message || fallback;
}

function NoticeLine({ notice }: { notice: Notice }) {
  if (!notice) return null;
  const ok = notice.kind === 'ok';
  return (
    <div
      className={`flex items-start gap-2 rounded-md border p-3 text-sm ${
        ok ? 'border-border bg-muted/40' : 'border-destructive/40 bg-destructive/10'
      }`}
      role={ok ? 'status' : 'alert'}
    >
      {ok ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" /> : <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />}
      <span>{notice.text}</span>
    </div>
  );
}

/** Tell the server to re-read this account now (name/photo shown to admins). */
async function resyncServerProfile() {
  try {
    await apiFetch('/api/profile', { method: 'POST' });
  } catch {
    /* the server re-syncs on its own within a minute */
  }
}

// ── Personal details ──────────────────────────────────────────────────────

export function PersonalDetailsCard() {
  const { user } = useUser();
  const [firstName, setFirstName] = React.useState('');
  const [lastName, setLastName] = React.useState('');
  const [busy, setBusy] = React.useState<'name' | 'photo' | null>(null);
  const [notice, setNotice] = React.useState<Notice>(null);
  const fileRef = React.useRef<HTMLInputElement>(null);

  React.useEffect(() => {
    setFirstName(user?.firstName ?? '');
    setLastName(user?.lastName ?? '');
  }, [user?.firstName, user?.lastName]);

  if (!user) return null;
  const nameChanged = firstName.trim() !== (user.firstName ?? '') || lastName.trim() !== (user.lastName ?? '');
  const displayName = user.fullName || user.primaryEmailAddress?.emailAddress || 'You';

  const saveName = async () => {
    setBusy('name');
    setNotice(null);
    try {
      await user.update({ firstName: firstName.trim(), lastName: lastName.trim() });
      await resyncServerProfile();
      setNotice({ kind: 'ok', text: 'Name updated.' });
    } catch (error) {
      setNotice({ kind: 'error', text: messageOf(error, 'Could not update your name.') });
    } finally {
      setBusy(null);
    }
  };

  const setPhoto = async (file: File | null) => {
    setBusy('photo');
    setNotice(null);
    try {
      if (file && file.size > 10 * 1024 * 1024) throw new Error('Choose an image under 10 MB.');
      await user.setProfileImage({ file });
      await user.reload();
      await resyncServerProfile();
      setNotice({ kind: 'ok', text: file ? 'Photo updated.' : 'Photo removed.' });
    } catch (error) {
      setNotice({ kind: 'error', text: messageOf(error, 'Could not update your photo.') });
    } finally {
      setBusy(null);
      if (fileRef.current) fileRef.current.value = '';
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <UserRound className="h-5 w-5 text-primary" />
          Personal details
        </CardTitle>
        <CardDescription>Your name and photo appear in the console header and the audit trail.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="flex flex-wrap items-center gap-4">
          <UserAvatar name={displayName} imageUrl={user.hasImage ? user.imageUrl : null} size={64} />
          <div className="flex flex-wrap gap-2">
            <input
              ref={fileRef}
              type="file"
              accept="image/png,image/jpeg,image/gif,image/webp"
              className="hidden"
              onChange={(event) => void setPhoto(event.target.files?.[0] ?? null)}
            />
            <Button variant="outline" size="sm" onClick={() => fileRef.current?.click()} disabled={busy !== null}>
              {busy === 'photo' ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Camera className="mr-2 h-4 w-4" />}
              {user.hasImage ? 'Change photo' : 'Upload photo'}
            </Button>
            {user.hasImage && (
              <Button variant="ghost" size="sm" onClick={() => void setPhoto(null)} disabled={busy !== null}>
                Remove
              </Button>
            )}
          </div>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2">
            <Label htmlFor="acct-first">First name</Label>
            <Input id="acct-first" value={firstName} onChange={(e) => setFirstName(e.target.value)} autoComplete="given-name" />
          </div>
          <div className="space-y-2">
            <Label htmlFor="acct-last">Last name</Label>
            <Input id="acct-last" value={lastName} onChange={(e) => setLastName(e.target.value)} autoComplete="family-name" />
          </div>
        </div>

        <div className="space-y-2">
          <Label>Email</Label>
          <div className="flex flex-wrap items-center gap-2 rounded-md border border-border px-3 py-2 text-sm">
            <span className="font-medium text-foreground">{user.primaryEmailAddress?.emailAddress ?? 'No email on file'}</span>
            {user.primaryEmailAddress?.verification?.status === 'verified' && (
              <span className="text-xs text-muted-foreground">verified · primary</span>
            )}
          </div>
        </div>

        <NoticeLine notice={notice} />

        <Button onClick={() => void saveName()} disabled={!nameChanged || busy !== null}>
          {busy === 'name' && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          Save details
        </Button>
      </CardContent>
    </Card>
  );
}

// ── Sign-in methods ───────────────────────────────────────────────────────

const SOCIAL = [
  { provider: 'google', strategy: 'oauth_google' },
  { provider: 'github', strategy: 'oauth_github' },
] as const;

export function SignInMethodsCard() {
  const { user } = useUser();
  const [busy, setBusy] = React.useState<string | null>(null);
  const [notice, setNotice] = React.useState<Notice>(null);
  const [showPassword, setShowPassword] = React.useState(false);
  const [currentPassword, setCurrentPassword] = React.useState('');
  const [newPassword, setNewPassword] = React.useState('');
  const [confirmPassword, setConfirmPassword] = React.useState('');
  const [signOutOthers, setSignOutOthers] = React.useState(true);

  // Sensitive changes may ask the user to confirm it is them first; Clerk
  // shows that prompt and then retries the call.
  const updatePassword = useReverification((params: { currentPassword?: string; newPassword: string; signOutOfOtherSessions: boolean }) =>
    user!.updatePassword(params)
  );
  const connect = useReverification((strategy: 'oauth_google' | 'oauth_github') =>
    user!.createExternalAccount({ strategy, redirectUrl: `${window.location.origin}/profile` })
  );
  const disconnect = useReverification(async (id: string) => {
    const account = user!.externalAccounts.find((entry) => entry.id === id);
    await account?.destroy();
    return true;
  });

  if (!user) return null;

  const connected = new Map(user.externalAccounts.map((account) => [String(account.provider).replace(/^oauth_/, ''), account]));
  const methodCount = user.externalAccounts.length + (user.passwordEnabled ? 1 : 0);

  const onConnect = async (strategy: 'oauth_google' | 'oauth_github', provider: string) => {
    setBusy(provider);
    setNotice(null);
    try {
      const account = await connect(strategy);
      const next = account?.verification?.externalVerificationRedirectURL;
      if (next) {
        window.location.assign(next.toString());
        return;
      }
      await user.reload();
      await resyncServerProfile();
    } catch (error) {
      setNotice({ kind: 'error', text: messageOf(error, `Could not connect ${providerLabel(provider)}.`) });
    }
    setBusy(null);
  };

  const onDisconnect = async (id: string, provider: string) => {
    setBusy(provider);
    setNotice(null);
    try {
      await disconnect(id);
      await user.reload();
      await resyncServerProfile();
      setNotice({ kind: 'ok', text: `${providerLabel(provider)} disconnected.` });
    } catch (error) {
      setNotice({ kind: 'error', text: messageOf(error, `Could not disconnect ${providerLabel(provider)}.`) });
    }
    setBusy(null);
  };

  const passwordValid = newPassword.length >= 8 && newPassword === confirmPassword && (!user.passwordEnabled || currentPassword);
  const onSavePassword = async () => {
    setBusy('password');
    setNotice(null);
    try {
      await updatePassword({
        currentPassword: user.passwordEnabled ? currentPassword : undefined,
        newPassword,
        signOutOfOtherSessions: signOutOthers,
      });
      await resyncServerProfile();
      setNotice({ kind: 'ok', text: signOutOthers ? 'Password saved. Your other devices were signed out.' : 'Password saved.' });
      setShowPassword(false);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (error) {
      setNotice({ kind: 'error', text: messageOf(error, 'Could not save your password.') });
    }
    setBusy(null);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <KeyRound className="h-5 w-5 text-primary" />
          Sign-in methods
        </CardTitle>
        <CardDescription>Any of these signs you in to the same account.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {/* Email + password */}
        <div className="rounded-lg border border-border p-3">
          <div className="flex flex-wrap items-center gap-3">
            <span className="flex h-9 w-9 items-center justify-center rounded-full border border-border">
              <ProviderIcon provider="email" size={16} />
            </span>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium text-foreground">Email and password</p>
              <p className="truncate text-xs text-muted-foreground">
                {user.primaryEmailAddress?.emailAddress ?? 'No email'} · {user.passwordEnabled ? 'password set' : 'no password yet'}
              </p>
            </div>
            <Button variant="outline" size="sm" onClick={() => setShowPassword((value) => !value)} disabled={busy !== null}>
              {user.passwordEnabled ? 'Change password' : 'Set a password'}
            </Button>
          </div>

          {showPassword && (
            <div className="mt-4 grid gap-3 sm:grid-cols-3">
              {user.passwordEnabled && (
                <div className="space-y-1.5">
                  <Label htmlFor="acct-current">Current password</Label>
                  <Input id="acct-current" type="password" autoComplete="current-password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} />
                </div>
              )}
              <div className="space-y-1.5">
                <Label htmlFor="acct-new">New password</Label>
                <Input id="acct-new" type="password" autoComplete="new-password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="acct-confirm">Confirm</Label>
                <Input id="acct-confirm" type="password" autoComplete="new-password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} />
              </div>
              <label className="flex items-center gap-2 text-sm text-muted-foreground sm:col-span-3">
                <input type="checkbox" checked={signOutOthers} onChange={(e) => setSignOutOthers(e.target.checked)} />
                Sign out of my other devices
              </label>
              {confirmPassword && newPassword !== confirmPassword && (
                <p className="text-xs text-destructive sm:col-span-3">The two passwords do not match.</p>
              )}
              <div className="sm:col-span-3">
                <Button size="sm" onClick={() => void onSavePassword()} disabled={!passwordValid || busy !== null}>
                  {busy === 'password' && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  Save password
                </Button>
              </div>
            </div>
          )}
        </div>

        {/* Google / GitHub */}
        {SOCIAL.map(({ provider, strategy }) => {
          const account = connected.get(provider);
          const isOnly = Boolean(account) && methodCount <= 1;
          return (
            <div key={provider} className="flex flex-wrap items-center gap-3 rounded-lg border border-border p-3">
              {account?.imageUrl ? (
                <UserAvatar name={account.emailAddress || provider} imageUrl={account.imageUrl} size={36} />
              ) : (
                <span className="flex h-9 w-9 items-center justify-center rounded-full border border-border">
                  <ProviderIcon provider={provider} size={16} />
                </span>
              )}
              <div className="min-w-0 flex-1">
                <p className="flex items-center gap-1.5 text-sm font-medium text-foreground">
                  <ProviderIcon provider={provider} size={13} /> {providerLabel(provider)}
                </p>
                <p className="truncate text-xs text-muted-foreground">
                  {account ? account.emailAddress || account.username || 'connected' : 'Not connected'}
                </p>
              </div>
              {account ? (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => void onDisconnect(account.id, provider)}
                  disabled={busy !== null || isOnly}
                  title={isOnly ? 'Add another way to sign in before removing this one.' : undefined}
                >
                  {busy === provider ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Trash2 className="mr-2 h-4 w-4" />}
                  Disconnect
                </Button>
              ) : (
                <Button variant="outline" size="sm" onClick={() => void onConnect(strategy, provider)} disabled={busy !== null}>
                  {busy === provider && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  Connect
                </Button>
              )}
            </div>
          );
        })}

        <NoticeLine notice={notice} />
      </CardContent>
    </Card>
  );
}

// ── Signed-in devices ─────────────────────────────────────────────────────

type DeviceSession = Awaited<ReturnType<NonNullable<ReturnType<typeof useUser>['user']>['getSessions']>>[number];

export function DevicesCard() {
  const { user } = useUser();
  const { session: current } = useSession();
  const [sessions, setSessions] = React.useState<DeviceSession[] | null>(null);
  const [busy, setBusy] = React.useState<string | null>(null);
  const [notice, setNotice] = React.useState<Notice>(null);

  const load = React.useCallback(async () => {
    if (!user) return;
    try {
      const list = await user.getSessions();
      setSessions(list.filter((entry) => entry.status === 'active'));
    } catch (error) {
      setNotice({ kind: 'error', text: messageOf(error, 'Could not load your devices.') });
      setSessions([]);
    }
  }, [user]);

  React.useEffect(() => {
    void load();
  }, [load]);

  const revoke = async (entry: DeviceSession) => {
    setBusy(entry.id);
    setNotice(null);
    try {
      await entry.revoke();
      await load();
      setNotice({ kind: 'ok', text: 'That device was signed out.' });
    } catch (error) {
      setNotice({ kind: 'error', text: messageOf(error, 'Could not sign that device out.') });
    }
    setBusy(null);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Laptop className="h-5 w-5 text-primary" />
          Signed-in devices
        </CardTitle>
        <CardDescription>Browsers currently signed in to your account.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {sessions === null && <p className="text-sm text-muted-foreground">Loading…</p>}
        {sessions?.map((entry) => {
          const activity = entry.latestActivity;
          const here = entry.id === current?.id;
          const place = [activity?.city, activity?.country].filter(Boolean).join(', ');
          return (
            <div key={entry.id} className="flex flex-wrap items-center gap-3 rounded-lg border border-border p-3">
              <span className="flex h-9 w-9 items-center justify-center rounded-full border border-border">
                {activity?.isMobile ? <Smartphone className="h-4 w-4" /> : <Laptop className="h-4 w-4" />}
              </span>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-foreground">
                  {[activity?.browserName, activity?.deviceType].filter(Boolean).join(' on ') || 'Unknown browser'}
                  {here && <span className="ml-2 text-xs font-normal text-muted-foreground">this device</span>}
                </p>
                <p className="text-xs text-muted-foreground">
                  {[place, activity?.ipAddress, `active ${new Date(entry.lastActiveAt).toLocaleString()}`].filter(Boolean).join(' · ')}
                </p>
              </div>
              {!here && (
                <Button variant="ghost" size="sm" onClick={() => void revoke(entry)} disabled={busy !== null}>
                  {busy === entry.id ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <LogOut className="mr-2 h-4 w-4" />}
                  Sign out
                </Button>
              )}
            </div>
          );
        })}
        <NoticeLine notice={notice} />
      </CardContent>
    </Card>
  );
}
