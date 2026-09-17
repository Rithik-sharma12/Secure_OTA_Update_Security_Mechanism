'use client';

import React from 'react';
import { AlertCircle, CheckCircle2, KeyRound, Loader2, ShieldCheck, UserRound } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { UserManagementCard } from '@/components/profile/UserManagementCard';
import { apiFetch, clearAuthSession, persistAuthSession } from '@/lib/client-auth';
import { formatUtcDateTime } from '@/lib/formatters';
import { USER_ROLE_OPTIONS, type ManagedUser, type ProfileSession } from '@/lib/profile-types';

function DetailRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1 border-b border-border/50 py-3 last:border-0 sm:flex-row sm:items-center sm:justify-between">
      <span className="text-sm text-muted-foreground">{label}</span>
      <span className="text-sm font-medium text-foreground">{value}</span>
    </div>
  );
}

export default function ProfilePage() {
  const [user, setUser] = React.useState<ManagedUser | null>(null);
  const [session, setSession] = React.useState<ProfileSession | null>(null);
  const [isLoading, setIsLoading] = React.useState(true);
  const [loadError, setLoadError] = React.useState<string | null>(null);

  const [username, setUsername] = React.useState('');
  const [currentPassword, setCurrentPassword] = React.useState('');
  const [newPassword, setNewPassword] = React.useState('');
  const [confirmPassword, setConfirmPassword] = React.useState('');
  const [isSaving, setIsSaving] = React.useState(false);
  const [saveError, setSaveError] = React.useState<string | null>(null);
  const [saveNotice, setSaveNotice] = React.useState<string | null>(null);

  const loadProfile = React.useCallback(async () => {
    try {
      const response = await apiFetch('/api/profile', { cache: 'no-store' });

      // Same contract the runtime snapshot uses: an expired or revoked
      // session goes back to the login screen rather than rendering an empty
      // profile. Changing your own password elsewhere lands here too.
      if (response.status === 401) {
        await clearAuthSession();
        window.location.href = '/login';
        return;
      }

      if (!response.ok) {
        const payload = (await response.json().catch(() => ({}))) as { error?: string };
        setLoadError(payload?.error || `Could not load your profile (${response.status}).`);
        return;
      }

      const payload = (await response.json()) as { user: ManagedUser; session: ProfileSession };
      setUser(payload.user);
      setSession(payload.session);
      setUsername(payload.user.username);
      setLoadError(null);
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : 'Could not load your profile.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void loadProfile();
  }, [loadProfile]);

  const usernameChanged = Boolean(user) && username.trim() !== user?.username;
  const wantsPasswordChange = newPassword.length > 0;
  const canSave =
    !isSaving &&
    Boolean(currentPassword) &&
    (usernameChanged || wantsPasswordChange) &&
    (!wantsPasswordChange || newPassword === confirmPassword);

  const handleSave = async () => {
    setIsSaving(true);
    setSaveError(null);
    setSaveNotice(null);

    try {
      const body: Record<string, unknown> = { currentPassword };
      if (usernameChanged) body.username = username.trim();
      if (wantsPasswordChange) body.newPassword = newPassword;

      const response = await apiFetch('/api/profile', {
        method: 'PATCH',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });

      if (!response.ok) {
        const payload = (await response.json().catch(() => ({}))) as { error?: string };
        setSaveError(payload?.error || `Update failed (${response.status}).`);
        return;
      }

      const payload = (await response.json()) as { user: ManagedUser };
      setUser(payload.user);
      setUsername(payload.user.username);
      // The header reads the cached copy, so keep it in step with the change.
      persistAuthSession({ id: payload.user.id, username: payload.user.username, role: payload.user.role });

      setSaveNotice(
        wantsPasswordChange
          ? 'Account updated. Other devices signed in as you have been signed out.'
          : 'Account updated.'
      );
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (error) {
      setSaveError(error instanceof Error ? error.message : 'Update failed.');
    } finally {
      setIsSaving(false);
    }
  };

  const roleDescription = USER_ROLE_OPTIONS.find((option) => option.value === user?.role)?.description;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-foreground">Profile</h1>
        <p className="mt-1 text-foreground/70">Your account details, credentials and permissions</p>
      </div>

      {loadError && (
        <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
          <span>{loadError}</span>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <UserRound className="h-5 w-5 text-primary" />
              Signed in as
            </CardTitle>
            <CardDescription>Read from your current session, not from browser storage.</CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <p className="text-sm text-muted-foreground">Loading your account…</p>
            ) : user ? (
              <>
                <div className="mb-4 flex items-center gap-3">
                  <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-gradient-to-br from-accent to-primary text-base font-bold text-accent-foreground">
                    {user.username.slice(0, 2).toUpperCase()}
                  </div>
                  <div>
                    <p className="text-lg font-semibold text-foreground">{user.username}</p>
                    <div className="mt-1 flex items-center gap-2">
                      <Badge className="bg-chart-2/20 text-chart-2">{user.role}</Badge>
                      <Badge
                        className={user.isActive ? 'bg-chart-1/20 text-chart-1' : 'bg-muted text-muted-foreground'}
                      >
                        {user.isActive ? 'active' : 'disabled'}
                      </Badge>
                    </div>
                  </div>
                </div>

                <DetailRow label="User ID" value={<code className="text-xs">{user.id}</code>} />
                <DetailRow label="Last login" value={user.lastLoginAt ? formatUtcDateTime(user.lastLoginAt) : 'never'} />
                <DetailRow label="Account created" value={user.createdAt ? formatUtcDateTime(user.createdAt) : '—'} />
                <DetailRow label="Last updated" value={user.updatedAt ? formatUtcDateTime(user.updatedAt) : '—'} />
                <DetailRow
                  label="Session expires"
                  value={session ? formatUtcDateTime(session.expiresAt) : '—'}
                />

                <div className="mt-4 flex items-start gap-2 rounded-md border border-border/60 bg-muted/20 p-3">
                  <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-chart-2" />
                  <p className="text-xs text-muted-foreground">{roleDescription}</p>
                </div>
              </>
            ) : (
              <p className="text-sm text-muted-foreground">No account loaded.</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <KeyRound className="h-5 w-5 text-primary" />
              Change credentials
            </CardTitle>
            <CardDescription>
              Your current password is required for any change, even though you are already signed in.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="profile-username">Username</Label>
              <Input
                id="profile-username"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                autoComplete="username"
                disabled={isLoading || isSaving}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="profile-current-password">Current password</Label>
              <Input
                id="profile-current-password"
                type="password"
                value={currentPassword}
                onChange={(event) => setCurrentPassword(event.target.value)}
                autoComplete="current-password"
                disabled={isLoading || isSaving}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="profile-new-password">New password</Label>
              <Input
                id="profile-new-password"
                type="password"
                value={newPassword}
                onChange={(event) => setNewPassword(event.target.value)}
                placeholder="Leave blank to keep your current password"
                autoComplete="new-password"
                disabled={isLoading || isSaving}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="profile-confirm-password">Confirm new password</Label>
              <Input
                id="profile-confirm-password"
                type="password"
                value={confirmPassword}
                onChange={(event) => setConfirmPassword(event.target.value)}
                autoComplete="new-password"
                disabled={isLoading || isSaving || !wantsPasswordChange}
              />
              {wantsPasswordChange && confirmPassword && newPassword !== confirmPassword && (
                <p className="text-xs text-destructive">The two passwords do not match.</p>
              )}
              {wantsPasswordChange && newPassword.length < 12 && (
                <p className="text-xs text-muted-foreground">Passwords must be at least 12 characters.</p>
              )}
            </div>

            {saveError && (
              <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm">
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
                <span>{saveError}</span>
              </div>
            )}
            {saveNotice && !saveError && (
              <div className="flex items-start gap-2 rounded-md border border-chart-1/40 bg-chart-1/10 p-3 text-sm">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-chart-1" />
                <span>{saveNotice}</span>
              </div>
            )}

            <Button onClick={handleSave} disabled={!canSave}>
              {isSaving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Save changes
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Admins only. The API refuses everyone else regardless of what renders. */}
      {user?.role === 'admin' && <UserManagementCard currentUserId={user.id} />}
    </div>
  );
}
