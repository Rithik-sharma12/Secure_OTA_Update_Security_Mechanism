'use client';

import React from 'react';
import { AlertCircle, CheckCircle2, KeyRound, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { apiFetch, persistAuthSession } from '@/lib/client-auth';
import type { ManagedUser } from '@/lib/profile-types';

/**
 * Username and password for local accounts (used when Clerk is not
 * configured). Clerk accounts manage these in "Sign-in methods" instead.
 */
export function LocalCredentialsCard({ user, onSaved }: { user: ManagedUser; onSaved: (user: ManagedUser) => void }) {
  const [username, setUsername] = React.useState(user.username);
  const [currentPassword, setCurrentPassword] = React.useState('');
  const [newPassword, setNewPassword] = React.useState('');
  const [confirmPassword, setConfirmPassword] = React.useState('');
  const [isSaving, setIsSaving] = React.useState(false);
  const [saveError, setSaveError] = React.useState<string | null>(null);
  const [saveNotice, setSaveNotice] = React.useState<string | null>(null);

  React.useEffect(() => setUsername(user.username), [user.username]);

  const usernameChanged = username.trim() !== user.username;
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
      onSaved(payload.user);
      // The header reads the cached copy, so keep it in step with the change.
      persistAuthSession({ id: payload.user.id, username: payload.user.username, role: payload.user.role });
      setSaveNotice(
        wantsPasswordChange ? 'Account updated. Other devices signed in as you have been signed out.' : 'Account updated.'
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

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <KeyRound className="h-5 w-5 text-primary" />
          Username and password
        </CardTitle>
        <CardDescription>Your current password is required for any change.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="profile-username">Username</Label>
          <Input id="profile-username" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" disabled={isSaving} />
        </div>
        <div className="space-y-2">
          <Label htmlFor="profile-current-password">Current password</Label>
          <Input id="profile-current-password" type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} autoComplete="current-password" disabled={isSaving} />
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2">
            <Label htmlFor="profile-new-password">New password</Label>
            <Input
              id="profile-new-password"
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="Leave blank to keep it"
              autoComplete="new-password"
              disabled={isSaving}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="profile-confirm-password">Confirm new password</Label>
            <Input
              id="profile-confirm-password"
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              autoComplete="new-password"
              disabled={isSaving || !wantsPasswordChange}
            />
          </div>
        </div>
        {wantsPasswordChange && confirmPassword && newPassword !== confirmPassword && (
          <p className="text-xs text-destructive">The two passwords do not match.</p>
        )}
        {wantsPasswordChange && newPassword.length < 12 && (
          <p className="text-xs text-muted-foreground">Passwords must be at least 12 characters.</p>
        )}
        {saveError && (
          <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
            <span>{saveError}</span>
          </div>
        )}
        {saveNotice && !saveError && (
          <div className="flex items-start gap-2 rounded-md border border-border bg-muted/40 p-3 text-sm">
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{saveNotice}</span>
          </div>
        )}
        <Button onClick={handleSave} disabled={!canSave}>
          {isSaving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          Save changes
        </Button>
      </CardContent>
    </Card>
  );
}
