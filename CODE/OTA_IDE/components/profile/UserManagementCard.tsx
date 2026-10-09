'use client';

import React from 'react';
import { AlertCircle, CheckCircle2, Loader2, Pencil, Trash2, UserPlus, Users } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { apiFetch } from '@/lib/client-auth';
import { formatUtcDateTime } from '@/lib/formatters';
import type { ManagedUser, UserRole } from '@/lib/profile-types';
import { USER_ROLE_OPTIONS } from '@/lib/profile-types';

type Draft = {
  username: string;
  password: string;
  role: UserRole;
  isActive: boolean;
};

const emptyDraft: Draft = { username: '', password: '', role: 'viewer', isActive: true };

function roleBadgeClass(role: UserRole) {
  if (role === 'admin') return 'bg-chart-4/20 text-chart-4';
  if (role === 'operator') return 'bg-chart-2/20 text-chart-2';
  return 'bg-muted text-muted-foreground';
}

async function readError(response: Response, fallback: string) {
  try {
    const payload = (await response.json()) as { error?: string };
    return payload?.error || fallback;
  } catch {
    return fallback;
  }
}

/**
 * Admin-only user CRUD.
 *
 * The server enforces every rule here a second time (role, self-lockout,
 * last-admin), so this component's job is to explain the rules rather than
 * be the thing that applies them — a disabled button is a courtesy, not a
 * control.
 */
export function UserManagementCard({ currentUserId }: { currentUserId: string }) {
  const [users, setUsers] = React.useState<ManagedUser[]>([]);
  const [isLoading, setIsLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [notice, setNotice] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);

  const [createOpen, setCreateOpen] = React.useState(false);
  const [createDraft, setCreateDraft] = React.useState<Draft>(emptyDraft);

  const [editTarget, setEditTarget] = React.useState<ManagedUser | null>(null);
  const [editDraft, setEditDraft] = React.useState<Draft>(emptyDraft);

  const [deleteTarget, setDeleteTarget] = React.useState<ManagedUser | null>(null);

  const activeAdminCount = users.filter((user) => user.role === 'admin' && user.isActive).length;

  const loadUsers = React.useCallback(async () => {
    try {
      const response = await apiFetch('/api/users', { cache: 'no-store' });
      if (!response.ok) {
        setError(await readError(response, `Could not load users (${response.status}).`));
        return;
      }

      const payload = (await response.json()) as { users?: ManagedUser[] };
      setUsers(payload.users || []);
      setError(null);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : 'Could not load users.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void loadUsers();
  }, [loadUsers]);

  const runMutation = async (
    action: () => Promise<Response>,
    successMessage: string,
    onDone: () => void
  ) => {
    setBusy(true);
    setError(null);
    setNotice(null);

    try {
      const response = await action();
      if (!response.ok) {
        setError(await readError(response, `Request failed (${response.status}).`));
        return;
      }

      setNotice(successMessage);
      onDone();
      await loadUsers();
    } catch (mutationError) {
      setError(mutationError instanceof Error ? mutationError.message : 'Request failed.');
    } finally {
      setBusy(false);
    }
  };

  const handleCreate = () =>
    runMutation(
      () =>
        apiFetch('/api/users', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(createDraft),
        }),
      `User "${createDraft.username}" created.`,
      () => {
        setCreateOpen(false);
        setCreateDraft(emptyDraft);
      }
    );

  const handleEdit = () => {
    if (!editTarget) return;

    // Only send the password when one was typed; an empty box means "leave it".
    const body: Record<string, unknown> = {
      username: editDraft.username,
      role: editDraft.role,
      isActive: editDraft.isActive,
    };
    if (editDraft.password) {
      body.password = editDraft.password;
    }

    return runMutation(
      () =>
        apiFetch(`/api/users/${encodeURIComponent(editTarget.id)}`, {
          method: 'PATCH',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(body),
        }),
      `User "${editDraft.username}" updated.`,
      () => setEditTarget(null)
    );
  };

  const handleDelete = () => {
    if (!deleteTarget) return;

    return runMutation(
      () => apiFetch(`/api/users/${encodeURIComponent(deleteTarget.id)}`, { method: 'DELETE' }),
      `User "${deleteTarget.username}" deleted.`,
      () => setDeleteTarget(null)
    );
  };

  const openEdit = (user: ManagedUser) => {
    setEditTarget(user);
    setEditDraft({ username: user.username, password: '', role: user.role, isActive: user.isActive });
  };

  // Why a row's destructive actions are unavailable, or null when they are fine.
  const lockReason = (user: ManagedUser) => {
    if (user.id === currentUserId) return 'You cannot delete or deactivate your own account.';
    if (user.role === 'admin' && user.isActive && activeAdminCount <= 1) {
      return 'This is the last active admin. Promote another admin first.';
    }
    return null;
  };

  const roleField = (draft: Draft, setDraft: (next: Draft) => void, idPrefix: string) => (
    <div className="space-y-2">
      <Label>Role</Label>
      <div className="flex flex-wrap gap-2">
        {USER_ROLE_OPTIONS.map((option) => (
          <button
            key={option.value}
            id={`${idPrefix}-role-${option.value}`}
            type="button"
            onClick={() => setDraft({ ...draft, role: option.value })}
            aria-pressed={draft.role === option.value}
            title={option.description}
            className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
              draft.role === option.value
                ? 'border-primary bg-primary/15 text-primary'
                : 'border-border text-muted-foreground hover:border-primary/40'
            }`}
          >
            {option.label}
          </button>
        ))}
      </div>
      <p className="text-xs text-muted-foreground">
        {USER_ROLE_OPTIONS.find((option) => option.value === draft.role)?.description}
      </p>
    </div>
  );

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Users className="h-5 w-5 text-primary" />
              User management
            </CardTitle>
            <CardDescription>
              Create, edit and remove dashboard accounts. Admin only — every action here is re-checked
              on the server.
            </CardDescription>
          </div>
          <Button
            onClick={() => {
              setCreateDraft(emptyDraft);
              setCreateOpen(true);
            }}
            disabled={busy}
          >
            <UserPlus className="mr-2 h-4 w-4" />
            Add user
          </Button>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {error && (
          <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
            <span>{error}</span>
          </div>
        )}
        {notice && !error && (
          <div className="flex items-start gap-2 rounded-md border border-chart-1/40 bg-chart-1/10 p-3 text-sm">
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-chart-1" />
            <span>{notice}</span>
          </div>
        )}

        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Username</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Last login</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {users.map((user) => {
                const locked = lockReason(user);
                return (
                  <TableRow key={user.id}>
                    <TableCell className="font-medium">
                      {user.username}
                      {user.id === currentUserId && (
                        <span className="ml-2 text-xs text-muted-foreground">(you)</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge className={roleBadgeClass(user.role)}>{user.role}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge className={user.isActive ? 'bg-chart-1/20 text-chart-1' : 'bg-muted text-muted-foreground'}>
                        {user.isActive ? 'active' : 'disabled'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {user.lastLoginAt ? formatUtcDateTime(user.lastLoginAt) : 'never'}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {user.createdAt ? formatUtcDateTime(user.createdAt) : '—'}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button variant="ghost" size="icon" onClick={() => openEdit(user)} disabled={busy} title="Edit user">
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => setDeleteTarget(user)}
                          disabled={busy || Boolean(locked)}
                          title={locked || `Delete ${user.username}`}
                        >
                          <Trash2 className="h-4 w-4 text-destructive" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
              {!isLoading && users.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-sm text-muted-foreground">
                    No accounts yet.
                  </TableCell>
                </TableRow>
              )}
              {isLoading && (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-sm text-muted-foreground">
                    Loading accounts…
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      </CardContent>

      {/* Create */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add user</DialogTitle>
            <DialogDescription>
              The account can sign in immediately. Passwords must be at least 12 characters.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="create-username">Username</Label>
              <Input
                id="create-username"
                value={createDraft.username}
                onChange={(event) => setCreateDraft({ ...createDraft, username: event.target.value })}
                placeholder="e.g. lab_operator"
                autoComplete="off"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="create-password">Password</Label>
              <Input
                id="create-password"
                type="password"
                value={createDraft.password}
                onChange={(event) => setCreateDraft({ ...createDraft, password: event.target.value })}
                autoComplete="new-password"
              />
            </div>
            {roleField(createDraft, setCreateDraft, 'create')}
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={createDraft.isActive}
                onChange={(event) => setCreateDraft({ ...createDraft, isActive: event.target.checked })}
                className="h-4 w-4 accent-primary"
              />
              Active (can sign in)
            </label>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)} disabled={busy}>
              Cancel
            </Button>
            <Button onClick={handleCreate} disabled={busy || !createDraft.username || !createDraft.password}>
              {busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Create user
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit */}
      <Dialog open={Boolean(editTarget)} onOpenChange={(open) => !open && setEditTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit {editTarget?.username}</DialogTitle>
            <DialogDescription>
              Changing a role, or setting a new password, signs this account out of every device.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="edit-username">Username</Label>
              <Input
                id="edit-username"
                value={editDraft.username}
                onChange={(event) => setEditDraft({ ...editDraft, username: event.target.value })}
                autoComplete="off"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-password">New password</Label>
              <Input
                id="edit-password"
                type="password"
                value={editDraft.password}
                onChange={(event) => setEditDraft({ ...editDraft, password: event.target.value })}
                placeholder="Leave blank to keep the current password"
                autoComplete="new-password"
              />
            </div>
            {roleField(editDraft, setEditDraft, 'edit')}
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={editDraft.isActive}
                onChange={(event) => setEditDraft({ ...editDraft, isActive: event.target.checked })}
                className="h-4 w-4 accent-primary"
                disabled={editTarget?.id === currentUserId}
              />
              Active (can sign in)
            </label>
            {editTarget && lockReason(editTarget) && (
              <p className="text-xs text-chart-4">{lockReason(editTarget)}</p>
            )}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setEditTarget(null)} disabled={busy}>
              Cancel
            </Button>
            <Button onClick={handleEdit} disabled={busy || !editDraft.username}>
              {busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Save changes
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete */}
      <AlertDialog open={Boolean(deleteTarget)} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete {deleteTarget?.username}?</AlertDialogTitle>
            <AlertDialogDescription>
              The account and all of its sessions are removed immediately. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleDelete} disabled={busy}>
              {busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
}
