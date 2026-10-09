'use client';

import React from 'react';
import Link from 'next/link';
import { Ban, Loader2, RotateCcw, Rocket } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { PermissionNotice } from '@/components/auth/PermissionNotice';
import {
  type FleetDeployment,
  cancelDeployment,
  deployToDevices,
  listDeployments,
  retryDeployment,
} from '@/lib/device-control';
import { subscribeToGatewayChanges } from '@/lib/live-updates';
import { useRuntimeSnapshot } from '@/lib/runtime-data';
import { useCurrentUser } from '@/lib/use-current-user';

const STATUS_STYLE: Record<string, string> = {
  in_progress: 'bg-chart-3/20 text-chart-3',
  success: 'bg-chart-1/20 text-chart-1',
  partial: 'bg-chart-3/20 text-chart-3',
  failed: 'bg-chart-4/20 text-chart-4',
  cancelled: 'bg-muted text-muted-foreground',
};

/** Rough progress of one target from what its device has reported. */
function targetProgress(state: string, phase?: string, progress?: number | null) {
  if (state === 'confirmed') return 100;
  if (state !== 'pending') return 0;
  switch (phase) {
    case 'downloading':
      return 10 + Math.round((progress ?? 0) * 0.6);
    case 'verifying':
    case 'installing':
      return 75;
    case 'rebooting':
    case 'health_check':
      return 90;
    default:
      return 2;
  }
}

export default function DeploymentsPage() {
  const { snapshot } = useRuntimeSnapshot();
  const { can } = useCurrentUser();
  const mayDeploy = can('devices.flash');

  const [deployments, setDeployments] = React.useState<FleetDeployment[]>([]);
  const [releaseId, setReleaseId] = React.useState('');
  const [selected, setSelected] = React.useState<Set<string>>(new Set());
  const [busy, setBusy] = React.useState<string | null>(null);
  const [message, setMessage] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  const published = snapshot.releases.filter((release) => release.status === 'published');
  const release = published.find((entry) => entry.id === releaseId) ?? published[0];

  const compatible = (deviceType: string) =>
    !release || release.compatible.length === 0 || release.compatible.includes(deviceType as never);

  const load = React.useCallback(async () => {
    try {
      setDeployments(await listDeployments());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  React.useEffect(() => {
    void load();
    return subscribeToGatewayChanges(() => void load());
  }, [load]);

  const toggle = (id: string) =>
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const selectAllCompatible = () =>
    setSelected(new Set(snapshot.devices.filter((device) => compatible(device.type)).map((device) => device.id)));

  const act = async (key: string, action: () => Promise<string>) => {
    setBusy(key);
    setError(null);
    setMessage(null);
    try {
      setMessage(await action());
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const deploy = () =>
    act('deploy', async () => {
      if (!release) throw new Error('Publish a release first.');
      const ids = [...selected];
      if (ids.length === 0) throw new Error('Select at least one device.');
      const deployment = await deployToDevices(ids, release.id);
      setSelected(new Set());
      return (
        `v${deployment.version} assigned to ${ids.length} device(s): ${deployment.pendingCount} starting within ~15 s, ` +
        `${deployment.successCount} already current, ${deployment.failureCount} refused (see reasons below).`
      );
    });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-foreground">Fleet deployments</h1>
        <p className="mt-1 text-foreground/70">
          Roll a release out to many boards at once and watch each one download, install and confirm. Boards are reached
          over the internet through their heartbeats; nothing needs to be on your network.
        </p>
      </div>

      {error && <p className="text-sm text-chart-4">{error}</p>}
      {message && !error && <p className="text-sm text-chart-1">{message}</p>}

      <Card>
        <CardHeader>
          <CardTitle>New deployment</CardTitle>
          <CardDescription>
            The gateway refuses wrong-architecture boards, quarantined boards and downgrades per device, and tells you why.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {!mayDeploy && <PermissionNotice capability="devices.flash" action="Deploying firmware" />}
          <div className="flex flex-wrap items-end gap-3">
            <label className="space-y-1 text-sm">
              <span className="block text-muted-foreground">Release</span>
              <select
                className="h-9 min-w-56 rounded-md border border-border bg-background px-2"
                value={release?.id ?? ''}
                onChange={(event) => setReleaseId(event.target.value)}
                disabled={published.length === 0}
              >
                {published.length === 0 && <option value="">No published release</option>}
                {published.map((entry) => (
                  <option key={entry.id} value={entry.id}>
                    v{entry.version} · {entry.compatible.join(', ') || 'all boards'}
                  </option>
                ))}
              </select>
            </label>
            <Button variant="outline" onClick={selectAllCompatible} disabled={!release}>
              Select all compatible
            </Button>
            <Button onClick={deploy} disabled={!mayDeploy || !release || selected.size === 0 || Boolean(busy)}>
              {busy === 'deploy' ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Rocket className="mr-2 h-4 w-4" />}
              Deploy to {selected.size} device{selected.size === 1 ? '' : 's'}
            </Button>
          </div>

          <div className="max-h-72 overflow-auto rounded-md border border-border/60">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-10" />
                  <TableHead>Device</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Firmware</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Health</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {snapshot.devices.map((device) => {
                  const fits = compatible(device.type);
                  return (
                    <TableRow key={device.id} className={fits ? '' : 'opacity-50'}>
                      <TableCell>
                        <input
                          type="checkbox"
                          aria-label={`Select ${device.id}`}
                          checked={selected.has(device.id)}
                          onChange={() => toggle(device.id)}
                          disabled={!fits}
                          title={fits ? undefined : `v${release?.version} is not built for ${device.type}`}
                        />
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        <Link href={`/devices/${encodeURIComponent(device.id)}`} className="hover:underline">
                          {device.id}
                        </Link>
                      </TableCell>
                      <TableCell>{device.type}</TableCell>
                      <TableCell>v{device.firmwareVersion}</TableCell>
                      <TableCell className="capitalize">{device.status}</TableCell>
                      <TableCell className="capitalize">{device.health}</TableCell>
                    </TableRow>
                  );
                })}
                {snapshot.devices.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={6} className="py-6 text-center text-sm text-muted-foreground">
                      No devices have checked in yet.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      <div className="space-y-4">
        {deployments.map((deployment) => {
          const targets = Object.entries(deployment.targets);
          const retryable = deployment.failureCount + (deployment.cancelledCount ?? 0);
          return (
            <Card key={deployment.id}>
              <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3 space-y-0">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    v{deployment.version}
                    <Badge variant="outline" className={STATUS_STYLE[deployment.status] ?? ''}>
                      {deployment.status.replace('_', ' ')}
                    </Badge>
                  </CardTitle>
                  <CardDescription>
                    {deployment.id} · started {new Date(deployment.startedAt).toLocaleString()}
                    {deployment.retryOf ? ` · retry of ${deployment.retryOf}` : ''} · {deployment.successCount} confirmed,{' '}
                    {deployment.pendingCount} pending, {deployment.failureCount} failed
                    {deployment.cancelledCount ? `, ${deployment.cancelledCount} cancelled` : ''}
                  </CardDescription>
                </div>
                <div className="flex gap-2">
                  {deployment.pendingCount > 0 && (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={!mayDeploy || Boolean(busy)}
                      onClick={() =>
                        act(`cancel-${deployment.id}`, async () => {
                          const result = await cancelDeployment(deployment.id);
                          return `Cancelled ${result.cancelled} pending target(s) of v${deployment.version}.`;
                        })
                      }
                    >
                      <Ban className="mr-2 h-4 w-4" /> Cancel pending
                    </Button>
                  )}
                  {retryable > 0 && deployment.pendingCount === 0 && (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={!mayDeploy || Boolean(busy)}
                      onClick={() =>
                        act(`retry-${deployment.id}`, async () => {
                          const next = await retryDeployment(deployment.id);
                          return `Retrying ${Object.keys(next.targets).length} device(s) as ${next.id}.`;
                        })
                      }
                    >
                      <RotateCcw className="mr-2 h-4 w-4" /> Retry {retryable} failed
                    </Button>
                  )}
                </div>
              </CardHeader>
              <CardContent className="space-y-2">
                {targets.map(([deviceId, target]) => (
                  <div key={deviceId} className="grid grid-cols-1 items-center gap-2 text-sm md:grid-cols-[minmax(0,14rem)_11rem_1fr]">
                    <Link href={`/devices/${encodeURIComponent(deviceId)}`} className="truncate font-mono text-xs hover:underline">
                      {deviceId}
                    </Link>
                    <span className={target.state === 'failed' ? 'text-chart-4' : target.state === 'confirmed' ? 'text-chart-1' : 'text-foreground/80'}>
                      {target.state}
                      {target.state === 'pending' && target.phase ? ` · ${target.phase.replace('_', ' ')}` : ''}
                    </span>
                    {target.state === 'pending' ? (
                      <Progress value={targetProgress(target.state, target.phase, target.progress)} />
                    ) : (
                      <span className="text-xs text-muted-foreground">{target.reason || (target.state === 'confirmed' ? 'Device reported the new version.' : '')}</span>
                    )}
                  </div>
                ))}
              </CardContent>
            </Card>
          );
        })}
        {deployments.length === 0 && (
          <Card>
            <CardContent className="py-6 text-center text-sm text-muted-foreground">
              No deployments yet. Pick a release and devices above.
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
