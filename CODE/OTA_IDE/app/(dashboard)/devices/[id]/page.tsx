'use client';

import React from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { ArrowLeft, Loader2, Power, RefreshCw, Rocket, Sun } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { TelemetryCharts } from '@/components/devices/TelemetryCharts';
import {
  type AuditEntry,
  type DeviceCommandType,
  type DeviceDetail,
  type TelemetrySeries,
  deployToDevices,
  getAudit,
  getDeviceDetail,
  getTelemetry,
  queueDeviceCommand,
} from '@/lib/device-control';
import { subscribeToGatewayChanges } from '@/lib/live-updates';
import { useCurrentUser } from '@/lib/use-current-user';

const RANGES = [
  { label: '1 h', hours: 1 },
  { label: '6 h', hours: 6 },
  { label: '24 h', hours: 24 },
  { label: '7 d', hours: 168 },
];

const PHASE_ORDER = ['downloading', 'rebooting', 'health_check', 'succeeded'];

function when(iso?: string | null) {
  return iso ? new Date(iso).toLocaleString() : '—';
}

export default function DeviceDetailPage() {
  const params = useParams<{ id: string }>();
  const deviceId = decodeURIComponent(params.id);
  const { can, reasonFor } = useCurrentUser();
  const mayControl = can('devices.control');
  const mayDeploy = can('devices.flash');

  const [detail, setDetail] = React.useState<DeviceDetail | null>(null);
  const [telemetry, setTelemetry] = React.useState<TelemetrySeries | null>(null);
  const [audit, setAudit] = React.useState<AuditEntry[] | null>(null);
  const [hours, setHours] = React.useState(24);
  const [error, setError] = React.useState<string | null>(null);
  const [message, setMessage] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState<string | null>(null);

  const load = React.useCallback(async () => {
    try {
      const [nextDetail, nextTelemetry] = await Promise.all([getDeviceDetail(deviceId), getTelemetry(deviceId, hours)]);
      setDetail(nextDetail);
      setTelemetry(nextTelemetry);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
    // Audit is operator-only; a viewer simply does not get that card.
    getAudit({ deviceId, limit: 20 })
      .then((result) => setAudit(result.entries))
      .catch(() => setAudit(null));
  }, [deviceId, hours]);

  React.useEffect(() => {
    void load();
    return subscribeToGatewayChanges(() => void load());
  }, [load]);

  const run = async (label: string, action: () => Promise<string>) => {
    setBusy(label);
    setError(null);
    setMessage(null);
    try {
      setMessage(await action());
      void load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const command = (type: DeviceCommandType, label: string) =>
    run(label, async () => {
      await queueDeviceCommand(deviceId, type);
      return `${label} queued; delivered with the next heartbeat (about 15 s).`;
    });

  const deployLatest = () =>
    run('deploy', async () => {
      const deployment = await deployToDevices([deviceId]);
      const target = deployment.targets[deviceId];
      if (target?.state === 'failed') throw new Error(target.reason || 'The gateway refused this deployment.');
      return target?.state === 'confirmed'
        ? `Already running v${deployment.version}.`
        : `v${deployment.version} assigned. Progress appears below as the device reports it.`;
    });

  const device = detail?.device;
  const ota = device?.ota;
  const otaActive = ota && !['succeeded', 'failed', 'rolled_back'].includes(ota.phase);
  const phaseIndex = ota ? PHASE_ORDER.indexOf(ota.phase) : -1;
  const progressValue = ota?.phase === 'downloading' ? ota.progress ?? 0 : phaseIndex >= 0 ? ((phaseIndex + 1) / PHASE_ORDER.length) * 100 : 0;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <Link href="/devices" className="mb-2 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
            <ArrowLeft className="h-4 w-4" /> Devices
          </Link>
          <h1 className="text-3xl font-bold text-foreground font-mono">{deviceId}</h1>
          <p className="mt-1 text-foreground/70">
            {device ? `${device.arch ?? 'ESP32'} · firmware v${device.fw ?? '?'} · ${device.status ?? 'unknown'} · last seen ${when(device.last_seen)}` : 'Loading…'}
          </p>
          {device && (
            <div className="mt-2 flex flex-wrap gap-2">
              <Badge variant="outline">{detail?.credentials.registered ? (detail.credentials.revoked ? 'Token revoked' : 'Own device token') : 'Fleet key'}</Badge>
              {device.ip && <Badge variant="outline">IP {device.ip}</Badge>}
              {typeof device.ash === 'number' && <Badge variant="outline">ASH {device.ash}</Badge>}
              {device.rollbackPending && <Badge variant="outline" className="text-chart-3">Health check pending</Badge>}
            </div>
          )}
        </div>
        <div className="flex flex-wrap gap-2">
          <Button onClick={deployLatest} disabled={!mayDeploy || Boolean(busy)} title={mayDeploy ? undefined : reasonFor('devices.flash')}>
            {busy === 'deploy' ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Rocket className="mr-2 h-4 w-4" />}
            Deploy latest
          </Button>
          <Button variant="outline" onClick={() => command('check_update', 'Update check')} disabled={!mayControl || Boolean(busy)}>
            <RefreshCw className="mr-2 h-4 w-4" /> Check update
          </Button>
          <Button variant="outline" onClick={() => command('identify', 'Identify')} disabled={!mayControl || Boolean(busy)}>
            <Sun className="mr-2 h-4 w-4" /> Identify
          </Button>
          <Button variant="outline" onClick={() => command('reboot', 'Restart')} disabled={!mayControl || Boolean(busy)}>
            <Power className="mr-2 h-4 w-4" /> Restart
          </Button>
        </div>
      </div>

      {error && <p className="text-sm text-chart-4">{error}</p>}
      {message && !error && <p className="text-sm text-chart-1">{message}</p>}

      <Card>
        <CardHeader>
          <CardTitle>Over-the-air update</CardTitle>
          <CardDescription>Reported by the device itself as it downloads, verifies, installs and passes its health check.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {ota ? (
            <>
              <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
                <span>
                  <span className="font-medium capitalize">{ota.phase.replace('_', ' ')}</span> · v{ota.version}
                  {ota.detail ? <span className="text-muted-foreground"> — {ota.detail}</span> : null}
                </span>
                <span className="text-muted-foreground">{when(ota.at)}</span>
              </div>
              {(otaActive || ota.phase === 'succeeded') && <Progress value={progressValue} />}
            </>
          ) : (
            <p className="text-sm text-muted-foreground">No update reported yet.</p>
          )}
          {device?.otaHistory && device.otaHistory.length > 0 && (
            <ol className="space-y-1 text-xs text-muted-foreground">
              {[...device.otaHistory].reverse().slice(0, 12).map((entry) => (
                <li key={`${entry.at}-${entry.phase}`} className="flex justify-between gap-4">
                  <span>
                    <span className={entry.phase === 'failed' || entry.phase === 'rolled_back' ? 'text-chart-4' : 'text-foreground/80'}>
                      {entry.phase.replace('_', ' ')}
                    </span>{' '}
                    v{entry.version}
                    {entry.detail ? ` — ${entry.detail}` : ''}
                  </span>
                  <span>{when(entry.at)}</span>
                </li>
              ))}
            </ol>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2 space-y-0">
          <div>
            <CardTitle>Telemetry history</CardTitle>
            <CardDescription>
              {telemetry
                ? `${telemetry.rawSamples} heartbeats, averaged into ${Math.round(telemetry.bucketSeconds / 60) || 1}-minute points. Kept for ${telemetry.retentionDays} days.`
                : 'Loading…'}
            </CardDescription>
          </div>
          <div className="flex gap-1" role="group" aria-label="Time range">
            {RANGES.map((range) => (
              <Button
                key={range.hours}
                size="sm"
                variant={hours === range.hours ? 'default' : 'outline'}
                onClick={() => setHours(range.hours)}
                aria-pressed={hours === range.hours}
              >
                {range.label}
              </Button>
            ))}
          </div>
        </CardHeader>
        <CardContent>{telemetry && <TelemetryCharts points={telemetry.points} hours={hours} />}</CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Commands</CardTitle>
            <CardDescription>Sent from the dashboard, delivered in heartbeat responses.</CardDescription>
          </CardHeader>
          <CardContent>
            {detail && detail.commands.length > 0 ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Command</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Result</TableHead>
                    <TableHead>Queued</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {detail.commands.slice(0, 15).map((entry) => (
                    <TableRow key={entry.id}>
                      <TableCell className="font-mono text-xs">{entry.type}</TableCell>
                      <TableCell className={entry.status === 'failed' || entry.status === 'expired' ? 'text-chart-4' : ''}>{entry.status}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{entry.result || '—'}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{when(entry.createdAt)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <p className="text-sm text-muted-foreground">No commands sent to this device.</p>
            )}
          </CardContent>
        </Card>

        {audit && (
          <Card>
            <CardHeader>
              <CardTitle>Audit</CardTitle>
              <CardDescription>Who changed this device, from where.</CardDescription>
            </CardHeader>
            <CardContent>
              {audit.length > 0 ? (
                <ul className="space-y-2 text-sm">
                  {audit.map((entry) => (
                    <li key={entry.id} className="flex flex-wrap justify-between gap-2 border-b border-border/40 pb-2 last:border-0">
                      <span>
                        <span className="font-medium">{entry.action || `${entry.method} ${entry.path}`}</span>
                        <span className="text-muted-foreground"> by {entry.actor}</span>
                        {entry.status >= 400 && <span className="text-chart-4"> · HTTP {entry.status}</span>}
                      </span>
                      <span className="text-xs text-muted-foreground">{when(entry.timestamp)}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-muted-foreground">No recorded changes.</p>
              )}
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
