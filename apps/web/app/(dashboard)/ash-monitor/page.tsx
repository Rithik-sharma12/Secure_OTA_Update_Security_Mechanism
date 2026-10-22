'use client';

import React from 'react';
import Link from 'next/link';
import { Activity, AlertTriangle, Download, ShieldAlert } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { EmptyState, SkeletonRows } from '@/components/ui/empty-state';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { formatUtcDateTime } from '@/lib/formatters';
import { useRuntimeSnapshot } from '@/lib/runtime-data';
import { downloadRuntimePayload, executeRuntimeAction, type RuntimeDownloadPayload } from '@/lib/runtime-actions';
import { StatGrid, StatTile } from '@/components/ui/stat-tile';

/**
 * At or below this ASH score the gateway refuses to deploy to a device
 * (QUARANTINE_ASH_THRESHOLD in apps/gateway/gateway/deployment.py).
 */
const QUARANTINE_ASH_THRESHOLD = 40;

function scoreClass(score: number) {
  if (score <= QUARANTINE_ASH_THRESHOLD) return 'text-chart-4';
  if (score <= 60) return 'text-chart-3';
  return 'text-chart-1';
}

/** Alert lines are stored as "[<iso time>] message". */
function parseAlert(line: string) {
  const match = /^\[([^\]]+)\]\s*(.*)$/.exec(line);
  const at = match ? new Date(match[1]) : null;
  return { at: at && !Number.isNaN(at.getTime()) ? at : null, message: match ? match[2] : line };
}

export default function ASHMonitorPage() {
  const { snapshot, isLoading } = useRuntimeSnapshot();
  const [busy, setBusy] = React.useState(false);
  const [message, setMessage] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  // Raw scores from the gateway's ash_devices list, keyed by device id.
  const rawScores = React.useMemo(
    () => new Map(snapshot.ashDevices.map((entry) => [entry.id, entry.score])),
    [snapshot.ashDevices]
  );

  const rows = snapshot.devices
    .map((device) => ({ device, score: rawScores.get(device.id) ?? device.ash }))
    .sort((left, right) => left.score - right.score);

  const fleetAverage = rows.length > 0 ? rows.reduce((sum, row) => sum + row.score, 0) / rows.length : null;
  const quarantined = rows.filter((row) => row.score <= QUARANTINE_ASH_THRESHOLD).length;
  const alerts = snapshot.alerts.slice(0, 20).map(parseAlert);

  const handleExport = async () => {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const response = await executeRuntimeAction<RuntimeDownloadPayload>('reports.export', { dataset: 'devices', format: 'CSV' });
      if (response.data) downloadRuntimePayload(response.data);
      setMessage(response.message || 'Export downloaded.');
    } catch (exportError) {
      setError(exportError instanceof Error ? exportError.message : 'Export failed.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="rounded-lg bg-accent/20 p-3 text-accent">
            <Activity className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-foreground">ASH Monitor</h1>
            <p className="mt-1 text-foreground/70">
              Adaptive security health score each device reports with its heartbeat. At {QUARANTINE_ASH_THRESHOLD} or below the gateway will not deploy to it.
            </p>
          </div>
        </div>
        <Button variant="outline" onClick={() => void handleExport()} disabled={busy || rows.length === 0}>
          <Download className="mr-2 h-4 w-4" />
          {busy ? 'Exporting...' : 'Export devices CSV'}
        </Button>
      </div>
      {!snapshot.connection.reachable && snapshot.connection.error && (
        <p className="text-sm text-chart-4">{snapshot.connection.error}</p>
      )}
      {error && <p className="text-sm text-chart-4">{error}</p>}
      {message && !error && <p className="text-sm text-chart-1">{message}</p>}

      <StatGrid columns={3}>
        <StatTile
          label="Fleet average ASH"
          value={fleetAverage === null ? 'No data' : fleetAverage.toFixed(0)}
          suffix={fleetAverage === null ? undefined : 'of 100'}
          tone={fleetAverage === null ? 'neutral' : fleetAverage <= QUARANTINE_ASH_THRESHOLD ? 'bad' : fleetAverage < 70 ? 'warn' : 'good'}
          hint="Mean health score of reporting boards"
        />
        <StatTile
          label="Quarantined"
          value={quarantined}
          tone={quarantined > 0 ? 'bad' : 'neutral'}
          hint={`ASH ${QUARANTINE_ASH_THRESHOLD} or below; updates are held`}
        />
        <StatTile label="Devices reporting" value={rows.length} hint="Sent a health score" />
      </StatGrid>

      <Card>
        <CardHeader>
          <CardTitle>Devices</CardTitle>
          <CardDescription>Lowest score first. Values are the last heartbeat each device sent.</CardDescription>
        </CardHeader>
        <CardContent>
          {rows.length === 0 ? (
            isLoading ? (
              <SkeletonRows rows={4} columns={6} />
            ) : (
              <EmptyState
                icon={<Activity className="h-5 w-5" />}
                title="No devices have checked in yet."
                action={
                  <Button asChild variant="outline">
                    <Link href="/devices">Set up a device</Link>
                  </Button>
                }
              >
                ASH scores appear here once a board sends its first heartbeat.
              </EmptyState>
            )
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Device</TableHead>
                  <TableHead className="text-right">ASH</TableHead>
                  <TableHead>Reported status</TableHead>
                  <TableHead className="text-right">CPU</TableHead>
                  <TableHead className="text-right">Memory</TableHead>
                  <TableHead className="text-right">Signal</TableHead>
                  <TableHead>Last heartbeat</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map(({ device, score }) => (
                  <TableRow key={device.id}>
                    <TableCell>
                      <Link href={`/devices/${encodeURIComponent(device.id)}`} className="font-medium hover:underline">
                        {device.name}
                      </Link>
                      {score <= QUARANTINE_ASH_THRESHOLD && (
                        <Badge variant="destructive" className="ml-2">Quarantined</Badge>
                      )}
                    </TableCell>
                    <TableCell className={`text-right font-semibold tabular-nums ${scoreClass(score)}`}>{score}</TableCell>
                    <TableCell>{device.reportedStatus || 'Not reported'}</TableCell>
                    <TableCell className="text-right tabular-nums">{device.cpuUsage.toFixed(1)}%</TableCell>
                    <TableCell className="text-right tabular-nums">{device.memoryUsage.toFixed(1)}%</TableCell>
                    <TableCell className="text-right tabular-nums">
                      {device.signalStrength !== undefined ? `${device.signalStrength} dBm` : 'Not reported'}
                    </TableCell>
                    <TableCell className="whitespace-nowrap">
                      {device.lastSync ? `${formatUtcDateTime(device.lastSync)} UTC` : 'Never'}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Gateway alerts</CardTitle>
          <CardDescription>Newest first, as the gateway recorded them.</CardDescription>
        </CardHeader>
        <CardContent>
          {alerts.length === 0 ? (
            <EmptyState compact icon={<ShieldAlert className="h-5 w-5" />} title="No alerts have been raised." />
          ) : (
            <div className="space-y-2">
              {alerts.map((alert, index) => (
                <div key={`${index}-${alert.message}`} className="flex items-start gap-3 rounded-lg border border-border/20 p-3">
                  <AlertTriangle className="mt-0.5 h-4 w-4 text-chart-3" />
                  <div className="min-w-0 flex-1">
                    <p className="text-sm text-foreground">{alert.message}</p>
                    {alert.at && <p className="mt-1 text-xs text-foreground/50">{formatUtcDateTime(alert.at)} UTC</p>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
