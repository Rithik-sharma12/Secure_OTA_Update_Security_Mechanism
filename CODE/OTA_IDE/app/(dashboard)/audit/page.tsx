'use client';

import React from 'react';
import Link from 'next/link';
import { Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { type AuditEntry, getAudit } from '@/lib/device-control';
import { subscribeToGatewayChanges } from '@/lib/live-updates';

const PAGE = 100;

export default function AuditPage() {
  const [entries, setEntries] = React.useState<AuditEntry[]>([]);
  const [nextBefore, setNextBefore] = React.useState<number | null>(null);
  const [actor, setActor] = React.useState('');
  const [deviceId, setDeviceId] = React.useState('');
  const [failuresOnly, setFailuresOnly] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const result = await getAudit({ limit: PAGE, actor: actor.trim() || undefined, deviceId: deviceId.trim() || undefined });
      setEntries(result.entries);
      setNextBefore(result.nextBeforeId);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [actor, deviceId]);

  React.useEffect(() => {
    const timer = window.setTimeout(() => void load(), 250);
    return () => window.clearTimeout(timer);
  }, [load]);

  React.useEffect(() => subscribeToGatewayChanges(() => void load()), [load]);

  const loadMore = async () => {
    if (!nextBefore) return;
    setLoading(true);
    try {
      const result = await getAudit({ limit: PAGE, beforeId: nextBefore, actor: actor.trim() || undefined, deviceId: deviceId.trim() || undefined });
      setEntries((current) => [...current, ...result.entries]);
      setNextBefore(result.nextBeforeId);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const shown = failuresOnly ? entries.filter((entry) => entry.status >= 400) : entries;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-foreground">Audit trail</h1>
        <p className="mt-1 text-foreground/70">
          Every change made through the gateway — releases, deployments, commands, device registration and removal — with
          who made it and from where. Refused requests are kept too: a run of 401s is someone guessing keys.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Filters</CardTitle>
          <CardDescription>Stored on the gateway in SQLite; the newest 50,000 rows are kept.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-3">
          <Input className="w-56" placeholder="Actor contains…" value={actor} onChange={(event) => setActor(event.target.value)} />
          <Input className="w-56" placeholder="Device id" value={deviceId} onChange={(event) => setDeviceId(event.target.value)} />
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={failuresOnly} onChange={(event) => setFailuresOnly(event.target.checked)} />
            Refused requests only
          </label>
          {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
        </CardContent>
      </Card>

      {error && <p className="text-sm text-chart-4">{error}</p>}

      <Card>
        <CardContent className="pt-6">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>When</TableHead>
                <TableHead>Who</TableHead>
                <TableHead>What</TableHead>
                <TableHead>Device</TableHead>
                <TableHead>Result</TableHead>
                <TableHead>From</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {shown.map((entry) => (
                <TableRow key={entry.id}>
                  <TableCell className="whitespace-nowrap text-xs text-muted-foreground">{new Date(entry.timestamp).toLocaleString()}</TableCell>
                  <TableCell className="text-sm">{entry.actor}</TableCell>
                  <TableCell className="text-sm">
                    <div className="font-medium">{entry.action || `${entry.method} ${entry.path}`}</div>
                    {entry.detail && <div className="text-xs text-muted-foreground">{entry.detail}</div>}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {entry.deviceId ? (
                      <Link href={`/devices/${encodeURIComponent(entry.deviceId)}`} className="hover:underline">
                        {entry.deviceId}
                      </Link>
                    ) : (
                      '—'
                    )}
                  </TableCell>
                  <TableCell className={entry.status >= 400 ? 'text-chart-4' : 'text-foreground/80'}>HTTP {entry.status}</TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">{entry.sourceIp || '—'}</TableCell>
                </TableRow>
              ))}
              {shown.length === 0 && !loading && (
                <TableRow>
                  <TableCell colSpan={6} className="py-6 text-center text-sm text-muted-foreground">
                    Nothing recorded for these filters.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
          {nextBefore && (
            <div className="mt-4 flex justify-center">
              <Button variant="outline" onClick={loadMore} disabled={loading}>
                Load older entries
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
