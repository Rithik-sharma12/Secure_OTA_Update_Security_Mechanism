'use client';

import React from 'react';
import { AlertTriangle, Bug, CheckCircle, CircleSlash, RefreshCw, XCircle } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { SkeletonRows } from '@/components/ui/empty-state';
import { apiFetch } from '@/lib/client-auth';
import { formatUtcDateTime } from '@/lib/formatters';

type CheckStatus = 'ok' | 'warning' | 'error' | 'off';
type Check = { id: string; name: string; status: CheckStatus; detail: string; latencyMs?: number };
type DiagnosticsResult = {
  checkedAt: string;
  gatewayUrl: string;
  checks: Check[];
  hostStats: { ip: string; temp: string; load: string } | null;
};

const STATUS_LABEL: Record<CheckStatus, string> = { ok: 'OK', warning: 'Warning', error: 'Failing', off: 'Not configured' };

function StatusIcon({ status }: { status: CheckStatus }) {
  if (status === 'ok') return <CheckCircle className="h-4 w-4 text-chart-1" />;
  if (status === 'warning') return <AlertTriangle className="h-4 w-4 text-chart-3" />;
  if (status === 'error') return <XCircle className="h-4 w-4 text-chart-4" />;
  return <CircleSlash className="h-4 w-4 text-muted-foreground" />;
}

export default function DiagnosticsPage() {
  const [result, setResult] = React.useState<DiagnosticsResult | null>(null);
  const [running, setRunning] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const runChecks = React.useCallback(async () => {
    setRunning(true);
    setError(null);
    try {
      const response = await apiFetch('/api/health/diagnostics', { cache: 'no-store' });
      const body = (await response.json().catch(() => null)) as (DiagnosticsResult & { ok?: boolean; error?: string }) | null;
      if (!response.ok || !body?.ok) throw new Error(body?.error || `Diagnostics returned ${response.status}.`);
      setResult(body);
    } catch (checkError) {
      setError(checkError instanceof Error ? checkError.message : 'Diagnostics failed.');
    } finally {
      setRunning(false);
    }
  }, []);

  React.useEffect(() => {
    void runChecks();
  }, [runChecks]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="rounded-lg bg-primary/20 p-3 text-primary">
            <Bug className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-foreground">Diagnostics</h1>
            <p className="mt-1 text-foreground/70">Live checks of what this console depends on, run from its server.</p>
          </div>
        </div>
        <Button onClick={() => void runChecks()} disabled={running}>
          <RefreshCw className={`mr-2 h-4 w-4 ${running ? 'animate-spin' : ''}`} />
          {running ? 'Checking...' : 'Run checks again'}
        </Button>
      </div>
      {error && <p className="text-sm text-chart-4">{error}</p>}

      <Card>
        <CardHeader>
          <CardTitle>Checks</CardTitle>
          <CardDescription>
            {result ? `Last run ${formatUtcDateTime(result.checkedAt)} UTC.` : 'Running checks...'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {!result ? (
            <SkeletonRows rows={5} columns={3} />
          ) : (
            <div className="space-y-3">
              {result.checks.map((check) => (
                <div key={check.id} className="flex items-start justify-between gap-3 rounded-lg border border-border/40 p-3">
                  <div className="flex items-start gap-3">
                    <span className="mt-0.5"><StatusIcon status={check.status} /></span>
                    <div>
                      <p className="text-sm font-medium text-foreground">{check.name}</p>
                      <p className="text-xs text-foreground/60">{check.detail}</p>
                    </div>
                  </div>
                  <div className="flex shrink-0 flex-col items-end gap-1">
                    <Badge variant="outline">{STATUS_LABEL[check.status]}</Badge>
                    {check.latencyMs !== undefined && (
                      <span className="text-xs tabular-nums text-foreground/50">{check.latencyMs} ms</span>
                    )}
                  </div>
                </div>
              ))}
              <p className="text-xs text-muted-foreground">
                The local USB agent runs on your own computer, so it is checked from the Devices page in your browser, not here.
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Gateway host</CardTitle>
          <CardDescription>What the gateway reports about the machine it runs on.</CardDescription>
        </CardHeader>
        <CardContent>
          {result?.hostStats ? (
            <dl className="grid grid-cols-1 gap-4 text-sm sm:grid-cols-3">
              <div>
                <dt className="text-xs text-foreground/50">Address</dt>
                <dd className="font-mono">{result.hostStats.ip || 'Not reported'}</dd>
              </div>
              <div>
                <dt className="text-xs text-foreground/50">Temperature</dt>
                <dd>{result.hostStats.temp || 'Not reported'}</dd>
              </div>
              <div>
                <dt className="text-xs text-foreground/50">Load average (1 min)</dt>
                <dd className="tabular-nums">{result.hostStats.load || 'Not reported'}</dd>
              </div>
            </dl>
          ) : (
            <p className="text-sm text-muted-foreground">
              {result ? 'The gateway did not report host stats.' : 'Waiting for the checks to finish.'}
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
