'use client';

import React from 'react';
import { Download, Rocket, ScrollText, Zap } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { downloadRuntimePayload, executeRuntimeAction, type RuntimeDownloadPayload } from '@/lib/runtime-actions';
import { useCurrentUser } from '@/lib/use-current-user';

type Dataset = 'devices' | 'deployments' | 'audit';
type Format = 'CSV' | 'JSON';

const DATASETS: Array<{ key: Dataset; name: string; description: string; icon: React.ReactNode; operatorOnly?: boolean }> = [
  {
    key: 'devices',
    name: 'Devices',
    description: 'Every device the gateway knows: architecture, firmware, ASH score, last heartbeat, address and signal.',
    icon: <Zap className="h-5 w-5 text-primary" />,
  },
  {
    key: 'deployments',
    name: 'Deployments',
    description: 'Every deployment: release, status, start and finish times, and per-status target counts.',
    icon: <Rocket className="h-5 w-5 text-primary" />,
  },
  {
    key: 'audit',
    name: 'Audit trail',
    description: 'The newest 1,000 changes made through the gateway, with who made them and from where.',
    icon: <ScrollText className="h-5 w-5 text-primary" />,
    operatorOnly: true,
  },
];

/**
 * Exports of live gateway data. Each download is built at the moment it is
 * requested from the gateway's own records; nothing is stored or scheduled.
 */
export default function ReportsPage() {
  const { user } = useCurrentUser();
  const [busy, setBusy] = React.useState<string | null>(null);
  const [message, setMessage] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  const isViewer = user?.role === 'viewer';

  const handleExport = async (dataset: Dataset, format: Format) => {
    setBusy(`${dataset}:${format}`);
    setError(null);
    setMessage(null);
    try {
      const response = await executeRuntimeAction<RuntimeDownloadPayload>('reports.export', { dataset, format });
      if (response.data) downloadRuntimePayload(response.data);
      setMessage(response.message || 'Export downloaded.');
    } catch (exportError) {
      setError(exportError instanceof Error ? exportError.message : 'Export failed.');
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-foreground">Reports</h1>
        <p className="mt-1 text-foreground/70">
          Download the gateway&apos;s current records as CSV or JSON. Each file is built from live data when you ask for it.
        </p>
      </div>
      {error && <p className="text-sm text-chart-4">{error}</p>}
      {message && !error && <p className="text-sm text-chart-1">{message}</p>}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {DATASETS.map((dataset) => {
          const locked = dataset.operatorOnly && isViewer;
          return (
            <Card key={dataset.key}>
              <CardHeader>
                <div className="flex items-center gap-2">
                  {dataset.icon}
                  <CardTitle className="text-base">{dataset.name}</CardTitle>
                </div>
                <CardDescription>{dataset.description}</CardDescription>
              </CardHeader>
              <CardContent className="flex flex-wrap gap-2">
                {(['CSV', 'JSON'] as const).map((format) => (
                  <Button
                    key={format}
                    size="sm"
                    variant="outline"
                    disabled={busy !== null || locked}
                    title={locked ? 'The audit trail is available to operators and admins.' : undefined}
                    onClick={() => void handleExport(dataset.key, format)}
                  >
                    <Download className="mr-2 h-4 w-4" />
                    {busy === `${dataset.key}:${format}` ? 'Exporting...' : format}
                  </Button>
                ))}
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
