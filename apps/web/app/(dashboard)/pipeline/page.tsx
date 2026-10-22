'use client';

import React from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { CheckCircle, AlertCircle, Clock, ChevronDown, RotateCw } from 'lucide-react';
import { formatUtcDateTime } from '@/lib/formatters';
import { useRuntimeSnapshot } from '@/lib/runtime-data';
import { executeRuntimeAction } from '@/lib/runtime-actions';
import { useCurrentUser } from '@/lib/use-current-user';
import { StatGrid, StatTile } from '@/components/ui/stat-tile';

function getStageStatusIcon(status: string) {
  switch (status) {
    case 'success':
      return <CheckCircle className="w-5 h-5 text-chart-1" />;
    case 'running':
      return <Clock className="w-5 h-5 text-chart-3 animate-spin" />;
    case 'failed':
      return <AlertCircle className="w-5 h-5 text-chart-4" />;
    case 'pending':
      return <Clock className="w-5 h-5 text-muted-foreground" />;
    default:
      return <CheckCircle className="w-5 h-5" />;
  }
}

function getStageStatusColor(status: string) {
  switch (status) {
    case 'success':
      return 'bg-chart-1/20 text-chart-1';
    case 'running':
      return 'bg-chart-3/20 text-chart-3';
    case 'failed':
      return 'bg-chart-4/20 text-chart-4';
    case 'pending':
      return 'bg-muted text-muted-foreground';
    default:
      return 'bg-muted text-muted-foreground';
  }
}

function formatSeconds(seconds: number | undefined) {
  if (seconds === undefined || !Number.isFinite(seconds)) return 'Not recorded';
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  return `${(seconds / 60).toFixed(1)} min`;
}

export default function PipelinePage() {
  const { snapshot, isLoading, refresh } = useRuntimeSnapshot();
  const { canRunAction } = useCurrentUser();
  const mayRerun = canRunAction('pipeline.rerun');
  const livePipeline = snapshot.pipeline;
  const release = livePipeline ? snapshot.releases.find((entry) => entry.id === livePipeline.releaseId) : undefined;
  const [isRunningAction, setIsRunningAction] = React.useState(false);
  const [showLogs, setShowLogs] = React.useState(false);
  const [actionMessage, setActionMessage] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);

  const handleRerun = async () => {
    setIsRunningAction(true);
    setActionError(null);
    setActionMessage(null);
    try {
      const response = await executeRuntimeAction('pipeline.rerun', { releaseId: livePipeline?.releaseId });
      setActionMessage(response.message || 'Re-verification finished.');
      setShowLogs(true);
      await refresh();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to re-run the pipeline.');
    } finally {
      setIsRunningAction(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Release Pipeline</h1>
          <p className="text-foreground/70 mt-1">
            The stages the gateway ran for its most recent publish or re-verification.
          </p>
          {!snapshot.connection.reachable && snapshot.connection.error && (
            <p className="text-sm text-chart-4 mt-2">{snapshot.connection.error}</p>
          )}
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => setShowLogs((value) => !value)} disabled={!livePipeline}>
            {showLogs ? 'Hide logs' : 'View logs'}
          </Button>
          <Button
            onClick={() => void handleRerun()}
            disabled={isRunningAction || !livePipeline || !mayRerun}
            title={mayRerun ? 'Read the cached artifact back, check its SHA-256 and re-sign it' : 'Requires an operator or admin.'}
          >
            <RotateCw className="w-4 h-4 mr-2" />
            {isRunningAction ? 'Re-running...' : 'Re-run checks'}
          </Button>
        </div>
      </div>
      {actionError && <p className="text-sm text-chart-4">{actionError}</p>}
      {actionMessage && !actionError && <p className="text-sm text-chart-1">{actionMessage}</p>}

      {/* Pipeline Overview */}
      <Card className="glass border-border/50">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>{livePipeline ? (release ? `v${release.version}` : livePipeline.releaseId) : 'No pipeline has run'}</CardTitle>
              <CardDescription>
                {isLoading
                  ? 'Loading pipeline...'
                  : livePipeline
                    ? `Pipeline ${livePipeline.id}`
                    : 'A pipeline runs when a release is published.'}
              </CardDescription>
            </div>
            {livePipeline && (
              <Badge variant="outline" className={`capitalize ${getStageStatusColor(livePipeline.status)}`}>
                {livePipeline.status}
              </Badge>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {!livePipeline && (
            <p className="text-sm text-foreground/60">Publish a release on the Releases page and its stages appear here.</p>
          )}

          <div className="space-y-4">
            {livePipeline?.stages.map((stage, index) => (
              <div key={stage.id}>
                <div className="flex items-center gap-4 mb-2">
                  <div className="flex items-center gap-3 flex-1">
                    {getStageStatusIcon(stage.status)}
                    <div>
                      <h4 className="font-semibold text-foreground capitalize">{stage.name}</h4>
                      <p className="text-xs text-foreground/50">{formatSeconds(stage.duration)}</p>
                    </div>
                  </div>
                  <Badge variant="outline" className={`capitalize text-xs ${getStageStatusColor(stage.status)}`}>
                    {stage.status}
                  </Badge>
                </div>

                {showLogs && (
                  <div className="bg-muted/20 rounded-lg p-3 mb-3 font-mono text-xs text-foreground/70 max-h-48 overflow-y-auto">
                    {stage.logs
                      ? stage.logs.split('\n').map((line, i) => <div key={i} className="break-all">{line || '\u00A0'}</div>)
                      : 'This stage wrote no log.'}
                  </div>
                )}

                {index < livePipeline.stages.length - 1 && (
                  <div className="flex items-center gap-2 my-4">
                    <div className="flex-1 h-px bg-border/50" />
                    <ChevronDown className="w-4 h-4 text-muted-foreground" />
                    <div className="flex-1 h-px bg-border/50" />
                  </div>
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {livePipeline && (
        <StatGrid columns={4}>
          <StatTile label="Started" value={<span className="text-base">{formatUtcDateTime(livePipeline.createdAt)} UTC</span>} />
          <StatTile label="Duration" value={formatSeconds(livePipeline.totalDuration)} />
          <StatTile
            label="Passed stages"
            value={livePipeline.stages.filter((stage) => stage.status === 'success').length}
            suffix={`of ${livePipeline.stages.length}`}
            tone={livePipeline.stages.every((stage) => stage.status === 'success') ? 'good' : 'neutral'}
          />
          <StatTile
            label="Status"
            value={livePipeline.status.charAt(0).toUpperCase() + livePipeline.status.slice(1)}
            tone={livePipeline.status === 'success' ? 'good' : livePipeline.status === 'failed' ? 'bad' : 'warn'}
          />
        </StatGrid>
      )}
    </div>
  );
}
