'use client';

import React from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { CheckCircle, AlertCircle, Clock, Play, Pause, StopCircle, ChevronDown } from 'lucide-react';
import { formatUtcDateTime } from '@/lib/formatters';
import { useRuntimeSnapshot } from '@/lib/runtime-data';
import { executeRuntimeAction } from '@/lib/runtime-actions';

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

export default function PipelinePage() {
  const { snapshot, isLoading } = useRuntimeSnapshot();
  const livePipeline = snapshot.pipeline;
  const [isRunningAction, setIsRunningAction] = React.useState(false);
  const [actionMessage, setActionMessage] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);

  const handlePipelineAction = async (command: string) => {
    setIsRunningAction(true);
    setActionError(null);
    setActionMessage(null);

    try {
      const response = await executeRuntimeAction('pipeline.control', {
        command,
        pipelineId: livePipeline?.id,
      });
      setActionMessage(response.message || `Pipeline command '${command}' executed.`);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to execute pipeline action.');
    } finally {
      setIsRunningAction(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Deployment Pipeline</h1>
          <p className="text-foreground/70 mt-1">CI/CD workflow and deployment status</p>
          {!snapshot.connection.reachable && snapshot.connection.error && (
            <p className="text-sm text-chart-4 mt-2">{snapshot.connection.error}</p>
          )}
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            className="border-border"
            onClick={() => void handlePipelineAction('pause')}
            disabled={isRunningAction || !livePipeline}
          >
            <Pause className="w-4 h-4 mr-2" />
            Pause
          </Button>
          <Button
            variant="outline"
            className="border-border"
            onClick={() => void handlePipelineAction('cancel')}
            disabled={isRunningAction || !livePipeline}
          >
            <StopCircle className="w-4 h-4 mr-2" />
            Cancel
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
              <CardTitle>
                {livePipeline ? `Build #${livePipeline.id.split('-')[1] || livePipeline.id}` : 'No active pipeline'}
              </CardTitle>
              <CardDescription>
                {isLoading
                  ? 'Loading live pipeline telemetry...'
                  : livePipeline
                    ? `Release ${livePipeline.releaseId}`
                    : 'No deployment stage is currently running.'}
              </CardDescription>
            </div>
            <Badge variant="outline" className="bg-chart-3/20 text-chart-3 capitalize">
              {livePipeline?.status || 'idle'}
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          {/* Pipeline Stages */}
          {!livePipeline && (
            <p className="text-sm text-foreground/60">Pipeline stage telemetry will appear here once deployment starts.</p>
          )}

          <div className="space-y-4">
            {livePipeline?.stages.map((stage, index) => (
              <div key={stage.id}>
                {/* Stage Header */}
                <div className="flex items-center gap-4 mb-2">
                  <div className="flex items-center gap-3 flex-1">
                    {getStageStatusIcon(stage.status)}
                    <div>
                      <h4 className="font-semibold text-foreground capitalize">{stage.name}</h4>
                      <p className="text-xs text-foreground/50">
                        {stage.duration ? `${(stage.duration / 60).toFixed(1)}m` : 'Not started'}
                      </p>
                    </div>
                  </div>
                  <Badge
                    variant="outline"
                    className={`capitalize text-xs ${getStageStatusColor(stage.status)}`}
                  >
                    {stage.status}
                  </Badge>
                </div>

                {/* Stage Progress Bar */}
                <div className="w-full bg-muted/30 rounded-full h-1.5 mb-3 overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${
                      stage.status === 'success'
                        ? 'bg-chart-1'
                        : stage.status === 'running'
                        ? 'bg-chart-3'
                        : stage.status === 'failed'
                        ? 'bg-chart-4'
                        : 'bg-muted-foreground'
                    }`}
                    style={{
                      width: stage.status === 'success' ? '100%' : stage.status === 'running' ? '65%' : '0%',
                    }}
                  />
                </div>

                {/* Stage Logs */}
                {stage.logs && (
                  <div className="bg-muted/20 rounded-lg p-3 mb-3 font-mono text-xs text-foreground/70 max-h-32 overflow-y-auto">
                    {stage.logs.split('\n').map((line, i) => (
                      <div key={i}>{line || '\u00A0'}</div>
                    ))}
                  </div>
                )}

                {/* Divider */}
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

      {/* Pipeline Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Started', value: livePipeline ? formatUtcDateTime(livePipeline.createdAt) : 'n/a', icon: '📅' },
          {
            label: 'Duration',
            value: livePipeline ? `${(livePipeline.stages.reduce((sum, s) => sum + (s.duration || 0), 0) / 60).toFixed(1)}m` : 'n/a',
            icon: '⏱️'
          },
          {
            label: 'Completed Stages',
            value: livePipeline
              ? `${livePipeline.stages.filter(s => s.status === 'success').length}/${livePipeline.stages.length}`
              : '0/0',
            icon: '✓'
          },
          {
            label: 'Status',
            value: livePipeline ? livePipeline.status.charAt(0).toUpperCase() + livePipeline.status.slice(1) : 'Idle',
            icon: '🔄'
          },
        ].map((stat) => (
          <Card key={stat.label} className="glass border-border/50">
            <CardContent className="pt-6">
              <p className="text-sm text-foreground/70 mb-1">{stat.label}</p>
              <p className="text-lg font-semibold text-foreground">{stat.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Actions */}
      <Card className="glass border-border/50">
        <CardHeader>
          <CardTitle>Pipeline Actions</CardTitle>
          <CardDescription>Manage this deployment pipeline</CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Button
            variant="outline"
            className="border-border justify-start"
            onClick={() => void handlePipelineAction('resume')}
            disabled={isRunningAction}
          >
            <Play className="w-4 h-4 mr-2" />
            Resume Pipeline
          </Button>
          <Button
            variant="outline"
            className="border-border justify-start"
            onClick={() => void handlePipelineAction('view-logs')}
            disabled={isRunningAction}
          >
            View Logs
          </Button>
          <Button
            variant="outline"
            className="border-border justify-start text-chart-4"
            onClick={() => void handlePipelineAction('cancel')}
            disabled={isRunningAction}
          >
            Cancel Pipeline
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
