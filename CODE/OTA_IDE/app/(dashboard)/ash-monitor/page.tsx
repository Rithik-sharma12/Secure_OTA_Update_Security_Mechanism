'use client';

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Activity, AlertTriangle, CheckCircle, Zap, AlertCircle, Thermometer, HardDrive, Wifi, Battery } from 'lucide-react';
import { downloadRuntimePayload, executeRuntimeAction, type RuntimeDownloadPayload } from '@/lib/runtime-actions';

export default function ASHMonitorPage() {
  const systemHealth = 0;
  const [busyAction, setBusyAction] = React.useState<string | null>(null);
  const [actionMessage, setActionMessage] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);

  const handleRunHealthCheck = async () => {
    setBusyAction('ash.scan');
    setActionError(null);
    setActionMessage(null);

    try {
      const response = await executeRuntimeAction('ash.scan', {
        scope: 'full-health-check',
      });
      setActionMessage(response.message || 'ASH health check completed successfully.');
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to run ASH health check.');
    } finally {
      setBusyAction(null);
    }
  };

  const handleExportReport = async () => {
    setBusyAction('ash.export');
    setActionError(null);
    setActionMessage(null);

    try {
      const generated = await executeRuntimeAction<{ report?: { id: string } }>('reports.generate', {
        type: 'ash-monitor',
        format: 'CSV',
        notes: 'ASH Monitor export report',
      });

      const reportId = generated.data?.report?.id;
      if (!reportId) {
        throw new Error('Report generation did not return a report id.');
      }

      const download = await executeRuntimeAction<RuntimeDownloadPayload>('reports.download', {
        reportId,
      });

      if (download.data) {
        downloadRuntimePayload(download.data);
      }

      setActionMessage(download.message || 'ASH monitor report exported.');
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to export ASH report.');
    } finally {
      setBusyAction(null);
    }
  };
  
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-8">
        <div className="p-3 rounded-lg bg-accent/20 text-accent">
          <Activity className="w-6 h-6" />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-foreground">ASH Monitor</h1>
          <p className="text-foreground/70 mt-1">Advanced System Health monitoring and diagnostics</p>
        </div>
      </div>
      {actionError && <p className="text-sm text-chart-4">{actionError}</p>}
      {actionMessage && !actionError && <p className="text-sm text-chart-1">{actionMessage}</p>}

      {/* Health Overview */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          { 
            label: 'Overall Health', 
            value: '0%', 
            color: 'text-chart-1',
            icon: <CheckCircle className="w-5 h-5" />,
            bgColor: 'bg-chart-1/20'
          },
          { 
            label: 'Critical Issues', 
            value: '0', 
            color: 'text-muted-foreground',
            icon: <AlertCircle className="w-5 h-5" />,
            bgColor: 'bg-muted'
          },
          { 
            label: 'Active Warnings', 
            value: '0', 
            color: 'text-chart-3',
            icon: <AlertTriangle className="w-5 h-5" />,
            bgColor: 'bg-chart-3/20'
          },
        ].map((stat) => (
          <Card key={stat.label} className="glass border-border/50 hover:border-border/80 transition-all">
            <CardContent className="pt-6">
              <div className="flex items-start justify-between mb-3">
                <p className="text-sm font-medium text-foreground/70">{stat.label}</p>
                <div className={`p-2 rounded-lg ${stat.bgColor}`}>{stat.icon}</div>
              </div>
              <p className={`text-3xl font-bold ${stat.color}`}>{stat.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Health Meter */}
      <Card className="glass border-border/50 hover:border-border/80 transition-all">
        <CardHeader>
          <CardTitle>System Health Score</CardTitle>
          <CardDescription>Overall system integrity and reliability</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-3">
            <div className="flex items-end justify-between">
              <p className="text-sm text-foreground/70">Health Status</p>
              <p className="text-4xl font-bold text-chart-1">{systemHealth}%</p>
            </div>
            <div className="w-full bg-muted/30 rounded-full h-4 overflow-hidden">
              <div 
                className="h-full bg-gradient-to-r from-chart-1 to-primary rounded-full transition-all"
                style={{ width: `${systemHealth}%` }}
              />
            </div>
          </div>
          <p className="text-sm text-foreground/70 text-center">
            0
          </p>
        </CardContent>
      </Card>

      {/* Component Health */}
      <Card className="glass border-border/50 hover:border-border/80 transition-all">
        <CardHeader>
          <CardTitle>Component Health</CardTitle>
          <CardDescription>Individual component status and metrics</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {[
            { 
              component: 'Storage', 
              health: 0, 
              status: 'warning',
              icon: <HardDrive className="w-4 h-4" />,
              details: '0'
            },
            { 
              component: 'Network', 
              health: 0, 
              status: 'warning',
              icon: <Wifi className="w-4 h-4" />,
              details: '0'
            },
            { 
              component: 'Processor', 
              health: 0, 
              status: 'warning',
              icon: <Zap className="w-4 h-4" />,
              details: '0'
            },
            { 
              component: 'Memory', 
              health: 0, 
              status: 'warning',
              icon: <Activity className="w-4 h-4" />,
              details: '0'
            },
            { 
              component: 'Power', 
              health: 0, 
              status: 'warning',
              icon: <Battery className="w-4 h-4" />,
              details: '0'
            },
          ].map((item) => (
            <div key={item.component} className="p-4 rounded-lg border border-border/20 bg-muted/20 hover:border-border/40 transition-colors">
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-3">
                  <div className="text-primary">{item.icon}</div>
                  <div>
                    <p className="font-semibold text-foreground">{item.component}</p>
                    <p className="text-xs text-foreground/60">{item.details}</p>
                  </div>
                </div>
                <Badge className={item.status === 'healthy' ? 'bg-chart-1/20 text-chart-1' : 'bg-chart-3/20 text-chart-3'}>
                  {item.status}
                </Badge>
              </div>
              <div className="w-full bg-muted/30 rounded-full h-2 overflow-hidden">
                <div 
                  className={`h-full rounded-full transition-all ${item.health > 90 ? 'bg-chart-1' : item.health > 75 ? 'bg-yellow-500' : 'bg-chart-4'}`}
                  style={{ width: `${item.health}%` }}
                />
              </div>
              <div className="flex items-center justify-between mt-2">
                <span className="text-xs text-foreground/50">Health Score</span>
                <span className="text-xs font-bold text-foreground">{item.health}%</span>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Recent Alerts */}
      <Card className="glass border-border/50 hover:border-border/80 transition-all">
        <CardHeader>
          <CardTitle>Recent Health Events</CardTitle>
          <CardDescription>Latest system alerts and notifications</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {[
              { severity: 'info', message: '0', time: '0' },
            ].map((event, i) => (
              <div key={i} className="p-3 rounded-lg border border-border/20 bg-muted/10 flex items-start gap-3">
                <div className="mt-1">
                  {event.severity === 'warning' && <AlertTriangle className="w-4 h-4 text-chart-3" />}
                  {event.severity === 'info' && <Activity className="w-4 h-4 text-primary" />}
                  {event.severity === 'success' && <CheckCircle className="w-4 h-4 text-chart-1" />}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-foreground">{event.message}</p>
                  <p className="text-xs text-foreground/50 mt-1">{event.time}</p>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Actions */}
      <div className="flex gap-2">
        <Button
          className="bg-primary hover:bg-primary/90 text-primary-foreground flex-1"
          onClick={() => void handleRunHealthCheck()}
          disabled={busyAction === 'ash.scan'}
        >
          <Activity className="w-4 h-4 mr-2" />
          {busyAction === 'ash.scan' ? 'Running...' : 'Run Full Health Check'}
        </Button>
        <Button
          variant="outline"
          className="border-border flex-1"
          onClick={() => void handleExportReport()}
          disabled={busyAction === 'ash.export'}
        >
          Export Report
        </Button>
      </div>
    </div>
  );
}
