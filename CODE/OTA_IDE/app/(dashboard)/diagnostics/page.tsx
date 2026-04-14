'use client';

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line } from 'recharts';
import { Activity, AlertTriangle, CheckCircle, Zap, HardDrive, Wifi, Bug } from 'lucide-react';
import { executeRuntimeAction } from '@/lib/runtime-actions';

const diagnosticsData = [
  { metric: 'CPU', value: 45, threshold: 80, status: 'normal', icon: <Zap className="w-4 h-4" /> },
  { metric: 'Memory', value: 62, threshold: 85, status: 'normal', icon: <Activity className="w-4 h-4" /> },
  { metric: 'Disk', value: 38, threshold: 90, status: 'normal', icon: <HardDrive className="w-4 h-4" /> },
  { metric: 'Network', value: 28, threshold: 100, status: 'normal', icon: <Wifi className="w-4 h-4" /> },
];

const timeSeriesData = [
  { time: '00:00', cpu: 32, memory: 45, disk: 28 },
  { time: '04:00', cpu: 38, memory: 52, disk: 32 },
  { time: '08:00', cpu: 45, memory: 58, disk: 35 },
  { time: '12:00', cpu: 52, memory: 62, disk: 38 },
  { time: '16:00', cpu: 48, memory: 60, disk: 36 },
  { time: '20:00', cpu: 42, memory: 55, disk: 33 },
  { time: '24:00', cpu: 45, memory: 62, disk: 38 },
];

const systemChecks = [
  { name: 'Database Connectivity', status: 'healthy', time: '2 seconds ago', icon: <CheckCircle className="w-4 h-4 text-chart-1" /> },
  { name: 'API Gateway', status: 'healthy', time: '1 minute ago', icon: <CheckCircle className="w-4 h-4 text-chart-1" /> },
  { name: 'Device Sync', status: 'healthy', time: '30 seconds ago', icon: <CheckCircle className="w-4 h-4 text-chart-1" /> },
  { name: 'Certificate Validation', status: 'warning', time: '5 minutes ago', icon: <AlertTriangle className="w-4 h-4 text-yellow-500" /> },
];

export default function DiagnosticsPage() {
  const [isScanning, setIsScanning] = React.useState(false);
  const [actionMessage, setActionMessage] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);

  const handleRunFullScan = async () => {
    setIsScanning(true);
    setActionError(null);
    setActionMessage(null);

    try {
      const response = await executeRuntimeAction('diagnostics.scan', {
        scope: 'full-system',
      });
      setActionMessage(response.message || 'Full diagnostics scan completed.');
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to run diagnostics scan.');
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-lg bg-primary/20 text-primary">
            <Bug className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-foreground">Diagnostics</h1>
            <p className="text-foreground/70 mt-1">System health and comprehensive performance analysis</p>
          </div>
        </div>
        <Button
          className="bg-primary hover:bg-primary/90 text-primary-foreground"
          onClick={() => void handleRunFullScan()}
          disabled={isScanning}
        >
          <Activity className="w-4 h-4 mr-2" />
          {isScanning ? 'Scanning...' : 'Run Full Scan'}
        </Button>
      </div>
      {actionError && <p className="text-sm text-chart-4">{actionError}</p>}
      {actionMessage && !actionError && <p className="text-sm text-chart-1">{actionMessage}</p>}

      {/* System Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {diagnosticsData.map((item) => (
          <Card key={item.metric} className="glass border-border/50 hover:border-border/80 transition-all">
            <CardContent className="pt-6">
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2">
                  <div className="text-primary/60">{item.icon}</div>
                  <p className="text-sm font-medium text-foreground">{item.metric}</p>
                </div>
                <Badge variant="outline" className="bg-chart-1/20 text-chart-1 text-xs">
                  {item.status}
                </Badge>
              </div>
              <p className="text-3xl font-bold text-foreground mb-3">{item.value}%</p>
              <div className="w-full bg-muted/30 rounded-full h-2.5 overflow-hidden">
                <div 
                  className={`h-full rounded-full transition-all ${item.value > item.threshold ? 'bg-chart-4' : 'bg-chart-1'}`}
                  style={{ width: `${item.value}%` }}
                />
              </div>
              <p className="text-xs text-foreground/50 mt-2">Threshold: {item.threshold}%</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* System Health Checks */}
      <Card className="glass border-border/50 hover:border-border/80 transition-all">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <CheckCircle className="w-5 h-5 text-chart-1" />
            System Health Checks
          </CardTitle>
          <CardDescription>Real-time component status verification</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {systemChecks.map((check) => (
              <div key={check.name} className="flex items-center justify-between p-3 rounded-lg bg-muted/20 hover:bg-muted/30 transition-colors border border-border/20">
                <div className="flex items-center gap-3">
                  {check.icon}
                  <div>
                    <p className="text-sm font-medium text-foreground">{check.name}</p>
                    <p className="text-xs text-foreground/50">{check.time}</p>
                  </div>
                </div>
                <Badge variant="outline" className={check.status === 'healthy' ? 'bg-chart-1/20 text-chart-1' : 'bg-yellow-500/20 text-yellow-500'}>
                  {check.status}
                </Badge>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Performance Over Time */}
      <Card className="glass border-border/50 hover:border-border/80 transition-all">
        <CardHeader>
          <CardTitle>Performance Timeline (24 Hours)</CardTitle>
          <CardDescription>System resource usage trends</CardDescription>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={timeSeriesData}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
              <XAxis dataKey="time" stroke="rgba(255,255,255,0.5)" style={{ fontSize: '12px' }} />
              <YAxis stroke="rgba(255,255,255,0.5)" style={{ fontSize: '12px' }} />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: 'rgba(25,0,25,0.95)', 
                  border: '1px solid rgba(133,79,108,0.3)',
                  borderRadius: '8px'
                }}
              />
              <Line type="monotone" dataKey="cpu" stroke="#854f6c" strokeWidth={2} dot={false} name="CPU" />
              <Line type="monotone" dataKey="memory" stroke="#4CAF50" strokeWidth={2} dot={false} name="Memory" />
              <Line type="monotone" dataKey="disk" stroke="#FF9800" strokeWidth={2} dot={false} name="Disk" />
            </LineChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* Detailed Logs */}
      <Card className="glass border-border/50 hover:border-border/80 transition-all">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bug className="w-5 h-5 text-primary" />
            System Logs
          </CardTitle>
          <CardDescription>Recent diagnostic events and warnings</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-1 font-mono text-xs max-h-64 overflow-y-auto bg-muted/20 p-4 rounded-lg border border-border/20">
            {[
              { msg: '[INFO] System startup completed - 0ms', time: '00:00:01' },
              { msg: '[INFO] Device connection pool initialized - 12 devices', time: '00:00:02' },
              { msg: '[INFO] API gateway started on 0.0.0.0:3000', time: '00:00:03' },
              { msg: '[WARN] CPU usage approaching threshold (72%)', time: '12:34:56' },
              { msg: '[INFO] Backup cycle completed - 1.2GB archived', time: '14:22:10' },
              { msg: '[WARN] Certificate expires in 30 days - ota-api.crt', time: '16:55:42' },
              { msg: '[INFO] Network latency: 12ms average', time: '18:10:05' },
              { msg: '[INFO] All health checks passed', time: '20:30:00' },
            ].map((log, i) => (
              <div key={i} className="text-foreground/70 py-1 border-b border-border/10 last:border-b-0">
                <span className="text-foreground/40">{log.time}</span>
                <span className="mx-2">│</span>
                <span>{log.msg}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
