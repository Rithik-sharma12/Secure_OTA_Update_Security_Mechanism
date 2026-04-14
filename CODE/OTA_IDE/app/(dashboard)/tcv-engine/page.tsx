'use client';

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Activity, AlertCircle, CheckCircle, Cpu, HardDrive, Zap, Shield } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { executeRuntimeAction } from '@/lib/runtime-actions';

const performanceData = [
  { time: '00:00', verification: 45 },
  { time: '04:00', verification: 52 },
  { time: '08:00', verification: 68 },
  { time: '12:00', verification: 78 },
  { time: '16:00', verification: 72 },
  { time: '20:00', verification: 65 },
  { time: '24:00', verification: 55 },
];

export default function TCVEnginePage() {
  const [autoVerifyOnBoot, setAutoVerifyOnBoot] = React.useState(true);
  const [strictVerificationMode, setStrictVerificationMode] = React.useState(false);
  const [isSavingConfig, setIsSavingConfig] = React.useState(false);
  const [actionMessage, setActionMessage] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);

  const handleSaveConfig = async () => {
    setIsSavingConfig(true);
    setActionError(null);
    setActionMessage(null);

    try {
      const response = await executeRuntimeAction('tcv.save-config', {
        autoVerifyOnBoot,
        strictVerificationMode,
      });
      setActionMessage(response.message || 'TCV configuration saved.');
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to save TCV configuration.');
    } finally {
      setIsSavingConfig(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-8">
        <div className="p-3 rounded-lg bg-primary/20 text-primary">
          <Shield className="w-6 h-6" />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-foreground">TCV Engine</h1>
          <p className="text-foreground/70 mt-1">Trusted Computation Verification - Security monitoring and verification</p>
        </div>
      </div>
      {actionError && <p className="text-sm text-chart-4">{actionError}</p>}
      {actionMessage && !actionError && <p className="text-sm text-chart-1">{actionMessage}</p>}

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Engine Status', value: 'Active', icon: <Activity className="w-5 h-5" />, color: 'bg-chart-1/20 text-chart-1' },
          { label: 'Uptime', value: '45d 12h', icon: <Zap className="w-5 h-5" />, color: 'bg-primary/20 text-primary' },
          { label: 'Verified Devices', value: '5', icon: <CheckCircle className="w-5 h-5" />, color: 'bg-chart-1/20 text-chart-1' },
          { label: 'Verification Rate', value: '99.8%', icon: <Shield className="w-5 h-5" />, color: 'bg-accent/20 text-accent' },
        ].map((stat) => (
          <Card key={stat.label} className="glass border-border/50 hover:border-border/80 transition-all">
            <CardContent className="pt-6">
              <div className="flex items-start justify-between mb-3">
                <p className="text-sm font-medium text-foreground/70">{stat.label}</p>
                <div className={`p-2 rounded-lg ${stat.color}`}>{stat.icon}</div>
              </div>
              <p className="text-3xl font-bold text-foreground">{stat.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Performance Chart */}
      <Card className="glass border-border/50 hover:border-border/80 transition-all">
        <CardHeader>
          <CardTitle>Verification Performance (24 Hours)</CardTitle>
          <CardDescription>Verification requests processed over time</CardDescription>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={performanceData}>
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
              <Line type="monotone" dataKey="verification" stroke="#854f6c" strokeWidth={2} dot={{ fill: '#854f6c', r: 4 }} name="Verifications" />
            </LineChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* Engine Metrics */}
      <Card className="glass border-border/50 hover:border-border/80 transition-all">
        <CardHeader>
          <CardTitle>Engine Performance</CardTitle>
          <CardDescription>Real-time resource usage and metrics</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {[
            { name: 'CPU Usage', value: '12%', max: 80, icon: <Cpu className="w-4 h-4" /> },
            { name: 'Memory Usage', value: '34%', max: 85, icon: <HardDrive className="w-4 h-4" /> },
            { name: 'Verification Queue', value: '0', status: 'Clear', icon: <Activity className="w-4 h-4" /> },
          ].map((metric) => (
            <div key={metric.name} className="p-4 rounded-lg border border-border/20 bg-muted/20 hover:border-border/40 transition-colors">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <div className="text-primary">{metric.icon}</div>
                  <span className="text-sm font-medium text-foreground">{metric.name}</span>
                </div>
                <span className="text-sm font-bold text-foreground">{metric.value}{metric.max ? '%' : ''}</span>
              </div>
              {metric.max && (
                <div className="w-full bg-muted/30 rounded-full h-2 overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-primary to-accent rounded-full transition-all"
                    style={{ width: metric.value }}
                  />
                </div>
              )}
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Verified Devices */}
      <Card className="glass border-border/50 hover:border-border/80 transition-all">
        <CardHeader>
          <CardTitle>Verified Devices</CardTitle>
          <CardDescription>Devices with trusted computation verification enabled</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {[
              { device: 'ESP32-Dev-01', status: 'verified', lastCheck: '2 minutes ago' },
              { device: 'ESP32-Dev-02', status: 'verified', lastCheck: '5 minutes ago' },
              { device: 'STM32-Test-01', status: 'verified', lastCheck: '1 minute ago' },
              { device: 'ATmega-Prod-01', status: 'pending', lastCheck: 'In progress' },
              { device: 'ESP8266-Beta-01', status: 'verified', lastCheck: '10 seconds ago' },
            ].map((item) => (
              <div key={item.device} className="p-3 rounded-lg bg-muted/20 border border-border/20 flex items-center justify-between hover:border-border/40 transition-colors">
                <div>
                  <p className="text-sm font-medium text-foreground">{item.device}</p>
                  <p className="text-xs text-foreground/60">Last check: {item.lastCheck}</p>
                </div>
                <Badge className={item.status === 'verified' ? 'bg-chart-1/20 text-chart-1' : 'bg-chart-3/20 text-chart-3'}>
                  {item.status}
                </Badge>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Settings */}
      <Card className="glass border-border/50 hover:border-border/80 transition-all">
        <CardHeader>
          <CardTitle>TCV Configuration</CardTitle>
          <CardDescription>Adjust verification settings and policies</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-3">
            <div className="p-3 rounded-lg bg-muted/20 border border-border/20 flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-foreground">Auto-verify on boot</p>
                <p className="text-xs text-foreground/60">Automatically verify devices on startup</p>
              </div>
              <input
                type="checkbox"
                checked={autoVerifyOnBoot}
                onChange={(event) => setAutoVerifyOnBoot(event.target.checked)}
                className="w-5 h-5 rounded cursor-pointer"
              />
            </div>
            <div className="p-3 rounded-lg bg-muted/20 border border-border/20 flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-foreground">Strict verification mode</p>
                <p className="text-xs text-foreground/60">Require verification for all operations</p>
              </div>
              <input
                type="checkbox"
                checked={strictVerificationMode}
                onChange={(event) => setStrictVerificationMode(event.target.checked)}
                className="w-5 h-5 rounded cursor-pointer"
              />
            </div>
          </div>
          <Button
            className="w-full bg-primary hover:bg-primary/90 text-primary-foreground"
            onClick={() => void handleSaveConfig()}
            disabled={isSavingConfig}
          >
            Save Configuration
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
