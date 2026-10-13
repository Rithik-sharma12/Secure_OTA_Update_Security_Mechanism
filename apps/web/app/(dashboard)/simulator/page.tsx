'use client';

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Play, Pause, RotateCcw, Zap, Cpu, Thermometer, Wifi, Plus, Trash2 } from 'lucide-react';
import { executeRuntimeAction, fetchRuntimeActionState } from '@/lib/runtime-actions';

type RuntimeSimulator = {
  name: string;
  deviceType: string;
  firmwareVersion: string;
  status: 'running' | 'paused' | 'stopped';
  startedAt: string | null;
  updatedAt: string;
};

const defaultSimulator: RuntimeSimulator = {
  name: '0',
  deviceType: '0',
  firmwareVersion: '0',
  status: 'stopped',
  startedAt: null,
  updatedAt: new Date().toISOString(),
};

function formatUptime(startedAt: string | null) {
  void startedAt;
  return '0';
}

export default function SimulatorPage() {
  const [simulator, setSimulator] = React.useState<RuntimeSimulator>(defaultSimulator);
  const [simulationName, setSimulationName] = React.useState('0');
  const [deviceType, setDeviceType] = React.useState('0');
  const [firmwareVersion, setFirmwareVersion] = React.useState('0');
  const [busyAction, setBusyAction] = React.useState<string | null>(null);
  const [actionMessage, setActionMessage] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);

  React.useEffect(() => {
    const loadSimulator = async () => {
      try {
        const response = await fetchRuntimeActionState<{ simulator?: RuntimeSimulator }>();
        if (response.data?.simulator) {
          setSimulator(response.data.simulator);
          setSimulationName(response.data.simulator.name);
          setDeviceType(response.data.simulator.deviceType);
          setFirmwareVersion(response.data.simulator.firmwareVersion);
        }
      } catch {
        setSimulator(defaultSimulator);
      }
    };

    void loadSimulator();
  }, []);

  const runSimulatorAction = async (action: string, payload: Record<string, unknown>) => {
    setBusyAction(action);
    setActionError(null);
    setActionMessage(null);

    try {
      const response = await executeRuntimeAction(action, payload);
      if (response.data && typeof response.data === 'object' && 'simulator' in response.data) {
        setSimulator(response.data.simulator as RuntimeSimulator);
      }

      if (action === 'simulator.launch') {
        setSimulator((current) => ({
          ...current,
          name: simulationName,
          deviceType,
          firmwareVersion,
          status: 'stopped',
          startedAt: null,
          updatedAt: new Date().toISOString(),
        }));
      }

      setActionMessage(response.message || 'Simulator action completed.');
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to run simulator action.');
    } finally {
      setBusyAction(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-8">
        <div className="p-3 rounded-lg bg-primary/20 text-primary">
          <Zap className="w-6 h-6" />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-foreground">Device Simulator</h1>
          <p className="text-foreground/70 mt-1">Test firmware and simulate device behavior in a virtual environment</p>
        </div>
      </div>
      {actionError && <p className="text-sm text-chart-4">{actionError}</p>}
      {actionMessage && !actionError && <p className="text-sm text-chart-1">{actionMessage}</p>}

      <Card className="glass border-border/50 hover:border-border/80 transition-all">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Active Simulation</CardTitle>
              <CardDescription>
                Virtual {simulator.deviceType} device running firmware {simulator.firmwareVersion}
              </CardDescription>
            </div>
            <div className="flex gap-2">
              <Badge className={simulator.status === 'running' ? 'bg-chart-1/20 text-chart-1 flex items-center gap-1' : 'bg-chart-3/20 text-chart-3 flex items-center gap-1'}>
                <div className={`w-2 h-2 rounded-full ${simulator.status === 'running' ? 'bg-chart-1 animate-pulse' : 'bg-chart-3'}`} />
                {simulator.status.charAt(0).toUpperCase() + simulator.status.slice(1)}
              </Badge>
              <Badge variant="outline" className="bg-primary/20 text-primary">
                Uptime: {formatUptime(simulator.startedAt)}
              </Badge>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {[
              { label: 'CPU Usage', value: '0%', icon: <Cpu className="w-4 h-4" />, color: 'text-primary' },
              { label: 'Memory', value: '0%', icon: <Thermometer className="w-4 h-4" />, color: 'text-accent' },
              { label: 'Temperature', value: '0', icon: <Thermometer className="w-4 h-4" />, color: 'text-chart-1' },
              { label: 'Network', value: '0', icon: <Wifi className="w-4 h-4" />, color: 'text-chart-1' },
            ].map((metric) => (
              <div key={metric.label} className="p-3 rounded-lg bg-muted/20 border border-border/20">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-xs text-foreground/60 font-medium uppercase tracking-wider">{metric.label}</p>
                  <div className={metric.color}>{metric.icon}</div>
                </div>
                <p className="text-2xl font-bold text-foreground">{metric.value}</p>
              </div>
            ))}
          </div>

          <div>
            <p className="text-sm font-semibold text-foreground mb-2">Console Output</p>
            <div className="bg-muted/30 rounded-lg p-4 font-mono text-xs text-foreground/70 max-h-64 overflow-y-auto border border-border/20">
              <div className="text-foreground/60">[{new Date().toISOString()}] Device state: {simulator.status}</div>
              <div className="text-foreground/60">[{new Date().toISOString()}] Simulator: {simulator.name}</div>
              <div className="text-chart-1">[{new Date().toISOString()}] [INFO] Firmware {simulator.firmwareVersion} configured</div>
              <div className="text-foreground/60">[{new Date().toISOString()}] Awaiting simulator commands...</div>
            </div>
          </div>

          <div className="flex gap-2 flex-wrap">
            <Button
              className="bg-primary hover:bg-primary/90 text-primary-foreground"
              onClick={() => void runSimulatorAction('simulator.control', { command: 'resume' })}
              disabled={busyAction !== null}
            >
              <Play className="w-4 h-4 mr-2" />
              Resume
            </Button>
            <Button
              variant="outline"
              className="border-border"
              onClick={() => void runSimulatorAction('simulator.control', { command: 'pause' })}
              disabled={busyAction !== null}
            >
              <Pause className="w-4 h-4 mr-2" />
              Pause
            </Button>
            <Button
              variant="outline"
              className="border-border"
              onClick={() => void runSimulatorAction('simulator.control', { command: 'restart' })}
              disabled={busyAction !== null}
            >
              <RotateCcw className="w-4 h-4 mr-2" />
              Restart
            </Button>
            <Button
              variant="outline"
              className="border-border ml-auto"
              onClick={() => void runSimulatorAction('simulator.control', { command: 'stop' })}
              disabled={busyAction !== null}
            >
              <Trash2 className="w-4 h-4 mr-2" />
              Stop
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card className="glass border-border/50 hover:border-border/80 transition-all">
        <CardHeader>
          <CardTitle>Create Simulation</CardTitle>
          <CardDescription>Start a new virtual device environment</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium text-foreground block mb-2">Device Type</label>
                <select
                  value={deviceType}
                  onChange={(event) => setDeviceType(event.target.value)}
                  className="w-full px-3 py-2 bg-muted/50 border border-border/50 rounded-lg text-sm text-foreground focus:outline-none focus:border-primary/50"
                >
                  <option>0</option>
                  <option>ESP32</option>
                  <option>ESP8266</option>
                  <option>ATmega328P</option>
                  <option>STM32F103</option>
                </select>
              </div>
              <div>
                <label className="text-sm font-medium text-foreground block mb-2">Firmware Version</label>
                <select
                  value={firmwareVersion}
                  onChange={(event) => setFirmwareVersion(event.target.value)}
                  className="w-full px-3 py-2 bg-muted/50 border border-border/50 rounded-lg text-sm text-foreground focus:outline-none focus:border-primary/50"
                >
                  <option>0</option>
                  <option>v2.4.0</option>
                  <option>v2.3.1</option>
                  <option>v2.2.0</option>
                </select>
              </div>
            </div>
            <div>
              <label className="text-sm font-medium text-foreground block mb-2">Simulation Name</label>
              <input
                type="text"
                value={simulationName}
                onChange={(event) => setSimulationName(event.target.value)}
                placeholder="My test device..."
                className="w-full px-3 py-2 bg-muted/50 border border-border/50 rounded-lg text-sm text-foreground placeholder-foreground/40 focus:outline-none focus:border-primary/50"
              />
            </div>
            <Button
              className="w-full bg-primary hover:bg-primary/90 text-primary-foreground"
              onClick={() => void runSimulatorAction('simulator.launch', {
                name: simulationName,
                deviceType,
                firmwareVersion,
              })}
              disabled={busyAction !== null}
            >
              <Plus className="w-4 h-4 mr-2" />
              Launch Simulation
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
