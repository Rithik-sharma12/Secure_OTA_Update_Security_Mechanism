'use client';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Play, Pause, RotateCcw, Zap, Cpu, Thermometer, Wifi, Plus, Trash2 } from 'lucide-react';

export default function SimulatorPage() {
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

      {/* Simulation Control */}
      <Card className="glass border-border/50 hover:border-border/80 transition-all">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Active Simulation</CardTitle>
              <CardDescription>Virtual ESP32 device running firmware v2.4.0</CardDescription>
            </div>
            <div className="flex gap-2">
              <Badge className="bg-chart-1/20 text-chart-1 flex items-center gap-1">
                <div className="w-2 h-2 rounded-full bg-chart-1 animate-pulse" />
                Running
              </Badge>
              <Badge variant="outline" className="bg-primary/20 text-primary">
                Uptime: 2h 34m
              </Badge>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Metrics Grid */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {[
              { label: 'CPU Usage', value: '45%', icon: <Cpu className="w-4 h-4" />, color: 'text-primary' },
              { label: 'Memory', value: '62%', icon: <Thermometer className="w-4 h-4" />, color: 'text-accent' },
              { label: 'Temperature', value: '52°C', icon: <Thermometer className="w-4 h-4" />, color: 'text-chart-1' },
              { label: 'Network', value: 'Connected', icon: <Wifi className="w-4 h-4" />, color: 'text-chart-1' },
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

          {/* Console Output */}
          <div>
            <p className="text-sm font-semibold text-foreground mb-2">Console Output</p>
            <div className="bg-muted/30 rounded-lg p-4 font-mono text-xs text-foreground/70 max-h-64 overflow-y-auto border border-border/20">
              <div className="text-foreground/60">[2024-04-08 12:45:23] Device started</div>
              <div className="text-foreground/60">[2024-04-08 12:45:24] Firmware v2.4.0 loaded</div>
              <div className="text-foreground/60">[2024-04-08 12:45:25] Bootloader verified - Checksum OK</div>
              <div className="text-foreground/60">[2024-04-08 12:45:26] Network stack initialized</div>
              <div className="text-chart-1">[2024-04-08 12:45:27] [INFO] Connected to WiFi SSID: Redmi Note 12 5G</div>
              <div className="text-chart-1">[2024-04-08 12:45:28] [INFO] Syncing with server...</div>
              <div className="text-foreground/60">[2024-04-08 12:45:30] Device ready for commands</div>
              <div className="text-chart-1">[2024-04-08 13:20:15] [INFO] Update available: v2.5.0</div>
              <div className="text-chart-1">[2024-04-08 13:20:16] [INFO] Downloading firmware...</div>
              <div className="text-foreground/60">[2024-04-08 13:21:45] Download complete - 245.3 KB</div>
            </div>
          </div>

          {/* Control Buttons */}
          <div className="flex gap-2 flex-wrap">
            <Button className="bg-primary hover:bg-primary/90 text-primary-foreground">
              <Play className="w-4 h-4 mr-2" />
              Resume
            </Button>
            <Button variant="outline" className="border-border">
              <Pause className="w-4 h-4 mr-2" />
              Pause
            </Button>
            <Button variant="outline" className="border-border">
              <RotateCcw className="w-4 h-4 mr-2" />
              Restart
            </Button>
            <Button variant="outline" className="border-border ml-auto">
              <Trash2 className="w-4 h-4 mr-2" />
              Stop
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Create New Simulation */}
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
                <select className="w-full px-3 py-2 bg-muted/50 border border-border/50 rounded-lg text-sm text-foreground focus:outline-none focus:border-primary/50">
                  <option>ESP32</option>
                  <option>ESP8266</option>
                  <option>ATmega328P</option>
                  <option>STM32F103</option>
                </select>
              </div>
              <div>
                <label className="text-sm font-medium text-foreground block mb-2">Firmware Version</label>
                <select className="w-full px-3 py-2 bg-muted/50 border border-border/50 rounded-lg text-sm text-foreground focus:outline-none focus:border-primary/50">
                  <option>v2.4.0 (Latest)</option>
                  <option>v2.3.1</option>
                  <option>v2.2.0</option>
                </select>
              </div>
            </div>
            <div>
              <label className="text-sm font-medium text-foreground block mb-2">Simulation Name</label>
              <input 
                type="text"
                placeholder="My test device..."
                className="w-full px-3 py-2 bg-muted/50 border border-border/50 rounded-lg text-sm text-foreground placeholder-foreground/40 focus:outline-none focus:border-primary/50"
              />
            </div>
            <Button className="w-full bg-primary hover:bg-primary/90 text-primary-foreground">
              <Plus className="w-4 h-4 mr-2" />
              Launch Simulation
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
