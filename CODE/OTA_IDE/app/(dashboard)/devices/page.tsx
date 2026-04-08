'use client';

import React from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from '@/components/ui/table';
import { 
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Search, MoreVertical, Upload, AlertCircle, CheckCircle, WifiOff } from 'lucide-react';
import { DeviceConnectionCard } from '@/components/devices/DeviceConnectionCard';
import { mockDevices } from '@/lib/mock-data';

const timeFormatter = new Intl.DateTimeFormat('en-US', {
  timeZone: 'UTC',
  hour: 'numeric',
  minute: '2-digit',
  second: '2-digit',
  hour12: true,
});

function getStatusIcon(status: string) {
  switch (status) {
    case 'online':
      return <CheckCircle className="w-4 h-4 text-chart-1" />;
    case 'offline':
      return <WifiOff className="w-4 h-4 text-chart-4" />;
    case 'updating':
      return <Upload className="w-4 h-4 text-chart-3" />;
    default:
      return <AlertCircle className="w-4 h-4 text-chart-2" />;
  }
}

function getHealthColor(health: string) {
  switch (health) {
    case 'excellent':
      return 'bg-chart-1/20 text-chart-1';
    case 'good':
      return 'bg-chart-2/20 text-chart-2';
    case 'fair':
      return 'bg-chart-3/20 text-chart-3';
    case 'poor':
      return 'bg-chart-4/20 text-chart-4';
    default:
      return 'bg-muted text-muted-foreground';
  }
}

export default function DevicesPage() {
  const [searchTerm, setSearchTerm] = React.useState('');
  const [workflowHint, setWorkflowHint] = React.useState<{ deviceName: string; mode: 'serial' | 'ota' } | null>(null);

  const scrollToConnectionPanel = () => {
    document.getElementById('device-connection-panel')?.scrollIntoView({
      behavior: 'smooth',
      block: 'start',
    });
  };

  const handleConnectionAction = (deviceName: string, mode: 'serial' | 'ota') => {
    setWorkflowHint({ deviceName, mode });
    scrollToConnectionPanel();
  };
  
  const filteredDevices = mockDevices.filter(device =>
    device.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    device.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
    device.type.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Devices</h1>
          <p className="text-foreground/70 mt-1">Manage and monitor your device fleet, COM sessions, and OTA updates</p>
        </div>
        <Button className="bg-primary hover:bg-primary/90 text-primary-foreground" onClick={scrollToConnectionPanel}>
          Connect Device
        </Button>
      </div>

      <DeviceConnectionCard
        workflowHint={workflowHint}
        onWorkflowHandled={() => setWorkflowHint(null)}
      />

      {/* Search and Filters */}
      <Card className="glass border-border/50">
        <CardContent className="pt-6">
          <div className="relative">
            <Search className="absolute left-3 top-3 w-4 h-4 text-muted-foreground" />
            <Input
              placeholder="Search devices by name, ID, or type..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10 bg-muted/50 border-border/50"
            />
          </div>
        </CardContent>
      </Card>

      {/* Devices Table */}
      <Card className="glass border-border/50">
        <CardHeader>
          <CardTitle>Device Inventory</CardTitle>
          <CardDescription>{filteredDevices.length} device(s) found</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="border-border/50 hover:bg-transparent">
                  <TableHead className="text-foreground/70">Device</TableHead>
                  <TableHead className="text-foreground/70">Type</TableHead>
                  <TableHead className="text-foreground/70">Status</TableHead>
                  <TableHead className="text-foreground/70">Version</TableHead>
                  <TableHead className="text-foreground/70">Health</TableHead>
                  <TableHead className="text-foreground/70">Last Sync</TableHead>
                  <TableHead className="text-foreground/70">Uptime</TableHead>
                  <TableHead className="text-right text-foreground/70">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredDevices.map((device) => {
                  const needsUpdate = device.firmwareVersion !== device.latestVersion;
                  return (
                    <TableRow key={device.id} className="border-border/50 hover:bg-muted/30">
                      <TableCell className="font-medium text-foreground">
                        <div>
                          <p>{device.name}</p>
                          <p className="text-xs text-foreground/50 mt-1">{device.id}</p>
                        </div>
                      </TableCell>
                      <TableCell className="text-foreground/80">{device.type}</TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          {getStatusIcon(device.status)}
                          <span className="text-sm capitalize text-foreground/80">{device.status}</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-foreground/80">
                        <div className="flex items-center gap-2">
                          <span>{device.firmwareVersion}</span>
                          {needsUpdate && (
                            <Badge variant="outline" className="bg-chart-3/20 text-chart-3 text-xs">
                              {device.latestVersion} available
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={`capitalize text-xs ${getHealthColor(device.health)}`}>
                          {device.health}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-foreground/80 text-sm">
                        {timeFormatter.format(device.lastSync)}
                      </TableCell>
                      <TableCell className="text-foreground/80 text-sm">
                        {device.uptime}h
                      </TableCell>
                      <TableCell className="text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon" className="h-8 w-8">
                              <MoreVertical className="w-4 h-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end" className="bg-card border-border">
                            <DropdownMenuItem className="text-foreground cursor-pointer">
                              View Details
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              className="text-foreground cursor-pointer"
                              onClick={() => handleConnectionAction(device.name, 'serial')}
                            >
                              Flash via COM Port
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              className="text-foreground cursor-pointer"
                              onClick={() => handleConnectionAction(device.name, 'ota')}
                            >
                              Deploy via OTA
                            </DropdownMenuItem>
                            <DropdownMenuItem className="text-foreground cursor-pointer">
                              Restart Device
                            </DropdownMenuItem>
                            <DropdownMenuItem className="text-chart-4 cursor-pointer">
                              Remove Device
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Total Devices', value: mockDevices.length, color: 'bg-chart-2/20 text-chart-2' },
          { label: 'Online', value: mockDevices.filter(d => d.status === 'online').length, color: 'bg-chart-1/20 text-chart-1' },
          { label: 'Offline', value: mockDevices.filter(d => d.status === 'offline').length, color: 'bg-chart-4/20 text-chart-4' },
          { label: 'Updates Needed', value: mockDevices.filter(d => d.firmwareVersion !== d.latestVersion).length, color: 'bg-chart-3/20 text-chart-3' },
        ].map((stat) => (
          <Card key={stat.label} className="glass border-border/50">
            <CardContent className="pt-6">
              <p className="text-sm text-foreground/70 mb-1">{stat.label}</p>
              <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
