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
import { HostAccessCard } from '@/components/devices/HostAccessCard';
import { WebSerialFlashCard } from '@/components/devices/WebSerialFlashCard';
import { UsbProvisionCard } from '@/components/devices/UsbProvisionCard';
import {
  type DeviceCommandType,
  deployToDevices,
  getDeviceDetail,
  queueDeviceCommand,
  removeDevice,
  waitForCommand,
} from '@/lib/device-control';
import { useRuntimeSnapshot } from '@/lib/runtime-data';
import { formatUtcTime } from '@/lib/formatters';
import { useCurrentUser } from '@/lib/use-current-user';

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
  const [otaHostHint, setOtaHostHint] = React.useState<string | null>(null);
  const [busyDeviceId, setBusyDeviceId] = React.useState<string | null>(null);
  const [actionMessage, setActionMessage] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);
  const { snapshot, isLoading } = useRuntimeSnapshot();
  const { can, reasonFor } = useCurrentUser();
  const mayControlDevices = can('devices.control');
  const mayFlash = can('devices.flash');

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

  /**
   * Remote commands travel dashboard -> gateway -> device's next heartbeat
   * response, so they work wherever the board is on the internet. The result
   * the device reports is followed in the background and shown when it lands.
   */
  const COMMAND_LABELS: Record<DeviceCommandType, string> = {
    reboot: 'Restart',
    identify: 'Identify (blink LED)',
    check_update: 'Update check',
    update: 'Update',
  };

  const sendCommand = async (deviceId: string, deviceName: string, type: DeviceCommandType) => {
    const label = COMMAND_LABELS[type];
    const command = await queueDeviceCommand(deviceId, type);
    setActionMessage(`${label} queued for ${deviceName}. It is delivered with the device's next heartbeat (about 15 s).`);
    void waitForCommand(deviceId, command.id, 90_000).then((final) => {
      if (!final || final.status === 'queued' || final.status === 'delivered') {
        setActionMessage(`${label} for ${deviceName} is still waiting - the device has not checked in. Is it online?`);
      } else if (final.status === 'succeeded') {
        setActionError(null);
        setActionMessage(`${label} on ${deviceName}: ${final.result || 'done'}.`);
      } else {
        setActionError(`${label} on ${deviceName} ${final.status}: ${final.result || 'no detail'}.`);
      }
    }).catch(() => undefined);
  };

  const handleDeviceAction = async (deviceId: string, deviceName: string, command: string) => {
    setBusyDeviceId(deviceId);
    setActionError(null);
    setActionMessage(null);

    try {
      if (command === 'restart') {
        await sendCommand(deviceId, deviceName, 'reboot');
      } else if (command === 'identify') {
        await sendCommand(deviceId, deviceName, 'identify');
      } else if (command === 'check-update') {
        await sendCommand(deviceId, deviceName, 'check_update');
      } else if (command === 'remove') {
        if (!window.confirm(`Remove ${deviceName} from the gateway? Its token and queued commands are deleted. A board that is still running with the fleet key will reappear on its next heartbeat.`)) {
          return;
        }
        await removeDevice(deviceId);
        setActionMessage(`${deviceName} removed from the gateway registry.`);
      } else if (command === 'view-details') {
        const detail = await getDeviceDetail(deviceId);
        const ota = detail.device?.ota;
        const last = detail.commands[0];
        setActionMessage(
          [
            `${deviceName}: firmware v${detail.device?.fw ?? '?'}`,
            detail.credentials.registered
              ? `own device token${detail.credentials.revoked ? ' (revoked)' : ''}`
              : 'authenticates with the fleet key',
            ota ? `last OTA: ${ota.phase} v${ota.version}${ota.detail ? ` - ${ota.detail}` : ''}` : 'no OTA reported yet',
            last ? `last command: ${last.type} ${last.status}${last.result ? ` (${last.result})` : ''}` : 'no commands sent',
          ].join(' · ')
        );
      }
    } catch (error) {
      setActionError(error instanceof Error ? error.message : `Unable to execute ${command}.`);
    } finally {
      setBusyDeviceId(null);
    }
  };

  /**
   * Assign the newest compatible release to one device. The gateway refuses
   * an incompatible board, a quarantined one or a downgrade, and otherwise
   * nudges the device to fetch it on its next heartbeat.
   */
  const handleDeployOta = async (deviceId: string, deviceName: string) => {
    setBusyDeviceId(deviceId);
    setActionError(null);
    setActionMessage(null);
    try {
      // Releases arrive newest first; take the newest published one this
      // board's architecture can run. The gateway re-checks all of this.
      const device = snapshot.devices.find((entry) => entry.id === deviceId);
      const compatible = snapshot.releases.find(
        (release) =>
          release.status === 'published' &&
          (release.compatible.length === 0 || !device || release.compatible.includes(device.type))
      );
      const deployment = await deployToDevices([deviceId], compatible?.id);
      const target = deployment.targets[deviceId];
      if (!target) {
        setActionError(`The gateway did not create a target for ${deviceName}.`);
      } else if (target.state === 'failed') {
        setActionError(`Not deployed to ${deviceName}: ${target.reason || 'refused by the gateway'}.`);
      } else if (target.state === 'confirmed') {
        setActionMessage(`${deviceName} is already running v${deployment.version}.`);
      } else {
        setActionMessage(
          `v${deployment.version} assigned to ${deviceName}. It starts the download on its next heartbeat (about 15 s); ` +
            'progress shows in the Status column and the deployment confirms when the device reports the new version.'
        );
      }
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Deployment failed.');
    } finally {
      setBusyDeviceId(null);
    }
  };
  
  const filteredDevices = snapshot.devices.filter(device =>
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
          {!snapshot.connection.reachable && snapshot.connection.error && (
            <p className="text-sm text-chart-4 mt-2">{snapshot.connection.error}</p>
          )}
        </div>
        <Button className="bg-primary hover:bg-primary/90 text-primary-foreground" onClick={scrollToConnectionPanel}>
          Connect Device
        </Button>
      </div>
      {actionError && <p className="text-sm text-chart-4">{actionError}</p>}
      {actionMessage && !actionError && <p className="text-sm text-chart-1">{actionMessage}</p>}

      <HostAccessCard
        onDeployToHost={(ip) => {
          setOtaHostHint(ip);
          scrollToConnectionPanel();
        }}
      />

      <WebSerialFlashCard
        releases={snapshot.releases}
        releasesStatus={isLoading ? 'loading' : snapshot.connection.reachable ? 'ready' : 'unavailable'}
      />

      <UsbProvisionCard />

      <DeviceConnectionCard
        workflowHint={workflowHint}
        onWorkflowHandled={() => setWorkflowHint(null)}
        otaHostHint={otaHostHint}
        onOtaHostHandled={() => setOtaHostHint(null)}
        onBrowserPortAction={() => document.getElementById('web-serial-flash')?.scrollIntoView({ behavior: 'smooth', block: 'start' })}
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
          <CardDescription>
            {isLoading ? 'Loading live devices...' : `${filteredDevices.length} device(s) found`}
          </CardDescription>
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
                        {device.ota && (
                          <p
                            className={`text-xs mt-1 ${device.ota.phase === 'failed' || device.ota.phase === 'rolled_back' ? 'text-chart-4' : 'text-foreground/50'}`}
                            title={device.ota.detail || undefined}
                          >
                            OTA {device.ota.phase.replace('_', ' ')} v{device.ota.version}
                            {typeof device.ota.progress === 'number' && device.ota.phase === 'downloading' ? ` · ${device.ota.progress}%` : ''}
                          </p>
                        )}
                        {device.rollbackPending && <p className="text-xs mt-1 text-chart-3">Health check pending</p>}
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
                        {formatUtcTime(device.lastSync)}
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
                            <DropdownMenuItem
                              className="text-foreground cursor-pointer"
                              onClick={() => void handleDeviceAction(device.id, device.name, 'view-details')}
                            >
                              {busyDeviceId === device.id ? 'Processing...' : 'View Details'}
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              className="text-foreground cursor-pointer"
                              disabled={!mayFlash}
                              title={mayFlash ? undefined : reasonFor('devices.flash')}
                              onClick={() => handleConnectionAction(device.name, 'serial')}
                            >
                              Flash via COM Port
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              className="text-foreground cursor-pointer"
                              disabled={!mayFlash}
                              title={mayFlash ? undefined : reasonFor('devices.flash')}
                              onClick={() => void handleDeployOta(device.id, device.name)}
                            >
                              {busyDeviceId === device.id ? 'Processing...' : 'Deploy latest via OTA'}
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              className="text-foreground cursor-pointer"
                              disabled={!mayControlDevices}
                              title={mayControlDevices ? undefined : reasonFor('devices.control')}
                              onClick={() => void handleDeviceAction(device.id, device.name, 'check-update')}
                            >
                              Check for update now
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              className="text-foreground cursor-pointer"
                              disabled={!mayControlDevices}
                              title={mayControlDevices ? undefined : reasonFor('devices.control')}
                              onClick={() => void handleDeviceAction(device.id, device.name, 'identify')}
                            >
                              Identify (blink LED)
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              className="text-foreground cursor-pointer"
                              disabled={!mayFlash}
                              title={mayFlash ? undefined : reasonFor('devices.flash')}
                              onClick={() => handleConnectionAction(device.name, 'ota')}
                            >
                              ArduinoOTA push (LAN)
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              className="text-foreground cursor-pointer"
                              disabled={!mayControlDevices}
                              title={mayControlDevices ? undefined : reasonFor('devices.control')}
                              onClick={() => void handleDeviceAction(device.id, device.name, 'restart')}
                            >
                              {busyDeviceId === device.id ? 'Processing...' : 'Restart Device'}
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              className="text-chart-4 cursor-pointer"
                              disabled={!mayControlDevices}
                              title={mayControlDevices ? undefined : reasonFor('devices.control')}
                              onClick={() => void handleDeviceAction(device.id, device.name, 'remove')}
                            >
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
            {!isLoading && filteredDevices.length === 0 && (
              <p className="py-6 text-center text-sm text-foreground/50">
                No live devices reported yet. Start heartbeat publishing to populate this table.
              </p>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Total Devices', value: snapshot.devices.length, color: 'bg-chart-2/20 text-chart-2' },
          { label: 'Online', value: snapshot.devices.filter(d => d.status === 'online').length, color: 'bg-chart-1/20 text-chart-1' },
          { label: 'Offline', value: snapshot.devices.filter(d => d.status === 'offline' || d.status === 'error').length, color: 'bg-chart-4/20 text-chart-4' },
          { label: 'Updates Needed', value: snapshot.devices.filter(d => d.firmwareVersion !== d.latestVersion).length, color: 'bg-chart-3/20 text-chart-3' },
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
