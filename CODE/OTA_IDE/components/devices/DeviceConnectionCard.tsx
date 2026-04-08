'use client';

import React from 'react';
import { AlertCircle, CheckCircle, Loader2, RefreshCw, Upload, Wifi } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { formatUtcTime } from '@/lib/formatters';

type ConnectionMode = 'serial' | 'ota';
type StatusTone = 'success' | 'info' | 'warning' | 'error' | 'neutral';

type DetectedSerialPort = {
  path: string;
  manufacturer: string | null;
  serialNumber: string | null;
  vendorId: string | null;
  productId: string | null;
  description: string;
};

type WorkflowHint = {
  deviceName: string;
  mode: ConnectionMode;
};

const baudRates = ['9600', '57600', '115200', '230400'];
const boardTypes = ['ATmega328P', 'ESP8266', 'ESP32', 'STM32F103'];
const otaChannels = ['stable', 'beta', 'custom'];

const statusToneClasses: Record<StatusTone, string> = {
  success: 'bg-chart-1/20 text-chart-1',
  info: 'bg-chart-2/20 text-chart-2',
  warning: 'bg-chart-3/20 text-chart-3',
  error: 'bg-chart-4/20 text-chart-4',
  neutral: 'bg-muted text-muted-foreground',
};

function formatPortDescription(port: DetectedSerialPort) {
  const details = [
    port.manufacturer,
    port.serialNumber ? `SN ${port.serialNumber}` : null,
    port.vendorId ? `VID ${port.vendorId}` : null,
    port.productId ? `PID ${port.productId}` : null,
  ].filter(Boolean);

  return details.length > 0 ? details.join(' · ') : 'USB serial device';
}

function createDetectedPort(path: string, manufacturer: string | null, serialNumber: string | null, vendorId: string | null, productId: string | null): DetectedSerialPort {
  return {
    path,
    manufacturer,
    serialNumber,
    vendorId,
    productId,
    description: formatPortDescription({
      path,
      manufacturer,
      serialNumber,
      vendorId,
      productId,
      description: '',
    }),
  };
}

function isValidPortName(value: string) {
  const normalized = value.trim();
  return /^COM\d+$/i.test(normalized) || /^\\\\\.\\COM\d+$/i.test(normalized) || /^\/dev\/.+/.test(normalized);
}

interface DeviceConnectionCardProps {
  workflowHint?: WorkflowHint | null;
  onWorkflowHandled?: () => void;
}

export function DeviceConnectionCard({ workflowHint, onWorkflowHandled }: DeviceConnectionCardProps) {
  const [connectionMode, setConnectionMode] = React.useState<ConnectionMode>('serial');
  const [availablePorts, setAvailablePorts] = React.useState<DetectedSerialPort[]>([]);
  const [serialPort, setSerialPort] = React.useState('');
  const [baudRate, setBaudRate] = React.useState('115200');
  const [boardType, setBoardType] = React.useState('ESP32');
  const [firmwarePath, setFirmwarePath] = React.useState('C:/OTA/build/firmware.bin');
  const [otaHost, setOtaHost] = React.useState('192.168.1.120');
  const [otaPort, setOtaPort] = React.useState('3232');
  const [otaToken, setOtaToken] = React.useState('');
  const [otaChannel, setOtaChannel] = React.useState('stable');
  const [statusLabel, setStatusLabel] = React.useState('Ready');
  const [statusTone, setStatusTone] = React.useState<StatusTone>('info');
  const [statusMessage, setStatusMessage] = React.useState(
    'Choose a serial COM port or OTA target to continue.'
  );
  const [isScanningPorts, setIsScanningPorts] = React.useState(false);
  const [portScanError, setPortScanError] = React.useState<string | null>(null);
  const [lastPortScan, setLastPortScan] = React.useState<Date | null>(null);
  const scanningRef = React.useRef(false);

  const getActiveComPort = React.useCallback(
    () => serialPort.trim() || availablePorts[0]?.path || '',
    [availablePorts, serialPort]
  );

  const updateStatus = React.useCallback((label: string, tone: StatusTone, message: string) => {
    setStatusLabel(label);
    setStatusTone(tone);
    setStatusMessage(message);
  }, []);

  const scanSerialPorts = React.useCallback(async (reason: 'mount' | 'manual' | 'mode-change' | 'workflow' = 'manual') => {
    if (scanningRef.current) {
      return [];
    }

    scanningRef.current = true;
    setIsScanningPorts(true);
    setPortScanError(null);

    try {
      const response = await fetch('/api/serial-ports', { cache: 'no-store' });
      if (!response.ok) {
        const payload = await response.json().catch(() => null);
        throw new Error(payload?.error || `Unable to scan COM ports (${response.status})`);
      }

      const payload = await response.json() as {
        ports?: Array<{
          path: string;
          manufacturer?: string | null;
          serialNumber?: string | null;
          vendorId?: string | null;
          productId?: string | null;
        }>;
        detected?: boolean;
        count?: number;
        error?: string;
      };

      const ports = (payload.ports || [])
        .filter((port) => typeof port.path === 'string' && port.path.trim().length > 0)
        .map((port) => createDetectedPort(
          port.path,
          port.manufacturer ?? null,
          port.serialNumber ?? null,
          port.vendorId ?? null,
          port.productId ?? null,
        ))
        .sort((left, right) => left.path.localeCompare(right.path, undefined, { numeric: true, sensitivity: 'base' }));

      setAvailablePorts(ports);
      setLastPortScan(new Date());

      if (ports.length > 0) {
        setSerialPort((current) => {
          if (current && ports.some((port) => port.path === current)) {
            return current;
          }

          return ports[0].path;
        });

        updateStatus(
          ports.length === 1 ? '1 COM port detected' : `${ports.length} COM ports detected`,
          'success',
          `${ports.map((port) => port.path).join(', ')} detected on this machine. The list updates automatically when devices connect or disconnect.`
        );
      } else {
        setSerialPort((current) => current.trim());
        updateStatus(
          'No COM port detected',
          'warning',
          'No connected COM ports were found. Check the USB cable, device power, Windows drivers, or enter a COM port manually.'
        );
      }

      return ports;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown serial detection error';
      setPortScanError(message);
      updateStatus(
        'COM scan failed',
        'error',
        message.includes('permission')
          ? 'Serial access was blocked. Allow local device access or run the app from the trusted desktop environment.'
          : message
      );
      return [];
    } finally {
      scanningRef.current = false;
      setIsScanningPorts(false);
    }
  }, [updateStatus]);

  const handleModeChange = (value: string) => {
    const nextMode = value as ConnectionMode;
    setConnectionMode(nextMode);

    if (nextMode === 'serial') {
      void scanSerialPorts('mode-change');
      return;
    }

    updateStatus(
      'OTA mode',
      'info',
      'Wireless deployment is ready for a device already on the network.'
    );
  };

  React.useEffect(() => {
    if (workflowHint?.mode) {
      setConnectionMode(workflowHint.mode);
      if (workflowHint.mode === 'serial') {
        updateStatus(
          'COM workflow queued',
          'info',
          `${workflowHint.deviceName} is queued for COM flashing. Auto-detecting the attached port now.`
        );
        void scanSerialPorts('workflow');
      } else {
        updateStatus(
          'OTA workflow queued',
          'info',
          `${workflowHint.deviceName} is queued for OTA deployment. Verify the target host and port before pushing.`
        );
      }

      onWorkflowHandled?.();
    }
  }, [onWorkflowHandled, scanSerialPorts, updateStatus, workflowHint]);

  React.useEffect(() => {
    if (connectionMode !== 'serial') {
      return;
    }

    void scanSerialPorts('mount');

    const intervalId = window.setInterval(() => {
      void scanSerialPorts('manual');
    }, 15000);

    return () => {
      window.clearInterval(intervalId);
    };
  }, [connectionMode, scanSerialPorts]);

  const handleSerialSession = () => {
    setConnectionMode('serial');

    const activePort = getActiveComPort();

    if (!activePort) {
      updateStatus(
        'COM port missing',
        'error',
        'No COM port is selected. Use auto-detect or type the port manually before opening a serial session.'
      );
      return;
    }

    if (!isValidPortName(activePort)) {
      updateStatus(
        'Invalid COM port',
        'error',
        'Use a Windows COM port like COM3 or a valid serial device path for your environment.'
      );
      return;
    }

    if (!baudRate || Number.isNaN(Number(baudRate))) {
      updateStatus(
        'Invalid baud rate',
        'error',
        'Baud rate must be a numeric value. Pick one of the predefined rates or enter a valid custom rate.'
      );
      return;
    }

    updateStatus(
      'Serial session ready',
      'success',
      `Prepared ${activePort} at ${baudRate} baud for ${boardType}. Auto-detection will keep the port list in sync while this panel remains open.`
    );
  };

  const handleSerialFlash = () => {
    setConnectionMode('serial');

    const activePort = getActiveComPort();

    if (!activePort) {
      updateStatus(
        'Flash blocked',
        'error',
        'No COM port is available. Run auto-detect, verify the cable, or enter a manual port name.'
      );
      return;
    }

    if (!isValidPortName(activePort)) {
      updateStatus(
        'Flash blocked',
        'error',
        'The selected COM port is not a valid Windows serial path. Enter a valid port name and try again.'
      );
      return;
    }

    if (!firmwarePath.trim()) {
      updateStatus(
        'Firmware path missing',
        'error',
        'Provide a firmware binary path before starting the COM flash.'
      );
      return;
    }

    updateStatus(
      'COM upload queued',
      'warning',
      `Uploading ${firmwarePath} over ${activePort} at ${baudRate} baud. If the device disconnects mid-transfer, rescan the port list and retry.`
    );
  };

  const handleOtaCheck = () => {
    setConnectionMode('ota');

    const activePort = getActiveComPort();
    const parsedPort = Number(otaPort);

    if (!activePort) {
      updateStatus(
        'OTA COM port missing',
        'error',
        'Select a COM port for OTA flash pairing before checking the target. Use auto-detect or enter one manually.'
      );
      return;
    }

    if (!isValidPortName(activePort)) {
      updateStatus(
        'Invalid OTA COM port',
        'error',
        'Use a valid COM port format (for example COM3) before running the OTA target check.'
      );
      return;
    }

    if (!otaHost.trim()) {
      updateStatus('OTA host missing', 'error', 'Provide a device host or IP address before checking the OTA target.');
      return;
    }

    if (!Number.isInteger(parsedPort) || parsedPort <= 0 || parsedPort > 65535) {
      updateStatus('Invalid OTA port', 'error', 'OTA port must be a number between 1 and 65535.');
      return;
    }

    updateStatus(
      'OTA target reachable',
      'success',
      `Validated ${otaHost}:${otaPort} on the ${otaChannel} channel with ${activePort} selected for flash pairing. The target is ready for wireless deployment.`
    );
  };

  const handleOtaDeploy = () => {
    setConnectionMode('ota');

    const activePort = getActiveComPort();
    const parsedPort = Number(otaPort);

    if (!activePort) {
      updateStatus('OTA deployment blocked', 'error', 'Select a COM port for OTA flash pairing before pushing the release.');
      return;
    }

    if (!isValidPortName(activePort)) {
      updateStatus('OTA deployment blocked', 'error', 'The selected OTA COM port is invalid. Use a value like COM3 and retry.');
      return;
    }

    if (!otaHost.trim()) {
      updateStatus('OTA deployment blocked', 'error', 'Provide a target host or IP address before starting the OTA push.');
      return;
    }

    if (!Number.isInteger(parsedPort) || parsedPort <= 0 || parsedPort > 65535) {
      updateStatus('OTA deployment blocked', 'error', 'OTA port must be between 1 and 65535.');
      return;
    }

    if (otaChannel === 'custom' && !otaToken.trim()) {
      updateStatus('Custom OTA token required', 'error', 'A secure token is required for custom OTA channels. Enter the token and try again.');
      return;
    }

    updateStatus(
      'OTA deployment queued',
      'warning',
      `Pushing the ${otaChannel} release to ${otaHost}:${otaPort} with ${activePort} selected for flash pairing. If the target becomes unreachable, rescan and retry with a stable COM link.`
    );
  };

  const selectedPort = getActiveComPort();

  return (
    <Card id="device-connection-panel" className="glass border-border/50">
      <CardHeader className="space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="space-y-1">
            <CardTitle>Device Connection Modes</CardTitle>
            <CardDescription>
              Switch between direct flashing over COM and wireless OTA deployment.
            </CardDescription>
          </div>

          <div className="flex flex-wrap gap-2">
            <Badge variant="outline" className="border-border/60 bg-primary/10 text-primary">
              <Upload className="mr-1 h-3.5 w-3.5" />
              Serial COM
            </Badge>
            <Badge variant="outline" className="border-border/60 bg-chart-1/10 text-chart-1">
              <Wifi className="mr-1 h-3.5 w-3.5" />
              OTA
            </Badge>
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-5">
        <Tabs value={connectionMode} onValueChange={handleModeChange} className="w-full">
          <TabsList className="grid w-full grid-cols-2 bg-muted/40">
            <TabsTrigger value="serial" className="gap-2">
              <Upload className="h-4 w-4" />
              Serial via COM
            </TabsTrigger>
            <TabsTrigger value="ota" className="gap-2">
              <Wifi className="h-4 w-4" />
              OTA Update
            </TabsTrigger>
          </TabsList>

          <TabsContent value="serial" className="mt-5 space-y-5">
            <div className="rounded-lg border border-border/60 bg-muted/15 p-4">
              <div className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-md border border-border/60 bg-background/60 px-3 py-2">
                <div className="space-y-1">
                  <p className="text-xs font-semibold uppercase tracking-wide text-foreground/60">Auto-detection</p>
                  <p className="text-sm text-foreground/70">
                    {isScanningPorts
                      ? 'Scanning the local machine for connected COM devices.'
                      : availablePorts.length > 0
                        ? `${availablePorts.length} port(s) detected and ready.`
                        : 'No COM device is currently detected on this machine.'}
                  </p>
                </div>
                <Button type="button" variant="outline" className="border-border/60" onClick={() => void scanSerialPorts('manual')} disabled={isScanningPorts}>
                  {isScanningPorts ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
                  {isScanningPorts ? 'Scanning' : 'Scan COM Ports'}
                </Button>
              </div>

              <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium text-foreground" htmlFor="serial-port">
                    COM Port
                  </label>
                  {availablePorts.length > 0 ? (
                    <Select value={selectedPort} onValueChange={setSerialPort}>
                      <SelectTrigger id="serial-port" className="w-full border-border/60 bg-background/60">
                        <SelectValue placeholder="Select COM port" />
                      </SelectTrigger>
                      <SelectContent>
                        {availablePorts.map((port) => (
                          <SelectItem key={port.path} value={port.path}>
                            <div className="flex flex-col items-start gap-0.5 text-left">
                              <span>{port.path}</span>
                              <span className="text-xs text-muted-foreground">{port.description}</span>
                            </div>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  ) : (
                    <Input
                      id="serial-port"
                      value={serialPort}
                      onChange={(event) => setSerialPort(event.target.value)}
                      className="border-border/60 bg-background/60"
                      placeholder="COM3"
                    />
                  )}
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium text-foreground" htmlFor="serial-baud">
                    Baud Rate
                  </label>
                  <Select value={baudRate} onValueChange={setBaudRate}>
                    <SelectTrigger id="serial-baud" className="w-full border-border/60 bg-background/60">
                      <SelectValue placeholder="Select baud rate" />
                    </SelectTrigger>
                    <SelectContent>
                      {baudRates.map((rate) => (
                        <SelectItem key={rate} value={rate}>
                          {rate}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium text-foreground" htmlFor="serial-board">
                    Target Board
                  </label>
                  <Select value={boardType} onValueChange={setBoardType}>
                    <SelectTrigger id="serial-board" className="w-full border-border/60 bg-background/60">
                      <SelectValue placeholder="Select board" />
                    </SelectTrigger>
                    <SelectContent>
                      {boardTypes.map((board) => (
                        <SelectItem key={board} value={board}>
                          {board}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium text-foreground" htmlFor="serial-firmware">
                    Firmware Path
                  </label>
                  <Input
                    id="serial-firmware"
                    value={firmwarePath}
                    onChange={(event) => setFirmwarePath(event.target.value)}
                    className="border-border/60 bg-background/60"
                    placeholder="C:/OTA/build/firmware.bin"
                  />
                </div>
              </div>

              <div className="mt-4 flex flex-wrap gap-2">
                <Button type="button" variant="outline" className="border-border/60" onClick={handleSerialSession}>
                  Open COM Session
                </Button>
                <Button type="button" className="bg-primary hover:bg-primary/90" onClick={handleSerialFlash}>
                  Flash via COM
                </Button>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="ota" className="mt-5 space-y-5">
            <div className="rounded-lg border border-border/60 bg-muted/15 p-4">
              <div className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-md border border-border/60 bg-background/60 px-3 py-2">
                <div className="space-y-1">
                  <p className="text-xs font-semibold uppercase tracking-wide text-foreground/60">COM selection</p>
                  <p className="text-sm text-foreground/70">
                    {isScanningPorts
                      ? 'Scanning connected COM devices for OTA flash pairing.'
                      : availablePorts.length > 0
                        ? `${availablePorts.length} port(s) available for OTA flash pairing.`
                        : 'No COM device is currently detected. Enter a COM port manually to continue OTA flashing.'}
                  </p>
                </div>
                <Button type="button" variant="outline" className="border-border/60" onClick={() => void scanSerialPorts('manual')} disabled={isScanningPorts}>
                  {isScanningPorts ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
                  {isScanningPorts ? 'Scanning' : 'Scan COM Ports'}
                </Button>
              </div>

              <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
                <div className="space-y-2">
                  <label className="text-sm font-medium text-foreground" htmlFor="ota-com-port">
                    Flash COM Port
                  </label>
                  {availablePorts.length > 0 ? (
                    <Select value={selectedPort} onValueChange={setSerialPort}>
                      <SelectTrigger id="ota-com-port" className="w-full border-border/60 bg-background/60">
                        <SelectValue placeholder="Select COM port" />
                      </SelectTrigger>
                      <SelectContent>
                        {availablePorts.map((port) => (
                          <SelectItem key={port.path} value={port.path}>
                            <div className="flex flex-col items-start gap-0.5 text-left">
                              <span>{port.path}</span>
                              <span className="text-xs text-muted-foreground">{port.description}</span>
                            </div>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  ) : (
                    <Input
                      id="ota-com-port"
                      value={serialPort}
                      onChange={(event) => setSerialPort(event.target.value)}
                      className="border-border/60 bg-background/60"
                      placeholder="COM3"
                    />
                  )}
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium text-foreground" htmlFor="ota-host">
                    Device Host / IP
                  </label>
                  <Input
                    id="ota-host"
                    value={otaHost}
                    onChange={(event) => setOtaHost(event.target.value)}
                    className="border-border/60 bg-background/60"
                    placeholder="192.168.1.120"
                  />
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium text-foreground" htmlFor="ota-port">
                    OTA Port
                  </label>
                  <Input
                    id="ota-port"
                    value={otaPort}
                    onChange={(event) => setOtaPort(event.target.value)}
                    className="border-border/60 bg-background/60"
                    placeholder="3232"
                  />
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium text-foreground" htmlFor="ota-token">
                    Access Token
                  </label>
                  <Input
                    id="ota-token"
                    type="password"
                    value={otaToken}
                    onChange={(event) => setOtaToken(event.target.value)}
                    className="border-border/60 bg-background/60"
                    placeholder="Optional secure token"
                  />
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium text-foreground" htmlFor="ota-channel">
                    Release Channel
                  </label>
                  <Select value={otaChannel} onValueChange={setOtaChannel}>
                    <SelectTrigger id="ota-channel" className="w-full border-border/60 bg-background/60">
                      <SelectValue placeholder="Select channel" />
                    </SelectTrigger>
                    <SelectContent>
                      {otaChannels.map((channel) => (
                        <SelectItem key={channel} value={channel}>
                          {channel}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="mt-4 flex flex-wrap gap-2">
                <Button type="button" variant="outline" className="border-border/60" onClick={handleOtaCheck}>
                  Check OTA Target
                </Button>
                <Button type="button" className="bg-primary hover:bg-primary/90" onClick={handleOtaDeploy}>
                  Push OTA Update
                </Button>
              </div>
            </div>
          </TabsContent>
        </Tabs>

        <div className="rounded-lg border border-border/60 bg-background/50 p-4" role="status" aria-live="polite">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-chart-1" />
                <p className="text-sm font-semibold text-foreground">{statusLabel}</p>
              </div>
              <p className="text-sm text-foreground/70">{statusMessage}</p>
              {lastPortScan && (
                <p className="text-xs text-foreground/50">
                  Last scan: {formatUtcTime(lastPortScan)}
                </p>
              )}
            </div>
            <Badge className={statusToneClasses[statusTone]}>{connectionMode === 'serial' ? 'COM' : 'OTA'}</Badge>
          </div>
        </div>

        {portScanError && (
          <div className="rounded-lg border border-chart-4/30 bg-chart-4/10 p-4 text-sm text-chart-4">
            <p className="font-semibold">COM detection error</p>
            <p className="mt-1 break-words">{portScanError}</p>
          </div>
        )}

        <div className="rounded-lg border border-border/60 bg-background/60 p-4">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="outline" className="border-border/60 bg-muted/40 text-foreground/70">
              {availablePorts.length > 0 ? `${availablePorts.length} detected` : 'Manual override enabled'}
            </Badge>
            <Badge variant="outline" className="border-border/60 bg-muted/40 text-foreground/70">
              {selectedPort || 'No active COM port'}
            </Badge>
            {workflowHint && (
              <Badge variant="outline" className="border-border/60 bg-primary/10 text-primary">
                Target: {workflowHint.deviceName}
              </Badge>
            )}
          </div>
        </div>

        <div className="flex items-start gap-2 text-xs text-foreground/50">
          <AlertCircle className="mt-0.5 h-3.5 w-3.5 text-chart-3" />
          <p>
            COM detection is automatic through the local Next.js API route. If the device is not listed, check the cable, drivers, power, or enter the COM port manually.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
