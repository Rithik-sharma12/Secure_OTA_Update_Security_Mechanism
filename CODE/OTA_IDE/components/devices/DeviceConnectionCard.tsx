'use client';

import React from 'react';
import { AlertCircle, CheckCircle, Download, Loader2, Play, RefreshCw, Square, Trash2, Upload, Wifi } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Progress } from '@/components/ui/progress';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { formatUtcTime } from '@/lib/formatters';
import { apiFetch } from '@/lib/client-auth';

type ConnectionMode = 'serial' | 'ota';
type StatusTone = 'success' | 'info' | 'warning' | 'error' | 'neutral';
type MonitorTone = 'info' | 'success' | 'warning' | 'error';
type UploadJobStatus = 'queued' | 'compiling' | 'uploading' | 'success' | 'failed';

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

type MonitorEntry = {
  id: string;
  mode: ConnectionMode;
  source: string;
  tone: MonitorTone;
  message: string;
  timestamp: Date;
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

const monitorToneClasses: Record<MonitorTone, string> = {
  info: 'text-chart-2',
  success: 'text-chart-1',
  warning: 'text-chart-3',
  error: 'text-chart-4',
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

function normalizeComPortName(value: string) {
  return value.trim().replace(/^\\\\\.\\/, '').toUpperCase();
}

interface DeviceConnectionCardProps {
  workflowHint?: WorkflowHint | null;
  onWorkflowHandled?: () => void;
}

export function DeviceConnectionCard({ workflowHint, onWorkflowHandled }: DeviceConnectionCardProps) {
  const defaultFirmwarePath = (process.env.NEXT_PUBLIC_OTA_DEFAULT_FIRMWARE_PATH || '').trim();
  const firmwarePathPlaceholder = 'C:/path/to/OTA_IOT/CODE/frimware_code/esp32_ota_main/esp32_ota_main.ino';
  const defaultOtaHost = (process.env.NEXT_PUBLIC_OTA_DEFAULT_HOST || '').trim();
  const [connectionMode, setConnectionMode] = React.useState<ConnectionMode>('serial');
  const [availablePorts, setAvailablePorts] = React.useState<DetectedSerialPort[]>([]);
  const [serialPort, setSerialPort] = React.useState('');
  const [baudRate, setBaudRate] = React.useState('115200');
  const [boardType, setBoardType] = React.useState('ESP32');
  const [firmwarePath, setFirmwarePath] = React.useState(defaultFirmwarePath);
  const [wifiSsid, setWifiSsid] = React.useState('');
  const [wifiPassword, setWifiPassword] = React.useState('');
  const [otaHost, setOtaHost] = React.useState(defaultOtaHost);
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
  const [monitorEntries, setMonitorEntries] = React.useState<MonitorEntry[]>([]);
  const [isMonitorRunning, setIsMonitorRunning] = React.useState(false);
  const [monitorMode, setMonitorMode] = React.useState<ConnectionMode | null>(null);
  const [autoScrollMonitor, setAutoScrollMonitor] = React.useState(true);
  const [uploadJobId, setUploadJobId] = React.useState<string | null>(null);
  const [uploadStatus, setUploadStatus] = React.useState<UploadJobStatus | 'idle'>('idle');
  const [uploadProgress, setUploadProgress] = React.useState(0);
  const [uploadError, setUploadError] = React.useState<string | null>(null);
  const [isCheckingOta, setIsCheckingOta] = React.useState(false);
  const [lastOtaCheckAt, setLastOtaCheckAt] = React.useState<Date | null>(null);
  const scanningRef = React.useRef(false);
  const monitorIntervalRef = React.useRef<number | null>(null);
  const uploadPollingRef = React.useRef<number | null>(null);
  const uploadLastSequenceRef = React.useRef(0);
  const uploadSourceRef = React.useRef('');
  const monitorLogRef = React.useRef<HTMLDivElement | null>(null);
  const seenMonitorEventIdsRef = React.useRef<Set<string>>(new Set());
  const previousDetectedPortsRef = React.useRef<string[]>([]);

  const getActiveComPort = React.useCallback(
    () => serialPort.trim() || availablePorts[0]?.path || '',
    [availablePorts, serialPort]
  );

  const selectedPort = getActiveComPort();
  const isSelectedPortConnected = React.useMemo(() => {
    if (!selectedPort) {
      return false;
    }

    const target = normalizeComPortName(selectedPort);
    return availablePorts.some((port) => normalizeComPortName(port.path) === target);
  }, [availablePorts, selectedPort]);

  // Only these two boards have WiFi macros in ota_config.h; the AVR and STM32
  // targets have no WiFi radio, so provisioning fields are meaningless there.
  const supportsWifiProvisioning = boardType === 'ESP32' || boardType === 'ESP8266';

  const appendMonitorEntry = React.useCallback((entry: Omit<MonitorEntry, 'id' | 'timestamp'> & { timestamp?: Date }) => {
    setMonitorEntries((current) => {
      const nextEntry: MonitorEntry = {
        ...entry,
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        timestamp: entry.timestamp || new Date(),
      };

      return [...current.slice(-299), nextEntry];
    });
  }, []);

  const stopMonitorStream = React.useCallback(() => {
    if (monitorIntervalRef.current !== null) {
      window.clearInterval(monitorIntervalRef.current);
      monitorIntervalRef.current = null;
    }
  }, []);

  const stopUploadPolling = React.useCallback(() => {
    if (uploadPollingRef.current !== null) {
      window.clearInterval(uploadPollingRef.current);
      uploadPollingRef.current = null;
    }
  }, []);

  React.useEffect(() => {
    return () => {
      stopMonitorStream();
      stopUploadPolling();
    };
  }, [stopMonitorStream, stopUploadPolling]);

  React.useEffect(() => {
    if (!autoScrollMonitor || !monitorLogRef.current) {
      return;
    }

    monitorLogRef.current.scrollTop = monitorLogRef.current.scrollHeight;
  }, [autoScrollMonitor, monitorEntries]);

  const startMonitor = () => {
    const activeMode = connectionMode;
    const activePort = getActiveComPort();

    if (activeMode === 'serial' && !activePort) {
      updateStatus('Monitor blocked', 'error', 'Select a COM port before starting the device monitor.');
      return;
    }

    if (activeMode === 'serial' && availablePorts.length === 0) {
      updateStatus('Monitor blocked', 'error', 'No connected USB serial COM port detected. Connect the device and rescan before monitoring.');
      return;
    }

    if (activeMode === 'serial' && !isSelectedPortConnected) {
      updateStatus('Monitor blocked', 'error', `Selected port ${activePort} is not currently connected. Choose a detected COM port and retry.`);
      return;
    }

    if (activeMode === 'serial' && !isValidPortName(activePort)) {
      updateStatus('Monitor blocked', 'error', 'The selected COM port is invalid. Use a value like COM3 and retry.');
      return;
    }

    if (activeMode === 'ota') {
      const parsedPort = Number(otaPort);
      if (!otaHost.trim()) {
        updateStatus('Monitor blocked', 'error', 'Provide an OTA host or IP before starting OTA monitoring.');
        return;
      }

      if (!Number.isInteger(parsedPort) || parsedPort <= 0 || parsedPort > 65535) {
        updateStatus('Monitor blocked', 'error', 'OTA monitor needs a valid OTA port between 1 and 65535.');
        return;
      }
    }

    stopMonitorStream();
    setIsMonitorRunning(true);
    setMonitorMode(activeMode);

    appendMonitorEntry({
      mode: activeMode,
      source: activeMode === 'serial' ? activePort : `${otaHost}:${otaPort}`,
      tone: 'success',
      message:
        activeMode === 'serial'
          ? `Serial monitor started on ${activePort} at ${baudRate} baud.`
          : `OTA monitor started for ${otaHost}:${otaPort}.`,
    });

    monitorIntervalRef.current = window.setInterval(() => {
      void (async () => {
        try {
          const response = await apiFetch('/api/runtime/snapshot', { cache: 'no-store' });
          if (!response.ok) {
            return;
          }

          const payload = await response.json() as {
            events?: Array<{
              id?: string;
              title?: string;
              description?: string;
              severity?: string;
              deviceId?: string;
            }>;
          };

          const liveEvents = Array.isArray(payload.events) ? payload.events : [];
          const newEvents = liveEvents.filter((event) => event.id && !seenMonitorEventIdsRef.current.has(event.id));

          newEvents.slice(0, 8).forEach((event) => {
            if (!event.id) {
              return;
            }

            seenMonitorEventIdsRef.current.add(event.id);
            appendMonitorEntry({
              mode: activeMode,
              source: activeMode === 'serial' ? activePort : `${otaHost}:${otaPort}`,
              tone:
                event.severity === 'error'
                  ? 'error'
                  : event.severity === 'warning'
                    ? 'warning'
                    : event.severity === 'success'
                      ? 'success'
                      : 'info',
              message: `${event.title || 'Runtime event'}${event.description ? `: ${event.description}` : ''}`,
            });
          });
        } catch {
          // Ignore intermittent polling failures while monitor is active.
        }
      })();
    }, 3000);
  };

  const stopMonitor = () => {
    if (!isMonitorRunning) {
      return;
    }

    stopMonitorStream();
    setIsMonitorRunning(false);

    appendMonitorEntry({
      mode: monitorMode || connectionMode,
      source: monitorMode === 'ota' ? `${otaHost}:${otaPort}` : getActiveComPort() || 'COM',
      tone: 'warning',
      message: 'Device monitor stopped.',
    });
  };

  const clearMonitor = () => {
    setMonitorEntries([]);
    seenMonitorEventIdsRef.current.clear();
  };

  const exportMonitor = () => {
    if (monitorEntries.length === 0) {
      return;
    }

    const lines = monitorEntries
      .map((entry) => `[${formatUtcTime(entry.timestamp)}] [${entry.mode.toUpperCase()}] [${entry.source}] ${entry.message}`)
      .join('\n');

    const blob = new Blob([lines], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `device-monitor-${Date.now()}.log`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const updateStatus = React.useCallback((label: string, tone: StatusTone, message: string) => {
    setStatusLabel(label);
    setStatusTone(tone);
    setStatusMessage(message);
  }, []);

  const pollUploadJob = React.useCallback(async (jobId: string) => {
    try {
      const response = await apiFetch(`/api/serial/upload/${jobId}?since=${uploadLastSequenceRef.current}`);
      const payload = (await response.json()) as {
        ok?: boolean;
        status?: UploadJobStatus;
        progress?: number;
        errorMessage?: string;
        logs?: Array<{
          sequence: number;
          level: 'info' | 'warning' | 'error' | 'success';
          message: string;
          loggedAt: string;
        }>;
        lastSequence?: number;
        error?: string;
      };

      if (!response.ok || !payload.ok) {
        const message = payload.error || 'Unable to fetch upload progress.';
        setUploadError(message);
        updateStatus('Upload monitor error', 'error', message);
        stopUploadPolling();
        return;
      }

      if (Array.isArray(payload.logs)) {
        payload.logs.forEach((log) => {
          appendMonitorEntry({
            mode: 'serial',
            source: uploadSourceRef.current || getActiveComPort() || 'COM',
            tone: log.level === 'error' ? 'error' : log.level === 'warning' ? 'warning' : log.level === 'success' ? 'success' : 'info',
            message: log.message,
            timestamp: new Date(log.loggedAt),
          });
        });
      }

      if (typeof payload.lastSequence === 'number') {
        uploadLastSequenceRef.current = Math.max(uploadLastSequenceRef.current, payload.lastSequence);
      }

      if (payload.status) {
        setUploadStatus(payload.status);
      }

      if (typeof payload.progress === 'number') {
        setUploadProgress(payload.progress);
      }

      if (payload.errorMessage) {
        setUploadError(payload.errorMessage);
      }

      if (payload.status === 'success') {
        updateStatus(
          'Serial upload complete',
          'success',
          `Sketch ${firmwarePath.split(/[\\/]/).pop() || firmwarePath} uploaded successfully to ${uploadSourceRef.current || getActiveComPort()}.`
        );
        stopUploadPolling();
      }

      if (payload.status === 'failed') {
        updateStatus(
          'Serial upload failed',
          'error',
          payload.errorMessage || 'Upload failed. Review monitor logs for compiler or serial-port errors.'
        );
        stopUploadPolling();
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Upload polling failed unexpectedly.';
      setUploadError(message);
      updateStatus('Upload polling failed', 'error', message);
      stopUploadPolling();
    }
  }, [appendMonitorEntry, firmwarePath, getActiveComPort, stopUploadPolling, updateStatus]);

  const startUploadPolling = React.useCallback((jobId: string) => {
    uploadLastSequenceRef.current = 0;
    stopUploadPolling();
    void pollUploadJob(jobId);

    uploadPollingRef.current = window.setInterval(() => {
      void pollUploadJob(jobId);
    }, 1200);
  }, [pollUploadJob, stopUploadPolling]);

  const scanSerialPorts = React.useCallback(async (reason: 'mount' | 'manual' | 'mode-change' | 'workflow' = 'manual') => {
    if (scanningRef.current) {
      return [];
    }

    scanningRef.current = true;
    setIsScanningPorts(true);
    setPortScanError(null);

    try {
      const response = await apiFetch('/api/serial-ports', { cache: 'no-store' });
      if (!response.ok) {
        const payload = await response.json().catch(() => null);
        throw new Error(payload?.error || `Unable to scan COM ports (${response.status})`);
      }

      const payload = await response.json() as {
        supported?: boolean;
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

      const previousPorts = new Set(previousDetectedPortsRef.current.map((value) => normalizeComPortName(value)));
      const currentPorts = new Set(ports.map((port) => normalizeComPortName(port.path)));
      const connectedNow = Array.from(currentPorts).filter((value) => !previousPorts.has(value));
      const disconnectedNow = Array.from(previousPorts).filter((value) => !currentPorts.has(value));
      previousDetectedPortsRef.current = ports.map((port) => port.path);

      if (reason !== 'mount') {
        connectedNow.forEach((portPath) => {
          appendMonitorEntry({
            mode: 'serial',
            source: portPath,
            tone: 'success',
            message: `Connected serial device detected on ${portPath}.`,
          });
        });

        disconnectedNow.forEach((portPath) => {
          appendMonitorEntry({
            mode: 'serial',
            source: portPath,
            tone: 'warning',
            message: `Serial device on ${portPath} disconnected.`,
          });
        });
      }

      if (ports.length > 0) {
        setSerialPort((current) => {
          const normalizedCurrent = normalizeComPortName(current || '');
          if (normalizedCurrent && ports.some((port) => normalizeComPortName(port.path) === normalizedCurrent)) {
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
        setSerialPort('');
        updateStatus(
          'No COM port detected',
          'warning',
          payload.supported === false
            ? 'Automatic COM detection is unavailable on this host. Use a Windows host for real COM auto-detection.'
            : 'No connected USB serial COM devices were found. Check cable, drivers, board power, and rescan.'
        );
      }

      return ports;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown serial detection error';
      setAvailablePorts([]);
      setSerialPort('');
      previousDetectedPortsRef.current = [];
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
  }, [appendMonitorEntry, updateStatus]);

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

    if (availablePorts.length === 0) {
      updateStatus(
        'COM port missing',
        'error',
        'No connected USB serial COM port detected. Connect the device and run Scan COM Ports.'
      );
      return;
    }

    if (!activePort) {
      updateStatus(
        'COM port missing',
        'error',
        'No COM port is selected. Select one of the detected ports before opening a serial session.'
      );
      return;
    }

    if (!isSelectedPortConnected) {
      updateStatus(
        'COM port disconnected',
        'error',
        `Selected port ${activePort} is not connected. Choose a detected COM port and retry.`
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

    appendMonitorEntry({
      mode: 'serial',
      source: activePort,
      tone: 'success',
      message: `Serial session prepared for ${boardType} at ${baudRate} baud.`,
    });
  };

  const handleSerialFlash = async () => {
    setConnectionMode('serial');

    const activePort = getActiveComPort();

    if (availablePorts.length === 0) {
      updateStatus(
        'Flash blocked',
        'error',
        'No connected USB serial COM port detected. Connect the device, rescan, then retry flashing.'
      );
      return;
    }

    if (!activePort) {
      updateStatus(
        'Flash blocked',
        'error',
        'No COM port is available. Select one of the detected COM ports and retry.'
      );
      return;
    }

    if (!isSelectedPortConnected) {
      updateStatus(
        'Flash blocked',
        'error',
        `Selected port ${activePort} is not connected. Choose a detected COM port and retry.`
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
        'Provide a firmware sketch path before starting the COM flash.'
      );
      return;
    }

    const normalizedPath = firmwarePath.trim();
    if (!normalizedPath.toLowerCase().endsWith('.ino')) {
      updateStatus(
        'Unsupported file type',
        'error',
        'Serial upload currently supports .ino sketches. Select an Arduino sketch file and retry.'
      );
      return;
    }

    const normalizedSsid = wifiSsid.trim();
    // The password may legitimately be blank — open networks exist — but a
    // device flashed without an SSID can never reach the gateway, so it is
    // required whenever the board has a radio.
    if (supportsWifiProvisioning && !normalizedSsid) {
      updateStatus(
        'WiFi network missing',
        'error',
        `${boardType} needs a WiFi SSID baked in at flash time to reach the gateway. Enter the network name and retry.`
      );
      return;
    }

    setUploadStatus('queued');
    setUploadProgress(0);
    setUploadError(null);
    uploadSourceRef.current = activePort;

    updateStatus(
      'COM upload queued',
      'warning',
      `Upload job queued for ${normalizedPath} over ${activePort}. Preparing compile and serial flash pipeline.`
    );

    appendMonitorEntry({
      mode: 'serial',
      source: activePort,
      tone: 'info',
      message: `Starting .ino upload job for ${normalizedPath} at ${baudRate} baud.`,
    });

    try {
      const response = await apiFetch('/api/serial/upload', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          filePath: normalizedPath,
          boardType,
          comPort: activePort,
          baudRate,
          ...(supportsWifiProvisioning
            ? { wifiSsid: normalizedSsid, wifiPassword }
            : {}),
        }),
      });

      const payload = (await response.json()) as {
        ok?: boolean;
        jobId?: string;
        status?: UploadJobStatus;
        progress?: number;
        error?: string;
      };

      if (!response.ok || !payload.ok || !payload.jobId) {
        throw new Error(payload.error || 'Unable to start serial upload.');
      }

      setUploadJobId(payload.jobId);
      setUploadStatus(payload.status || 'queued');
      setUploadProgress(typeof payload.progress === 'number' ? payload.progress : 0);

      appendMonitorEntry({
        mode: 'serial',
        source: activePort,
        tone: 'info',
        message: `Upload job ${payload.jobId} started. Waiting for compile and upload output...`,
      });

      startUploadPolling(payload.jobId);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Serial upload failed to start.';
      setUploadStatus('failed');
      setUploadError(message);
      updateStatus('Upload start failed', 'error', message);

      appendMonitorEntry({
        mode: 'serial',
        source: activePort,
        tone: 'error',
        message,
      });
    }
  };

  const performOtaCheck = React.useCallback(async () => {
    const parsedPort = Number(otaPort);
    const host = otaHost.trim();

    if (!host) {
      updateStatus('OTA host missing', 'error', 'Provide a device host or IP address before checking the OTA target.');
      return null;
    }

    if (!Number.isInteger(parsedPort) || parsedPort <= 0 || parsedPort > 65535) {
      updateStatus('Invalid OTA port', 'error', 'OTA port must be a number between 1 and 65535.');
      return null;
    }

    setIsCheckingOta(true);

    try {
      const response = await apiFetch('/api/ota/check', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          host,
          port: parsedPort,
        }),
      });

      const payload = (await response.json()) as {
        ok?: boolean;
        reachable?: boolean;
        latencyMs?: number;
        error?: string;
        latestVersion?: string | null;
        checkedAt?: string;
      };

      if (!response.ok || !payload.ok) {
        throw new Error(payload.error || 'Unable to validate OTA target.');
      }

      const reachable = Boolean(payload.reachable);
      const latency = typeof payload.latencyMs === 'number' ? payload.latencyMs : null;
      const latestVersion = payload.latestVersion || null;

      if (payload.checkedAt) {
        setLastOtaCheckAt(new Date(payload.checkedAt));
      } else {
        setLastOtaCheckAt(new Date());
      }

      if (reachable) {
        updateStatus(
          'OTA target reachable',
          'success',
          `${host}:${parsedPort} is reachable${latency !== null ? ` (${latency} ms)` : ''}. ${latestVersion ? `Latest gateway release: ${latestVersion}.` : 'No gateway manifest version detected yet.'}`
        );

        appendMonitorEntry({
          mode: 'ota',
          source: `${host}:${parsedPort}`,
          tone: 'success',
          message: `OTA target check passed${latency !== null ? ` in ${latency} ms` : ''}${latestVersion ? ` (latest ${latestVersion})` : ''}.`,
        });
      } else {
        const errorMessage = payload.error || 'Target did not accept a TCP connection.';
        updateStatus('OTA target unreachable', 'error', `${host}:${parsedPort} is unreachable. ${errorMessage}`);

        appendMonitorEntry({
          mode: 'ota',
          source: `${host}:${parsedPort}`,
          tone: 'error',
          message: `OTA target unreachable: ${errorMessage}`,
        });
      }

      return {
        host,
        port: parsedPort,
        reachable,
        latencyMs: latency,
        latestVersion,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unable to validate OTA target.';
      updateStatus('OTA check failed', 'error', message);
      appendMonitorEntry({
        mode: 'ota',
        source: `${host || 'host'}:${Number.isInteger(parsedPort) ? parsedPort : otaPort}`,
        tone: 'error',
        message,
      });
      return null;
    } finally {
      setIsCheckingOta(false);
    }
  }, [appendMonitorEntry, otaHost, otaPort, updateStatus]);

  const handleOtaCheck = async () => {
    setConnectionMode('ota');
    await performOtaCheck();
  };

  const handleOtaDeploy = async () => {
    setConnectionMode('ota');

    const check = await performOtaCheck();
    if (!check?.reachable) {
      updateStatus('OTA deployment blocked', 'error', 'Target is unreachable. Run Check OTA Target and confirm connectivity before deploying.');
      return;
    }

    if (otaChannel === 'custom' && !otaToken.trim()) {
      updateStatus('Custom OTA token required', 'error', 'A secure token is required for custom OTA channels. Enter the token and try again.');
      return;
    }

    updateStatus(
      'OTA deployment queued',
      'warning',
      `Pushing the ${otaChannel} release to ${check.host}:${check.port}. Reachability validated${check.latestVersion ? ` with latest release ${check.latestVersion}` : ''}.`
    );

    appendMonitorEntry({
      mode: 'ota',
      source: `${check.host}:${check.port}`,
      tone: 'warning',
      message: `OTA deployment queued on ${otaChannel} channel.`,
    });
  };

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
                        : 'No connected USB serial device detected on this machine.'}
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
                      placeholder="No detected COM ports"
                      disabled
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
                    placeholder={firmwarePathPlaceholder}
                  />
                </div>

                {supportsWifiProvisioning && (
                  <>
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-foreground" htmlFor="serial-wifi-ssid">
                        WiFi Network (SSID)
                      </label>
                      <Input
                        id="serial-wifi-ssid"
                        value={wifiSsid}
                        onChange={(event) => setWifiSsid(event.target.value)}
                        className="border-border/60 bg-background/60"
                        placeholder="home-network-2g"
                        maxLength={32}
                        autoComplete="off"
                      />
                      <p className="text-xs text-foreground/60">
                        Baked into the firmware at compile time so the device can reach the gateway
                        after its first flash.
                      </p>
                    </div>

                    <div className="space-y-2">
                      <label className="text-sm font-medium text-foreground" htmlFor="serial-wifi-password">
                        WiFi Password
                      </label>
                      <Input
                        id="serial-wifi-password"
                        type="password"
                        value={wifiPassword}
                        onChange={(event) => setWifiPassword(event.target.value)}
                        className="border-border/60 bg-background/60"
                        placeholder="Leave blank for an open network"
                        maxLength={64}
                        autoComplete="off"
                      />
                    </div>
                  </>
                )}
              </div>

              <div className="mt-4 flex flex-wrap gap-2">
                <Button type="button" variant="outline" className="border-border/60" onClick={handleSerialSession}>
                  Open COM Session
                </Button>
                <Button type="button" className="bg-primary hover:bg-primary/90" onClick={handleSerialFlash}>
                  Flash via COM
                </Button>
              </div>

              {uploadStatus !== 'idle' && (
                <div className="mt-4 rounded-lg border border-border/60 bg-background/60 p-3">
                  <div className="mb-2 flex items-center justify-between text-xs">
                    <span className="font-semibold text-foreground">Upload status: {uploadStatus}</span>
                    <span className="text-foreground/70">{uploadProgress}%</span>
                  </div>
                  <Progress value={uploadProgress} />
                  {uploadJobId && (
                    <p className="mt-2 text-[11px] text-foreground/60">Job ID: {uploadJobId}</p>
                  )}
                  {uploadError && (
                    <p className="mt-2 text-xs text-chart-4">{uploadError}</p>
                  )}
                </div>
              )}
            </div>
          </TabsContent>

          <TabsContent value="ota" className="mt-5 space-y-5">
            <div className="rounded-lg border border-border/60 bg-muted/15 p-4">
              <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium text-foreground" htmlFor="ota-host">
                    Device Host / IP
                  </label>
                  <Input
                    id="ota-host"
                    value={otaHost}
                    onChange={(event) => setOtaHost(event.target.value)}
                    className="border-border/60 bg-background/60"
                    placeholder="Enter ESP32 OTA host/IP"
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
                <Button type="button" variant="outline" className="border-border/60" onClick={() => void handleOtaCheck()} disabled={isCheckingOta}>
                  {isCheckingOta ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                  {isCheckingOta ? 'Checking OTA' : 'Check OTA Target'}
                </Button>
                <Button type="button" className="bg-primary hover:bg-primary/90" onClick={() => void handleOtaDeploy()} disabled={isCheckingOta}>
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
              {lastOtaCheckAt && connectionMode === 'ota' && (
                <p className="text-xs text-foreground/50">
                  Last OTA check: {formatUtcTime(lastOtaCheckAt)}
                </p>
              )}
            </div>
            <Badge className={statusToneClasses[statusTone]}>{connectionMode === 'serial' ? 'COM' : 'OTA'}</Badge>
          </div>
        </div>

        <div className="rounded-lg border border-border/60 bg-background/60 p-4">
          <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
            <div className="space-y-1">
              <p className="text-sm font-semibold text-foreground">Serial Monitor</p>
              <p className="text-xs text-foreground/60">Live console output for both Serial and OTA device sessions.</p>
            </div>

            <div className="flex flex-wrap gap-2">
              <Badge variant="outline" className="border-border/60 bg-muted/40 text-foreground/70">
                {isMonitorRunning
                  ? `Running (${(monitorMode || connectionMode).toUpperCase()})`
                  : 'Stopped'}
              </Badge>
              <Button
                type="button"
                variant={isMonitorRunning ? 'outline' : 'default'}
                className={isMonitorRunning ? 'border-border/60' : 'bg-primary hover:bg-primary/90'}
                onClick={isMonitorRunning ? stopMonitor : startMonitor}
              >
                {isMonitorRunning ? <Square className="mr-2 h-4 w-4" /> : <Play className="mr-2 h-4 w-4" />}
                {isMonitorRunning ? 'Stop Monitor' : 'Start Monitor'}
              </Button>
              <Button type="button" variant="outline" className="border-border/60" onClick={clearMonitor} disabled={monitorEntries.length === 0}>
                <Trash2 className="mr-2 h-4 w-4" />
                Clear
              </Button>
              <Button type="button" variant="outline" className="border-border/60" onClick={exportMonitor} disabled={monitorEntries.length === 0}>
                <Download className="mr-2 h-4 w-4" />
                Export Logs
              </Button>
              <Button
                type="button"
                variant="outline"
                className="border-border/60"
                onClick={() => setAutoScrollMonitor((current) => !current)}
              >
                {autoScrollMonitor ? 'Auto-scroll on' : 'Auto-scroll off'}
              </Button>
            </div>
          </div>

          <div
            ref={monitorLogRef}
            className="max-h-56 overflow-y-auto rounded-md border border-border/60 bg-background/40 p-3 font-mono text-xs"
          >
            {monitorEntries.length === 0 ? (
              <p className="text-foreground/50">No console output yet. Start monitor to stream device logs for the current mode.</p>
            ) : (
              <div className="space-y-1">
                {monitorEntries.map((entry) => (
                  <div key={entry.id} className="flex flex-wrap items-center gap-2">
                    <span className="text-foreground/40">[{formatUtcTime(entry.timestamp)}]</span>
                    <span className="text-foreground/60">[{entry.mode.toUpperCase()}]</span>
                    <span className="text-foreground/50">[{entry.source}]</span>
                    <span className={monitorToneClasses[entry.tone]}>{entry.message}</span>
                  </div>
                ))}
              </div>
            )}
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
            {connectionMode === 'serial' ? (
              <>
                <Badge variant="outline" className="border-border/60 bg-muted/40 text-foreground/70">
                  {availablePorts.length > 0 ? `${availablePorts.length} detected` : 'No connected device'}
                </Badge>
                <Badge variant="outline" className="border-border/60 bg-muted/40 text-foreground/70">
                  {selectedPort || 'No active COM port'}
                </Badge>
                <Badge variant="outline" className="border-border/60 bg-muted/40 text-foreground/70">
                  {isSelectedPortConnected ? 'Connected' : 'Disconnected'}
                </Badge>
              </>
            ) : (
              <>
                <Badge variant="outline" className="border-border/60 bg-muted/40 text-foreground/70">
                  Target {otaHost || 'unset'}
                </Badge>
                <Badge variant="outline" className="border-border/60 bg-muted/40 text-foreground/70">
                  Port {otaPort || 'unset'}
                </Badge>
                <Badge variant="outline" className="border-border/60 bg-muted/40 text-foreground/70">
                  Channel {otaChannel}
                </Badge>
              </>
            )}
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
            COM detection uses real connected USB serial devices from the local host. If your board is not listed, check cable, drivers, board power, and rescan.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
