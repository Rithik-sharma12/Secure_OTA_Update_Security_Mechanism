'use client';

import React from 'react';
import { AlertCircle, CheckCircle2, Cpu, Loader2, Plug, PlugZap, Square, Terminal, Usb, Zap } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import { apiFetch } from '@/lib/client-auth';
import {
  type BrowserSerialDevice,
  isWebSerialSupported,
  listAuthorizedDevices,
  onSerialDevicesChanged,
  requestSerialDevice,
} from '@/lib/web-serial';
import { getAgentJob, openAgentMonitor, startAgentFlash } from '@/lib/local-agent';
import { useLocalAgent } from '@/lib/use-local-agent';

type Transport = import('esptool-js').Transport;
type ESPLoader = import('esptool-js').ESPLoader;

/**
 * Where the image goes. PlatformIO's firmware.bin is the app image only and
 * lives at the app partition; a merged image (bootloader + partition table +
 * boot_app0 + app, as `./go-online.sh build` writes to firmware-full.bin)
 * starts at 0x0 and is what a blank board needs.
 */
const IMAGE_LAYOUTS = [
  { id: 'app', label: 'App image (0x10000)', address: 0x10000, hint: 'OTA-style firmware.bin, board already has a bootloader' },
  { id: 'full', label: 'Full image (0x0)', address: 0x0, hint: 'Merged image for a blank board' },
] as const;
type LayoutId = (typeof IMAGE_LAYOUTS)[number]['id'];

const DEVICE_TYPES = ['ESP32', 'ESP8266'] as const;
const FLASH_BAUD = 921600;
const MONITOR_BAUD = 115200;
const MAX_LOG_LINES = 400;

type Phase = 'idle' | 'connecting' | 'loading' | 'flashing' | 'done' | 'error';
type Source = 'file' | 'release';

type FlashImage = {
  label: string;
  bytes: Uint8Array;
  version?: string;
  sha256?: string;
};

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/**
 * Flash an ESP32 over USB straight from the browser (Web Serial + esptool-js).
 *
 * The dashboard runs in a container with no serial hardware, so the
 * arduino-cli path in DeviceConnectionCard cannot see a COM port there. This
 * card moves the flash to the machine the board is plugged into: the page is
 * served over HTTPS through the tunnel, Chrome/Edge grants the port, and the
 * bytes never touch the server except when pulling the latest release.
 */
export function WebSerialFlashCard() {
  const [supported, setSupported] = React.useState<boolean | null>(null);
  const [phase, setPhase] = React.useState<Phase>('idle');
  const [source, setSource] = React.useState<Source>('file');
  const [layout, setLayout] = React.useState<LayoutId>('app');
  const [deviceType, setDeviceType] = React.useState<(typeof DEVICE_TYPES)[number]>('ESP32');
  const [file, setFile] = React.useState<File | null>(null);
  const [eraseAll, setEraseAll] = React.useState(false);
  const [progress, setProgress] = React.useState(0);
  const [chipName, setChipName] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [summary, setSummary] = React.useState<string | null>(null);
  const [log, setLog] = React.useState<string[]>([]);
  const [monitoring, setMonitoring] = React.useState(false);
  const [devices, setDevices] = React.useState<BrowserSerialDevice[]>([]);
  const [selectedDeviceId, setSelectedDeviceId] = React.useState<string | null>(null);
  const [authorizing, setAuthorizing] = React.useState(false);

  // Local agent: real COM names, no picker, esptool on the user's machine.
  const { agent, ports: agentPorts, checked: agentChecked } = useLocalAgent();

  const fileInputRef = React.useRef<HTMLInputElement>(null);
  const logEndRef = React.useRef<HTMLDivElement>(null);
  const monitorStopRef = React.useRef<(() => Promise<void>) | null>(null);

  React.useEffect(() => {
    setSupported(isWebSerialSupported());
  }, []);

  const refreshDevices = React.useCallback(async () => {
    const found = await listAuthorizedDevices();
    setDevices(found);
  }, []);

  // Enumerate authorized devices on mount and whenever one is plugged or unplugged.
  React.useEffect(() => {
    if (supported !== true) return;
    void refreshDevices();
    return onSerialDevicesChanged(() => { void refreshDevices(); });
  }, [refreshDevices, supported]);

  // One list for the UI: agent ports first (they carry the COM name), then
  // browser-granted devices. Ids are prefixed so the two can't collide.
  type Target =
    | { kind: 'agent'; id: string; label: string; path: string; description: string }
    | { kind: 'browser'; id: string; label: string; device: BrowserSerialDevice };
  const targets = React.useMemo<Target[]>(
    () => [
      ...agentPorts.map((port) => ({
        kind: 'agent' as const,
        id: `agent:${port.path}`,
        label: `${port.path} · ${port.description}`,
        path: port.path,
        description: port.description,
      })),
      ...devices.map((device) => ({ kind: 'browser' as const, id: `browser:${device.id}`, label: device.label, device })),
    ],
    [agentPorts, devices]
  );

  // Keep the selection valid as devices come and go; prefer the first target.
  React.useEffect(() => {
    setSelectedDeviceId((current) => {
      if (current && targets.some((target) => target.id === current)) return current;
      return targets[0]?.id ?? null;
    });
  }, [targets]);

  const selectedTarget = targets.find((target) => target.id === selectedDeviceId) ?? null;
  const selectedDevice = selectedTarget?.kind === 'browser' ? selectedTarget.device : null;
  const canUsePort = Boolean(selectedTarget) || supported === true;

  // The browser picker is the one-time grant; afterwards the device shows up
  // in refreshDevices() without prompting.
  const authorizeDevice = async () => {
    setAuthorizing(true);
    setError(null);
    try {
      const device = await requestSerialDevice();
      await refreshDevices();
      if (device) setSelectedDeviceId(`browser:${device.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setAuthorizing(false);
    }
  };

  // Use the selected authorized device; only fall back to the picker when
  // nothing has been authorized yet.
  const pickPort = async (): Promise<SerialPort> => {
    if (selectedDevice) return selectedDevice.port;
    return navigator.serial.requestPort();
  };

  React.useEffect(() => {
    logEndRef.current?.scrollIntoView({ block: 'end' });
  }, [log]);

  // Stop a running monitor when the card unmounts so the port is released.
  React.useEffect(() => () => { void monitorStopRef.current?.(); }, []);

  const appendLog = React.useCallback((line: string) => {
    setLog((prev) => {
      const next = [...prev, line];
      return next.length > MAX_LOG_LINES ? next.slice(next.length - MAX_LOG_LINES) : next;
    });
  }, []);

  // esptool-js writes partial lines via write(); buffer them until a newline.
  const terminal = React.useMemo(() => {
    let pending = '';
    return {
      clean: () => setLog([]),
      writeLine: (data: string) => {
        appendLog(pending + data);
        pending = '';
      },
      write: (data: string) => {
        pending += data;
        if (pending.includes('\n')) {
          const parts = pending.split('\n');
          pending = parts.pop() ?? '';
          parts.forEach((part) => appendLog(part));
        }
      },
    };
  }, [appendLog]);

  const busy = phase === 'connecting' || phase === 'loading' || phase === 'flashing';
  const layoutInfo = IMAGE_LAYOUTS.find((entry) => entry.id === layout) ?? IMAGE_LAYOUTS[0];
  const canFlash = canUsePort && !busy && !monitoring && (source === 'release' || Boolean(file));

  const handleFile = (selected: File | null) => {
    setError(null);
    setSummary(null);
    if (selected && !selected.name.toLowerCase().endsWith('.bin')) {
      setFile(null);
      setError(`"${selected.name}" is not a .bin file.`);
      return;
    }
    setFile(selected);
    // A merged image from `./go-online.sh build` is the only thing that belongs at 0x0.
    if (selected?.name.toLowerCase().includes('full')) {
      setLayout('full');
    }
  };

  const loadImage = async (): Promise<FlashImage> => {
    if (source === 'file') {
      if (!file) throw new Error('Choose a .bin file first.');
      return { label: file.name, bytes: new Uint8Array(await file.arrayBuffer()) };
    }

    const response = await apiFetch(`/api/firmware/download?device_type=${encodeURIComponent(deviceType)}`, {
      cache: 'no-store',
    });
    if (!response.ok) {
      let detail = `Gateway download failed (${response.status}).`;
      try {
        const payload = (await response.json()) as { error?: string };
        if (payload?.error) detail = payload.error;
      } catch {
        // non-JSON error body; keep the status message
      }
      throw new Error(detail);
    }
    return {
      label: response.headers.get('X-Firmware-Filename') || 'latest release',
      version: response.headers.get('X-Firmware-Version') || undefined,
      sha256: response.headers.get('X-Firmware-Sha256') || undefined,
      bytes: new Uint8Array(await response.arrayBuffer()),
    };
  };

  const flash = async () => {
    if (!canFlash) return;
    setError(null);
    setSummary(null);
    setProgress(0);
    setChipName(null);
    setLog([]);

    let transport: Transport | null = null;
    try {
      setPhase('loading');
      const image = await loadImage();
      if (image.bytes.byteLength === 0) throw new Error('The firmware image is empty.');

      // Published releases are app images. Flashing one at 0x0 wipes the
      // bootloader and leaves the board unable to boot.
      const address = source === 'release' ? 0x10000 : layoutInfo.address;
      appendLog(`[web-flash] ${image.label} (${formatBytes(image.bytes.byteLength)}) -> 0x${address.toString(16)}`);
      if (image.version) appendLog(`[web-flash] release version ${image.version}`);

      // Agent path: esptool runs on the user's machine against the real COM port.
      if (selectedTarget?.kind === 'agent') {
        setPhase('connecting');
        appendLog(`[flash] using ${selectedTarget.path} via the SecureOTA Agent`);
        const jobId = await startAgentFlash({
          port: selectedTarget.path,
          address,
          // TypeScript 5.9 made Uint8Array generic over its backing buffer, so
          // a Uint8Array<ArrayBufferLike> no longer satisfies BlobPart (which
          // requires ArrayBuffer, not SharedArrayBuffer). The bytes here always
          // come from a fetch/File read, so the buffer is a plain ArrayBuffer;
          // slicing produces one with the narrow type and copies only the
          // region actually in use.
          file: new Blob([image.bytes.slice().buffer as ArrayBuffer]),
          filename: image.label.endsWith('.bin') ? image.label : 'firmware.bin',
          erase: eraseAll,
        });
        let seen = 0;
        for (;;) {
          await new Promise((resolve) => setTimeout(resolve, 700));
          const job = await getAgentJob(jobId, seen);
          job.log.forEach((line) => appendLog(line));
          seen = job.logLength;
          if (job.chip) setChipName(job.chip);
          if (job.status === 'running' && job.progress > 0) {
            setPhase('flashing');
            setProgress(job.progress);
          }
          if (job.status === 'success') {
            setProgress(100);
            setPhase('done');
            setSummary(
              `${image.label}${image.version ? ` (v${image.version})` : ''} written to ${job.chip ?? 'the board'} on ${selectedTarget.path} at 0x${address.toString(16)}. ` +
                'The board was reset; it should join Wi-Fi and heartbeat within ~15 s.'
            );
            return;
          }
          if (job.status === 'failed') {
            throw new Error(job.error || 'Flash failed.');
          }
        }
      }

      setPhase('connecting');
      // Loaded on demand: esptool-js touches navigator.serial at import time.
      const { ESPLoader, Transport } = await import('esptool-js');
      const port = await pickPort();
      transport = new Transport(port, false);

      const loader: ESPLoader = new ESPLoader({
        transport,
        baudrate: FLASH_BAUD,
        terminal,
        debugLogging: false,
      });

      const chip = await loader.main();
      setChipName(chip);
      appendLog(`[web-flash] connected: ${chip}`);

      setPhase('flashing');
      await loader.writeFlash({
        fileArray: [{ data: image.bytes, address }],
        flashSize: 'keep',
        flashMode: 'keep',
        flashFreq: 'keep',
        eraseAll,
        compress: true,
        reportProgress: (_fileIndex, written, total) => {
          setProgress(total > 0 ? Math.round((written / total) * 100) : 0);
        },
      });

      await loader.after('hard_reset');
      setProgress(100);
      setPhase('done');
      setSummary(
        `${image.label}${image.version ? ` (v${image.version})` : ''} written to ${chip} at 0x${address.toString(16)}. ` +
          'The board was reset; it should join Wi-Fi and heartbeat within ~15 s.'
      );
      appendLog('[web-flash] done, board reset');
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setPhase('error');
      setError(
        /No port selected/i.test(message)
          ? 'No port selected.'
          : /Failed to connect|Timed out|Invalid head of packet|Wrong boot mode/i.test(message)
            ? 'The board did not enter download mode. Click Connect & Flash again and hold the BOOT button on the board as soon as the yellow prompt appears — keep holding until the progress bar moves.'
            : message
      );
      appendLog(`[web-flash] error: ${message}`);
    } finally {
      try {
        await transport?.disconnect();
      } catch {
        // port already closed
      }
    }
  };

  const startMonitor = async () => {
    if (!canUsePort || busy || monitoring) return;
    setError(null);

    // Agent path: the agent opens the COM port and streams lines to us.
    if (selectedTarget?.kind === 'agent') {
      const path = selectedTarget.path;
      setMonitoring(true);
      const stop = openAgentMonitor(
        path,
        MONITOR_BAUD,
        appendLog,
        (err) => {
          monitorStopRef.current = null;
          setMonitoring(false);
          if (err) {
            setError(`Monitor: ${err}`);
            appendLog(`[monitor] ${err}`);
          } else {
            appendLog('[monitor] stopped');
          }
        }
      );
      monitorStopRef.current = async () => { stop(); };
      return;
    }

    let port: SerialPort | null = null;
    let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
    let stopped = false;

    try {
      port = await pickPort();
      await port.open({ baudRate: MONITOR_BAUD });
      setMonitoring(true);
      appendLog(`[monitor] listening at ${MONITOR_BAUD} baud`);

      monitorStopRef.current = async () => {
        stopped = true;
        try { await reader?.cancel(); } catch { /* stream already done */ }
        try { await port?.close(); } catch { /* port already closed */ }
        monitorStopRef.current = null;
        setMonitoring(false);
        appendLog('[monitor] stopped');
      };

      const decoder = new TextDecoder();
      let pending = '';
      while (!stopped && port.readable) {
        reader = port.readable.getReader();
        try {
          for (;;) {
            const { value, done } = await reader.read();
            if (done || stopped) break;
            pending += decoder.decode(value, { stream: true });
            const lines = pending.split(/\r?\n/);
            pending = lines.pop() ?? '';
            lines.forEach((line) => { if (line.length > 0) appendLog(line); });
          }
        } finally {
          reader.releaseLock();
          reader = null;
        }
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (!/No port selected/i.test(message)) setError(`Monitor: ${message}`);
      appendLog(`[monitor] ${message}`);
      await monitorStopRef.current?.();
    }
  };

  return (
    <Card id="web-serial-flash">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Usb className="w-5 h-5 text-primary" />
          Flash over USB (browser)
        </CardTitle>
        <CardDescription>
          Flashes the ESP32 plugged into <em>this</em> computer, directly from the page. Works from the
          public dashboard in Chrome or Edge - no tools installed, nothing goes through the server.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-5">
        {supported === false && !agent && agentChecked && (
          <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
            <span>
              This browser cannot access USB devices directly and the SecureOTA Agent is not running. Either open the
              dashboard in Chrome/Edge, or run the agent (see below) so any browser can use your COM ports.
            </span>
          </div>
        )}

        {/* Connected devices: local agent (COM names) + browser-granted devices */}
        <div className="rounded-lg border border-border/60 bg-muted/15 p-3 space-y-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide text-foreground/60">USB devices on this computer</p>
              <p className="text-sm text-foreground/70">
                {!agentChecked
                  ? 'Looking for the SecureOTA Agent…'
                  : targets.length === 0
                    ? agent
                      ? 'Agent connected, no serial device plugged in. Connect the board - it appears automatically.'
                      : supported
                        ? 'None found. Run the SecureOTA Agent for automatic detection, or authorize a device in the browser.'
                        : 'None found. Run the SecureOTA Agent for automatic detection.'
                    : `${targets.length} connected. Updates automatically on plug / unplug.`}
              </p>
              <p className="text-xs text-muted-foreground">
                {agent
                  ? `SecureOTA Agent v${agent.version} connected${agent.esptool ? '' : ' (flash tool missing - restart the agent to install it)'}.`
                  : agentChecked
                    ? 'SecureOTA Agent is not running on this computer.'
                    : ''}
              </p>
            </div>
            {supported && (
              <Button type="button" variant="outline" size="sm" onClick={authorizeDevice} disabled={authorizing || busy || monitoring}>
                {authorizing ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Usb className="mr-2 h-4 w-4" />}
                {authorizing ? 'Waiting for picker' : 'Authorize in browser'}
              </Button>
            )}
          </div>
          {targets.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {targets.map((target) => (
                <button
                  key={target.id}
                  type="button"
                  onClick={() => setSelectedDeviceId(target.id)}
                  aria-pressed={target.id === selectedDeviceId}
                  disabled={busy || monitoring}
                  title={target.kind === 'agent' ? 'Detected by the SecureOTA Agent' : 'Granted to this browser'}
                  className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
                    target.id === selectedDeviceId ? 'border-primary bg-primary/15 text-primary' : 'border-border text-muted-foreground hover:border-primary/40'
                  }`}
                >
                  <span className={`h-1.5 w-1.5 rounded-full ${target.id === selectedDeviceId ? 'bg-chart-1' : 'bg-muted-foreground/60'}`} />
                  {target.label}
                </button>
              ))}
            </div>
          )}
          {agentChecked && !agent && (
            <p className="text-xs text-muted-foreground">
              For automatic COM port detection, <a className="underline" href="/agent/secureota_agent.py" download>download the SecureOTA Agent</a> and
              open it with Python. Keep its window open while using this page; if the browser asks to allow access to your local network, choose Allow.
            </p>
          )}
        </div>

        {/* Source */}
        <div className="space-y-2">
          <Label>Firmware source</Label>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => setSource('file')}
              aria-pressed={source === 'file'}
              disabled={busy}
              className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
                source === 'file' ? 'border-primary bg-primary/15 text-primary' : 'border-border text-muted-foreground hover:border-primary/40'
              }`}
            >
              Local .bin file
            </button>
            <button
              type="button"
              onClick={() => setSource('release')}
              aria-pressed={source === 'release'}
              disabled={busy}
              className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
                source === 'release' ? 'border-primary bg-primary/15 text-primary' : 'border-border text-muted-foreground hover:border-primary/40'
              }`}
            >
              Latest published release
            </button>
          </div>
        </div>

        {source === 'file' ? (
          <div className="space-y-2">
            <Label htmlFor="web-flash-file">Firmware binary</Label>
            <div className="flex flex-wrap items-center gap-3">
              <Input
                id="web-flash-file"
                ref={fileInputRef}
                type="file"
                accept=".bin"
                disabled={busy}
                onChange={(event) => handleFile(event.target.files?.[0] ?? null)}
                className="max-w-sm"
              />
              {file && (
                <span className="text-xs text-muted-foreground">
                  {file.name} · {formatBytes(file.size)}
                </span>
              )}
            </div>
            <div className="flex flex-wrap gap-2 pt-1">
              {IMAGE_LAYOUTS.map((entry) => (
                <button
                  key={entry.id}
                  type="button"
                  onClick={() => setLayout(entry.id)}
                  aria-pressed={layout === entry.id}
                  disabled={busy}
                  title={entry.hint}
                  className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
                    layout === entry.id ? 'border-primary bg-primary/15 text-primary' : 'border-border text-muted-foreground hover:border-primary/40'
                  }`}
                >
                  {entry.label}
                </button>
              ))}
            </div>
            <p className="text-xs text-muted-foreground">{layoutInfo.hint}.</p>
          </div>
        ) : (
          <div className="space-y-2">
            <Label>Target architecture</Label>
            <div className="flex flex-wrap gap-2">
              {DEVICE_TYPES.map((entry) => (
                <button
                  key={entry}
                  type="button"
                  onClick={() => setDeviceType(entry)}
                  aria-pressed={deviceType === entry}
                  disabled={busy}
                  className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
                    deviceType === entry ? 'border-primary bg-primary/15 text-primary' : 'border-border text-muted-foreground hover:border-primary/40'
                  }`}
                >
                  {entry}
                </button>
              ))}
            </div>
            <p className="text-xs text-muted-foreground">
              Pulls the newest release the gateway serves for {deviceType} and writes it to the app partition
              (0x10000). The board must already have a bootloader - first flash a blank board from a full image.
            </p>
          </div>
        )}

        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={eraseAll}
            disabled={busy}
            onChange={(event) => setEraseAll(event.target.checked)}
            className="h-4 w-4 accent-primary"
          />
          Erase entire flash first (also clears saved Wi-Fi / OTA preferences)
        </label>

        {/* Actions */}
        <div className="flex flex-wrap items-center gap-2">
          <Button onClick={flash} disabled={!canFlash}>
            {busy ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Zap className="mr-2 h-4 w-4" />}
            {phase === 'loading' ? 'Loading image…' : phase === 'connecting' ? 'Connecting…' : phase === 'flashing' ? `Flashing ${progress}%` : 'Connect & Flash'}
          </Button>
          {monitoring ? (
            <Button variant="outline" onClick={() => void monitorStopRef.current?.()}>
              <Square className="mr-2 h-4 w-4" /> Stop monitor
            </Button>
          ) : (
            <Button variant="outline" onClick={startMonitor} disabled={!canUsePort || busy}>
              <Terminal className="mr-2 h-4 w-4" /> Serial monitor
            </Button>
          )}
          {chipName && (
            <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
              <Cpu className="h-3.5 w-3.5" /> {chipName}
            </span>
          )}
        </div>

        {busy && <Progress value={phase === 'flashing' ? progress : 0} className="h-2" />}

        {/* Many dev boards have no auto-program circuit: the flasher can reset
            the chip, but GPIO0 must be held low by the person at the board. */}
        {phase === 'connecting' && (
          <div className="flex items-start gap-3 rounded-md border border-chart-3/50 bg-chart-3/10 p-3 text-sm">
            <Cpu className="mt-0.5 h-5 w-5 shrink-0 text-chart-3" />
            <div className="space-y-1">
              <p className="font-semibold text-foreground">Press and hold the BOOT button on the board now</p>
              <p className="text-foreground/80">
                Keep it held until the progress bar starts moving, then let go. The board is reset automatically
                while you hold it — no need to press RESET.
              </p>
            </div>
          </div>
        )}

        {error && (
          <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
            <span>{error}</span>
          </div>
        )}

        {summary && (
          <div className="flex items-start gap-2 rounded-md border border-chart-1/40 bg-chart-1/10 p-3 text-sm">
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-chart-1" />
            <span>{summary}</span>
          </div>
        )}

        {/* Log */}
        {log.length > 0 && (
          <div className="rounded-md border border-border bg-muted/40 p-3 font-mono text-xs leading-5 max-h-64 overflow-y-auto">
            {log.map((line, index) => (
              <div key={index} className="whitespace-pre-wrap break-all">{line}</div>
            ))}
            <div ref={logEndRef} />
          </div>
        )}

        <p className="flex items-start gap-2 text-xs text-muted-foreground">
          {monitoring ? <PlugZap className="mt-0.5 h-3.5 w-3.5 shrink-0" /> : <Plug className="mt-0.5 h-3.5 w-3.5 shrink-0" />}
          <span>
            When you click Connect &amp; Flash, hold the board&apos;s BOOT button until flashing starts. A brand-new board
            needs a full image; a board that already runs this firmware takes an app image.
          </span>
        </p>
      </CardContent>
    </Card>
  );
}
