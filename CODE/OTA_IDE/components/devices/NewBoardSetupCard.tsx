'use client';

import React from 'react';
import { AlertCircle, CheckCircle2, Circle, Loader2, Rocket, Usb } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import { PermissionNotice } from '@/components/auth/PermissionNotice';
import { apiFetch } from '@/lib/client-auth';
import { getDeviceDetail, registerDevice } from '@/lib/device-control';
import { explainFlashError, flashImage, sha256Hex } from '@/lib/serial-flash';
import { type BoardLink, provisionBoard, readBoardInfo } from '@/lib/serial-provision';
import { useCurrentUser } from '@/lib/use-current-user';
import { useLocalAgent } from '@/lib/use-local-agent';
import {
  type BrowserSerialDevice,
  isWebSerialSupported,
  listAuthorizedDevices,
  onSerialDevicesChanged,
  requestSerialDevice,
} from '@/lib/web-serial';

/**
 * Bring a blank board onto the fleet from the website, then hand it to OTA.
 *
 *   1. Download the factory image (bootloader + partitions + app, written at
 *      0x0) of the newest release that has one, and check its SHA-256.
 *   2. Flash it over the COM port of the computer this page is open on:
 *      through the SecureOTA Agent, or Web Serial in Chrome/Edge.
 *   3. Read the board's id over the same cable, register it with the gateway
 *      for its own device token, and write Wi-Fi, gateway URL and token.
 *   4. Wait for its first heartbeat. From then on it is updated over the air:
 *      newer releases arrive as signed, encrypted OTA packages.
 */

// The firmware in CODE/firmware_code targets the ESP32 family, which the
// gateway files under one device type.
const DEVICE_TYPE = 'ESP32';
const MAX_LOG_LINES = 300;
const HEARTBEAT_TIMEOUT_MS = 120_000;
const HEARTBEAT_POLL_MS = 3_000;

type StepId = 'download' | 'flash' | 'identify' | 'provision' | 'online';
type StepState = 'pending' | 'active' | 'done' | 'failed';

const STEPS: Array<{ id: StepId; label: string }> = [
  { id: 'download', label: 'Download factory image' },
  { id: 'flash', label: 'Flash over USB' },
  { id: 'identify', label: 'Read board & issue its token' },
  { id: 'provision', label: 'Write Wi-Fi and gateway' },
  { id: 'online', label: 'First heartbeat: OTA ready' },
];

type Target =
  | { kind: 'agent'; id: string; label: string; path: string }
  | { kind: 'browser'; id: string; label: string; device: BrowserSerialDevice };

const noSubscription = () => () => undefined;

const initialSteps = (): Record<StepId, StepState> =>
  ({ download: 'pending', flash: 'pending', identify: 'pending', provision: 'pending', online: 'pending' });

export function NewBoardSetupCard() {
  const { can } = useCurrentUser();
  const mayFlash = can('devices.flash');
  const { agent, ports: agentPorts } = useLocalAgent();

  // Read once on the client; false during server rendering.
  const webSerial = React.useSyncExternalStore(noSubscription, isWebSerialSupported, () => false);
  const [browserDevices, setBrowserDevices] = React.useState<BrowserSerialDevice[]>([]);
  const [chosenId, setChosenId] = React.useState('');
  const [ssid, setSsid] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [gatewayUrl, setGatewayUrl] = React.useState('');
  const [eraseAll, setEraseAll] = React.useState(true);

  const [running, setRunning] = React.useState(false);
  const [steps, setSteps] = React.useState(initialSteps);
  const [progress, setProgress] = React.useState(0);
  const [log, setLog] = React.useState<string[]>([]);
  const [error, setError] = React.useState<string | null>(null);
  const [summary, setSummary] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (!webSerial) return;
    const refresh = () => void listAuthorizedDevices().then(setBrowserDevices);
    refresh();
    return onSerialDevicesChanged(refresh);
  }, [webSerial]);

  const targets = React.useMemo<Target[]>(
    () => [
      ...agentPorts.map((port) => ({
        kind: 'agent' as const,
        id: `agent:${port.path}`,
        label: `${port.path} · ${port.description} (agent)`,
        path: port.path,
      })),
      ...browserDevices.map((device) => ({
        kind: 'browser' as const,
        id: `browser:${device.id}`,
        label: `${device.label} (browser)`,
        device,
      })),
    ],
    [agentPorts, browserDevices]
  );
  const target = targets.find((entry) => entry.id === chosenId) ?? targets[0] ?? null;

  const appendLog = React.useCallback((line: string) => {
    setLog((previous) => {
      const next = [...previous, line];
      return next.length > MAX_LOG_LINES ? next.slice(next.length - MAX_LOG_LINES) : next;
    });
  }, []);

  const mark = (id: StepId, state: StepState) => setSteps((previous) => ({ ...previous, [id]: state }));

  const authorize = async () => {
    setError(null);
    try {
      const device = await requestSerialDevice();
      setBrowserDevices(await listAuthorizedDevices());
      if (device) setChosenId(`browser:${device.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const canStart = mayFlash && Boolean(target) && ssid.trim().length > 0 && !running;

  const run = async () => {
    if (!target || !canStart) return;
    setRunning(true);
    setSteps(initialSteps());
    setProgress(0);
    setLog([]);
    setError(null);
    setSummary(null);

    const link: BoardLink =
      target.kind === 'agent' ? { kind: 'agent', path: target.path } : { kind: 'browser', port: target.device.port };
    let current: StepId = 'download';

    try {
      // 1. Factory image, checked against the digest the gateway recorded.
      mark('download', 'active');
      const response = await apiFetch(
        `/api/firmware/download?image=factory&device_type=${DEVICE_TYPE}`,
        { cache: 'no-store' }
      );
      if (!response.ok) {
        const payload = (await response.json().catch(() => null)) as { error?: string } | null;
        throw new Error(payload?.error || `Factory image download failed (${response.status}).`);
      }
      const bytes = new Uint8Array(await response.arrayBuffer());
      const version = response.headers.get('X-Firmware-Version') || '';
      const latest = response.headers.get('X-Latest-Version') || version;
      const expected = (response.headers.get('X-Firmware-Sha256') || '').toLowerCase();
      const actual = await sha256Hex(bytes);
      if (!expected || actual !== expected) {
        throw new Error('The factory image does not match the digest the gateway recorded; not flashing it.');
      }
      appendLog(`[setup] factory image v${version} (${bytes.byteLength} bytes), sha256 ${actual.slice(0, 16)}… verified`);
      mark('download', 'done');

      // 2. Flash at 0x0: bootloader, partition table, boot_app0 and app.
      current = 'flash';
      mark('flash', 'active');
      const { chip } = await flashImage(
        target.kind === 'agent' ? { kind: 'agent', path: target.path } : { kind: 'browser', port: target.device.port },
        { bytes, address: 0x0, filename: `firmware_v${version}_factory.bin`, eraseAll },
        { onLog: appendLog, onProgress: setProgress }
      );
      mark('flash', 'done');

      // 3. Who is it? Then a token that only this board can use.
      current = 'identify';
      mark('identify', 'active');
      appendLog('[setup] waiting for the board to boot…');
      const info = await readBoardInfo(link);
      appendLog(`[setup] board ${info.device_id} (${info.chip || chip}) running v${info.version || version}`);
      const registered = await registerDevice(info.device_id, info.device_type || DEVICE_TYPE);
      const backendUrl = (gatewayUrl.trim() || registered.gatewayUrl || '').replace(/\/$/, '');
      if (!/^https?:\/\//.test(backendUrl)) {
        throw new Error('No gateway URL: enter the address boards use to reach the gateway.');
      }
      mark('identify', 'done');

      // 4. Wi-Fi, gateway and token into NVS; the board reboots onto the network.
      current = 'provision';
      mark('provision', 'active');
      const provisionedAt = Date.now();
      const written = await provisionBoard(link, {
        ssid: ssid.trim(),
        password,
        backend_url: backendUrl,
        device_token: registered.token,
        reset_health: true,
      });
      appendLog(`[setup] wrote ${written.join(', ')}; board is rebooting onto ${ssid.trim()}`);
      setPassword('');
      mark('provision', 'done');

      // 5. The board proves itself by heartbeating with its own token.
      current = 'online';
      mark('online', 'active');
      const deadline = Date.now() + HEARTBEAT_TIMEOUT_MS;
      let online: { fw?: string; ip?: string } | null = null;
      while (Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, HEARTBEAT_POLL_MS));
        try {
          const detail = await getDeviceDetail(info.device_id);
          const seen = detail.device?.last_seen ? Date.parse(detail.device.last_seen) : 0;
          // A little slack for clock skew between this browser and the gateway.
          if (detail.device && seen >= provisionedAt - 30_000) {
            online = { fw: detail.device.fw, ip: detail.device.ip };
            break;
          }
        } catch {
          // Not registered as online yet.
        }
      }
      if (!online) {
        throw new Error(
          `${info.device_id} was provisioned but has not reached the gateway within ${HEARTBEAT_TIMEOUT_MS / 1000} s. ` +
            'Check the Wi-Fi name and password and that the gateway URL is reachable from that network ' +
            '(the serial monitor in "Flash over USB" shows what the board is doing).'
        );
      }
      mark('online', 'done');
      setSummary(
        `${info.device_id} is online running v${online.fw || version}${online.ip ? ` at ${online.ip}` : ''}. ` +
          (latest && latest !== version
            ? `v${latest} is the newest release; the board receives it over the air.`
            : 'Future releases reach it over the air; no cable needed.')
      );
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      mark(current, 'failed');
      setError(current === 'flash' ? explainFlashError(message) : message);
      appendLog(`[setup] error: ${message}`);
    } finally {
      setRunning(false);
    }
  };

  return (
    <Card id="new-board-setup">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Rocket className="w-5 h-5 text-primary" />
          Set up a new board
        </CardTitle>
        <CardDescription>
          Plug a blank or previously used board into this computer. This flashes the latest factory image over the COM
          port, gives the board its Wi-Fi, the gateway address and its own device token over the same cable, and waits
          for it to come online. After that every update arrives over the air. Uses the SecureOTA Agent if it is running,
          otherwise Chrome or Edge (Web Serial).
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!mayFlash && <PermissionNotice capability="devices.flash" action="Setting up a board" />}

        <div className="grid gap-4 md:grid-cols-2">
          <div className="space-y-2">
            <Label htmlFor="setup-port">Board</Label>
            <div className="flex gap-2">
              <select
                id="setup-port"
                className="h-9 flex-1 rounded-md border border-border bg-background px-2 text-sm"
                value={target?.id ?? ''}
                onChange={(event) => setChosenId(event.target.value)}
                disabled={running || targets.length === 0}
              >
                {targets.length === 0 && <option value="">No board found</option>}
                {targets.map((entry) => (
                  <option key={entry.id} value={entry.id}>
                    {entry.label}
                  </option>
                ))}
              </select>
              {webSerial && (
                <Button type="button" variant="outline" onClick={() => void authorize()} disabled={running}>
                  <Usb className="mr-2 h-4 w-4" />
                  Add USB device
                </Button>
              )}
            </div>
            {!agent && !webSerial && (
              <p className="text-xs text-chart-4">
                Start the SecureOTA Agent on this computer, or open this page in Chrome or Edge to use Web Serial.
              </p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="setup-ssid">Wi-Fi name</Label>
            <Input id="setup-ssid" value={ssid} onChange={(event) => setSsid(event.target.value)} disabled={running} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="setup-password">Wi-Fi password</Label>
            <Input
              id="setup-password"
              type="password"
              autoComplete="off"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              disabled={running}
            />
          </div>

          <div className="space-y-2 md:col-span-2">
            <Label htmlFor="setup-gateway">Gateway URL (optional)</Label>
            <Input
              id="setup-gateway"
              placeholder="Defaults to the address this dashboard gives devices"
              value={gatewayUrl}
              onChange={(event) => setGatewayUrl(event.target.value)}
              disabled={running}
            />
          </div>
        </div>

        <label className="flex items-center gap-2 text-sm text-foreground/80">
          <input
            type="checkbox"
            checked={eraseAll}
            onChange={(event) => setEraseAll(event.target.checked)}
            disabled={running}
          />
          Erase the whole chip first (clears old settings and any previous OTA slot)
        </label>

        <ol className="space-y-1">
          {STEPS.map((step) => {
            const state = steps[step.id];
            return (
              <li key={step.id} className="flex items-center gap-2 text-sm">
                {state === 'done' && <CheckCircle2 className="h-4 w-4 text-chart-1" />}
                {state === 'active' && <Loader2 className="h-4 w-4 animate-spin text-primary" />}
                {state === 'failed' && <AlertCircle className="h-4 w-4 text-destructive" />}
                {state === 'pending' && <Circle className="h-4 w-4 text-muted-foreground" />}
                <span className={state === 'pending' ? 'text-muted-foreground' : 'text-foreground'}>{step.label}</span>
              </li>
            );
          })}
        </ol>

        {steps.flash === 'active' && <Progress value={progress} />}

        {error && (
          <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}
        {summary && (
          <div className="flex items-start gap-2 rounded-md border border-chart-1/40 bg-chart-1/10 px-3 py-2 text-sm text-chart-1">
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{summary}</span>
          </div>
        )}

        <Button onClick={() => void run()} disabled={!canStart}>
          {running ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Rocket className="mr-2 h-4 w-4" />}
          Flash &amp; set up
        </Button>

        {log.length > 0 && (
          <pre className="max-h-56 overflow-auto rounded-md bg-muted/50 p-3 text-xs leading-relaxed">{log.join('\n')}</pre>
        )}
      </CardContent>
    </Card>
  );
}
