'use client';

import React from 'react';
import { AlertCircle, CheckCircle2, Loader2, Rocket, Usb } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import { PermissionNotice } from '@/components/auth/PermissionNotice';
import { apiFetch } from '@/lib/client-auth';
import { getDeviceDetail, registerDevice } from '@/lib/device-control';
import { explainFlashError, flashImage, sha256Hex } from '@/lib/serial-flash';
import { inspectEspImage } from '@/lib/esp-image';
import { type BoardLink, BoardSilentError, inDownloadMode, provisionBoard, readBoardInfo } from '@/lib/serial-provision';
import { useCurrentUser } from '@/lib/use-current-user';
import { useLocalAgent } from '@/lib/use-local-agent';
import { ManualBootPanel } from '@/components/devices/ManualBootPanel';
import { fetchLocalBuildFile, useLocalBuilds } from '@/lib/local-build';
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

// The firmware in firmware targets the ESP32 family, which the
// gateway files under one device type.
const DEVICE_TYPE = 'ESP32';
const MAX_LOG_LINES = 300;
const HEARTBEAT_TIMEOUT_MS = 120_000;
const HEARTBEAT_POLL_MS = 3_000;

type StepId = 'download' | 'flash' | 'identify' | 'provision' | 'online';
type StepState = 'pending' | 'active' | 'done' | 'failed' | 'skipped';

const STEPS: Array<{ id: StepId; label: string; detail: string }> = [
  { id: 'download', label: 'Check the full image', detail: 'Reads firmware-full.bin and verifies its layout and SHA-256.' },
  { id: 'flash', label: 'Flash over USB', detail: 'Writes bootloader, partition table and app at 0x0 through the COM port.' },
  { id: 'identify', label: 'Read the board, issue its token', detail: 'Reads the board id over USB and registers it with the gateway.' },
  { id: 'provision', label: 'Write Wi-Fi and gateway', detail: 'Stores Wi-Fi, gateway URL and the device token on the board.' },
  { id: 'online', label: 'First heartbeat', detail: 'Waits for the board to check in. From here updates are over the air.' },
];

const STATE_TEXT: Record<StepState, string> = {
  pending: 'Waiting',
  active: 'Running',
  done: 'Done',
  failed: 'Failed',
  skipped: 'Skipped',
};

type Target =
  | { kind: 'agent'; id: string; label: string; path: string }
  | { kind: 'browser'; id: string; label: string; device: BrowserSerialDevice };

const noSubscription = () => () => undefined;

type ImageSource = 'build' | 'gateway' | 'file';

/** A board on Wi-Fi cannot reach "localhost" or 127.0.0.1: that is itself. */
function unreachableFromBoard(url: string) {
  return /^https?:\/\/(localhost|127\.|0\.0\.0\.0|\[::1\])/i.test(url);
}

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
  const [manualBoot, setManualBoot] = React.useState(false);
  const [manualWait, setManualWait] = React.useState<number | null>(null);
  const [imageSource, setImageSource] = React.useState<ImageSource>('file');
  const [sourceTouched, setSourceTouched] = React.useState(false);
  // Board already running this firmware: skip the image and flash steps.
  const [skipFlash, setSkipFlash] = React.useState(false);
  const localBuilds = useLocalBuilds();
  const localBuild = localBuilds.builds[0] ?? null;
  const localFull = localBuild?.files.find((entry) => entry.name === 'firmware-full.bin') ?? null;
  React.useEffect(() => {
    if (localFull && !sourceTouched) setImageSource('build');
  }, [localFull, sourceTouched]);
  const [imageFile, setImageFile] = React.useState<File | null>(null);
  const [imageNote, setImageNote] = React.useState<{ ok: boolean; text: string } | null>(null);

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

  const chooseImageFile = async (file: File | null) => {
    setImageFile(file);
    setImageNote(null);
    if (!file) return;
    const info = inspectEspImage(new Uint8Array(await file.arrayBuffer()));
    if (info.kind === 'merged') setImageNote({ ok: true, text: info.description });
    else if (info.kind === 'app')
      setImageNote({
        ok: false,
        text: 'This is an app image only (firmware.bin). A new board needs the full image, firmware-full.bin, which also contains the bootloader and partition table.',
      });
    else setImageNote({ ok: false, text: info.description });
  };

  const blockers: string[] = [];
  if (!mayFlash) blockers.push('Your account is a viewer. Ask an admin to make you an operator (Profile, User management).');
  if (!target) blockers.push('No board found. Plug it in and click "Add USB device", or start the SecureOTA Agent.');
  if (!ssid.trim()) blockers.push('Enter the Wi-Fi name the board should join.');
  if (!skipFlash && imageSource === 'build' && !localFull)
    blockers.push(
      localBuilds.loaded
        ? `No firmware has been built on this computer. Run ${localBuilds.buildCommand ?? 'scripts\\build-firmware.cmd'}.`
        : 'Looking for firmware built on this computer…'
    );
  if (!skipFlash && imageSource === 'file' && !imageFile) blockers.push('Choose firmware-full.bin (built with scripts\\build-firmware.cmd).');
  if (!skipFlash && imageSource === 'file' && imageNote && !imageNote.ok) blockers.push(imageNote.text);
  if (gatewayUrl.trim() && unreachableFromBoard(gatewayUrl.trim()))
    blockers.push("A board cannot reach localhost. Use this computer's LAN address, for example http://192.168.1.20:5000.");
  const canStart = blockers.length === 0 && !running;

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
      // 1. Full image: from a local build, or the gateway's factory image
      //    checked against the digest it recorded.
      let bytes: Uint8Array = new Uint8Array();
      let version = '';
      let latest = '';
      let chip = '';
      const downloadAndFlash = async () => {
        current = 'download';
        mark('download', 'active');
        if (imageSource === 'build') {
          if (!localBuild || !localFull) throw new Error('No local build to flash.');
          const fetched = await fetchLocalBuildFile(localBuild.env, 'firmware-full.bin');
          if (localFull.sha256 && fetched.sha256 !== localFull.sha256) {
            throw new Error('firmware-full.bin changed since it was built (SHA-256 mismatch). Rebuild, then try again.');
          }
          bytes = fetched.bytes;
          version = localBuild.version;
          const info = inspectEspImage(bytes);
          if (info.kind !== 'merged') throw new Error(`${fetched.path} is not a full image. ${info.description}`);
          appendLog(`[setup] ${fetched.path}: ${info.description}`);
        } else if (imageSource === 'file') {
          if (!imageFile) throw new Error('Choose firmware-full.bin first.');
          bytes = new Uint8Array(await imageFile.arrayBuffer());
          const info = inspectEspImage(bytes);
          if (info.kind !== 'merged') {
            throw new Error(`${imageFile.name} is not a full image. ${info.description}`);
          }
          appendLog(`[setup] ${imageFile.name}: ${info.description}`);
        } else {
          const response = await apiFetch(
            `/api/firmware/download?image=factory&device_type=${DEVICE_TYPE}`,
            { cache: 'no-store' }
          );
          if (!response.ok) {
            const payload = (await response.json().catch(() => null)) as { error?: string } | null;
            throw new Error(
              (payload?.error || `Factory image download failed (${response.status}).`) +
                ' Pick "This computer\'s build" above instead, or publish that build first (Flash over USB, Publish as a release).'
            );
          }
          bytes = new Uint8Array(await response.arrayBuffer());
          version = response.headers.get('X-Firmware-Version') || '';
          latest = response.headers.get('X-Latest-Version') || version;
          const expected = (response.headers.get('X-Firmware-Sha256') || '').toLowerCase();
          const actual = await sha256Hex(bytes);
          if (!expected || actual !== expected) {
            throw new Error('The factory image does not match the digest the gateway recorded; not flashing it.');
          }
          const info = inspectEspImage(bytes);
          if (info.kind !== 'merged') throw new Error(`The gateway's factory image is not a full image. ${info.description}`);
          appendLog(`[setup] factory image v${version} (${bytes.byteLength} bytes), sha256 ${actual.slice(0, 16)}… verified`);
        }
        mark('download', 'done');

        // 2. Flash at 0x0: bootloader, partition table, boot_app0 and app.
        current = 'flash';
        mark('flash', 'active');
        const flashed = await flashImage(
          target.kind === 'agent' ? { kind: 'agent', path: target.path } : { kind: 'browser', port: target.device.port },
          { bytes, address: 0x0, filename: imageFile?.name ?? `firmware_v${version}_full.bin`, eraseAll },
          { onLog: appendLog, onProgress: setProgress, onManualBoot: setManualWait },
          { manualBoot }
        );
        chip = flashed.chip;
        mark('flash', 'done');
      };

      if (skipFlash) {
        mark('download', 'skipped');
        mark('flash', 'skipped');
        appendLog('[setup] skipping the flash: the board already runs SecureOTA firmware');
      } else {
        await downloadAndFlash();
      }

      // 3. Who is it? Then a token that only this board can use.
      current = 'identify';
      mark('identify', 'active');
      appendLog('[setup] waiting for the board to boot…');
      let info: Awaited<ReturnType<typeof readBoardInfo>>;
      try {
        info = await readBoardInfo(link);
      } catch (err) {
        // "Already runs SecureOTA" was ticked, but the board sits in the ROM
        // bootloader: it has no firmware to run. That is exactly the state a
        // flash needs, so flash the factory image now instead of failing.
        const message = err instanceof Error ? err.message : String(err);
        const downloadMode = err instanceof BoardSilentError ? inDownloadMode(err.output) : /download mode/i.test(message);
        if (!skipFlash || !downloadMode) throw err;
        appendLog('[setup] the board is in ROM download mode, so it is not running firmware; flashing the factory image instead');
        await downloadAndFlash();
        current = 'identify';
        mark('identify', 'active');
        appendLog('[setup] waiting for the board to boot…');
        info = await readBoardInfo(link);
      }
      appendLog(`[setup] board ${info.device_id} (${info.chip || chip}) running v${info.version || version}`);
      const registered = await registerDevice(info.device_id, info.device_type || DEVICE_TYPE);
      const backendUrl = (gatewayUrl.trim() || registered.gatewayUrl || '').replace(/\/$/, '');
      if (!/^https?:\/\//.test(backendUrl)) {
        throw new Error('No gateway URL: enter the address boards use to reach the gateway.');
      }
      if (unreachableFromBoard(backendUrl)) {
        throw new Error(
          `The gateway address is ${backendUrl}, which a board on Wi-Fi cannot reach. Enter this computer's LAN ` +
            'address (for example http://192.168.1.20:5000) in Gateway URL, or set OTA_DEVICE_GATEWAY_URL.'
        );
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
        // Lets the board check the gateway's Ed25519 manifest signature (stage 5).
        ...(registered.gatewayKey ? { gateway_key: registered.gatewayKey } : {}),
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
      // `current` is also set inside downloadAndFlash(), which TS cannot see here.
      setError((current as StepId) === 'flash' ? explainFlashError(message) : message);
      appendLog(`[setup] error: ${message}`);
      // What the board printed while it was not answering, captured by the
      // agent or the Web Serial exchange: the real reason is usually in here.
      const output = (err as { output?: string[] }).output;
      if (output?.length) {
        appendLog('[setup] board output:');
        output.forEach((line) => appendLog(`  ${line}`));
      }
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
          Plug a blank or previously used board into this computer. This flashes a full firmware image over the COM
          port, gives the board its Wi-Fi, the gateway address and its own device token over the same cable, and waits
          for it to come online. After that every update arrives over the air. Uses the SecureOTA Agent if it is running,
          otherwise Chrome or Edge (Web Serial).
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!mayFlash && <PermissionNotice capability="devices.flash" action="Setting up a board" />}

        <div className="space-y-2">
          <Label>Firmware</Label>
          <div className="flex flex-wrap gap-2">
            {([
              ['build', "This computer's build"],
              ['file', 'Choose firmware-full.bin'],
              ['gateway', 'Factory image from the gateway'],
            ] as const).map(([id, label]) => (
              <button
                key={id}
                type="button"
                onClick={() => {
                  setSourceTouched(true);
                  setImageSource(id);
                }}
                aria-pressed={imageSource === id}
                disabled={running || skipFlash}
                className={`rounded-md border px-3 py-1 text-xs font-medium transition-colors ${
                  imageSource === id ? 'border-primary bg-primary/15 text-primary' : 'border-border text-muted-foreground hover:border-primary/40'
                }`}
              >
                {label}
              </button>
            ))}
          </div>
          {imageSource === 'build' ? (
            localFull && localBuild ? (
              <p className="text-xs text-muted-foreground">
                v{localBuild.version} ({localBuild.env}), built {new Date(localBuild.builtAt).toLocaleString()}:{' '}
                <code className="break-all rounded bg-muted px-1.5 py-0.5 text-foreground">{localFull.path}</code>
              </p>
            ) : (
              <p className="text-xs text-chart-4">
                No firmware has been built on this computer yet. Run{' '}
                <code className="rounded bg-muted px-1.5 py-0.5 text-foreground">{localBuilds.buildCommand ?? 'scripts\\build-firmware.cmd'}</code>{' '}
                and it appears here.{' '}
                <button type="button" className="underline" onClick={() => void localBuilds.reload()}>
                  Look again
                </button>
              </p>
            )
          ) : imageSource === 'file' ? (
            <>
              <Input
                type="file"
                accept=".bin"
                disabled={running}
                onChange={(event) => void chooseImageFile(event.target.files?.[0] ?? null)}
                className="max-w-sm"
              />
              <p className={`text-xs ${imageNote && !imageNote.ok ? 'text-destructive' : 'text-muted-foreground'}`}>
                {imageNote
                  ? imageNote.text
                  : `Pick firmware-full.bin, the factory image flashed at 0x0 (bootloader, partition table and app). ` +
                    `Not firmware.bin (app only, 0x10000) or firmware-ota.bin (signed OTA package for releases). ` +
                    (localFull
                      ? `Yours is at ${localFull.path}`
                      : 'scripts\\build-firmware.cmd writes it to firmware\\dist\\esp32dev\\.')}
              </p>
            </>
          ) : (
            <p className="text-xs text-muted-foreground">
              Uses the newest published release that has a factory image (publish one on the Releases page).
            </p>
          )}
        </div>

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
              placeholder="http://<this computer's LAN IP>:5000, or blank for the configured default"
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
        <label className="flex items-center gap-2 text-sm text-foreground/80">
          <input
            type="checkbox"
            checked={manualBoot}
            onChange={(event) => setManualBoot(event.target.checked)}
            disabled={running || skipFlash}
          />
          Manual download mode (I will press BOOT and EN; also used automatically if the reset fails)
        </label>
        <label className="flex items-center gap-2 text-sm text-foreground/80">
          <input
            type="checkbox"
            checked={skipFlash}
            onChange={(event) => setSkipFlash(event.target.checked)}
            disabled={running}
          />
          The board already runs SecureOTA firmware: skip flashing, only provision it (if it turns out to be in download mode, the image above is flashed anyway)
        </label>

        <div className="rounded-lg border border-border/60 bg-muted/10 p-3">
          <p className="mb-2 text-xs font-medium text-muted-foreground">
            Progress. These steps run in order, on their own, when you click Flash &amp; set up.
          </p>
          <ol className="grid gap-2 sm:grid-cols-5">
            {STEPS.map((step, index) => {
              const state = skipFlash && (step.id === 'download' || step.id === 'flash') && steps[step.id] === 'pending'
                ? 'skipped'
                : steps[step.id];
              const tone =
                state === 'done'
                  ? 'border-chart-1/50 bg-chart-1/10'
                  : state === 'active'
                    ? 'border-primary/60 bg-primary/10'
                    : state === 'failed'
                      ? 'border-destructive/50 bg-destructive/10'
                      : 'border-border/60 bg-background/40';
              return (
                <li key={step.id} className={`rounded-md border px-3 py-2 ${tone}`} title={step.detail}>
                  <div className="flex items-center gap-2">
                    <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-current text-[11px] font-semibold text-muted-foreground">
                      {state === 'done' ? (
                        <CheckCircle2 className="h-4 w-4 text-chart-1" />
                      ) : state === 'active' ? (
                        <Loader2 className="h-4 w-4 animate-spin text-primary" />
                      ) : state === 'failed' ? (
                        <AlertCircle className="h-4 w-4 text-destructive" />
                      ) : (
                        index + 1
                      )}
                    </span>
                    <span className="text-[11px] uppercase tracking-wide text-muted-foreground">{STATE_TEXT[state]}</span>
                  </div>
                  <p className={`mt-1.5 text-xs font-medium ${state === 'pending' || state === 'skipped' ? 'text-muted-foreground' : 'text-foreground'}`}>
                    {step.label}
                  </p>
                </li>
              );
            })}
          </ol>
        </div>

        <ManualBootPanel seconds={manualWait} />
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

        {!running && blockers.length > 0 && (
          <ul className="space-y-1 text-xs text-muted-foreground">
            {blockers.map((reason) => (
              <li key={reason} className="flex items-start gap-1.5">
                <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                <span>{reason}</span>
              </li>
            ))}
          </ul>
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
