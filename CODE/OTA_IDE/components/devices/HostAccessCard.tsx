'use client';

import React from 'react';
import {
  AlertCircle,
  CheckCircle2,
  Loader2,
  Lock,
  Network,
  Radar,
  RefreshCw,
  ShieldCheck,
  Unlock,
  Usb,
  Wifi,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  type BrowserSerialDevice,
  forgetSerialDevice,
  isWebSerialSupported,
  listAuthorizedDevices,
  onSerialDevicesChanged,
  requestSerialDevice,
} from '@/lib/web-serial';
import { useLocalAgent } from '@/lib/use-local-agent';
import { apiFetch } from '@/lib/client-auth';
import { useCurrentUser } from '@/lib/use-current-user';

type SerialPort = {
  path: string;
  description: string;
  manufacturer: string | null;
  granted: boolean;
};

type LocalNetwork = {
  cidr: string;
  address: string;
  interfaceName: string;
  granted: boolean;
};

type Grant = {
  id: string;
  resourceType: 'serial' | 'network';
  resourceId: string;
  label: string;
  grantedAt: string;
  expiresAt: number | null;
};

type DiscoveredHost = {
  ip: string;
  openPorts: number[];
  latencyMs: number;
  likelyRole: string;
};

type HostAccessState = {
  serial: { supported: boolean; error?: string; ports: SerialPort[] };
  networks: LocalNetwork[];
  grants: Grant[];
};

interface HostAccessCardProps {
  onDeployToHost?: (ip: string) => void;
}

export function HostAccessCard({ onDeployToHost }: HostAccessCardProps) {
  const [state, setState] = React.useState<HostAccessState | null>(null);
  const [isLoading, setIsLoading] = React.useState(true);
  const [pendingResource, setPendingResource] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [scanCidr, setScanCidr] = React.useState<string | null>(null);
  const [isScanning, setIsScanning] = React.useState(false);
  const [scanSummary, setScanSummary] = React.useState<string | null>(null);
  const [discovered, setDiscovered] = React.useState<DiscoveredHost[]>([]);

  // Browser-side COM access. The dashboard's server has no USB, so the
  // permission that matters is the browser's own Web Serial grant, which is
  // per-device, per-origin, and asked for through the browser's picker.
  const [browserSerial, setBrowserSerial] = React.useState<boolean | null>(null);
  const [browserDevices, setBrowserDevices] = React.useState<BrowserSerialDevice[]>([]);
  const [browserDevicesLoaded, setBrowserDevicesLoaded] = React.useState(false);
  const [isRequestingSerial, setIsRequestingSerial] = React.useState(false);
  const [serialPromptOpen, setSerialPromptOpen] = React.useState(false);
  const [serialPromptDismissed, setSerialPromptDismissed] = React.useState(false);

  // Local agent: lists COM ports by name with no browser prompt at all.
  const { agent, ports: agentPorts, checked: agentChecked, error: agentError } = useLocalAgent();

  const refreshBrowserDevices = React.useCallback(async () => {
    const devices = await listAuthorizedDevices();
    setBrowserDevices(devices);
    setBrowserDevicesLoaded(true);
    return devices;
  }, []);

  React.useEffect(() => {
    const supported = isWebSerialSupported();
    setBrowserSerial(supported);
    if (!supported) return;
    void refreshBrowserDevices();
    return onSerialDevicesChanged(() => { void refreshBrowserDevices(); });
  }, [refreshBrowserDevices]);

  // Ask for COM access as soon as we know nothing has been granted yet. The
  // picker itself needs a click, so the ask is a dialog with one button.
  // Only ask when the agent is definitely absent — with the agent running the
  // ports are already visible and a permission dialog would be noise.
  React.useEffect(() => {
    if (browserSerial && browserDevicesLoaded && browserDevices.length === 0 && !serialPromptDismissed && agentChecked && !agent) {
      setSerialPromptOpen(true);
    }
  }, [agent, agentChecked, browserDevices.length, browserDevicesLoaded, browserSerial, serialPromptDismissed]);

  const requestSerialAccess = async () => {
    setIsRequestingSerial(true);
    setError(null);
    try {
      const device = await requestSerialDevice();
      await refreshBrowserDevices();
      if (device) {
        setSerialPromptOpen(false);
        // Asked and answered — don't ask again this visit, even after a revoke.
        setSerialPromptDismissed(true);
      } else {
        setError('No device was selected in the browser picker. Plug the board in and try again.');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The browser refused serial access.');
    } finally {
      setIsRequestingSerial(false);
    }
  };

  const revokeSerialAccess = async (device: BrowserSerialDevice) => {
    setPendingResource(`serial:${device.id}`);
    setError(null);
    try {
      await forgetSerialDevice(device);
      await refreshBrowserDevices();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to revoke serial access.');
    } finally {
      setPendingResource(null);
    }
  };

  const loadState = React.useCallback(async () => {
    setError(null);
    try {
      const response = await apiFetch('/api/host/access', { cache: 'no-store' });
      const payload = (await response.json()) as HostAccessState & { ok?: boolean; error?: string };
      if (!response.ok || !payload.ok) {
        throw new Error(payload.error || `Unable to load host access (${response.status}).`);
      }
      setState({ serial: payload.serial, networks: payload.networks, grants: payload.grants });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load host access state.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void loadState();
  }, [loadState]);

  // Consent to use a port or sweep a subnet precedes flashing, so it sits at
  // the same level: operators and admins.
  const { can, reasonFor } = useCurrentUser();
  const mayGrant = can('host.grant');

  const grant = async (resourceType: 'serial' | 'network', resourceId: string, label: string) => {
    setPendingResource(`${resourceType}:${resourceId}`);
    setError(null);
    try {
      const response = await apiFetch('/api/host/access', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ resourceType, resourceId, label }),
      });
      const payload = (await response.json()) as { ok?: boolean; error?: string };
      if (!response.ok || !payload.ok) {
        throw new Error(payload.error || 'Unable to grant access.');
      }
      await loadState();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to grant access.');
    } finally {
      setPendingResource(null);
    }
  };

  const revoke = async (grantId: string, resourceKey: string) => {
    setPendingResource(resourceKey);
    setError(null);
    try {
      const response = await apiFetch('/api/host/access', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ grantId }),
      });
      const payload = (await response.json()) as { ok?: boolean; error?: string };
      if (!response.ok || !payload.ok) {
        throw new Error(payload.error || 'Unable to revoke access.');
      }
      await loadState();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to revoke access.');
    } finally {
      setPendingResource(null);
    }
  };

  const grantIdFor = React.useCallback(
    (resourceType: 'serial' | 'network', resourceId: string) => {
      const target = resourceType === 'serial' ? resourceId.toUpperCase() : resourceId.toLowerCase();
      return state?.grants.find(
        (g) =>
          g.resourceType === resourceType &&
          (resourceType === 'serial'
            ? g.resourceId.toUpperCase() === target
            : g.resourceId.toLowerCase() === target)
      )?.id;
    },
    [state?.grants]
  );

  const runScan = async (cidr: string) => {
    setScanCidr(cidr);
    setIsScanning(true);
    setScanSummary(null);
    setDiscovered([]);
    setError(null);
    try {
      const response = await apiFetch('/api/network/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cidr }),
      });
      const payload = (await response.json()) as {
        ok?: boolean;
        error?: string;
        found?: DiscoveredHost[];
        scannedHosts?: number;
        durationMs?: number;
      };
      if (!response.ok || !payload.ok) {
        throw new Error(payload.error || 'Network scan failed.');
      }
      setDiscovered(payload.found || []);
      setScanSummary(
        `${payload.found?.length ?? 0} device(s) responding across ${payload.scannedHosts ?? 0} host(s) in ${payload.durationMs ?? 0} ms.`
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Network scan failed.');
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <Card className="glass border-border/50">
      <Dialog
        open={serialPromptOpen}
        onOpenChange={(open) => {
          setSerialPromptOpen(open);
          if (!open) setSerialPromptDismissed(true);
        }}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Usb className="h-5 w-5 text-primary" />
              Allow COM port access?
            </DialogTitle>
            <DialogDescription>
              SecureOTA needs permission to use the USB serial port your board is plugged into on this
              computer. Your browser will show a list of connected devices — pick the board (for an ESP32
              devkit this is usually <span className="font-mono">CP210x</span>, <span className="font-mono">CH340</span> or{' '}
              <span className="font-mono">USB JTAG/serial</span>). Nothing is sent to the server; the permission
              stays in your browser and can be revoked here at any time.
            </DialogDescription>
          </DialogHeader>
          {error && (
            <p className="rounded-md border border-chart-4/30 bg-chart-4/10 p-2 text-xs text-chart-4">{error}</p>
          )}
          <DialogFooter className="gap-2 sm:gap-0">
            <Button
              type="button"
              variant="outline"
              className="border-border/60"
              onClick={() => {
                setSerialPromptOpen(false);
                setSerialPromptDismissed(true);
              }}
            >
              Not now
            </Button>
            <Button
              type="button"
              className="bg-primary hover:bg-primary/90"
              disabled={isRequestingSerial}
              onClick={() => void requestSerialAccess()}
            >
              {isRequestingSerial ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Unlock className="mr-2 h-4 w-4" />}
              Choose device &amp; allow
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <CardHeader className="space-y-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="space-y-1">
            <CardTitle className="flex items-center gap-2">
              <ShieldCheck className="h-5 w-5 text-chart-1" />
              Host Access Control
            </CardTitle>
            <CardDescription>
              Grant this account explicit, time-limited access to a physical COM port or the local
              network before any flash or OTA operation can use it.
            </CardDescription>
          </div>
          <Button
            type="button"
            variant="outline"
            className="border-border/60"
            onClick={() => {
              void loadState();
              if (browserSerial) void refreshBrowserDevices();
            }}
            disabled={isLoading}
          >
            {isLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
            Refresh
          </Button>
        </div>
      </CardHeader>

      <CardContent className="space-y-6">
        {error && (
          <div className="rounded-lg border border-chart-4/30 bg-chart-4/10 p-3 text-sm text-chart-4">
            {error}
          </div>
        )}

        {/* Serial (COM) access */}
        <section className="space-y-3">
          <div className="flex items-center gap-2">
            <Usb className="h-4 w-4 text-primary" />
            <p className="text-sm font-semibold text-foreground">Serial (COM) port access</p>
          </div>

          {/* Local agent status + its ports (no browser permission involved) */}
          <div className={`flex flex-wrap items-center justify-between gap-3 rounded-md border p-3 ${agent ? 'border-chart-1/40 bg-chart-1/10' : 'border-border/60 bg-muted/20'}`}>
            <div className="space-y-0.5">
              <p className="text-sm text-foreground/80">
                {!agentChecked
                  ? 'Looking for the SecureOTA Agent on this computer…'
                  : agent
                    ? `SecureOTA Agent v${agent.version} connected - COM ports on this computer are detected automatically.`
                    : 'SecureOTA Agent is not running on this computer.'}
              </p>
              <p className="text-xs text-foreground/55">
                {agent
                  ? agent.esptool
                    ? 'Flashing and the serial monitor run through the agent.'
                    : 'The flash tool is missing - restart the agent to install it.'
                  : agentChecked
                    ? 'The agent lists ports by name (COM7) and works in any browser. If it is running but not detected, Chrome may have asked "allow this site to access your local network" - choose Allow, then Refresh.'
                    : ''}
              </p>
              {agentError && <p className="text-xs text-chart-4">{agentError}</p>}
            </div>
            {agentChecked && !agent && (
              <div className="text-xs text-foreground/70">
                <a className="underline" href="/agent/secureota_agent.py" download>Download the SecureOTA Agent</a>
                {' '}and open it with Python; keep its window open.
              </div>
            )}
          </div>

          {agentPorts.map((port) => (
            <div
              key={`agent:${port.path}`}
              className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-border/60 bg-background/50 p-3"
            >
              <div className="min-w-0 space-y-0.5">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm text-foreground">{port.path}</span>
                  <Badge className="bg-chart-1/20 text-chart-1">
                    <Unlock className="mr-1 h-3 w-3" />
                    Available
                  </Badge>
                </div>
                <p className="truncate text-xs text-foreground/60">
                  {port.description}
                  {port.serialNumber ? ` · SN ${port.serialNumber}` : ''}
                  {port.vendorId ? ` · VID ${port.vendorId}` : ''}
                  {port.productId ? ` · PID ${port.productId}` : ''}
                </p>
              </div>
              <span className="text-xs text-foreground/50">via SecureOTA Agent</span>
            </div>
          ))}

          {agent && agentPorts.length === 0 && (
            <p className="rounded-md border border-border/60 bg-muted/20 p-3 text-sm text-foreground/60">
              No USB serial device is plugged into this computer. Connect the board - it appears here within a few seconds.
            </p>
          )}

          {browserSerial && !agent ? (
            <div className="space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-border/60 bg-muted/20 p-3">
                <div className="space-y-0.5">
                  <p className="text-sm text-foreground/80">
                    {!browserDevicesLoaded
                      ? 'Checking which COM devices this browser may use…'
                      : browserDevices.length === 0
                        ? 'No COM port is granted to this dashboard yet.'
                        : `${browserDevices.length} COM device(s) granted and connected to this computer.`}
                  </p>
                  <p className="text-xs text-foreground/55">
                    Access is granted by your browser, per device. It persists for this site until revoked.
                  </p>
                </div>
                <Button
                  type="button"
                  className="bg-primary hover:bg-primary/90"
                  disabled={isRequestingSerial}
                  onClick={() => void requestSerialAccess()}
                >
                  {isRequestingSerial ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Unlock className="mr-2 h-4 w-4" />}
                  {browserDevices.length === 0 ? 'Grant COM port access' : 'Grant another device'}
                </Button>
              </div>

              {browserDevices.map((device) => {
                const resourceKey = `serial:${device.id}`;
                const isPending = pendingResource === resourceKey;
                return (
                  <div
                    key={device.id}
                    className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-border/60 bg-background/50 p-3"
                  >
                    <div className="min-w-0 space-y-0.5">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm text-foreground">{device.label}</span>
                        <Badge className="bg-chart-1/20 text-chart-1">
                          <Unlock className="mr-1 h-3 w-3" />
                          Granted
                        </Badge>
                      </div>
                      <p className="truncate text-xs text-foreground/60">
                        {device.description}
                        {device.vendorId ? ` · VID ${device.vendorId}` : ''}
                        {device.productId ? ` · PID ${device.productId}` : ''}
                      </p>
                    </div>
                    <Button
                      type="button"
                      variant="outline"
                      className="border-border/60"
                      disabled={isPending}
                      onClick={() => void revokeSerialAccess(device)}
                    >
                      {isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Lock className="mr-2 h-4 w-4" />}
                      Revoke
                    </Button>
                  </div>
                );
              })}
            </div>
          ) : agent ? null : browserSerial === false && agentChecked ? (
            <p className="rounded-md border border-chart-4/30 bg-chart-4/10 p-3 text-sm text-chart-4">
              This browser cannot access COM ports directly (no Web Serial). Run the SecureOTA Agent above, or open the
              dashboard in Chrome or Edge on the computer the board is plugged into.
            </p>
          ) : isLoading ? (
            <p className="text-sm text-foreground/50">Detecting connected devices…</p>
          ) : !state?.serial.supported ? (
            <p className="rounded-md border border-border/60 bg-muted/20 p-3 text-sm text-foreground/60">
              {state?.serial.error || 'Automatic COM detection is not available on this host.'}
            </p>
          ) : state.serial.ports.length === 0 ? (
            <p className="rounded-md border border-border/60 bg-muted/20 p-3 text-sm text-foreground/60">
              No connected USB serial device detected. Plug in a board and press Refresh.
            </p>
          ) : (
            <div className="space-y-2">
              {state.serial.ports.map((port) => {
                const resourceKey = `serial:${port.path}`;
                const isPending = pendingResource === resourceKey;
                return (
                  <div
                    key={port.path}
                    className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-border/60 bg-background/50 p-3"
                  >
                    <div className="min-w-0 space-y-0.5">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm text-foreground">{port.path}</span>
                        {port.granted ? (
                          <Badge className="bg-chart-1/20 text-chart-1">
                            <Unlock className="mr-1 h-3 w-3" />
                            Granted
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="border-border/60 text-foreground/60">
                            <Lock className="mr-1 h-3 w-3" />
                            Not granted
                          </Badge>
                        )}
                      </div>
                      <p className="truncate text-xs text-foreground/60">{port.description}</p>
                    </div>
                    {port.granted ? (
                      <Button
                        type="button"
                        variant="outline"
                        className="border-border/60"
                        disabled={isPending}
                        onClick={() => {
                          const id = grantIdFor('serial', port.path);
                          if (id) void revoke(id, resourceKey);
                        }}
                      >
                        {isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Lock className="mr-2 h-4 w-4" />}
                        Revoke
                      </Button>
                    ) : (
                      <Button
                        type="button"
                        className="bg-primary hover:bg-primary/90"
                        disabled={isPending || !mayGrant}
                        title={mayGrant ? undefined : reasonFor('host.grant')}
                        onClick={() => void grant('serial', port.path, port.description)}
                      >
                        {isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Unlock className="mr-2 h-4 w-4" />}
                        Grant access
                      </Button>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </section>

        {/* Local network access */}
        <section className="space-y-3">
          <div className="flex items-center gap-2">
            <Network className="h-4 w-4 text-chart-2" />
            <p className="text-sm font-semibold text-foreground">Local network access</p>
          </div>

          {isLoading ? (
            <p className="text-sm text-foreground/50">Reading host network interfaces…</p>
          ) : !state || state.networks.length === 0 ? (
            <p className="rounded-md border border-border/60 bg-muted/20 p-3 text-sm text-foreground/60">
              No local IPv4 network detected on this host.
            </p>
          ) : (
            <div className="space-y-2">
              {state.networks.map((network) => {
                const resourceKey = `network:${network.cidr}`;
                const isPending = pendingResource === resourceKey;
                return (
                  <div
                    key={network.cidr}
                    className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-border/60 bg-background/50 p-3"
                  >
                    <div className="min-w-0 space-y-0.5">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm text-foreground">{network.cidr}</span>
                        {network.granted ? (
                          <Badge className="bg-chart-1/20 text-chart-1">
                            <Unlock className="mr-1 h-3 w-3" />
                            Granted
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="border-border/60 text-foreground/60">
                            <Lock className="mr-1 h-3 w-3" />
                            Not granted
                          </Badge>
                        )}
                      </div>
                      <p className="truncate text-xs text-foreground/60">
                        {network.interfaceName} · host {network.address}
                      </p>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {network.granted && (
                        <Button
                          type="button"
                          variant="outline"
                          className="border-border/60"
                          disabled={isScanning}
                          onClick={() => void runScan(network.cidr)}
                        >
                          {isScanning && scanCidr === network.cidr ? (
                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          ) : (
                            <Radar className="mr-2 h-4 w-4" />
                          )}
                          Discover devices
                        </Button>
                      )}
                      {network.granted ? (
                        <Button
                          type="button"
                          variant="outline"
                          className="border-border/60"
                          disabled={isPending}
                          onClick={() => {
                            const id = grantIdFor('network', network.cidr);
                            if (id) void revoke(id, resourceKey);
                          }}
                        >
                          {isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Lock className="mr-2 h-4 w-4" />}
                          Revoke
                        </Button>
                      ) : (
                        <Button
                          type="button"
                          className="bg-primary hover:bg-primary/90"
                          disabled={isPending || !mayGrant}
                          title={mayGrant ? undefined : reasonFor('host.grant')}
                          onClick={() => void grant('network', network.cidr, `LAN ${network.cidr}`)}
                        >
                          {isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Unlock className="mr-2 h-4 w-4" />}
                          Grant access
                        </Button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {scanSummary && (
            <p className="flex items-center gap-2 text-xs text-foreground/60">
              <CheckCircle2 className="h-3.5 w-3.5 text-chart-1" />
              {scanSummary}
            </p>
          )}

          {discovered.length > 0 && (
            <div className="space-y-2 rounded-lg border border-border/60 bg-background/40 p-3">
              <p className="text-xs font-semibold uppercase tracking-wide text-foreground/60">
                Discovered devices
              </p>
              {discovered.map((host) => (
                <div
                  key={host.ip}
                  className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-border/50 bg-background/60 p-2.5"
                >
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <Wifi className="h-3.5 w-3.5 text-chart-2" />
                      <span className="font-mono text-sm text-foreground">{host.ip}</span>
                      <Badge variant="outline" className="border-border/60 text-foreground/60">
                        {host.likelyRole}
                      </Badge>
                    </div>
                    <p className="text-xs text-foreground/50">
                      Ports {host.openPorts.join(', ')} · {host.latencyMs} ms
                    </p>
                  </div>
                  {onDeployToHost && (
                    <Button
                      type="button"
                      variant="outline"
                      className="border-border/60"
                      onClick={() => onDeployToHost(host.ip)}
                    >
                      Deploy via OTA
                    </Button>
                  )}
                </div>
              ))}
            </div>
          )}
        </section>

        <div className="flex items-start gap-2 text-xs text-foreground/50">
          <AlertCircle className="mt-0.5 h-3.5 w-3.5 text-chart-3" />
          <p>
            {browserSerial
              ? 'COM access is a browser permission on this computer and never expires until revoked. Network grants are recorded per account and expire automatically. A flash or scan is refused with a clear prompt until the matching resource is granted here.'
              : 'Grants are recorded per account and expire automatically. A COM flash or network scan is refused with a clear prompt until the matching resource is granted here.'}
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
