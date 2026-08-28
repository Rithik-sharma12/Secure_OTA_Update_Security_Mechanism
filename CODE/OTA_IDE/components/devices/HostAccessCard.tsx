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
import { apiFetch } from '@/lib/client-auth';

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
            onClick={() => void loadState()}
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

          {isLoading ? (
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
                        disabled={isPending}
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
                          disabled={isPending}
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
            Grants are recorded per account and expire automatically. A COM flash or network scan is
            refused with a clear prompt until the matching resource is granted here.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
