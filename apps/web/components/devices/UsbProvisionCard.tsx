'use client';

import React from 'react';
import { AlertCircle, CheckCircle2, KeyRound, Loader2, Search, Wifi } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PermissionNotice } from '@/components/auth/PermissionNotice';
import { type AgentDeviceInfo, getAgentDeviceInfo, provisionAgentDevice } from '@/lib/local-agent';
import { registerDevice } from '@/lib/device-control';
import { useLocalAgent } from '@/lib/use-local-agent';
import { useCurrentUser } from '@/lib/use-current-user';

type Phase = 'idle' | 'reading' | 'registering' | 'writing' | 'done';

/**
 * Configure a freshly flashed board from the website, over its COM port.
 *
 * 1. Ask the board for its id (SOTA:INFO via the local agent).
 * 2. Ask the gateway, through this dashboard's server, for a token that only
 *    that board can use.
 * 3. Write Wi-Fi, gateway URL and token into the board's NVS (SOTA:PROVISION).
 *
 * After its reboot the board joins Wi-Fi, heartbeats with its own token and
 * appears in the device table, from where it can be updated over the internet.
 */
export function UsbProvisionCard() {
  const { agent, ports, checked } = useLocalAgent(true);
  const { can } = useCurrentUser();
  const mayProvision = can('devices.flash');

  const [chosenPort, setPort] = React.useState('');
  const [reading, setBoardReading] = React.useState<{ port: string; info: AgentDeviceInfo } | null>(null);
  const [ssid, setSsid] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [gatewayUrl, setGatewayUrl] = React.useState('');
  const [issueToken, setIssueToken] = React.useState(true);
  const [phase, setPhase] = React.useState<Phase>('idle');
  const [error, setError] = React.useState<string | null>(null);
  const [summary, setSummary] = React.useState<string | null>(null);

  // Follow plug/unplug without an effect: fall back to the first port when
  // the chosen one disappears, and only trust a board reading for its port.
  const port = ports.some((entry) => entry.path === chosenPort) ? chosenPort : (ports[0]?.path ?? '');
  const board = reading && reading.port === port ? reading.info : null;
  const setBoard = (info: AgentDeviceInfo | null) => setBoardReading(info ? { port, info } : null);

  const busy = phase === 'reading' || phase === 'registering' || phase === 'writing';
  const agentTooOld = Boolean(agent && agent.version.localeCompare('1.1.0', undefined, { numeric: true }) < 0);

  const readBoard = async () => {
    if (!port) return;
    setError(null);
    setSummary(null);
    setPhase('reading');
    try {
      const info = await getAgentDeviceInfo(port);
      setBoard(info);
      if (info.wifi_ssid && !ssid) setSsid(info.wifi_ssid);
      if (info.backend_url && !gatewayUrl && !info.backend_url.startsWith('CHANGE_ME')) setGatewayUrl(info.backend_url);
      setPhase('idle');
    } catch (err) {
      setBoard(null);
      setError(err instanceof Error ? err.message : String(err));
      setPhase('idle');
    }
  };

  const provision = async () => {
    if (!board || !port) return;
    setError(null);
    setSummary(null);
    try {
      let token: string | undefined;
      let backendUrl = gatewayUrl.trim().replace(/\/$/, '');

      if (issueToken) {
        setPhase('registering');
        const registered = await registerDevice(board.device_id, board.device_type);
        token = registered.token;
        if (!backendUrl && registered.gatewayUrl) {
          backendUrl = registered.gatewayUrl;
          setGatewayUrl(backendUrl);
        }
      }

      if (backendUrl && !/^https?:\/\//.test(backendUrl)) {
        throw new Error('Gateway URL must start with http:// or https://');
      }

      setPhase('writing');
      const written = await provisionAgentDevice(port, {
        ...(ssid.trim() ? { ssid: ssid.trim(), password } : {}),
        ...(backendUrl ? { backend_url: backendUrl } : {}),
        ...(token ? { device_token: token } : {}),
      });
      setPhase('done');
      setSummary(
        `Wrote ${written.join(', ')} to ${board.device_id} on ${port}. The board is rebooting; it should appear in the ` +
          'device table within about 20 seconds and can then be updated over the internet.'
      );
      setPassword('');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setPhase('idle');
    }
  };

  return (
    <Card id="usb-provision">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <KeyRound className="w-5 h-5 text-primary" />
          Provision over USB
        </CardTitle>
        <CardDescription>
          After flashing, give the board its Wi-Fi, the gateway address and its own device token through the COM
          port. Needs the SecureOTA Agent (v1.1.0+) and firmware 2.5.0+. The Wi-Fi password goes from this page to the
          agent on your computer and down the USB cable; it never passes through the server.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!mayProvision && <PermissionNotice capability="devices.flash" action="Provisioning a board" />}

        {checked && !agent && (
          <p className="text-sm text-muted-foreground">
            The SecureOTA Agent is not running on this computer. Start it (see the flash card above) and plug in the board.
          </p>
        )}
        {agentTooOld && (
          <p className="text-sm text-chart-4">
            Agent v{agent?.version} cannot provision. Download the current agent from /agent/secureota_agent.py and restart it.
          </p>
        )}

        {agent && (
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="provision-port">COM port</Label>
              <div className="flex gap-2">
                <select
                  id="provision-port"
                  className="h-9 flex-1 rounded-md border border-border bg-background px-2 text-sm"
                  value={port}
                  onChange={(event) => {
                    setPort(event.target.value);
                    setBoard(null);
                  }}
                  disabled={busy || ports.length === 0}
                >
                  {ports.length === 0 && <option value="">No board plugged in</option>}
                  {ports.map((entry) => (
                    <option key={entry.path} value={entry.path}>
                      {entry.path} - {entry.description}
                    </option>
                  ))}
                </select>
                <Button type="button" variant="outline" onClick={readBoard} disabled={!port || busy || !mayProvision || agentTooOld}>
                  {phase === 'reading' ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Search className="mr-2 h-4 w-4" />}
                  Read board
                </Button>
              </div>
              {board && (
                <div className="rounded-md border border-border/60 bg-muted/20 p-3 text-xs space-y-1">
                  <p>
                    <span className="text-muted-foreground">Device id:</span> <span className="font-mono">{board.device_id}</span>
                  </p>
                  <p>
                    <span className="text-muted-foreground">Firmware:</span> v{board.version} · {board.chip || board.device_type}
                  </p>
                  <p>
                    <span className="text-muted-foreground">Wi-Fi:</span>{' '}
                    {board.wifi_configured ? `${board.wifi_ssid || 'configured'}${board.wifi_connected ? ` (connected, ${board.ip})` : ' (not connected)'}` : 'not configured'}
                  </p>
                  <p>
                    <span className="text-muted-foreground">Gateway:</span> {board.backend_url || 'not set'} ·{' '}
                    {board.has_device_token ? 'has a device token' : 'no device token'}
                  </p>
                </div>
              )}
            </div>

            <div className="space-y-3">
              <div className="space-y-1">
                <Label htmlFor="provision-ssid">Wi-Fi network</Label>
                <Input id="provision-ssid" value={ssid} onChange={(event) => setSsid(event.target.value)} disabled={busy} placeholder="Leave blank to keep the current one" />
              </div>
              <div className="space-y-1">
                <Label htmlFor="provision-pass">Wi-Fi password</Label>
                <Input id="provision-pass" type="password" autoComplete="off" value={password} onChange={(event) => setPassword(event.target.value)} disabled={busy || !ssid.trim()} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="provision-url">Gateway URL the board should use</Label>
                <Input id="provision-url" value={gatewayUrl} onChange={(event) => setGatewayUrl(event.target.value)} disabled={busy} placeholder="https://gw.example.com (blank = server default)" />
              </div>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={issueToken} onChange={(event) => setIssueToken(event.target.checked)} disabled={busy} />
                Issue a new device token (replaces any previous token for this board)
              </label>
              <Button type="button" onClick={provision} disabled={!board || busy || !mayProvision || agentTooOld} className="w-full">
                {busy ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Wifi className="mr-2 h-4 w-4" />}
                {phase === 'registering' ? 'Issuing token…' : phase === 'writing' ? 'Writing to board…' : 'Provision board'}
              </Button>
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
      </CardContent>
    </Card>
  );
}
