'use client';

import React from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { formatNumber, formatUtcDate, formatUtcTime } from '@/lib/formatters';
import { useRuntimeSnapshot } from '@/lib/runtime-data';
import { chartAxis, chartColors, chartTooltipLabelStyle, chartTooltipStyle } from '@/lib/chart-theme';
import { useGuidedMode } from '@/lib/use-guided-mode';
import {
  AdoptionTile,
  FleetTile,
  PressureTile,
  ReleasesTile,
  RolloutTile,
  VersionTile,
} from '@/components/dashboard/ConsoleTiles';

const weekLabels = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

/** major*10000 + minor*100 + patch, mirroring the firmware's comparison. */
function versionRank(v: string): number {
  const [a = 0, b = 0, c = 0] = v.split('.').map((n) => parseInt(n, 10) || 0);
  return a * 10000 + b * 100 + c;
}

export default function DashboardPage() {
  const router = useRouter();
  const { snapshot, isLoading } = useRuntimeSnapshot();
  const [guided] = useGuidedMode();

  const devices = snapshot.devices;
  const fleetCount = devices.length;
  const onlineCount = devices.filter((d) => d.status === 'online').length;
  const offlineCount = devices.filter((d) => d.status === 'offline' || d.status === 'error').length;
  const updatingCount = devices.filter((d) => d.status === 'updating').length;
  // ASH-quarantined. The snapshot exposes the mapped health band rather than
  // the raw score; poor/critical are the bands under 45.
  const heldCount = devices.filter((d) => d.health === 'poor' || d.health === 'critical').length;
  const needsUpdateCount = devices.filter((d) => d.firmwareVersion !== d.latestVersion).length;

  const recentEvents = snapshot.events.slice(0, 5);
  const latestRelease = snapshot.releases[0];
  const latestVersion = latestRelease?.version ?? devices[0]?.latestVersion ?? '—';
  const onLatestCount = devices.filter((d) => d.firmwareVersion === latestVersion).length;

  const pct = (n: number) => (fleetCount > 0 ? Math.round((n / fleetCount) * 100) : 0);

  // ── Version spread across the fleet ──────────────────────────────────────
  const versionTicks = React.useMemo(() => {
    const counts = new Map<string, number>();
    devices.forEach((d) => counts.set(d.firmwareVersion, (counts.get(d.firmwareVersion) || 0) + 1));
    const sorted = [...counts.entries()].sort((a, b) => versionRank(a[0]) - versionRank(b[0]));
    const max = Math.max(1, ...sorted.map(([, n]) => n));
    return sorted.map(([version, n]) => ({
      key: version,
      height: (n / max) * 100,
      isLatest: version === latestVersion,
    }));
  }, [devices, latestVersion]);

  const needlePct = React.useMemo(() => {
    if (versionTicks.length === 0) return null;
    const i = versionTicks.findIndex((t) => t.isLatest);
    if (i < 0) return null;
    return ((i + 0.5) / versionTicks.length) * 100;
  }, [versionTicks]);

  const versionAxis = React.useMemo(() => {
    if (versionTicks.length === 0) return ['—'];
    const keys = versionTicks.map((t) => t.key);
    if (keys.length <= 4) return keys;
    return [keys[0], keys[Math.floor(keys.length / 3)], keys[Math.floor((keys.length * 2) / 3)], keys[keys.length - 1]];
  }, [versionTicks]);

  // ── 24h adoption, built from real update events ──────────────────────────
  const adoption = React.useMemo(() => {
    const now = Date.now();
    const dayAgo = now - 24 * 3600 * 1000;
    const buckets = new Array(24).fill(0);
    let seen = 0;

    snapshot.events.forEach((e) => {
      const t = e.timestamp?.getTime?.();
      if (typeof t !== 'number' || t < dayAgo || t > now) return;
      if (e.severity !== 'success') return;
      const hour = Math.min(23, Math.floor((t - dayAgo) / 3600000));
      buckets[hour] += 1;
      seen += 1;
    });

    if (seen === 0) {
      return { hasHistory: false, line: '', area: '', dot: null, delta: null };
    }

    // Cumulative, scaled into the 240x58 viewBox.
    let running = 0;
    const cumulative = buckets.map((n) => (running += n));
    const max = Math.max(1, cumulative[cumulative.length - 1]);
    const pts = cumulative.map((v, i) => {
      const x = (i / 23) * 240;
      const y = 54 - (v / max) * 48;
      return { x: Number(x.toFixed(1)), y: Number(y.toFixed(1)) };
    });

    return {
      hasHistory: true,
      line: pts.map((p) => `${p.x},${p.y}`).join(' '),
      area: `0,58 ${pts.map((p) => `${p.x},${p.y}`).join(' ')} 240,58`,
      dot: pts[pts.length - 1],
      delta: seen,
    };
  }, [snapshot.events]);

  // ── Rollout stage, from real deployments ─────────────────────────────────
  const rollout = React.useMemo(() => {
    type DeploymentLike = {
      status?: string;
      createdAt?: Date | string;
      targets?: { status?: string }[];
    };
    const list = (snapshot.deployments ?? []) as unknown as DeploymentLike[];
    const active = list.find((d) => d.status === 'pending' || d.status === 'in_progress');

    if (!active) {
      return {
        active: false,
        label: 'No rollout',
        pct: '—',
        timer: '--:--',
        note: 'Publish a release to start one',
      };
    }

    const targets = active.targets ?? [];
    const confirmed = targets.filter((t) => t.status === 'confirmed').length;
    const share = targets.length > 0 ? Math.round((confirmed / targets.length) * 100) : 0;

    const started = active.createdAt ? new Date(active.createdAt).getTime() : null;
    let timer = '--:--';
    if (started && !Number.isNaN(started)) {
      const secs = Math.max(0, Math.floor((Date.now() - started) / 1000));
      timer = `${String(Math.floor(secs / 60)).padStart(2, '0')}:${String(secs % 60).padStart(2, '0')}`;
    }

    return {
      active: true,
      label: 'In progress',
      pct: `${share}%`,
      timer,
      note: `${confirmed} of ${targets.length} confirmed`,
    };
  }, [snapshot.deployments]);

  const capsules = React.useMemo(() => {
    const slots = 10;
    const published = snapshot.releases.length;
    return Array.from({ length: slots }, (_, i) => ({
      key: `cap-${i}`,
      filled: i < Math.min(slots, published),
    }));
  }, [snapshot.releases]);

  // Onboarding steps. States are shown only where the snapshot can actually
  // determine them; the rest read as a plain action rather than a fake status.
  const steps = [
    { n: '1', label: 'Grant host access', href: '/devices', state: 'Open' },
    { n: '2', label: 'Flash a board over USB', href: '/code', state: 'Open' },
    {
      n: '3',
      label: 'Publish a signed release',
      href: '/releases',
      state: snapshot.releases.length > 0 ? 'Done' : 'Not run',
    },
    {
      n: '4',
      label: 'Watch the fleet confirm',
      href: '/devices',
      state: fleetCount > 0 ? `${onLatestCount} of ${fleetCount}` : 'No devices',
    },
  ];

  const metricsData = React.useMemo(() => {
    const counts = weekLabels.map((label) => ({ name: label, successful: 0, failed: 0 }));
    snapshot.events.forEach((event) => {
      const row = counts.find((item) => item.name === weekLabels[event.timestamp.getDay()]);
      if (!row) return;
      if (event.severity === 'success') row.successful += 1;
      else if (event.severity === 'error' || event.severity === 'warning') row.failed += 1;
    });
    return counts;
  }, [snapshot.events]);

  const deviceStatusData = React.useMemo(
    () => [
      { name: 'Online', value: onlineCount, color: chartColors.success },
      { name: 'Offline', value: offlineCount, color: chartColors.error },
      { name: 'Updating', value: updatingCount, color: chartColors.warning },
    ],
    [offlineCount, onlineCount, updatingCount]
  );

  return (
    <div className="flex flex-col gap-[22px]" style={{ animation: 'ota-in var(--dur-base) var(--ease-emphasis)' }}>
      {!snapshot.connection.reachable && snapshot.connection.error && (
        <p
          className="type-caption"
          style={{
            color: 'var(--app-err-ink)',
            background: 'var(--app-err-bg)',
            border: '1px solid var(--hairline-glow)',
            borderRadius: 8,
            padding: '10px 14px',
          }}
        >
          {snapshot.connection.error}
        </p>
      )}

      {/* ── Guided onboarding ─────────────────────────────────────────────── */}
      {guided && (
        <div
          className="relative flex flex-wrap items-center gap-6 overflow-hidden"
          style={{
            borderRadius: 18,
            border: '1px solid var(--hairline-glow)',
            backgroundColor: '#181818',
            backgroundImage:
              'linear-gradient(100deg,rgba(13,13,13,.985) 0%,rgba(13,13,13,.94) 50%,rgba(58,8,0,.88) 100%),linear-gradient(0deg,#ff2803,#ff2803),url("/brand/landing-bg.jpg")',
            backgroundBlendMode: 'normal,color,normal',
            backgroundSize: 'cover,cover,cover',
            backgroundPosition: 'center,center,center',
            padding: '26px 28px',
            boxShadow: 'var(--shadow-panel)',
          }}
        >
          <div className="min-w-[280px] flex-1">
            <div className="type-micro-cap mb-2" style={{ color: '#fff', opacity: 0.9 }}>
              Get to your first confirmed update
            </div>
            <h2 className="type-heading-lg mb-2" style={{ margin: '0 0 8px', color: '#fff' }}>
              Four steps, none of them optional.
            </h2>
            <p
              className="type-body-md"
              style={{ margin: 0, color: 'rgba(255,255,255,.86)', maxWidth: '56ch', textWrap: 'pretty' }}
            >
              Grant the console access to hardware, flash a board on your desk, publish a signed
              release, then wait for the device to confirm it. Switch to Dense once this is muscle
              memory.
            </p>
          </div>

          <div className="flex min-w-[260px] flex-col gap-2">
            {steps.map((s) => (
              <Link
                key={s.n}
                href={s.href}
                className="flex items-center gap-3 text-left"
                style={{
                  padding: '10px 14px',
                  borderRadius: 8,
                  border: '1px solid rgba(255,255,255,.22)',
                  background: 'rgba(13,13,13,.42)',
                  color: '#fff',
                  textDecoration: 'none',
                }}
              >
                <span
                  className="inline-flex shrink-0 items-center justify-center rounded-full"
                  style={{
                    width: 22,
                    height: 22,
                    font: '700 11px/1 var(--font-display)',
                    background: 'rgba(255,255,255,.16)',
                    color: '#fff',
                  }}
                >
                  {s.n}
                </span>
                <span className="type-body-strong flex-1">{s.label}</span>
                <span className="type-caption" style={{ opacity: 0.8 }}>
                  {s.state}
                </span>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* ── Console tiles ─────────────────────────────────────────────────── */}
      <div className="grid gap-3.5" style={{ gridTemplateColumns: 'repeat(auto-fit,minmax(262px,1fr))' }}>
        <PressureTile inFlight={updatingCount} total={fleetCount} />

        <RolloutTile
          active={rollout.active}
          label={rollout.label}
          pct={rollout.pct}
          timer={rollout.timer}
          note={rollout.note}
        />

        <VersionTile
          latest={latestVersion}
          ticks={versionTicks}
          needlePct={needlePct}
          axis={versionAxis}
        />

        <FleetTile
          online={onlineCount}
          total={fleetCount}
          note={
            fleetCount === 0
              ? 'No devices registered yet'
              : `${offlineCount} missed their last heartbeat · ASH under 40 is held back`
          }
          rings={[
            { label: 'online', pct: pct(onlineCount), color: '#f0f0ee', glow: 'rgba(240,240,238,.6)' },
            { label: 'updating', pct: pct(updatingCount), color: '#ff9742', glow: 'rgba(255,151,66,.7)' },
            { label: 'offline', pct: pct(offlineCount), color: '#c9c6c1', glow: 'rgba(201,198,193,.5)' },
            { label: 'held', pct: pct(heldCount), color: '#ff2803', glow: 'rgba(255,40,3,.8)' },
          ]}
        />

        <AdoptionTile
          onLatest={onLatestCount}
          latest={latestVersion}
          delta={adoption.delta}
          line={adoption.line}
          area={adoption.area}
          dot={adoption.dot}
          hasHistory={adoption.hasHistory}
          behindNote={
            needsUpdateCount > 0 ? `${needsUpdateCount} still need ${latestVersion}` : 'Whole fleet is current'
          }
        />

        <ReleasesTile
          signed={snapshot.releases.length}
          capsules={capsules}
          rotationNote={`${snapshot.keys.length} active key${snapshot.keys.length === 1 ? '' : 's'}`}
        />
      </div>

      {/* ── Charts ────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="glass border-border/50 lg:col-span-2">
          <CardHeader>
            <CardTitle>Deployment Success Rate</CardTitle>
            <CardDescription>Weekly firmware deployment performance</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={metricsData}>
                <CartesianGrid strokeDasharray="3 3" stroke={chartAxis.grid} />
                <XAxis dataKey="name" stroke={chartAxis.stroke} />
                <YAxis stroke={chartAxis.stroke} />
                <Tooltip contentStyle={chartTooltipStyle} labelStyle={chartTooltipLabelStyle} />
                <Bar dataKey="successful" fill={chartColors.success} radius={[8, 8, 0, 0]} />
                <Bar dataKey="failed" fill={chartColors.error} radius={[8, 8, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card className="glass border-border/50">
          <CardHeader>
            <CardTitle>Device Status</CardTitle>
            <CardDescription>Current device distribution</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={deviceStatusData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={2}
                  dataKey="value"
                >
                  {deviceStatusData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={chartTooltipStyle} labelStyle={chartTooltipLabelStyle} />
              </PieChart>
            </ResponsiveContainer>
            <div className="mt-4 space-y-2 text-sm">
              {deviceStatusData.map((item) => (
                <div key={item.name} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="h-2 w-2 rounded-full" style={{ backgroundColor: item.color }} />
                    <span className="text-foreground/70">{item.name}</span>
                  </div>
                  <span className="tabular font-semibold text-foreground">{item.value}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* ── Events and latest release ─────────────────────────────────────── */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card className="glass border-border/50">
          <CardHeader className="flex flex-row items-center justify-between space-y-0">
            <div>
              <CardTitle>Recent Events</CardTitle>
              <CardDescription>
                {isLoading ? 'Loading gateway telemetry…' : 'Latest system activity'}
              </CardDescription>
            </div>
            <Button variant="outline" size="sm" onClick={() => router.push('/event-logs')}>
              View All
            </Button>
          </CardHeader>
          <CardContent>
            {recentEvents.length === 0 ? (
              <p className="type-caption" style={{ color: 'var(--app-ink2)' }}>
                No events recorded yet.
              </p>
            ) : (
              <div className="space-y-3">
                {recentEvents.map((event) => (
                  <div
                    key={event.id}
                    className="flex items-start gap-3 border-b border-border/50 pb-3 last:border-0"
                  >
                    <div
                      className={`mt-1.5 h-2 w-2 flex-shrink-0 rounded-full ${
                        event.severity === 'success'
                          ? 'bg-chart-1'
                          : event.severity === 'error'
                            ? 'bg-chart-4'
                            : event.severity === 'warning'
                              ? 'bg-chart-3'
                              : 'bg-chart-2'
                      }`}
                    />
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium text-foreground">{event.title}</p>
                      <p className="mt-0.5 truncate text-xs text-foreground/50">{event.description}</p>
                      <p className="tabular mt-1 text-xs text-foreground/40">
                        {formatUtcTime(event.timestamp)}
                      </p>
                    </div>
                    <Badge
                      variant="outline"
                      className={`flex-shrink-0 ${
                        event.severity === 'success'
                          ? 'bg-chart-1/20 text-chart-1'
                          : event.severity === 'error'
                            ? 'bg-chart-4/20 text-chart-4'
                            : event.severity === 'warning'
                              ? 'bg-chart-3/20 text-chart-3'
                              : 'bg-chart-2/20 text-chart-2'
                      }`}
                    >
                      {event.severity}
                    </Badge>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="glass border-border/50">
          <CardHeader>
            <CardTitle>Latest Release</CardTitle>
            <CardDescription>
              {latestRelease ? `Firmware v${latestRelease.version}` : 'No releases published yet'}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {latestRelease ? (
              <>
                <div>
                  <p className="mb-1 text-xs text-foreground/50">Release Date</p>
                  <p className="tabular text-sm font-medium text-foreground">
                    {formatUtcDate(latestRelease.releaseDate)}
                  </p>
                </div>
                <div>
                  <p className="mb-1 text-xs text-foreground/50">Description</p>
                  <p className="text-sm text-foreground/80">{latestRelease.description}</p>
                </div>
                <div>
                  <p className="mb-1 text-xs text-foreground/50">Downloads</p>
                  <p className="tabular text-sm font-medium text-foreground">
                    {formatNumber(latestRelease.downloadCount)}
                  </p>
                </div>
                <div>
                  <p className="mb-2 text-xs text-foreground/50">Compatible Devices</p>
                  <div className="flex flex-wrap gap-2">
                    {latestRelease.compatible.map((device) => (
                      <Badge key={device} variant="secondary" className="bg-primary/20 text-primary">
                        {device}
                      </Badge>
                    ))}
                  </div>
                </div>
              </>
            ) : (
              <p className="type-caption" style={{ color: 'var(--app-ink2)' }}>
                A fresh gateway serves no manifest until the first release is published. That is the
                normal empty state, not a failure.
              </p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
