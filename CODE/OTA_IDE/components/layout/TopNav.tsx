'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  Activity,
  AlertCircle,
  BarChart3,
  Code,
  Cpu,
  FlaskConical,
  GitBranch,
  HelpCircle,
  Home,
  Info,
  LayoutList,
  Lock,
  Rocket,
  Settings,
  Shield,
  Tag,
  Zap,
} from 'lucide-react';
import Logo from '@/components/brand/Logo';
import { useRuntimeSnapshot } from '@/lib/runtime-data';
import { clearAuthSession, getStoredAuthUser } from '@/lib/client-auth';
import { useGuidedMode } from '@/lib/use-guided-mode';

type NavItem = { label: string; href: string; icon: React.ReactNode };
type NavGroup = { title: string; icon: React.ReactNode; items: NavItem[] };

// Same four groups and hrefs the sidebar used, re-presented as the design's
// horizontal nav.
const groups: NavGroup[] = [
  {
    title: 'Monitor',
    icon: <Activity className="h-4 w-4" />,
    items: [
      { label: 'Dashboard', href: '/dashboard', icon: <Home className="h-3.5 w-3.5" /> },
      { label: 'Devices', href: '/devices', icon: <Zap className="h-3.5 w-3.5" /> },
      { label: 'Event logs', href: '/event-logs', icon: <AlertCircle className="h-3.5 w-3.5" /> },
    ],
  },
  {
    title: 'Deploy',
    icon: <Rocket className="h-4 w-4" />,
    items: [
      { label: 'Pipeline', href: '/pipeline', icon: <GitBranch className="h-3.5 w-3.5" /> },
      { label: 'Releases', href: '/releases', icon: <Code className="h-3.5 w-3.5" /> },
      { label: 'Manifest', href: '/manifest', icon: <LayoutList className="h-3.5 w-3.5" /> },
      { label: 'Code', href: '/code', icon: <Code className="h-3.5 w-3.5" /> },
    ],
  },
  {
    title: 'Security',
    icon: <Shield className="h-4 w-4" />,
    items: [
      { label: 'TCV Engine', href: '/tcv-engine', icon: <Cpu className="h-3.5 w-3.5" /> },
      { label: 'ASH Monitor', href: '/ash-monitor', icon: <Activity className="h-3.5 w-3.5" /> },
      { label: 'Key Vault', href: '/key-vault', icon: <Lock className="h-3.5 w-3.5" /> },
    ],
  },
  {
    title: 'Config',
    icon: <Settings className="h-4 w-4" />,
    items: [
      { label: 'Settings', href: '/settings', icon: <Settings className="h-3.5 w-3.5" /> },
      { label: 'Diagnostics', href: '/diagnostics', icon: <BarChart3 className="h-3.5 w-3.5" /> },
      { label: 'Dead Letter', href: '/dead-letter', icon: <AlertCircle className="h-3.5 w-3.5" /> },
      { label: 'Reports', href: '/reports', icon: <BarChart3 className="h-3.5 w-3.5" /> },
      { label: 'Simulator', href: '/simulator', icon: <Shield className="h-3.5 w-3.5" /> },
      { label: 'Examples', href: '/examples', icon: <FlaskConical className="h-3.5 w-3.5" /> },
      { label: 'Help', href: '/help', icon: <HelpCircle className="h-3.5 w-3.5" /> },
      { label: 'About', href: '/about', icon: <Info className="h-3.5 w-3.5" /> },
      { label: 'Version', href: '/version', icon: <Tag className="h-3.5 w-3.5" /> },
    ],
  },
];

function relativeTime(from: Date | null): string {
  if (!from) return 'never';
  const secs = Math.max(0, Math.round((Date.now() - from.getTime()) / 1000));
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
  return `${Math.round(secs / 3600)}h ago`;
}

export default function TopNav() {
  const pathname = usePathname();
  const router = useRouter();
  const { snapshot } = useRuntimeSnapshot(5000);
  const [guided, setGuided] = useGuidedMode();
  const [userName, setUserName] = React.useState('Admin');
  const [, forceTick] = React.useReducer((n: number) => n + 1, 0);

  React.useEffect(() => {
    const user = getStoredAuthUser();
    if (user?.username) setUserName(user.username);
  }, []);

  // Keep the "updated Ns ago" label honest between snapshot polls.
  React.useEffect(() => {
    const id = window.setInterval(forceTick, 1000);
    return () => window.clearInterval(id);
  }, []);

  const online = snapshot.devices.filter((d) => d.status === 'online').length;
  const offline = snapshot.devices.filter(
    (d) => d.status === 'offline' || d.status === 'error'
  ).length;
  // Devices ASH-quarantined. The snapshot exposes the mapped health band
  // rather than the raw score; poor/critical are the bands below 45.
  const held = snapshot.devices.filter(
    (d) => d.health === 'poor' || d.health === 'critical'
  ).length;

  const lastSync = snapshot.devices.reduce<Date | null>((latest, d) => {
    if (!d.lastSync) return latest;
    return !latest || d.lastSync > latest ? d.lastSync : latest;
  }, null);

  const activeGroup =
    groups.find((g) => g.items.some((i) => pathname === i.href || pathname.startsWith(i.href + '/'))) ??
    groups[0];

  const handleSignOut = async () => {
    await clearAuthSession();
    router.replace('/login');
  };

  const initials = userName.slice(0, 2).toUpperCase();

  return (
    <header
      className="sticky top-0 z-20 flex flex-col"
      style={{
        borderBottom: '1px solid var(--app-line)',
        background: 'var(--app-nav)',
        backdropFilter: 'blur(8px)',
      }}
    >
      {/* ── Row 1: brand, groups, controls ──────────────────────────────── */}
      <div className="flex min-h-[60px] flex-wrap items-center gap-4 px-6 py-2">
        <Link href="/dashboard" className="flex shrink-0 items-center" aria-label="SecureOTA dashboard">
          <Logo size={30} wordmarkSize={20} />
        </Link>

        <nav
          aria-label="Sections"
          className="ota-nav-scroll flex min-w-0 flex-1 items-center gap-1 overflow-x-auto"
          style={{ scrollbarWidth: 'none' }}
        >
          {groups.map((group) => {
            const isActive = group.title === activeGroup.title;
            const badge = group.title === 'Security' && held > 0 ? held : null;
            return (
              <Link
                key={group.title}
                href={group.items[0].href}
                className="ds-navchip inline-flex min-h-[38px] shrink-0 items-center gap-2 whitespace-nowrap rounded-xl px-[15px]"
                data-active={isActive ? 'true' : undefined}
                aria-current={isActive ? 'page' : undefined}
              >
                {group.icon}
                {group.title}
                {badge !== null && (
                  <span
                    className="type-micro-cap tabular"
                    style={{
                      padding: '2px 6px',
                      borderRadius: 4,
                      background: 'var(--app-err-bg)',
                      color: 'var(--app-err-ink)',
                    }}
                    title={`${badge} device${badge === 1 ? '' : 's'} held back by ASH`}
                  >
                    {badge}
                  </span>
                )}
              </Link>
            );
          })}
        </nav>

        <div className="flex shrink-0 items-center gap-3">
          {/* Density toggle */}
          <div
            className="flex items-center gap-0.5 p-[3px]"
            style={{ borderRadius: 24, border: '1px solid var(--app-line)' }}
            role="group"
            aria-label="Console density"
          >
            {(['Guided', 'Dense'] as const).map((mode) => {
              const on = (mode === 'Guided') === guided;
              return (
                <button
                  key={mode}
                  type="button"
                  onClick={() => setGuided(mode === 'Guided')}
                  aria-pressed={on}
                  className="type-button-cap-light inline-flex min-h-[30px] items-center rounded-full px-3.5"
                  style={{
                    border: 'none',
                    cursor: 'pointer',
                    background: on ? 'var(--ember)' : 'transparent',
                    color: on ? '#fff' : 'var(--app-ink2)',
                    transitionProperty: 'background-color, color',
                    transitionDuration: 'var(--dur-fast)',
                    transitionTimingFunction: 'var(--ease-standard)',
                  }}
                >
                  {mode}
                </button>
              );
            })}
          </div>

          <span
            className="inline-flex h-9 w-9 items-center justify-center rounded-full"
            style={{
              background: 'var(--gradient-cta)',
              color: 'var(--carbon)',
              font: '700 12px/1 var(--font-display)',
            }}
            title={userName}
          >
            {initials || 'AD'}
          </span>

          <button
            type="button"
            onClick={handleSignOut}
            className="ds-ghost inline-flex min-h-[36px] items-center rounded-lg px-4"
            style={{ background: 'transparent', cursor: 'pointer' }}
          >
            Sign Out
          </button>
        </div>
      </div>

      {/* ── Row 2: sub-nav + live status ────────────────────────────────── */}
      <div
        className="flex flex-wrap items-center gap-3 px-6 pb-2.5 pt-2.5"
        style={{ borderTop: '1px solid var(--app-line2)' }}
      >
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-1.5">
          {activeGroup.items.map((item) => {
            const isActive = pathname === item.href || pathname.startsWith(item.href + '/');
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={isActive ? 'page' : undefined}
                data-active={isActive ? 'true' : undefined}
                className="ds-subchip inline-flex min-h-[32px] shrink-0 items-center gap-2 whitespace-nowrap rounded-[20px] px-3"
              >
                {item.icon}
                {item.label}
              </Link>
            );
          })}
        </div>

        <div
          className="type-caption flex shrink-0 items-center gap-2"
          style={{ color: 'var(--app-ink2)' }}
        >
          <span
            aria-hidden="true"
            className="shrink-0 rounded-full"
            style={{
              width: 7,
              height: 7,
              background: 'var(--amber)',
              animation: 'ota-pulse 2s infinite',
            }}
          />
          <span className="tabular">
            {online} online · {offline} offline · updated {relativeTime(lastSync)}
          </span>
        </div>
      </div>
    </header>
  );
}
