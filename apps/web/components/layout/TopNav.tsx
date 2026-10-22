'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { AccountMenu } from '@/components/profile/AccountMenu';
import {
  Activity,
  AlertCircle,
  Bell,
  BarChart3,
  Code,
  FlaskConical,
  GitBranch,
  HelpCircle,
  Home,
  Info,
  LayoutList,
  Lock,
  Rocket,
  ScrollText,
  Settings,
  Shield,
  Tag,
  UserRound,
  Zap,
} from 'lucide-react';
import Logo from '@/components/brand/Logo';
import { useRuntimeSnapshot } from '@/lib/runtime-data';
import { AppearanceMenu } from '@/components/layout/AppearanceMenu';
import { ConsoleSearch } from '@/components/layout/ConsoleSearch';

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
      { label: 'Deployments', href: '/deployments', icon: <Rocket className="h-3.5 w-3.5" /> },
      { label: 'Pipeline', href: '/pipeline', icon: <GitBranch className="h-3.5 w-3.5" /> },
      { label: 'Releases', href: '/releases', icon: <Code className="h-3.5 w-3.5" /> },
      { label: 'Manifest', href: '/manifest', icon: <LayoutList className="h-3.5 w-3.5" /> },
    ],
  },
  {
    title: 'Security',
    icon: <Shield className="h-4 w-4" />,
    items: [
      { label: 'ASH Monitor', href: '/ash-monitor', icon: <Activity className="h-3.5 w-3.5" /> },
      { label: 'Key Vault', href: '/key-vault', icon: <Lock className="h-3.5 w-3.5" /> },
      { label: 'Audit trail', href: '/audit', icon: <ScrollText className="h-3.5 w-3.5" /> },
    ],
  },
  {
    title: 'Config',
    icon: <Settings className="h-4 w-4" />,
    items: [
      { label: 'Profile', href: '/profile', icon: <UserRound className="h-3.5 w-3.5" /> },
      { label: 'Settings', href: '/settings', icon: <Settings className="h-3.5 w-3.5" /> },
      { label: 'Diagnostics', href: '/diagnostics', icon: <BarChart3 className="h-3.5 w-3.5" /> },
      { label: 'Reports', href: '/reports', icon: <BarChart3 className="h-3.5 w-3.5" /> },
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
  const { snapshot } = useRuntimeSnapshot(5000);
  const [, forceTick] = React.useReducer((n: number) => n + 1, 0);

  // Keep the "updated Ns ago" label honest between snapshot polls.
  React.useEffect(() => {
    const id = window.setInterval(forceTick, 1000);
    return () => window.clearInterval(id);
  }, []);

  const online = snapshot.devices.filter((d) => d.status === 'online').length;
  const offline = snapshot.devices.filter(
    (d) => d.status === 'offline' || d.status === 'error'
  ).length;
  // Devices ASH-quarantined: the gateway refuses deployments at ASH 40 or
  // below (QUARANTINE_ASH_THRESHOLD in apps/gateway/gateway/deployment.py).
  const held = snapshot.devices.filter((d) => d.ash <= 40).length;

  const alerts = offline + held;

  const lastSync = snapshot.devices.reduce<Date | null>((latest, d) => {
    if (!d.lastSync) return latest;
    return !latest || d.lastSync > latest ? d.lastSync : latest;
  }, null);

  const activeGroup =
    groups.find((g) => g.items.some((i) => pathname === i.href || pathname.startsWith(i.href + '/'))) ??
    groups[0];

  return (
    <header
      className="sticky top-0 z-20 flex flex-col"
      style={{
        borderBottom: '1px solid var(--app-line)',
        background: 'var(--app-nav)',
        backdropFilter: 'blur(8px)',
      }}
    >
      {/* ── Row 1: brand · pill navigation + search · notifications, appearance, account ── */}
      <div className="flex min-h-[60px] flex-wrap items-center gap-x-2 gap-y-2 px-3 py-2.5 sm:min-h-[64px] sm:gap-x-4 sm:px-6">
        <Link href="/dashboard" className="flex shrink-0 items-center" aria-label="SecureOTA dashboard">
          <Logo size={30} wordmarkSize={20} />
        </Link>

        <div className="flex min-w-0 items-center gap-2 md:flex-1 md:justify-center">
          {/* Phones use the bottom bar below instead of these tabs. */}
          <nav aria-label="Sections" className="ota-pillnav gloss-pillbar ota-nav-scroll hidden min-w-0 overflow-x-auto md:flex" style={{ scrollbarWidth: 'none' }}>
            {groups.map((group) => {
              const isActive = group.title === activeGroup.title;
              const badge = group.title === 'Security' && held > 0 ? held : null;
              return (
                <Link
                  key={group.title}
                  href={group.items[0].href}
                  className="ota-pill gloss-pill"
                  data-active={isActive ? 'true' : undefined}
                  aria-current={isActive ? 'page' : undefined}
                >
                  {group.icon}
                  {group.title}
                  {badge !== null && (
                    <span className="ota-pill-badge tabular" title={`${badge} device${badge === 1 ? '' : 's'} held back by ASH`}>
                      {badge}
                    </span>
                  )}
                </Link>
              );
            })}
          </nav>
          <ConsoleSearch groups={groups} />
        </div>

        <div className="ml-auto flex shrink-0 items-center gap-1.5 sm:gap-2">
          <Link
            href="/event-logs"
            className="ota-iconbtn gloss-iconbtn relative"
            aria-label={alerts > 0 ? `${alerts} devices need attention. Open event logs` : 'Event logs'}
            title={alerts > 0 ? `${alerts} device${alerts === 1 ? '' : 's'} offline or held back` : 'Event logs'}
          >
            <Bell className="h-[18px] w-[18px]" />
            {alerts > 0 && <span className="ota-iconbtn-dot" aria-hidden="true" />}
          </Link>
          <AppearanceMenu />
          <AccountMenu />
        </div>
      </div>

      {/* ── Row 2: sub-nav + live status ────────────────────────────────── */}
      <div
        className="flex items-center gap-3 px-4 pb-2.5 pt-2.5 sm:px-6"
        style={{ borderTop: '1px solid var(--app-line2)' }}
      >
        <div className="ota-nav-scroll flex min-w-0 flex-1 items-center gap-1.5 overflow-x-auto lg:flex-wrap" style={{ scrollbarWidth: 'none' }}>
          {activeGroup.items.map((item) => {
            const isActive = pathname === item.href || pathname.startsWith(item.href + '/');
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={isActive ? 'page' : undefined}
                data-active={isActive ? 'true' : undefined}
                className="ds-subchip inline-flex min-h-[32px] shrink-0 items-center gap-2 whitespace-nowrap rounded-md px-3"
              >
                {item.icon}
                {item.label}
              </Link>
            );
          })}
        </div>

        <div
          className="type-caption hidden shrink-0 items-center gap-2 md:flex"
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

/**
 * Phones: a glossy bottom tab bar (like a native app) in place of the header
 * tabs. Rendered by ConsoleLayout outside the header, because the header's
 * backdrop blur would otherwise become the bar's positioning context.
 */
export function MobileTabBar() {
  const pathname = usePathname();
  const onProfile = pathname.startsWith('/profile');
  const activeGroup =
    groups.find((g) => g.items.some((i) => pathname === i.href || pathname.startsWith(i.href + '/'))) ??
    groups[0];
  return (
    <nav aria-label="Sections" className="gloss-bottomnav md:hidden">
      {groups.map((group) => {
        const isActive = group.title === activeGroup.title && !onProfile;
        return (
          <Link
            key={group.title}
            href={group.items[0].href}
            data-active={isActive ? 'true' : undefined}
            aria-current={isActive ? 'page' : undefined}
          >
            {group.icon}
            <span>{group.title}</span>
          </Link>
        );
      })}
      <Link href="/profile" data-active={onProfile ? 'true' : undefined} aria-current={onProfile ? 'page' : undefined}>
        <UserRound className="h-4 w-4" />
        <span>Account</span>
      </Link>
    </nav>
  );
}
