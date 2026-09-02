'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  Home,
  Zap,
  AlertCircle,
  GitBranch,
  Settings,
  Menu,
  X,
  Activity,
  Code,
  Lock,
  BarChart3,
  HelpCircle,
  Tag,
  Cpu,
  Shield,
  Info,
  FlaskConical,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import Logo from '@/components/brand/Logo';
import { useIsMobile } from '@/hooks/use-mobile';
import { useRuntimeSnapshot } from '@/lib/runtime-data';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';

interface NavItem {
  label: string;
  href: string;
  icon: React.ReactNode;
  description?: string;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

interface SidebarProps {
  isOpen: boolean;
  onToggle: () => void;
  mobileOpen: boolean;
  onMobileOpenChange: (open: boolean) => void;
}

const navSections: NavSection[] = [
  {
    title: 'Monitor',
    items: [
      { label: 'Dashboard', href: '/dashboard', icon: <Home className="w-4 h-4" /> },
      { label: 'Devices', href: '/devices', icon: <Zap className="w-4 h-4" /> },
      { label: 'Event Logs', href: '/event-logs', icon: <AlertCircle className="w-4 h-4" /> },
    ],
  },
  {
    title: 'Deploy',
    items: [
      { label: 'Pipeline', href: '/pipeline', icon: <GitBranch className="w-4 h-4" /> },
      { label: 'Releases', href: '/releases', icon: <Code className="w-4 h-4" /> },
      { label: 'Manifest', href: '/manifest', icon: <Menu className="w-4 h-4" /> },
      { label: 'Code', href: '/code', icon: <Code className="w-4 h-4" /> },
    ],
  },
  {
    title: 'Security',
    items: [
      { label: 'TCV Engine', href: '/tcv-engine', icon: <Cpu className="w-4 h-4" /> },
      { label: 'ASH Monitor', href: '/ash-monitor', icon: <Activity className="w-4 h-4" /> },
      { label: 'Key Vault', href: '/key-vault', icon: <Lock className="w-4 h-4" /> },
    ],
  },
  {
    title: 'Config',
    items: [
      { label: 'Settings', href: '/settings', icon: <Settings className="w-4 h-4" /> },
      { label: 'Diagnostics', href: '/diagnostics', icon: <BarChart3 className="w-4 h-4" /> },
      { label: 'Dead Letter', href: '/dead-letter', icon: <AlertCircle className="w-4 h-4" /> },
      { label: 'Reports', href: '/reports', icon: <BarChart3 className="w-4 h-4" /> },
      { label: 'Simulator', href: '/simulator', icon: <Shield className="w-4 h-4" /> },
      { label: 'Examples', href: '/examples', icon: <FlaskConical className="w-4 h-4" /> },
      { label: 'Help', href: '/help', icon: <HelpCircle className="w-4 h-4" /> },
      { label: 'About', href: '/about', icon: <Info className="w-4 h-4" /> },
      { label: 'Version', href: '/version', icon: <Tag className="w-4 h-4" /> },
    ],
  },
];

function NavigationContent({
  compact,
  onLinkNavigate,
  onCollapseToggle,
}: {
  compact: boolean;
  onLinkNavigate?: () => void;
  onCollapseToggle?: () => void;
}) {
  const pathname = usePathname();
  const { snapshot } = useRuntimeSnapshot(5000);
  const onlineCount = snapshot.devices.filter((device) => device.status === 'online').length;
  const offlineCount = snapshot.devices.filter((device) => device.status === 'offline' || device.status === 'error').length;

  const isActive = (href: string) => {
    return pathname === href || pathname.startsWith(href + '/');
  };

  return (
    <>
      <div
        className={cn(
          'flex items-center gap-2 border-b border-sidebar-border px-4 py-5',
          compact ? 'justify-center' : 'justify-between'
        )}
      >
        <div className={cn('flex items-center gap-2', compact && 'justify-center')}>
          {compact ? (
            <Logo size={40} showWordmark={false} />
          ) : (
            <Logo size={48} wordmarkSize={20} />
          )}
        </div>

        {!compact && onCollapseToggle && (
          <button
            onClick={onCollapseToggle}
            className="rounded-lg p-1 transition-colors hover:bg-sidebar-accent/20"
            aria-label="Toggle sidebar"
          >
            <X className="w-4 h-4" />
          </button>
        )}

        {compact && onCollapseToggle && (
          <button
            onClick={onCollapseToggle}
            className="rounded-lg p-1 transition-colors hover:bg-sidebar-accent/20"
            aria-label="Expand sidebar"
            title="Expand sidebar"
          >
            <Menu className="w-4 h-4" />
          </button>
        )}
      </div>

      <nav className="flex-1 space-y-6 overflow-y-auto px-2 py-4">
        {navSections.map((section) => (
          <div key={section.title}>
            {!compact && (
              <h3 className="mb-2 px-3 text-xs font-semibold uppercase tracking-wide text-sidebar-foreground/60">
                {section.title}
              </h3>
            )}

            <div className="space-y-1">
              {section.items.map((item) => {
                const active = isActive(item.href);

                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    title={compact ? item.label : undefined}
                    aria-label={item.label}
                    onClick={onLinkNavigate}
                    className={cn(
                      'group relative flex items-center gap-3 rounded-lg text-sm transition-colors',
                      compact ? 'justify-center px-2 py-2.5' : 'px-3 py-2.5',
                      active
                        ? 'bg-sidebar-accent/20 font-medium text-accent'
                        : 'text-sidebar-foreground/70 hover:bg-sidebar-accent/10 hover:text-sidebar-foreground'
                    )}
                  >
                    <span
                      className={cn(
                        'flex h-5 w-5 shrink-0 items-center justify-center',
                        active && 'text-accent glow-accent'
                      )}
                    >
                      {item.icon}
                    </span>
                    {!compact && <span className="truncate">{item.label}</span>}
                    {active && !compact && (
                      <div className="absolute right-0 h-6 w-1 rounded-l bg-accent" />
                    )}
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {!compact && (
        <div className="border-t border-sidebar-border p-3 glass-sm">
          <div className="space-y-1 text-xs text-sidebar-foreground/50">
            <div className="flex items-center gap-2">
              <div className="h-2 w-2 rounded-full bg-chart-1" />
                <span>{onlineCount} Online</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="h-2 w-2 rounded-full bg-chart-4" />
                <span>{offlineCount} Offline</span>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

export default function Sidebar({
  isOpen,
  onToggle,
  mobileOpen,
  onMobileOpenChange,
}: SidebarProps) {
  const isMobile = useIsMobile();

  if (isMobile) {
    return (
      <Sheet open={mobileOpen} onOpenChange={onMobileOpenChange}>
        <SheetContent
          side="left"
          className="w-[18rem] max-w-[85vw] border-r border-sidebar-border bg-sidebar p-0 text-sidebar-foreground"
        >
          <SheetHeader className="sr-only">
            <SheetTitle>OTA IDE navigation</SheetTitle>
            <SheetDescription>Primary application navigation.</SheetDescription>
          </SheetHeader>
          <div className="flex h-full flex-col">
            <NavigationContent
              compact={false}
              onLinkNavigate={() => onMobileOpenChange(false)}
            />
          </div>
        </SheetContent>
      </Sheet>
    );
  }

  return (
    <aside
      className={cn(
        'hidden md:flex md:flex-shrink-0 transition-[width] duration-300',
        isOpen ? 'md:w-64' : 'md:w-20'
      )}
    >
      <div className="flex h-full min-h-svh w-full flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground glass-lg">
        <NavigationContent compact={!isOpen} onCollapseToggle={onToggle} />
      </div>
    </aside>
  );
}
