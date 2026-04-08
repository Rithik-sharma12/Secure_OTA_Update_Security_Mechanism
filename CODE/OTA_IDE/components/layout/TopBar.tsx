'use client';

import React from 'react';
import { usePathname } from 'next/navigation';
import { Search, Moon, Sun, ChevronRight, Menu } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

interface TopBarProps {
  onMenuClick: () => void;
}

export default function TopBar({ onMenuClick }: TopBarProps) {
  const pathname = usePathname();
  const [isDark, setIsDark] = React.useState(true);

  const breadcrumbs = React.useMemo(() => {
    const parts = pathname.split('/').filter((part) => part && part !== 'dashboard');
    const items = [{ label: 'Dashboard', href: '/dashboard' }];

    parts.forEach((part, index) => {
      const href = `/${parts.slice(0, index + 1).join('/')}`;
      items.push({
        label: part.charAt(0).toUpperCase() + part.slice(1).replace(/-/g, ' '),
        href,
      });
    });

    return items;
  }, [pathname]);

  const currentPageTitle = breadcrumbs[breadcrumbs.length - 1]?.label ?? 'OTA IDE';

  const toggleTheme = () => {
    setIsDark(!isDark);
    document.documentElement.classList.toggle('dark');
  };

  return (
    <div className="sticky top-0 z-40 border-b border-border bg-card/95 glass backdrop-blur">
      <div className="flex min-h-16 flex-wrap items-center gap-3 px-4 py-3 sm:px-6 lg:px-8">
        <div className="flex min-w-0 flex-1 items-center gap-3">
          <Button
            variant="ghost"
            size="icon"
            onClick={onMenuClick}
            className="md:hidden shrink-0 rounded-lg"
          >
            <Menu className="w-5 h-5" />
            <span className="sr-only">Open navigation</span>
          </Button>

          <div className="min-w-0">
            <div className="hidden max-w-full items-center gap-2 overflow-x-auto whitespace-nowrap sm:flex">
              {breadcrumbs.map((crumb, index) => (
                <React.Fragment key={crumb.href}>
                  {index > 0 && <ChevronRight className="w-4 h-4 shrink-0 text-muted-foreground" />}
                  <span className="shrink-0 text-sm text-foreground/70">
                    {crumb.label}
                  </span>
                </React.Fragment>
              ))}
            </div>
            <div className="truncate text-sm font-semibold text-foreground sm:hidden">
              {currentPageTitle}
            </div>
          </div>
        </div>

        <div className="ml-auto flex items-center gap-2 sm:gap-4">
          <div className="hidden items-center rounded-lg border border-border/50 bg-muted/50 px-3 py-2 sm:flex sm:w-48 lg:w-64">
            <Search className="mr-2 w-4 h-4 text-muted-foreground" />
            <Input
              type="text"
              placeholder="Search..."
              className="h-auto border-0 bg-transparent p-0 text-sm outline-none placeholder:text-muted-foreground"
            />
          </div>

          <Button
            variant="ghost"
            size="icon"
            onClick={toggleTheme}
            className="rounded-lg"
          >
            {isDark ? (
              <Sun className="w-4 h-4 text-accent" />
            ) : (
              <Moon className="w-4 h-4" />
            )}
          </Button>

          <div className="flex items-center gap-2 border-l border-border pl-2 sm:pl-4">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-accent to-primary text-xs font-bold text-accent-foreground">
              AD
            </div>
            <span className="hidden text-sm font-medium sm:inline">Admin</span>
          </div>
        </div>
      </div>
    </div>
  );
}
