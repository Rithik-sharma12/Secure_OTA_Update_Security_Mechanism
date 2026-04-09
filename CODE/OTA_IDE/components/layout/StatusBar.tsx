'use client';

import React, { useState, useEffect } from 'react';
import { Activity, AlertCircle, CheckCircle, GitBranch } from 'lucide-react';
import { useRuntimeSnapshot } from '@/lib/runtime-data';

export default function StatusBar() {
  const [mounted, setMounted] = useState(false);
  const [time, setTime] = useState('');
  const { snapshot } = useRuntimeSnapshot(5000);

  const onlineCount = snapshot.devices.filter((device) => device.status === 'online').length;
  const offlineCount = snapshot.devices.filter((device) => device.status === 'offline' || device.status === 'error').length;
  const activeDeployment = snapshot.pipeline?.status === 'running' || snapshot.devices.some((device) => device.status === 'updating');
  const latestVersion = snapshot.releases[0]?.version || 'n/a';
  const warningCount = snapshot.events.filter((event) => event.severity === 'warning' || event.severity === 'error').length;

  useEffect(() => {
    setMounted(true);
    const updateTime = () => {
      setTime(new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
    };

    updateTime();
    const interval = setInterval(updateTime, 60000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="border-t border-border bg-card glass px-4 py-2 text-xs sm:px-6">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
          <div className="flex items-center gap-2">
            <Activity className="w-3 h-3 text-chart-1" />
            <span className="text-foreground/70">
              {onlineCount} online, {offlineCount} offline
            </span>
          </div>

          <div className="hidden h-4 w-px bg-border sm:block" />

          <div className="flex items-center gap-2">
            {activeDeployment ? (
              <>
                <div className="h-2 w-2 animate-pulse rounded-full bg-yellow-500" />
                <span className="text-foreground/70">Build: In Progress</span>
              </>
            ) : (
              <>
                <CheckCircle className="w-3 h-3 text-chart-1" />
                <span className="text-foreground/70">Build: Success</span>
              </>
            )}
          </div>

          <div className="hidden h-4 w-px bg-border sm:block" />

          <div className="flex items-center gap-2">
            <div className="h-2 w-2 rounded-full bg-primary" />
            <span className="text-foreground/70">Latest: {latestVersion === 'n/a' ? latestVersion : `v${latestVersion}`}</span>
          </div>

          <div className="hidden h-4 w-px bg-border sm:block" />

          <div className="flex items-center gap-2">
            <GitBranch className="w-3 h-3" />
            <span className="text-foreground/70">main</span>
          </div>
        </div>

        <div className="flex items-center justify-between gap-4 sm:justify-end">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-3 h-3 text-yellow-500" />
            <span className="text-foreground/70">{warningCount} Warning{warningCount === 1 ? '' : 's'}</span>
          </div>

          {mounted && (
            <div className="text-foreground/50">
              {time}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
