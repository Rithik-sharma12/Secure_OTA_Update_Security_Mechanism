'use client';

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import Link from 'next/link';
import { toast } from 'sonner';
import { Settings as SettingsIcon, Bell, Database, Zap, Trash2, Copy, UserRound, ChevronRight, Sparkles } from 'lucide-react';
import { executeRuntimeAction, fetchRuntimeActionState } from '@/lib/runtime-actions';
import { useCurrentUser } from '@/lib/use-current-user';
import { ACCENTS, ACCENT_KEYS, useAccent, useConsoleLayoutMode, type Accent, type ConsoleLayoutMode } from '@/lib/accent';
import {
  WALLPAPER_COLORS,
  WALLPAPER_STRENGTH,
  WALLPAPER_STYLES,
  useLiveWallpaper,
  useWallpaperColor,
  useWallpaperStrength,
  useWallpaperStyle,
  type WallpaperStrength,
} from '@/components/brand/LiveWallpaper';

/** Pill-shaped single choice, used for the wallpaper options. */
function ChoicePills<T extends string>({
  label,
  options,
  value,
  onChange,
  disabled,
}: {
  label: string;
  options: Record<T, string>;
  value: T;
  onChange: (value: T) => void;
  disabled?: boolean;
}) {
  return (
    <div
      role="radiogroup"
      aria-label={label}
      className="inline-flex flex-wrap items-center gap-0.5 rounded-lg p-[3px]"
      style={{ border: '1px solid var(--app-line)', opacity: disabled ? 0.5 : 1 }}
    >
      {(Object.keys(options) as T[]).map((key) => {
        const on = key === value;
        return (
          <button
            key={key}
            type="button"
            role="radio"
            aria-checked={on}
            disabled={disabled}
            onClick={() => onChange(key)}
            className="min-h-[30px] rounded-md px-3.5 text-xs font-semibold transition-colors"
            style={{
              background: on ? 'var(--app-inv-bg)' : 'transparent',
              color: on ? 'var(--app-inv-ink)' : 'var(--app-ink2)',
              cursor: disabled ? 'not-allowed' : 'pointer',
            }}
          >
            {options[key]}
          </button>
        );
      })}
    </div>
  );
}

type RuntimeSettingsFormState = {
  autoUpdateFirmware: boolean;
  emailNotifications: boolean;
  twoFactorAuth: boolean;
  deviceTelemetry: boolean;
  apiEndpoint: string;
  requestTimeoutSec: number;
  cacheSizeMb: number;
};

const defaultSettings: RuntimeSettingsFormState = {
  autoUpdateFirmware: true,
  emailNotifications: true,
  twoFactorAuth: false,
  deviceTelemetry: true,
  apiEndpoint: 'https://api.ota-ide.example.com/v1',
  requestTimeoutSec: 30,
  cacheSizeMb: 500,
};

export default function SettingsPage() {
  const { can, reasonFor } = useCurrentUser();
  const mayWriteSettings = can('settings.write');
  const [liveWallpaper, setLiveWallpaper] = useLiveWallpaper();
  const [wallpaperStrength, setWallpaperStrength] = useWallpaperStrength();
  const [wallpaperStyle, setWallpaperStyle] = useWallpaperStyle();
  const [wallpaperColor, setWallpaperColor] = useWallpaperColor();
  const [accent, setAccent] = useAccent();
  const [layoutMode, setLayoutMode] = useConsoleLayoutMode();
  const accentLabels = Object.fromEntries(ACCENT_KEYS.map((key) => [key, ACCENTS[key].label])) as Record<Accent, string>;
  const layoutLabels: Record<ConsoleLayoutMode, string> = { framed: 'Framed', full: 'Full width' };
  const strengthLabels = Object.fromEntries(
    (Object.keys(WALLPAPER_STRENGTH) as WallpaperStrength[]).map((key) => [key, WALLPAPER_STRENGTH[key].label])
  ) as Record<WallpaperStrength, string>;
  const [settings, setSettings] = React.useState<RuntimeSettingsFormState>(defaultSettings);
  const [isLoading, setIsLoading] = React.useState(true);
  const [busyAction, setBusyAction] = React.useState<string | null>(null);
  const [actionMessage, setActionMessage] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);
  const [apiKeyPreview, setApiKeyPreview] = React.useState('••••••••••••••••••••••••');

  React.useEffect(() => {
    const loadSettings = async () => {
      try {
        const response = await fetchRuntimeActionState<{ settings?: RuntimeSettingsFormState }>();
        if (response.data?.settings) {
          setSettings(response.data.settings);
        }
      } catch {
        setSettings(defaultSettings);
      } finally {
        setIsLoading(false);
      }
    };

    void loadSettings();
  }, []);

  const setBooleanSetting = (key: keyof Pick<RuntimeSettingsFormState, 'autoUpdateFirmware' | 'emailNotifications' | 'twoFactorAuth' | 'deviceTelemetry'>, value: boolean) => {
    setSettings((current) => ({
      ...current,
      [key]: value,
    }));
  };

  const runAction = async (action: string, payload: Record<string, unknown> = {}) => {
    setBusyAction(action);
    setActionError(null);
    setActionMessage(null);

    try {
      const response = await executeRuntimeAction(action, payload);
      setActionMessage(response.message || 'Action completed.');
      toast.success(response.message || 'Done.');
      return response;
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Action failed.');
      toast.error(error instanceof Error ? error.message : 'Action failed.');
      return null;
    } finally {
      setBusyAction(null);
    }
  };

  const handleCopy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setActionError(null);
      setActionMessage('Copied to clipboard.');
    } catch {
      setActionError('Clipboard permission denied.');
    }
  };

  const handleSaveSettings = async () => {
    await runAction('settings.save', { settings });
  };

  const handleResetSettings = async () => {
    const response = await runAction('settings.reset');
    if (!response) {
      return;
    }

    const nextSettings = response?.data && typeof response.data === 'object' && 'settings' in response.data
      ? (response.data.settings as RuntimeSettingsFormState)
      : defaultSettings;
    setSettings(nextSettings);
  };

  const handleGenerateApiKey = async () => {
    const response = await runAction('keys.create', {
      name: `OTA API Key ${new Date().toISOString().slice(0, 10)}`,
      type: 'AES',
    });

    const key = response?.data && typeof response.data === 'object' && 'key' in response.data
      ? (response.data.key as { fingerprint?: string })
      : null;

    if (key?.fingerprint) {
      setApiKeyPreview(`${key.fingerprint.slice(0, 8)}••••••••••••••`);
    }
  };

  const settingRows = [
    {
      label: 'Auto-update firmware',
      description: 'Automatically deploy compatible firmware updates',
      value: settings.autoUpdateFirmware,
      icon: <Zap className="w-4 h-4" />,
      onChange: (value: boolean) => setBooleanSetting('autoUpdateFirmware', value),
    },
    {
      label: 'Email notifications',
      description: 'Receive alerts and updates via email',
      value: settings.emailNotifications,
      icon: <Bell className="w-4 h-4" />,
      onChange: (value: boolean) => setBooleanSetting('emailNotifications', value),
    },
    {
      label: 'Device telemetry',
      description: 'Collect anonymous usage analytics',
      value: settings.deviceTelemetry,
      icon: <Database className="w-4 h-4" />,
      onChange: (value: boolean) => setBooleanSetting('deviceTelemetry', value),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-8">
        <div className="p-3 rounded-lg bg-primary/20 text-primary">
          <SettingsIcon className="w-6 h-6" />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-foreground">Settings</h1>
          <p className="text-foreground/70 mt-1">Console preferences, integrations and storage</p>
        </div>
      </div>
      {isLoading && <p className="text-sm text-foreground/60">Loading persisted runtime settings...</p>}
      {actionError && <p className="text-sm text-chart-4">{actionError}</p>}
      {actionMessage && !actionError && <p className="text-sm text-chart-1">{actionMessage}</p>}

      <div className="space-y-4">
        {/* Account lives on the profile page; one place for "me". */}
        <Link
          href="/profile"
          className="flex items-center gap-3 rounded-xl border border-border/60 p-4 transition-colors hover:bg-muted/30"
        >
          <span className="rounded-lg bg-primary/15 p-2 text-primary">
            <UserRound className="h-5 w-5" />
          </span>
          <span className="flex-1">
            <span className="block text-sm font-semibold text-foreground">Account and security</span>
            <span className="block text-xs text-muted-foreground">
              Name, photo, password, Google and GitHub sign-in, and signed-in devices are on your profile.
            </span>
          </span>
          <ChevronRight className="h-4 w-4 text-muted-foreground" />
        </Link>

        {/* Appearance: per browser, stored locally, no server round trip. */}
        <Card className="glass border-border/50 hover:border-border/80 transition-all">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-primary" />
              Appearance
            </CardTitle>
            <CardDescription>Applies to this browser only.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="mb-3 flex flex-wrap items-center justify-between gap-3 p-3 rounded-lg bg-muted/20">
              <div>
                <p className="text-sm font-medium text-foreground">Colour theme</p>
                <p className="text-xs text-foreground/50 mt-1">Buttons, highlights, charts and the background follow it. Works in light and dark.</p>
              </div>
              <ChoicePills label="Colour theme" options={accentLabels} value={accent} onChange={setAccent} />
            </div>
            <div className="mb-3 flex flex-wrap items-center justify-between gap-3 p-3 rounded-lg bg-muted/20">
              <div>
                <p className="text-sm font-medium text-foreground">Layout</p>
                <p className="text-xs text-foreground/50 mt-1">Framed floats the console as one rounded panel on large screens.</p>
              </div>
              <ChoicePills label="Layout" options={layoutLabels} value={layoutMode} onChange={setLayoutMode} />
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg bg-muted/20 hover:bg-muted/30 transition-colors">
              <div className="flex-1">
                <Label htmlFor="live-wallpaper" className="text-sm font-medium text-foreground cursor-pointer">
                  Animated background
                </Label>
                <p className="text-xs text-foreground/50 mt-1">
                  A slow moving network behind the pages. Always still if your system asks to reduce motion.
                </p>
              </div>
              <Switch id="live-wallpaper" checked={liveWallpaper} onCheckedChange={setLiveWallpaper} />
            </div>
            <div className="mt-3 flex flex-wrap items-center justify-between gap-3 p-3 rounded-lg bg-muted/20">
              <div>
                <p className="text-sm font-medium text-foreground">Background strength</p>
                <p className="text-xs text-foreground/50 mt-1">How visible it is behind console pages. Cards stay solid so text stays readable.</p>
              </div>
              <ChoicePills label="Background strength" options={strengthLabels} value={wallpaperStrength} onChange={setWallpaperStrength} disabled={!liveWallpaper} />
            </div>
            <div className="mt-3 flex flex-wrap items-center justify-between gap-3 p-3 rounded-lg bg-muted/20">
              <div>
                <p className="text-sm font-medium text-foreground">Scene</p>
                <p className="text-xs text-foreground/50 mt-1">Cycle all fades between the scenes every half minute. Your video plays loop.webm / loop.mp4 from public/backgrounds (format guide in the README there).</p>
              </div>
              <ChoicePills label="Background scene" options={WALLPAPER_STYLES} value={wallpaperStyle} onChange={setWallpaperStyle} disabled={!liveWallpaper} />
            </div>
            <div className="mt-3 flex flex-wrap items-center justify-between gap-3 p-3 rounded-lg bg-muted/20">
              <div>
                <p className="text-sm font-medium text-foreground">Colour</p>
                <p className="text-xs text-foreground/50 mt-1">Match theme follows the colour theme above; Ember and Cyber blue are fixed.</p>
              </div>
              <ChoicePills label="Background colour" options={WALLPAPER_COLORS} value={wallpaperColor} onChange={setWallpaperColor} disabled={!liveWallpaper} />
            </div>
          </CardContent>
        </Card>

        {/* General Settings */}
        <Card className="glass border-border/50 hover:border-border/80 transition-all">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <SettingsIcon className="w-5 h-5 text-primary" />
              General Settings
            </CardTitle>
            <CardDescription>Customize your OTA IDE experience</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {settingRows.map((setting) => (
              <div key={setting.label} className="flex items-center justify-between p-3 rounded-lg bg-muted/20 hover:bg-muted/30 transition-colors">
                <div className="flex items-center gap-3 flex-1">
                  <div className="text-primary/60">{setting.icon}</div>
                  <div className="flex-1">
                    <Label className="text-sm font-medium text-foreground cursor-pointer">{setting.label}</Label>
                    <p className="text-xs text-foreground/50 mt-1">{setting.description}</p>
                  </div>
                </div>
                <Switch checked={setting.value} onCheckedChange={setting.onChange} />
              </div>
            ))}
          </CardContent>
        </Card>

        {/* API Configuration */}
        <Card className="glass border-border/50 hover:border-border/80 transition-all">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Database className="w-5 h-5 text-accent" />
              API Configuration
            </CardTitle>
            <CardDescription>Manage API keys and endpoints for integrations</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label className="text-sm font-medium text-foreground mb-2 block">API Endpoint</Label>
              <div className="flex gap-2">
                <input 
                  type="text" 
                  value={settings.apiEndpoint}
                  onChange={(event) => setSettings((current) => ({
                    ...current,
                    apiEndpoint: event.target.value,
                  }))}
                  className="flex-1 px-3 py-2 bg-muted/50 border border-border/50 rounded-lg text-sm text-foreground placeholder-foreground/40 focus:outline-none focus:border-primary/50"
                />
                <Button
                  size="sm"
                  variant="outline"
                  className="border-border"
                  onClick={() => void handleCopy(settings.apiEndpoint)}
                >
                  <Copy className="w-4 h-4" />
                </Button>
              </div>
            </div>
            
            <div>
              <div className="flex items-center justify-between mb-2">
                <Label className="text-sm font-medium text-foreground">API Key</Label>
                <Badge variant="outline" className="bg-chart-1/20 text-chart-1">Active</Badge>
              </div>
              <div className="flex gap-2">
                <input 
                  type="password" 
                  value={apiKeyPreview}
                  className="flex-1 px-3 py-2 bg-muted/50 border border-border/50 rounded-lg text-sm text-foreground"
                  readOnly
                />
                <Button
                  size="sm"
                  variant="outline"
                  className="border-border"
                  onClick={() => void handleCopy(apiKeyPreview)}
                >
                  <Copy className="w-4 h-4" />
                </Button>
              </div>
            </div>

            <Button
              className="w-full bg-primary hover:bg-primary/90 text-primary-foreground mt-4"
              onClick={() => void handleGenerateApiKey()}
              disabled={busyAction === 'keys.create'}
            >
              Generate New API Key
            </Button>
          </CardContent>
        </Card>

        {/* Network Settings */}
        <Card className="glass border-border/50 hover:border-border/80 transition-all">
          <CardHeader>
            <CardTitle>Network & Storage</CardTitle>
            <CardDescription>Configure network timeouts and storage preferences</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label className="text-sm font-medium text-foreground mb-2 block">Request Timeout (seconds)</Label>
              <input 
                type="number" 
                value={settings.requestTimeoutSec}
                onChange={(event) => setSettings((current) => ({
                  ...current,
                  requestTimeoutSec: Number(event.target.value || 0),
                }))}
                className="w-full px-3 py-2 bg-muted/50 border border-border/50 rounded-lg text-sm text-foreground focus:outline-none focus:border-primary/50"
              />
            </div>
            <div>
              <Label className="text-sm font-medium text-foreground mb-2 block">Cache Size (MB)</Label>
              <input 
                type="number" 
                value={settings.cacheSizeMb}
                onChange={(event) => setSettings((current) => ({
                  ...current,
                  cacheSizeMb: Number(event.target.value || 0),
                }))}
                className="w-full px-3 py-2 bg-muted/50 border border-border/50 rounded-lg text-sm text-foreground focus:outline-none focus:border-primary/50"
              />
            </div>
            <Button
              className="w-full bg-primary hover:bg-primary/90 text-primary-foreground"
              onClick={() => void handleSaveSettings()}
              disabled={busyAction === 'settings.save' || !mayWriteSettings}
              title={mayWriteSettings ? undefined : reasonFor('settings.write')}
            >
              Save Network Settings
            </Button>
          </CardContent>
        </Card>

        {/* Danger Zone */}
        <Card className="glass border-chart-4/20 hover:border-chart-4/40 transition-all">
          <CardHeader>
            <CardTitle className="text-chart-4 flex items-center gap-2">
              <Trash2 className="w-5 h-5" />
              Danger Zone
            </CardTitle>
            <CardDescription>Irreversible actions - proceed with caution</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <Button
              variant="outline"
              className="border-chart-4/50 text-chart-4 hover:bg-chart-4/10 w-full justify-start"
              onClick={() => void handleResetSettings()}
              disabled={busyAction === 'settings.reset' || !mayWriteSettings}
              title={mayWriteSettings ? undefined : reasonFor('settings.write')}
            >
              <Trash2 className="w-4 h-4 mr-2" />
              Reset All Settings
            </Button>
            <Button
              variant="outline"
              className="border-chart-4/50 text-chart-4 hover:bg-chart-4/10 w-full justify-start"
              onClick={() => void runAction('danger.clear-cache', { scope: 'cache-and-temp-files' })}
              disabled={busyAction === 'danger.clear-cache'}
            >
              <Trash2 className="w-4 h-4 mr-2" />
              Clear Cache & Temporary Files
            </Button>
            <Button
              variant="outline"
              className="border-chart-4/50 text-chart-4 hover:bg-chart-4/10 w-full justify-start"
              onClick={() => void runAction('danger.delete-deployments', { scope: 'saved-deployments' })}
              disabled={busyAction === 'danger.delete-deployments'}
            >
              <Trash2 className="w-4 h-4 mr-2" />
              Delete All Saved Deployments
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
