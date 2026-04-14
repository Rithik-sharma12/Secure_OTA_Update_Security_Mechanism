'use client';

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Settings as SettingsIcon, Bell, Lock, Database, Zap, Trash2, Copy } from 'lucide-react';
import { executeRuntimeAction, fetchRuntimeActionState } from '@/lib/runtime-actions';

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
      return response;
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Action failed.');
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
      label: 'Enable two-factor authentication',
      description: 'Require 2FA for secure account access',
      value: settings.twoFactorAuth,
      icon: <Lock className="w-4 h-4" />,
      onChange: (value: boolean) => setBooleanSetting('twoFactorAuth', value),
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
          <p className="text-foreground/70 mt-1">Manage application preferences and configuration</p>
        </div>
      </div>
      {isLoading && <p className="text-sm text-foreground/60">Loading persisted runtime settings...</p>}
      {actionError && <p className="text-sm text-chart-4">{actionError}</p>}
      {actionMessage && !actionError && <p className="text-sm text-chart-1">{actionMessage}</p>}

      <div className="space-y-4">
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
              disabled={busyAction === 'settings.save'}
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
              disabled={busyAction === 'settings.reset'}
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
