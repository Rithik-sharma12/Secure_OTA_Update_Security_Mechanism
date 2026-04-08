'use client';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Settings as SettingsIcon, Bell, Lock, Database, Zap, Trash2, Copy } from 'lucide-react';

export default function SettingsPage() {
  const settings = [
    { 
      label: 'Auto-update firmware', 
      description: 'Automatically deploy compatible firmware updates', 
      enabled: true,
      icon: <Zap className="w-4 h-4" />
    },
    { 
      label: 'Email notifications', 
      description: 'Receive alerts and updates via email', 
      enabled: true,
      icon: <Bell className="w-4 h-4" />
    },
    { 
      label: 'Enable two-factor authentication', 
      description: 'Require 2FA for secure account access', 
      enabled: false,
      icon: <Lock className="w-4 h-4" />
    },
    { 
      label: 'Device telemetry', 
      description: 'Collect anonymous usage analytics', 
      enabled: true,
      icon: <Database className="w-4 h-4" />
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
            {settings.map((setting) => (
              <div key={setting.label} className="flex items-center justify-between p-3 rounded-lg bg-muted/20 hover:bg-muted/30 transition-colors">
                <div className="flex items-center gap-3 flex-1">
                  <div className="text-primary/60">{setting.icon}</div>
                  <div className="flex-1">
                    <Label className="text-sm font-medium text-foreground cursor-pointer">{setting.label}</Label>
                    <p className="text-xs text-foreground/50 mt-1">{setting.description}</p>
                  </div>
                </div>
                <Switch defaultChecked={setting.enabled} />
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
                  value="https://api.ota-ide.example.com/v1"
                  className="flex-1 px-3 py-2 bg-muted/50 border border-border/50 rounded-lg text-sm text-foreground placeholder-foreground/40 focus:outline-none focus:border-primary/50"
                  readOnly
                />
                <Button size="sm" variant="outline" className="border-border">
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
                  value="••••••••••••••••••••••••"
                  className="flex-1 px-3 py-2 bg-muted/50 border border-border/50 rounded-lg text-sm text-foreground"
                  readOnly
                />
                <Button size="sm" variant="outline" className="border-border">
                  <Copy className="w-4 h-4" />
                </Button>
              </div>
            </div>

            <Button className="w-full bg-primary hover:bg-primary/90 text-primary-foreground mt-4">
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
                defaultValue="30"
                className="w-full px-3 py-2 bg-muted/50 border border-border/50 rounded-lg text-sm text-foreground focus:outline-none focus:border-primary/50"
              />
            </div>
            <div>
              <Label className="text-sm font-medium text-foreground mb-2 block">Cache Size (MB)</Label>
              <input 
                type="number" 
                defaultValue="500"
                className="w-full px-3 py-2 bg-muted/50 border border-border/50 rounded-lg text-sm text-foreground focus:outline-none focus:border-primary/50"
              />
            </div>
            <Button className="w-full bg-primary hover:bg-primary/90 text-primary-foreground">
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
            <Button variant="outline" className="border-chart-4/50 text-chart-4 hover:bg-chart-4/10 w-full justify-start">
              <Trash2 className="w-4 h-4 mr-2" />
              Reset All Settings
            </Button>
            <Button variant="outline" className="border-chart-4/50 text-chart-4 hover:bg-chart-4/10 w-full justify-start">
              <Trash2 className="w-4 h-4 mr-2" />
              Clear Cache & Temporary Files
            </Button>
            <Button variant="outline" className="border-chart-4/50 text-chart-4 hover:bg-chart-4/10 w-full justify-start">
              <Trash2 className="w-4 h-4 mr-2" />
              Delete All Saved Deployments
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
