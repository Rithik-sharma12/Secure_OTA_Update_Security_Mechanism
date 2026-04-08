'use client'

import { useState } from 'react'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Eye, EyeOff, Copy, RotateCcw } from 'lucide-react'

export default function SettingsPage() {
  const [showApiKey, setShowApiKey] = useState(false)
  const [theme, setTheme] = useState('system')
  const [notifications, setNotifications] = useState({
    updateAvailable: true,
    deploymentStatus: true,
    securityAlerts: true,
    deviceQuarantine: true,
  })

  const apiKey = 'ota_sk_1234567890abcdefghijklmnop'

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Settings</h1>
        <p className="text-slate-600 dark:text-slate-400 mt-1">
          Manage your OTA Control Center preferences and configuration
        </p>
      </div>

      {/* Account Settings */}
      <Card className="p-6">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-6">Account Settings</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
              Full Name
            </label>
            <Input
              type="text"
              defaultValue="John Admin"
              className="max-w-md"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
              Email Address
            </label>
            <Input
              type="email"
              defaultValue="admin@otacontrol.local"
              className="max-w-md"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
              Role
            </label>
            <div className="text-sm text-slate-600 dark:text-slate-400">
              Administrator
            </div>
          </div>
          <Button>Save Changes</Button>
        </div>
      </Card>

      {/* Appearance Settings */}
      <Card className="p-6">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-6">Appearance</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
              Theme
            </label>
            <Select value={theme} onValueChange={setTheme}>
              <SelectTrigger className="max-w-md">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="light">Light</SelectItem>
                <SelectItem value="dark">Dark</SelectItem>
                <SelectItem value="system">System</SelectItem>
              </SelectContent>
            </Select>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Choose your preferred color scheme
            </p>
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
              Sidebar Behavior
            </label>
            <Select defaultValue="auto">
              <SelectTrigger className="max-w-md">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="auto">Auto Collapse on Mobile</SelectItem>
                <SelectItem value="always-open">Always Open</SelectItem>
                <SelectItem value="always-closed">Always Collapsed</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      </Card>

      {/* Notification Settings */}
      <Card className="p-6">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-6">Notifications</h2>
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium text-slate-900 dark:text-white">Update Available</p>
              <p className="text-sm text-slate-600 dark:text-slate-400">Notify when new firmware updates are available</p>
            </div>
            <Switch
              checked={notifications.updateAvailable}
              onCheckedChange={(checked) =>
                setNotifications({ ...notifications, updateAvailable: checked })
              }
            />
          </div>
          <div className="border-t border-slate-200 dark:border-slate-700 pt-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-slate-900 dark:text-white">Deployment Status</p>
                <p className="text-sm text-slate-600 dark:text-slate-400">Notify on deployment stage changes</p>
              </div>
              <Switch
                checked={notifications.deploymentStatus}
                onCheckedChange={(checked) =>
                  setNotifications({ ...notifications, deploymentStatus: checked })
                }
              />
            </div>
          </div>
          <div className="border-t border-slate-200 dark:border-slate-700 pt-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-slate-900 dark:text-white">Security Alerts</p>
                <p className="text-sm text-slate-600 dark:text-slate-400">Notify of security vulnerabilities and updates</p>
              </div>
              <Switch
                checked={notifications.securityAlerts}
                onCheckedChange={(checked) =>
                  setNotifications({ ...notifications, securityAlerts: checked })
                }
              />
            </div>
          </div>
          <div className="border-t border-slate-200 dark:border-slate-700 pt-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-slate-900 dark:text-white">Device Quarantine</p>
                <p className="text-sm text-slate-600 dark:text-slate-400">Alert when devices are quarantined</p>
              </div>
              <Switch
                checked={notifications.deviceQuarantine}
                onCheckedChange={(checked) =>
                  setNotifications({ ...notifications, deviceQuarantine: checked })
                }
              />
            </div>
          </div>
        </div>
      </Card>

      {/* API Settings */}
      <Card className="p-6">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-6">API Configuration</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
              API Key
            </label>
            <div className="flex gap-2">
              <div className="flex-1 relative">
                <Input
                  type={showApiKey ? 'text' : 'password'}
                  value={apiKey}
                  readOnly
                  className="font-mono text-xs max-w-md"
                />
              </div>
              <Button
                variant="outline"
                size="icon"
                onClick={() => setShowApiKey(!showApiKey)}
              >
                {showApiKey ? (
                  <EyeOff className="w-4 h-4" />
                ) : (
                  <Eye className="w-4 h-4" />
                )}
              </Button>
              <Button variant="outline" size="icon">
                <Copy className="w-4 h-4" />
              </Button>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Use this key for API authentication in your CI/CD pipeline
            </p>
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
              API Endpoint
            </label>
            <Input
              type="text"
              defaultValue="https://api.otacontrol.local/v1"
              className="max-w-md"
              readOnly
            />
          </div>
          <Button>
            <RotateCcw className="w-4 h-4 mr-2" />
            Regenerate API Key
          </Button>
        </div>
      </Card>

      {/* Integration Settings */}
      <Card className="p-6">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-6">Integrations</h2>
        <div className="space-y-3">
          <div className="flex items-center justify-between p-4 rounded-lg bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-700">
            <div>
              <p className="font-medium text-slate-900 dark:text-white">GitHub Integration</p>
              <p className="text-sm text-slate-600 dark:text-slate-400">Sync releases and trigger deployments from GitHub</p>
            </div>
            <Button>Configure</Button>
          </div>
          <div className="flex items-center justify-between p-4 rounded-lg bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-700">
            <div>
              <p className="font-medium text-slate-900 dark:text-white">Slack Notifications</p>
              <p className="text-sm text-slate-600 dark:text-slate-400">Send deployment and alert notifications to Slack</p>
            </div>
            <Button>Configure</Button>
          </div>
          <div className="flex items-center justify-between p-4 rounded-lg bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-700">
            <div>
              <p className="font-medium text-slate-900 dark:text-white">Webhook Receiver</p>
              <p className="text-sm text-slate-600 dark:text-slate-400">Receive HTTP webhooks from external systems</p>
            </div>
            <Button>Configure</Button>
          </div>
        </div>
      </Card>

      {/* Danger Zone */}
      <Card className="p-6 border-red-200 dark:border-red-900">
        <h2 className="text-lg font-semibold text-red-600 dark:text-red-400 mb-6">Danger Zone</h2>
        <div className="space-y-4">
          <div>
            <p className="text-sm text-slate-600 dark:text-slate-400 mb-3">
              These actions are irreversible. Please proceed with caution.
            </p>
            <Button variant="outline" className="border-red-200 dark:border-red-900 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950">
              Clear Cache
            </Button>
          </div>
          <div className="border-t border-red-200 dark:border-red-900 pt-4">
            <Button variant="outline" className="border-red-200 dark:border-red-900 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950">
              Reset All Settings
            </Button>
          </div>
        </div>
      </Card>

      {/* Version Info */}
      <Card className="p-6 bg-slate-50 dark:bg-slate-900/50">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">System Information</h2>
        <div className="space-y-2 text-sm">
          <div className="flex justify-between">
            <span className="text-slate-600 dark:text-slate-400">Application Version</span>
            <span className="font-mono text-slate-900 dark:text-white">v1.0.0</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-600 dark:text-slate-400">API Version</span>
            <span className="font-mono text-slate-900 dark:text-white">v1.0.0</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-600 dark:text-slate-400">Database Schema</span>
            <span className="font-mono text-slate-900 dark:text-white">2024.02.15</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-600 dark:text-slate-400">Last Check-in</span>
            <span className="font-mono text-slate-900 dark:text-white">2 minutes ago</span>
          </div>
        </div>
      </Card>
    </div>
  )
}
