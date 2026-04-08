import { Gauge, Cpu, LogSquare, GitBranch, Package, FileJson, Shield, Heart, Key, Settings } from 'lucide-react'

export const navIcons = {
  dashboard: Gauge,
  devices: Cpu,
  eventLogs: LogSquare,
  pipeline: GitBranch,
  releases: Package,
  manifest: FileJson,
  tcvEngine: Shield,
  ashMonitor: Heart,
  keyVault: Key,
  settings: Settings,
}

export const navItems = [
  {
    group: 'MONITOR',
    items: [
      { name: 'Dashboard', href: '/dashboard', icon: 'dashboard' },
      { name: 'Devices', href: '/devices', icon: 'devices' },
      { name: 'Event Logs', href: '/event-logs', icon: 'eventLogs' },
    ],
  },
  {
    group: 'DEPLOY',
    items: [
      { name: 'Pipeline', href: '/pipeline', icon: 'pipeline' },
      { name: 'Releases', href: '/releases', icon: 'releases' },
      { name: 'Manifest', href: '/manifest', icon: 'manifest' },
    ],
  },
  {
    group: 'SECURITY',
    items: [
      { name: 'TCV Engine', href: '/tcv-engine', icon: 'tcvEngine' },
      { name: 'ASH Monitor', href: '/ash-monitor', icon: 'ashMonitor' },
      { name: 'Key Vault', href: '/key-vault', icon: 'keyVault' },
    ],
  },
  {
    group: 'CONFIG',
    items: [
      { name: 'Settings', href: '/settings', icon: 'settings' },
    ],
  },
]
