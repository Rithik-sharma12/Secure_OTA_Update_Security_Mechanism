import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Key, Copy, Eye, EyeOff, RotateCcw, Trash2, CheckCircle2 } from 'lucide-react'

export default function KeyVaultPage() {
  // Mock key data
  const keys = [
    {
      id: 'key-001',
      alias: 'Production Release Key',
      type: 'Ed25519',
      fingerprint: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
      status: 'active',
      createdAt: new Date('2024-01-15'),
      usageCount: 47,
      lastUsed: new Date('2024-02-14'),
      rotationSchedule: 'Every 90 days',
    },
    {
      id: 'key-002',
      alias: 'Staging Release Key',
      type: 'Ed25519',
      fingerprint: 'b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7',
      status: 'active',
      createdAt: new Date('2024-01-20'),
      usageCount: 23,
      lastUsed: new Date('2024-02-13'),
      rotationSchedule: 'Every 90 days',
    },
    {
      id: 'key-003',
      alias: 'Legacy Key (Deprecated)',
      type: 'Ed25519',
      fingerprint: 'c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8',
      status: 'deprecated',
      createdAt: new Date('2023-10-01'),
      usageCount: 156,
      lastUsed: new Date('2023-12-31'),
      rotationSchedule: 'Retired',
    },
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-start">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Key Vault</h1>
          <p className="text-slate-600 dark:text-slate-400 mt-1">
            Manage Ed25519 cryptographic keys for firmware signing
          </p>
        </div>
        <Button>
          <Key className="w-4 h-4 mr-2" />
          Generate New Key
        </Button>
      </div>

      {/* Key Management Overview */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="p-4">
          <p className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">Active Keys</p>
          <p className="text-3xl font-bold text-slate-900 dark:text-white">{keys.filter(k => k.status === 'active').length}</p>
        </Card>
        <Card className="p-4">
          <p className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">Total Usage</p>
          <p className="text-3xl font-bold text-slate-900 dark:text-white">
            {keys.reduce((sum, k) => sum + k.usageCount, 0)}
          </p>
        </Card>
        <Card className="p-4">
          <p className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">Rotation Due</p>
          <p className="text-lg font-bold text-yellow-600 dark:text-yellow-400">In 42 days</p>
        </Card>
      </div>

      {/* Keys Table */}
      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900/50">
                <th className="text-left px-6 py-3 font-semibold text-slate-900 dark:text-white">Key Alias</th>
                <th className="text-left px-6 py-3 font-semibold text-slate-900 dark:text-white">Fingerprint</th>
                <th className="text-left px-6 py-3 font-semibold text-slate-900 dark:text-white">Status</th>
                <th className="text-left px-6 py-3 font-semibold text-slate-900 dark:text-white">Usage</th>
                <th className="text-left px-6 py-3 font-semibold text-slate-900 dark:text-white">Last Used</th>
                <th className="text-left px-6 py-3 font-semibold text-slate-900 dark:text-white">Actions</th>
              </tr>
            </thead>
            <tbody>
              {keys.map((key) => (
                <tr key={key.id} className="border-b border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-900/50">
                  <td className="px-6 py-4">
                    <div>
                      <p className="font-medium text-slate-900 dark:text-white">{key.alias}</p>
                      <p className="text-xs text-slate-500 dark:text-slate-400 font-mono">{key.id}</p>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <code className="text-xs bg-slate-100 dark:bg-slate-900 px-2 py-1 rounded font-mono text-slate-600 dark:text-slate-300">
                        {key.fingerprint.substring(0, 16)}...
                      </code>
                      <button className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 transition-colors">
                        <Copy className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`px-3 py-1 rounded-full text-xs font-semibold ${
                      key.status === 'active'
                        ? 'bg-green-100 dark:bg-green-950 text-green-700 dark:text-green-300'
                        : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300'
                    }`}>
                      {key.status.charAt(0).toUpperCase() + key.status.slice(1)}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm text-slate-600 dark:text-slate-400">
                    {key.usageCount} times
                  </td>
                  <td className="px-6 py-4 text-sm text-slate-600 dark:text-slate-400">
                    {key.lastUsed.toLocaleDateString()}
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex gap-2">
                      {key.status === 'active' && (
                        <>
                          <button className="p-1 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 transition-colors" title="View">
                            <Eye className="w-4 h-4" />
                          </button>
                          <button className="p-1 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 transition-colors" title="Rotate">
                            <RotateCcw className="w-4 h-4" />
                          </button>
                        </>
                      )}
                      {key.status !== 'active' && (
                        <button className="p-1 text-slate-400 hover:text-red-600 dark:hover:text-red-400 transition-colors" title="Delete">
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Key Details */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Key Metadata Panel */}
        <Card className="p-6">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">Key Metadata</h2>
          <div className="space-y-4">
            <div className="pb-4 border-b border-slate-200 dark:border-slate-700">
              <p className="text-xs text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-1">Key Type</p>
              <p className="text-sm font-medium text-slate-900 dark:text-white">Ed25519 (Elliptic Curve)</p>
            </div>
            <div className="pb-4 border-b border-slate-200 dark:border-slate-700">
              <p className="text-xs text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-1">Key Size</p>
              <p className="text-sm font-medium text-slate-900 dark:text-white">256 bits (32 bytes)</p>
            </div>
            <div className="pb-4 border-b border-slate-200 dark:border-slate-700">
              <p className="text-xs text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-1">Full Fingerprint</p>
              <p className="text-xs font-mono bg-slate-100 dark:bg-slate-900 p-3 rounded text-slate-700 dark:text-slate-300 break-all">
                a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
              </p>
            </div>
            <div className="pb-4 border-b border-slate-200 dark:border-slate-700">
              <p className="text-xs text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-1">Created</p>
              <p className="text-sm font-medium text-slate-900 dark:text-white">2024-01-15 14:30:00 UTC</p>
            </div>
            <div>
              <p className="text-xs text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-1">Key Location</p>
              <p className="text-sm font-medium text-slate-900 dark:text-white">Hardware Security Module (HSM)</p>
            </div>
          </div>
        </Card>

        {/* CI/CD Integration Panel */}
        <Card className="p-6">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">CI/CD Integration</h2>
          <div className="space-y-4">
            <div className="pb-4 border-b border-slate-200 dark:border-slate-700">
              <p className="text-xs text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">Environment Variables</p>
              <code className="text-xs bg-slate-100 dark:bg-slate-900 px-3 py-2 rounded font-mono text-slate-700 dark:text-slate-300 block break-all">
                RELEASE_KEY_ID=key-001
              </code>
            </div>
            <div className="pb-4 border-b border-slate-200 dark:border-slate-700">
              <p className="text-xs text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">GitHub Secrets</p>
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0" />
                  <span className="text-xs text-slate-600 dark:text-slate-400">OTA_RELEASE_KEY</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0" />
                  <span className="text-xs text-slate-600 dark:text-slate-400">OTA_RELEASE_KEY_PASS</span>
                </div>
              </div>
            </div>
            <div>
              <p className="text-xs text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">Last CI/CD Run</p>
              <p className="text-sm text-slate-700 dark:text-slate-300">
                2024-02-14 at 10:15 AM
                <span className="ml-2 px-2 py-1 rounded-full bg-green-100 dark:bg-green-950 text-green-700 dark:text-green-300 text-xs font-semibold">
                  Success
                </span>
              </p>
            </div>
          </div>
        </Card>
      </div>

      {/* Rotation Schedule */}
      <Card className="p-6">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">Key Rotation Schedule</h2>
        <div className="space-y-3">
          {[
            { date: '2024-03-15', status: 'upcoming', label: 'Production Release Key Rotation Due' },
            { date: '2024-03-20', status: 'upcoming', label: 'Staging Release Key Rotation Due' },
            { date: '2024-01-15', status: 'completed', label: 'Previous Rotation Completed' },
          ].map((event) => (
            <div key={event.date} className={`flex items-center gap-3 p-3 rounded-lg ${
              event.status === 'completed'
                ? 'bg-slate-50 dark:bg-slate-900/50'
                : 'bg-yellow-50 dark:bg-yellow-950/20'
            }`}>
              <div className={`w-4 h-4 rounded-full flex-shrink-0 ${
                event.status === 'completed'
                  ? 'bg-slate-400'
                  : 'bg-yellow-500'
              }`} />
              <div className="flex-1">
                <p className={`text-sm font-medium ${
                  event.status === 'completed'
                    ? 'text-slate-600 dark:text-slate-400'
                    : 'text-yellow-900 dark:text-yellow-100'
                }`}>
                  {event.label}
                </p>
              </div>
              <p className={`text-sm font-mono ${
                event.status === 'completed'
                  ? 'text-slate-500'
                  : 'text-yellow-700 dark:text-yellow-300'
              }`}>
                {event.date}
              </p>
            </div>
          ))}
        </div>
      </Card>
    </div>
  )
}
