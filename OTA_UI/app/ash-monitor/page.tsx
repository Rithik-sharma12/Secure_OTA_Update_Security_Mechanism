'use client'

import { useState } from 'react'
import { useDevices } from '@/lib/data-hooks'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { AlertTriangle, Zap } from 'lucide-react'
import { getHealthCategory } from '@/lib/data-hooks'

export default function ASHMonitorPage() {
  const devices = useDevices()
  const [selectedDevice, setSelectedDevice] = useState(devices[0])

  const quarantinedDevices = devices.filter(d => d.status === 'quarantined')
  const warningDevices = devices.filter(d => d.healthScore < 60 && d.status !== 'quarantined')
  const healthyDevices = devices.filter(d => d.healthScore >= 60 && d.status !== 'quarantined')

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'critical':
        return 'bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-300'
      case 'warning':
        return 'bg-yellow-100 dark:bg-yellow-950 text-yellow-700 dark:text-yellow-300'
      case 'good':
        return 'bg-green-100 dark:bg-green-950 text-green-700 dark:text-green-300'
      case 'excellent':
        return 'bg-teal-100 dark:bg-teal-950 text-teal-700 dark:text-teal-300'
      default:
        return 'bg-slate-100 dark:bg-slate-900 text-slate-700 dark:text-slate-300'
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">ASH Monitor</h1>
        <p className="text-slate-600 dark:text-slate-400 mt-1">
          Autonomous System Health monitoring and device quarantine management
        </p>
      </div>

      {/* Health Summary */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="p-4">
          <p className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">Total Devices</p>
          <p className="text-3xl font-bold text-slate-900 dark:text-white">{devices.length}</p>
        </Card>
        <Card className="p-4">
          <p className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">Healthy</p>
          <p className="text-3xl font-bold text-green-600 dark:text-green-400">{healthyDevices.length}</p>
        </Card>
        <Card className="p-4">
          <p className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">Warning</p>
          <p className="text-3xl font-bold text-yellow-600 dark:text-yellow-400">{warningDevices.length}</p>
        </Card>
        <Card className="p-4 border-l-4 border-red-500">
          <p className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">Quarantined</p>
          <p className="text-3xl font-bold text-red-600 dark:text-red-400">{quarantinedDevices.length}</p>
        </Card>
      </div>

      {/* Quarantined Devices Alert */}
      {quarantinedDevices.length > 0 && (
        <Card className="p-6 border-l-4 border-red-500 bg-red-50/50 dark:bg-red-950/20">
          <div className="flex items-start gap-4">
            <AlertTriangle className="w-6 h-6 text-red-500 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <h3 className="font-semibold text-red-900 dark:text-red-100 mb-2">Quarantined Devices Detected</h3>
              <p className="text-sm text-red-800 dark:text-red-200 mb-3">
                {quarantinedDevices.length} device{quarantinedDevices.length > 1 ? 's' : ''} have been isolated due to health check failures. Review and take corrective action.
              </p>
              <div className="space-y-1">
                {quarantinedDevices.map(device => (
                  <p key={device.id} className="text-xs font-mono text-red-700 dark:text-red-300">
                    • {device.id} - Health: {Math.round(device.healthScore)}%
                  </p>
                ))}
              </div>
            </div>
          </div>
        </Card>
      )}

      {/* Device Health Grid */}
      <Card className="p-6">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">Device Health Matrix</h2>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
          {devices.map(device => {
            const category = getHealthCategory(device.healthScore)
            return (
              <button
                key={device.id}
                onClick={() => setSelectedDevice(device)}
                className={`p-4 rounded-lg border-2 transition-all cursor-pointer ${
                  selectedDevice.id === device.id
                    ? 'border-teal-500 bg-teal-50 dark:bg-teal-950'
                    : `border-slate-200 dark:border-slate-700 ${getCategoryColor(category)}`
                }`}
              >
                <p className="text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">{device.id}</p>
                <p className="text-2xl font-bold">{Math.round(device.healthScore)}</p>
                <div className="mt-1 h-1 bg-slate-300 dark:bg-slate-700 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${
                      device.healthScore >= 80
                        ? 'bg-teal-500'
                        : device.healthScore >= 60
                        ? 'bg-green-500'
                        : device.healthScore >= 40
                        ? 'bg-yellow-500'
                        : 'bg-red-500'
                    }`}
                    style={{ width: `${device.healthScore}%` }}
                  />
                </div>
              </button>
            )
          })}
        </div>
      </Card>

      {/* Selected Device Details */}
      {selectedDevice && (
        <Card className="p-6">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">Device Details</h2>
          <div className="space-y-4">
            {/* Header */}
            <div className="flex items-start justify-between pb-4 border-b border-slate-200 dark:border-slate-700">
              <div>
                <h3 className="text-2xl font-bold text-slate-900 dark:text-white">{selectedDevice.name}</h3>
                <p className="text-sm text-slate-500 dark:text-slate-400 font-mono">{selectedDevice.id}</p>
              </div>
              <div className="text-right">
                <p className="text-4xl font-bold text-slate-900 dark:text-white">
                  {Math.round(selectedDevice.healthScore)}
                </p>
                <p className={`text-sm font-semibold ${
                  selectedDevice.healthScore >= 80
                    ? 'text-teal-600 dark:text-teal-400'
                    : selectedDevice.healthScore >= 60
                    ? 'text-green-600 dark:text-green-400'
                    : selectedDevice.healthScore >= 40
                    ? 'text-yellow-600 dark:text-yellow-400'
                    : 'text-red-600 dark:text-red-400'
                }`}>
                  {getHealthCategory(selectedDevice.healthScore).toUpperCase()}
                </p>
              </div>
            </div>

            {/* Health Metrics Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div>
                <p className="text-xs text-slate-600 dark:text-slate-400 mb-1">Status</p>
                <p className={`font-semibold capitalize ${
                  selectedDevice.status === 'online'
                    ? 'text-green-600 dark:text-green-400'
                    : selectedDevice.status === 'pending'
                    ? 'text-yellow-600 dark:text-yellow-400'
                    : 'text-red-600 dark:text-red-400'
                }`}>
                  {selectedDevice.status}
                </p>
              </div>
              <div>
                <p className="text-xs text-slate-600 dark:text-slate-400 mb-1">Architecture</p>
                <p className="font-semibold text-slate-900 dark:text-white">{selectedDevice.architecture}</p>
              </div>
              <div>
                <p className="text-xs text-slate-600 dark:text-slate-400 mb-1">Firmware Version</p>
                <p className="font-mono text-sm text-slate-900 dark:text-white">{selectedDevice.firmwareVersion}</p>
              </div>
              <div>
                <p className="text-xs text-slate-600 dark:text-slate-400 mb-1">Location</p>
                <p className="text-sm text-slate-900 dark:text-white">{selectedDevice.location}</p>
              </div>
            </div>

            {/* Health Score Breakdown */}
            <div className="p-4 rounded-lg bg-slate-50 dark:bg-slate-900/50">
              <p className="text-sm font-semibold text-slate-900 dark:text-white mb-3">Health Score Factors</p>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-slate-700 dark:text-slate-300">Firmware Stability</span>
                  <div className="flex items-center gap-2">
                    <div className="w-20 h-2 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
                      <div className="bg-green-500 h-full w-[85%]" />
                    </div>
                    <span className="text-xs font-semibold text-slate-600 dark:text-slate-400 w-8">85%</span>
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-slate-700 dark:text-slate-300">Memory Usage</span>
                  <div className="flex items-center gap-2">
                    <div className="w-20 h-2 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
                      <div className="bg-yellow-500 h-full w-[65%]" />
                    </div>
                    <span className="text-xs font-semibold text-slate-600 dark:text-slate-400 w-8">65%</span>
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-slate-700 dark:text-slate-300">Update Success Rate</span>
                  <div className="flex items-center gap-2">
                    <div className="w-20 h-2 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
                      <div className="bg-teal-500 h-full w-[92%]" />
                    </div>
                    <span className="text-xs font-semibold text-slate-600 dark:text-slate-400 w-8">92%</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Actions */}
            <div className="flex flex-wrap gap-2 pt-4">
              {selectedDevice.status === 'quarantined' && (
                <>
                  <Button size="sm">
                    <Zap className="w-4 h-4 mr-2" />
                    Release from Quarantine
                  </Button>
                  <Button variant="outline" size="sm">
                    View Quarantine Reason
                  </Button>
                </>
              )}
              {selectedDevice.status !== 'quarantined' && (
                <>
                  <Button variant="outline" size="sm">
                    Trigger Health Check
                  </Button>
                  <Button variant="outline" size="sm">
                    View Events
                  </Button>
                </>
              )}
            </div>
          </div>
        </Card>
      )}
    </div>
  )
}
