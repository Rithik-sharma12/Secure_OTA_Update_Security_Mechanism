'use client'

import { useState, useMemo } from 'react'
import { useDevices } from '@/lib/data-hooks'
import { ArchitectureBadge } from '@/components/devices/architecture-badge'
import { HealthScoreIndicator } from '@/components/devices/health-score-indicator'
import { Card } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { formatDate } from '@/lib/data-hooks'
import { Search, Download, RefreshCw } from 'lucide-react'

export default function DevicesPage() {
  const devices = useDevices()
  const [searchQuery, setSearchQuery] = useState('')
  const [architectureFilter, setArchitectureFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')

  const filteredDevices = useMemo(() => {
    return devices.filter(device => {
      const matchesSearch =
        device.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        device.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        device.serialNumber.toLowerCase().includes(searchQuery.toLowerCase())

      const matchesArchitecture =
        architectureFilter === 'all' || device.architecture === architectureFilter

      const matchesStatus =
        statusFilter === 'all' || device.status === statusFilter

      return matchesSearch && matchesArchitecture && matchesStatus
    })
  }, [searchQuery, architectureFilter, statusFilter, devices])

  const getStatusBadge = (status: string) => {
    const colors = {
      online: 'bg-green-100 dark:bg-green-950 text-green-700 dark:text-green-300',
      pending: 'bg-yellow-100 dark:bg-yellow-950 text-yellow-700 dark:text-yellow-300',
      quarantined: 'bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-300',
    }
    return colors[status as keyof typeof colors] || colors.online
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row gap-4 justify-between items-start sm:items-center">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Device Registry</h1>
          <p className="text-slate-600 dark:text-slate-400 mt-1">
            Showing {filteredDevices.length} of {devices.length} devices
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm">
            <Download className="w-4 h-4 mr-2" />
            Export
          </Button>
          <Button variant="outline" size="sm">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Filters */}
      <Card className="p-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400" />
            <Input
              placeholder="Search by name, ID, or serial number..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10"
            />
          </div>
          <Select value={architectureFilter} onValueChange={setArchitectureFilter}>
            <SelectTrigger>
              <SelectValue placeholder="Filter by architecture" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Architectures</SelectItem>
              <SelectItem value="ATmega328P">ATmega328P</SelectItem>
              <SelectItem value="ESP8266/ESP32">ESP8266/ESP32</SelectItem>
              <SelectItem value="STM32">STM32</SelectItem>
              <SelectItem value="nRF52840">nRF52840</SelectItem>
            </SelectContent>
          </Select>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger>
              <SelectValue placeholder="Filter by status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Status</SelectItem>
              <SelectItem value="online">Online</SelectItem>
              <SelectItem value="pending">Pending Update</SelectItem>
              <SelectItem value="quarantined">Quarantined</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </Card>

      {/* Devices Table */}
      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900/50">
                <th className="text-left px-6 py-3 font-semibold text-slate-900 dark:text-white">Device Name</th>
                <th className="text-left px-6 py-3 font-semibold text-slate-900 dark:text-white">Architecture</th>
                <th className="text-left px-6 py-3 font-semibold text-slate-900 dark:text-white">Status</th>
                <th className="text-left px-6 py-3 font-semibold text-slate-900 dark:text-white">Health Score</th>
                <th className="text-left px-6 py-3 font-semibold text-slate-900 dark:text-white">Current Version</th>
                <th className="text-left px-6 py-3 font-semibold text-slate-900 dark:text-white">Target Version</th>
                <th className="text-left px-6 py-3 font-semibold text-slate-900 dark:text-white">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {filteredDevices.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-6 py-8 text-center">
                    <p className="text-slate-500 dark:text-slate-400">No devices found matching your filters.</p>
                  </td>
                </tr>
              ) : (
                filteredDevices.map((device) => (
                  <tr
                    key={device.id}
                    className="border-b border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-900/50 transition-colors"
                  >
                    <td className="px-6 py-4">
                      <div>
                        <p className="font-medium text-slate-900 dark:text-white">{device.name}</p>
                        <p className="text-xs text-slate-500 dark:text-slate-400">{device.id}</p>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <ArchitectureBadge architecture={device.architecture} size="sm" />
                    </td>
                    <td className="px-6 py-4">
                      <div className={`inline-block px-3 py-1 rounded-full text-sm font-medium ${getStatusBadge(device.status)}`}>
                        {device.status.charAt(0).toUpperCase() + device.status.slice(1)}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <HealthScoreIndicator score={Math.round(device.healthScore)} showLabel={false} />
                    </td>
                    <td className="px-6 py-4 text-sm text-slate-600 dark:text-slate-400">{device.currentRelease}</td>
                    <td className="px-6 py-4 text-sm text-slate-600 dark:text-slate-400">{device.targetRelease}</td>
                    <td className="px-6 py-4 text-sm text-slate-600 dark:text-slate-400">{formatDate(device.lastSeen)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}
