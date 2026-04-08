'use client'

import { useState, useMemo } from 'react'
import { useLogs, formatDate } from '@/lib/data-hooks'
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
import { Search, Download, FileText, CheckCircle2, AlertCircle, Info } from 'lucide-react'
import { cn } from '@/lib/utils'

export default function EventLogsPage() {
  const logs = useLogs()
  const [searchQuery, setSearchQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')
  const [autoScroll, setAutoScroll] = useState(true)

  const filteredLogs = useMemo(() => {
    return logs.filter(log => {
      const matchesSearch =
        log.message.toLowerCase().includes(searchQuery.toLowerCase()) ||
        log.device.toLowerCase().includes(searchQuery.toLowerCase()) ||
        log.id.toLowerCase().includes(searchQuery.toLowerCase())

      const matchesType = typeFilter === 'all' || log.type === typeFilter

      return matchesSearch && matchesType
    })
  }, [searchQuery, typeFilter, logs])

  const getLogIcon = (type: string) => {
    switch (type) {
      case 'success':
        return <CheckCircle2 className="w-4 h-4 text-green-500" />
      case 'error':
        return <AlertCircle className="w-4 h-4 text-red-500" />
      case 'warning':
        return <AlertCircle className="w-4 h-4 text-yellow-500" />
      case 'quarantine':
        return <AlertCircle className="w-4 h-4 text-red-600" />
      default:
        return <Info className="w-4 h-4 text-blue-500" />
    }
  }

  const getLogColor = (type: string) => {
    switch (type) {
      case 'success':
        return 'text-green-400'
      case 'error':
        return 'text-red-400'
      case 'warning':
        return 'text-yellow-400'
      case 'quarantine':
        return 'text-red-500'
      default:
        return 'text-blue-400'
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row gap-4 justify-between items-start sm:items-center">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Event Logs</h1>
          <p className="text-slate-600 dark:text-slate-400 mt-1">
            Showing {filteredLogs.length} of {logs.length} events
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm">
            <Download className="w-4 h-4 mr-2" />
            Export CSV
          </Button>
          <Button
            variant={autoScroll ? 'default' : 'outline'}
            size="sm"
            onClick={() => setAutoScroll(!autoScroll)}
          >
            Auto-scroll {autoScroll ? 'On' : 'Off'}
          </Button>
        </div>
      </div>

      {/* Filters */}
      <Card className="p-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400" />
            <Input
              placeholder="Search logs by message, device ID, or event ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10 font-mono"
            />
          </div>
          <Select value={typeFilter} onValueChange={setTypeFilter}>
            <SelectTrigger>
              <SelectValue placeholder="Filter by type" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Types</SelectItem>
              <SelectItem value="success">Success</SelectItem>
              <SelectItem value="error">Error</SelectItem>
              <SelectItem value="warning">Warning</SelectItem>
              <SelectItem value="info">Info</SelectItem>
              <SelectItem value="quarantine">Quarantine</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </Card>

      {/* Terminal-style Log Viewer */}
      <Card className="overflow-hidden bg-slate-950 border-slate-800">
        <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800 bg-slate-900">
          <div className="flex items-center gap-2">
            <FileText className="w-4 h-4 text-slate-400" />
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wide">Event Stream</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
            <span className="text-xs text-slate-400">Live</span>
          </div>
        </div>

        <div className="max-h-[600px] overflow-y-auto p-4 space-y-1 font-mono text-sm">
          {filteredLogs.length === 0 ? (
            <div className="text-slate-500 text-center py-8">No events found matching your filters.</div>
          ) : (
            filteredLogs.map((log) => (
              <div key={log.id} className="flex gap-3 text-xs hover:bg-slate-900/50 p-2 rounded transition-colors">
                {/* Timestamp */}
                <span className="text-slate-500 flex-shrink-0 whitespace-nowrap">
                  {formatDate(log.timestamp).split(' ').pop()}
                </span>

                {/* Icon and Type */}
                <div className="flex items-center gap-2 flex-shrink-0">
                  {getLogIcon(log.type)}
                  <span className={cn('uppercase font-bold w-12', getLogColor(log.type))}>
                    {log.type === 'quarantine' ? 'QUARANTINE' : log.type.toUpperCase()}
                  </span>
                </div>

                {/* Device ID */}
                <span className="text-cyan-400 flex-shrink-0">[{log.device}]</span>

                {/* Message */}
                <span className="text-slate-300 flex-1">{log.message}</span>

                {/* Details */}
                {log.details && (
                  <span className="text-slate-500">{log.details}</span>
                )}
              </div>
            ))
          )}
        </div>
      </Card>

      {/* Legend */}
      <Card className="p-4">
        <h3 className="font-semibold text-slate-900 dark:text-white mb-3">Log Types</h3>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {[
            { type: 'success', color: 'text-green-500', label: 'Success' },
            { type: 'error', color: 'text-red-500', label: 'Error' },
            { type: 'warning', color: 'text-yellow-500', label: 'Warning' },
            { type: 'info', color: 'text-blue-500', label: 'Info' },
            { type: 'quarantine', color: 'text-red-600', label: 'Quarantine' },
          ].map(({ type, color, label }) => (
            <div key={type} className="flex items-center gap-2">
              <div className={cn('w-2 h-2 rounded-full', color)} />
              <span className="text-sm text-slate-600 dark:text-slate-400">{label}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  )
}
