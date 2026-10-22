'use client';

import React from 'react';
import Link from 'next/link';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { 
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Search, Download, AlertCircle, CheckCircle, Info, AlertTriangle } from 'lucide-react';
import { formatUtcDateTime } from '@/lib/formatters';
import { useRuntimeSnapshot } from '@/lib/runtime-data';
import { downloadRuntimePayload, executeRuntimeAction, type RuntimeDownloadPayload } from '@/lib/runtime-actions';
import { StatGrid, StatTile } from '@/components/ui/stat-tile';

function getSeverityIcon(severity: string) {
  switch (severity) {
    case 'success':
      return <CheckCircle className="w-4 h-4 text-chart-1" />;
    case 'error':
      return <AlertCircle className="w-4 h-4 text-chart-4" />;
    case 'warning':
      return <AlertTriangle className="w-4 h-4 text-chart-3" />;
    case 'info':
      return <Info className="w-4 h-4 text-chart-2" />;
    default:
      return <Info className="w-4 h-4" />;
  }
}

function getSeverityColor(severity: string) {
  switch (severity) {
    case 'success':
      return 'bg-chart-1/20 text-chart-1';
    case 'error':
      return 'bg-chart-4/20 text-chart-4';
    case 'warning':
      return 'bg-chart-3/20 text-chart-3';
    case 'info':
      return 'bg-chart-2/20 text-chart-2';
    default:
      return 'bg-muted text-muted-foreground';
  }
}

export default function EventLogsPage() {
  const [searchTerm, setSearchTerm] = React.useState('');
  const [selectedSeverity, setSelectedSeverity] = React.useState('all');
  const [selectedType, setSelectedType] = React.useState('all');
  const [selectedEventId, setSelectedEventId] = React.useState<string | null>(null);
  const [isExporting, setIsExporting] = React.useState(false);
  const [actionMessage, setActionMessage] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);
  const { snapshot, isLoading } = useRuntimeSnapshot();

  const filteredEvents = snapshot.events.filter(event => {
    const matchesSearch = event.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      event.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      event.deviceId?.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesSeverity = selectedSeverity === 'all' || event.severity === selectedSeverity;
    const matchesType = selectedType === 'all' || event.type === selectedType;

    return matchesSearch && matchesSeverity && matchesType;
  });

  const eventTypes = Array.from(new Set(snapshot.events.map(e => e.type)));
  const severities = Array.from(new Set(snapshot.events.map(e => e.severity)));

  const handleExport = async () => {
    setIsExporting(true);
    setActionError(null);
    setActionMessage(null);

    try {
      const response = await executeRuntimeAction<RuntimeDownloadPayload>('events.export');

      if (response.data) {
        downloadRuntimePayload(response.data);
      }

      setActionMessage(response.message || 'Event export is ready.');
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to export events right now.');
    } finally {
      setIsExporting(false);
    }
  };

  const handleView = (eventId: string) => {
    setSelectedEventId((current) => (current === eventId ? null : eventId));
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Event Logs</h1>
          <p className="text-foreground/70 mt-1">System events and device activities</p>
          {!snapshot.connection.reachable && snapshot.connection.error && (
            <p className="text-sm text-chart-4 mt-2">{snapshot.connection.error}</p>
          )}
        </div>
        <Button
          variant="outline"
          className="border-border"
          onClick={handleExport}
          disabled={isExporting}
          title="Download the gateway's newest 500 events as CSV"
        >
          <Download className="w-4 h-4 mr-2" />
          {isExporting ? 'Exporting...' : 'Export CSV'}
        </Button>
      </div>
      {actionError && <p className="text-sm text-chart-4">{actionError}</p>}
      {actionMessage && !actionError && <p className="text-sm text-chart-1">{actionMessage}</p>}

      {/* Event statistics */}
      <StatGrid columns={4}>
        <StatTile label="Events" value={snapshot.events.length} hint="In the current window" />
        <StatTile
          label="Errors"
          value={snapshot.events.filter((e) => e.severity === 'error').length}
          tone={snapshot.events.some((e) => e.severity === 'error') ? 'bad' : 'neutral'}
        />
        <StatTile
          label="Warnings"
          value={snapshot.events.filter((e) => e.severity === 'warning').length}
          tone={snapshot.events.some((e) => e.severity === 'warning') ? 'warn' : 'neutral'}
        />
        <StatTile
          label="Success"
          value={snapshot.events.filter((e) => e.severity === 'success').length}
          tone={snapshot.events.some((e) => e.severity === 'success') ? 'good' : 'neutral'}
        />
      </StatGrid>

      {/* Filters */}
      <Card className="glass border-border/50">
        <CardContent className="pt-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Search */}
            <div className="relative">
              <Search className="absolute left-3 top-3 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search events..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 bg-muted/50 border-border/50"
              />
            </div>

            {/* Severity Filter */}
            <Select value={selectedSeverity} onValueChange={setSelectedSeverity}>
              <SelectTrigger className="bg-muted/50 border-border/50">
                <SelectValue placeholder="Filter by severity" />
              </SelectTrigger>
              <SelectContent className="bg-card border-border">
                <SelectItem value="all">All Severities</SelectItem>
                {severities.map((severity) => (
                  <SelectItem key={severity} value={severity}>
                    {severity.charAt(0).toUpperCase() + severity.slice(1)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            {/* Type Filter */}
            <Select value={selectedType} onValueChange={setSelectedType}>
              <SelectTrigger className="bg-muted/50 border-border/50">
                <SelectValue placeholder="Filter by type" />
              </SelectTrigger>
              <SelectContent className="bg-card border-border">
                <SelectItem value="all">All Types</SelectItem>
                {eventTypes.map((type) => (
                  <SelectItem key={type} value={type}>
                    {type.replace(/_/g, ' ').charAt(0).toUpperCase() + type.slice(1)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Events Timeline */}
      <Card className="glass border-border/50">
        <CardHeader>
          <CardTitle>Event Timeline</CardTitle>
          <CardDescription>
            {isLoading ? 'Loading live events...' : `${filteredEvents.length} event(s) found`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {filteredEvents.length > 0 ? (
              filteredEvents.map((event, index) => (
                <div
                  key={event.id}
                  className={`p-4 rounded-lg border glass-sm hover:border-border/80 transition-colors ${
                    selectedEventId === event.id ? 'border-primary/60' : 'border-border/50'
                  } ${
                    index !== filteredEvents.length - 1 ? 'pb-4' : ''
                  }`}
                >
                  <div className="flex items-start gap-4">
                    {/* Severity Icon */}
                    <div className={`p-2 rounded-lg ${getSeverityColor(event.severity)} mt-0.5`}>
                      {getSeverityIcon(event.severity)}
                    </div>

                    {/* Event Details */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <h3 className="font-semibold text-foreground">{event.title}</h3>
                        <Badge
                          variant="outline"
                          className={`text-xs capitalize ${getSeverityColor(event.severity)}`}
                        >
                          {event.severity}
                        </Badge>
                        <Badge
                          variant="outline"
                          className="text-xs bg-muted/50 text-foreground/70"
                        >
                          {event.type.replace(/_/g, ' ')}
                        </Badge>
                      </div>
                      <p className="text-sm text-foreground/70 mb-2">{event.description}</p>
                      <div className="flex items-center gap-4 text-xs text-foreground/50">
                        <span>{formatUtcDateTime(event.timestamp)}</span>
                        {event.deviceId && <span>Device: {event.deviceId}</span>}
                      </div>
                    </div>

                    {/* Action Button */}
                    <Button
                      variant="ghost"
                      size="sm"
                      className="flex-shrink-0"
                      onClick={() => handleView(event.id)}
                      aria-expanded={selectedEventId === event.id}
                    >
                      {selectedEventId === event.id ? 'Hide' : 'Details'}
                    </Button>
                  </div>
                  {selectedEventId === event.id && (
                    <dl className="mt-3 grid grid-cols-1 gap-2 rounded-lg bg-muted/30 p-3 text-xs sm:grid-cols-2">
                      <div>
                        <dt className="text-foreground/50">Event id</dt>
                        <dd className="break-all font-mono">{event.id}</dd>
                      </div>
                      <div>
                        <dt className="text-foreground/50">Time (UTC)</dt>
                        <dd className="font-mono">{event.timestamp.toISOString()}</dd>
                      </div>
                      <div>
                        <dt className="text-foreground/50">Type</dt>
                        <dd>{event.type}</dd>
                      </div>
                      <div>
                        <dt className="text-foreground/50">Device</dt>
                        <dd>
                          {event.deviceId ? (
                            <Link href={`/devices/${encodeURIComponent(event.deviceId)}`} className="underline">
                              {event.deviceId}
                            </Link>
                          ) : (
                            'Gateway'
                          )}
                        </dd>
                      </div>
                      <div className="sm:col-span-2">
                        <dt className="text-foreground/50">Description</dt>
                        <dd className="whitespace-pre-wrap break-words">{event.description || 'No description.'}</dd>
                      </div>
                    </dl>
                  )}
                </div>
              ))
            ) : (
              <div className="text-center py-12">
                <AlertCircle className="w-12 h-12 text-muted-foreground/50 mx-auto mb-3" />
                <p className="text-foreground/50 mb-2">{snapshot.events.length === 0 ? 'No events have been recorded yet.' : 'No event matches these filters.'}</p>
                <p className="text-sm text-foreground/40">Device heartbeats and gateway alerts appear here.</p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

    </div>
  );
}
