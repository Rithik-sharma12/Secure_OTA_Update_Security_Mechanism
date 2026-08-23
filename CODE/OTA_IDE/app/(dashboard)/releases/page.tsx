'use client';

import React from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Download, Plus, Archive, Eye } from 'lucide-react';
import { formatNumber, formatUtcDate } from '@/lib/formatters';
import { useRuntimeSnapshot } from '@/lib/runtime-data';
import { PublishFirmwareCard } from '@/components/dashboard/publish-firmware-card';
import { downloadRuntimePayload, executeRuntimeAction, fetchRuntimeActionState, type RuntimeDownloadPayload } from '@/lib/runtime-actions';

function getStatusColor(status: string) {
  switch (status) {
    case 'published':
      return 'bg-chart-1/20 text-chart-1';
    case 'draft':
      return 'bg-chart-3/20 text-chart-3';
    case 'archived':
      return 'bg-muted text-muted-foreground';
    default:
      return 'bg-muted text-muted-foreground';
  }
}

export default function ReleasesPage() {
  const { snapshot, isLoading, refresh } = useRuntimeSnapshot();
  const publishRef = React.useRef<HTMLDivElement>(null);
  const [archivedReleaseIds, setArchivedReleaseIds] = React.useState<string[]>([]);
  const [selectedReleaseId, setSelectedReleaseId] = React.useState<string | null>(null);
  const [busyReleaseId, setBusyReleaseId] = React.useState<string | null>(null);
  const [actionMessage, setActionMessage] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);
  const releases = snapshot.releases;

  React.useEffect(() => {
    const loadState = async () => {
      try {
        const response = await fetchRuntimeActionState<{ archivedReleaseIds?: string[] }>();
        setArchivedReleaseIds(response.data?.archivedReleaseIds || []);
      } catch {
        setArchivedReleaseIds([]);
      }
    };

    void loadState();
  }, []);

  const getReleaseStatus = (releaseId: string, fallbackStatus: string) => {
    if (archivedReleaseIds.includes(releaseId)) {
      return 'archived';
    }

    return fallbackStatus;
  };

  const handleDownload = async (releaseId: string, fileName?: string) => {
    setBusyReleaseId(releaseId);
    setActionError(null);
    setActionMessage(null);

    try {
      const response = await executeRuntimeAction<RuntimeDownloadPayload>('releases.download', {
        fileName,
      });

      if (response.data) {
        downloadRuntimePayload(response.data);
      }

      setActionMessage(response.message || 'Firmware download is ready.');
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Failed to download release asset.');
    } finally {
      setBusyReleaseId(null);
    }
  };

  const handleArchive = async (releaseId: string) => {
    setBusyReleaseId(releaseId);
    setActionError(null);
    setActionMessage(null);

    try {
      const response = await executeRuntimeAction('releases.archive', { releaseId });
      setArchivedReleaseIds((current) => (current.includes(releaseId) ? current : [...current, releaseId]));
      setActionMessage(response.message || `Release ${releaseId} archived.`);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to archive release.');
    } finally {
      setBusyReleaseId(null);
    }
  };

  const handleView = (releaseId: string) => {
    setSelectedReleaseId(releaseId);
    setActionError(null);
    setActionMessage(`Selected release ${releaseId} for detailed inspection.`);
  };

  const publishedCount = releases.filter((release) => getReleaseStatus(release.id, release.status) === 'published').length;
  const totalDownloads = releases.reduce((sum, release) => sum + release.downloadCount, 0);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Releases</h1>
          <p className="text-foreground/70 mt-1">Firmware release history and management</p>
          {!snapshot.connection.reachable && snapshot.connection.error && (
            <p className="text-sm text-chart-4 mt-2">{snapshot.connection.error}</p>
          )}
        </div>
        <Button
          className="bg-primary hover:bg-primary/90 text-primary-foreground"
          onClick={() => publishRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })}
        >
          <Plus className="w-4 h-4 mr-2" />
          New Release
        </Button>
      </div>
      {actionError && <p className="text-sm text-chart-4">{actionError}</p>}
      {actionMessage && !actionError && <p className="text-sm text-chart-1">{actionMessage}</p>}

      {/* Upload a compiled .bin and publish it as the latest release */}
      <div ref={publishRef}>
        <PublishFirmwareCard onPublished={() => void refresh()} />
      </div>

      {/* Releases List */}
      <div className="space-y-4">
        {isLoading && releases.length === 0 && (
          <Card className="glass border-border/50">
            <CardContent className="pt-6 text-sm text-foreground/60">Loading live releases...</CardContent>
          </Card>
        )}

        {!isLoading && releases.length === 0 && (
          <Card className="glass border-border/50">
            <CardContent className="pt-6 text-sm text-foreground/60">
              No live releases published yet. Push a gateway manifest to populate this section.
            </CardContent>
          </Card>
        )}

        {releases.map((release) => {
          const status = getReleaseStatus(release.id, release.status);
          const isBusy = busyReleaseId === release.id;
          return (
          <Card
            key={release.id}
            className={`glass border-border/50 hover:border-border/80 transition-colors ${
              selectedReleaseId === release.id ? 'ring-1 ring-primary/40' : ''
            }`}
          >
            <CardContent className="pt-6">
              <div className="flex items-start justify-between mb-4">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <h3 className="text-xl font-semibold text-foreground">
                      v{release.version}
                    </h3>
                    <Badge
                      variant="outline"
                      className={`capitalize text-xs ${getStatusColor(status)}`}
                    >
                      {status}
                    </Badge>
                  </div>
                  <p className="text-foreground/70 mb-3">{release.description}</p>
                  
                  {/* Release Info */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                    <div>
                      <p className="text-xs text-foreground/50 mb-1">Release Date</p>
                      <p className="text-sm font-medium text-foreground">
                        {formatUtcDate(release.releaseDate)}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-foreground/50 mb-1">Downloads</p>
                      <p className="text-sm font-medium text-foreground">
                        {formatNumber(release.downloadCount)}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-foreground/50 mb-1">Assets</p>
                      <p className="text-sm font-medium text-foreground">
                        {release.assets.length} file(s)
                      </p>
                    </div>
                  </div>

                  {/* Compatible Devices */}
                  <div className="mb-4">
                    <p className="text-xs text-foreground/50 mb-2">Compatible Devices</p>
                    <div className="flex flex-wrap gap-2">
                      {release.compatible.map((device) => (
                        <Badge
                          key={device}
                          variant="secondary"
                          className="bg-secondary/30 text-foreground/80 text-xs"
                        >
                          {device}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  {/* Changelog */}
                  <div className="bg-muted/30 rounded-lg p-3 mb-4">
                    <p className="text-xs text-foreground/50 mb-2">Changelog</p>
                    <pre className="text-xs text-foreground/70 whitespace-pre-wrap break-words font-mono">
                      {release.changelog}
                    </pre>
                  </div>
                </div>

                {/* Action Buttons */}
                <div className="flex-shrink-0 ml-4 flex flex-col gap-2">
                  <Button
                    size="sm"
                    className="bg-primary hover:bg-primary/90 text-primary-foreground"
                    onClick={() => void handleDownload(release.id)}
                    disabled={isBusy}
                  >
                    <Download className="w-4 h-4 mr-1" />
                    {isBusy ? 'Working...' : 'Download'}
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    className="border-border"
                    onClick={() => handleView(release.id)}
                  >
                    <Eye className="w-4 h-4 mr-1" />
                    View
                  </Button>
                  {status === 'published' && (
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-border"
                      onClick={() => void handleArchive(release.id)}
                      disabled={isBusy}
                    >
                      <Archive className="w-4 h-4 mr-1" />
                      Archive
                    </Button>
                  )}
                </div>
              </div>

              {/* Assets */}
              {release.assets.length > 0 && (
                <div className="border-t border-border/50 pt-4">
                  <p className="text-xs text-foreground/50 mb-3 font-semibold">Assets</p>
                  <div className="space-y-2">
                    {release.assets.map((asset) => (
                      <div key={asset.id} className="flex items-center justify-between p-2 rounded bg-muted/20 text-xs">
                        <div>
                          <p className="text-foreground font-medium">{asset.name}</p>
                          <p className="text-foreground/50">
                            {(asset.size / 1024).toFixed(2)} KB • SHA256: {asset.checksum.substring(0, 8)}...
                          </p>
                        </div>
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-7"
                          onClick={() => void handleDownload(release.id, asset.name)}
                          disabled={isBusy}
                        >
                          <Download className="w-3 h-3" />
                        </Button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        );
        })}
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          { label: 'Total Releases', value: releases.length, color: 'bg-chart-2/20 text-chart-2' },
          { label: 'Published', value: publishedCount, color: 'bg-chart-1/20 text-chart-1' },
          { label: 'Total Downloads', value: formatNumber(totalDownloads), color: 'bg-primary/20 text-primary' },
        ].map((stat) => (
          <Card key={stat.label} className="glass border-border/50">
            <CardContent className="pt-6">
              <p className="text-sm text-foreground/70 mb-1">{stat.label}</p>
              <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
