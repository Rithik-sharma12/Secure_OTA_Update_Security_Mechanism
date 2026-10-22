'use client';

import React from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Download, Plus, Archive, ArchiveRestore, Eye, Package } from 'lucide-react';
import { EmptyState, SkeletonRows } from '@/components/ui/empty-state';
import { formatBytes, formatNumber, formatUtcDate, formatUtcDateTime } from '@/lib/formatters';
import { useRuntimeSnapshot } from '@/lib/runtime-data';
import { PublishFirmwareCard } from '@/components/dashboard/publish-firmware-card';
import { downloadReleaseFile } from '@/lib/runtime-actions';
import { apiFetch } from '@/lib/client-auth';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { useCurrentUser } from '@/lib/use-current-user';
import { StatGrid, StatTile } from '@/components/ui/stat-tile';

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

async function setReleaseArchived(releaseId: string, archived: boolean) {
  const response = await apiFetch(`/api/releases/${encodeURIComponent(releaseId)}/${archived ? 'archive' : 'unarchive'}`, {
    method: 'POST',
  });
  const body = (await response.json().catch(() => null)) as { ok?: boolean; error?: string } | null;
  if (!response.ok || !body?.ok) {
    throw new Error(body?.error || `The gateway refused the request (${response.status}).`);
  }
}

export default function ReleasesPage() {
  const { can, reasonFor } = useCurrentUser();
  const mayArchive = can('releases.manage');
  const { snapshot, isLoading, refresh } = useRuntimeSnapshot();
  const publishRef = React.useRef<HTMLDivElement>(null);
  const [detailReleaseId, setDetailReleaseId] = React.useState<string | null>(null);
  const [busyReleaseId, setBusyReleaseId] = React.useState<string | null>(null);
  const [actionMessage, setActionMessage] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);
  const releases = snapshot.releases;
  const detailRelease = releases.find((release) => release.id === detailReleaseId) || null;

  const handleDownload = async (releaseId: string, fileName: string | undefined) => {
    if (!fileName) {
      setActionError('This release has no stored file to download.');
      return;
    }
    setBusyReleaseId(releaseId);
    setActionError(null);
    setActionMessage(null);
    try {
      await downloadReleaseFile(fileName);
      setActionMessage(`Downloaded ${fileName}.`);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Failed to download release asset.');
    } finally {
      setBusyReleaseId(null);
    }
  };

  const handleArchive = async (releaseId: string, version: string, archived: boolean) => {
    setBusyReleaseId(releaseId);
    setActionError(null);
    setActionMessage(null);
    try {
      await setReleaseArchived(releaseId, archived);
      setActionMessage(
        archived
          ? `v${version} archived. Devices are no longer offered it.`
          : `v${version} restored. Devices are offered it again.`
      );
      await refresh();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to change the release.');
    } finally {
      setBusyReleaseId(null);
    }
  };

  const publishedCount = releases.filter((release) => release.status === 'published').length;
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

      {/* Summary */}
      <StatGrid columns={3}>
        <StatTile label="Releases" value={releases.length} hint="Including archived" />
        <StatTile
          label="Published"
          value={publishedCount}
          tone={publishedCount > 0 ? 'good' : 'neutral'}
          hint={publishedCount > 0 ? 'Offered to compatible boards' : 'Publish a build to start OTA'}
        />
        <StatTile label="Downloads" value={formatNumber(totalDownloads)} hint="Firmware fetched by boards" />
      </StatGrid>

      {/* Upload a compiled .bin and publish it as the latest release */}
      <div ref={publishRef}>
        <PublishFirmwareCard onPublished={() => void refresh()} />
      </div>

      {/* Releases List */}
      <div className="space-y-4">
        {isLoading && releases.length === 0 && (
          <Card className="glass border-border/50">
            <CardContent className="pt-6">
              <SkeletonRows rows={3} columns={4} />
            </CardContent>
          </Card>
        )}

        {!isLoading && releases.length === 0 && (
          <Card className="glass border-border/50">
            <CardContent>
              <EmptyState icon={<Package className="h-5 w-5" />} title="No releases yet">
                Upload a compiled .bin above and publish it. Signed releases appear here and become available to your fleet.
              </EmptyState>
            </CardContent>
          </Card>
        )}

        {releases.map((release) => {
          const status = release.status;
          const isBusy = busyReleaseId === release.id;
          return (
          <Card
            key={release.id}
            className="glass border-border/50 hover:border-border/80 transition-colors"
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
                      {release.compatible.length === 0 && (
                        <span className="text-xs text-foreground/60">All architectures</span>
                      )}
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
                    onClick={() => void handleDownload(release.id, release.assets[0]?.name)}
                    disabled={isBusy || release.assets.length === 0}
                  >
                    <Download className="w-4 h-4 mr-1" />
                    {isBusy ? 'Working...' : 'Download'}
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    className="border-border"
                    onClick={() => setDetailReleaseId(release.id)}
                  >
                    <Eye className="w-4 h-4 mr-1" />
                    View
                  </Button>
                  {status === 'published' && (
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-border"
                      onClick={() => void handleArchive(release.id, release.version, true)}
                      disabled={isBusy || !mayArchive}
                      title={mayArchive ? 'Stop offering this release to devices' : reasonFor('releases.manage')}
                    >
                      <Archive className="w-4 h-4 mr-1" />
                      Archive
                    </Button>
                  )}
                  {status === 'archived' && (
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-border"
                      onClick={() => void handleArchive(release.id, release.version, false)}
                      disabled={isBusy || !mayArchive}
                      title={mayArchive ? 'Offer this release to devices again' : reasonFor('releases.manage')}
                    >
                      <ArchiveRestore className="w-4 h-4 mr-1" />
                      Restore
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
                            {formatBytes(asset.size)} · SHA-256 {asset.checksum ? `${asset.checksum.substring(0, 12)}...` : 'not recorded'}
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

      <Dialog open={detailRelease !== null} onOpenChange={(open) => !open && setDetailReleaseId(null)}>
        <DialogContent className="max-w-2xl">
          {detailRelease && (
            <>
              <DialogHeader>
                <DialogTitle>v{detailRelease.version}</DialogTitle>
                <DialogDescription>{detailRelease.description || 'No description.'}</DialogDescription>
              </DialogHeader>
              <dl className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
                <div>
                  <dt className="text-xs text-foreground/50">Status</dt>
                  <dd className="capitalize">
                    {detailRelease.status}
                    {detailRelease.archivedAt ? ` since ${formatUtcDateTime(detailRelease.archivedAt)} UTC` : ''}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs text-foreground/50">Created</dt>
                  <dd>{detailRelease.releaseDate.getTime() > 0 ? `${formatUtcDateTime(detailRelease.releaseDate)} UTC` : 'Not recorded'}</dd>
                </div>
                <div>
                  <dt className="text-xs text-foreground/50">Compatible</dt>
                  <dd>{detailRelease.compatible.length > 0 ? detailRelease.compatible.join(', ') : 'All architectures'}</dd>
                </div>
                <div>
                  <dt className="text-xs text-foreground/50">Package</dt>
                  <dd>{detailRelease.securePackage ? 'Encrypted package' : 'Plain image'}</dd>
                </div>
                <div>
                  <dt className="text-xs text-foreground/50">Downloads from the gateway</dt>
                  <dd>{formatNumber(detailRelease.downloadCount)}</dd>
                </div>
                <div>
                  <dt className="text-xs text-foreground/50">Release id</dt>
                  <dd className="break-all font-mono text-xs">{detailRelease.id}</dd>
                </div>
              </dl>
              {detailRelease.assets.map((asset) => (
                <div key={asset.id} className="space-y-1 rounded-lg bg-muted/30 p-3 text-sm">
                  <p className="font-medium">{asset.name || 'Unnamed file'}</p>
                  <p className="text-xs text-foreground/60">{formatBytes(asset.size)}</p>
                  <p className="break-all font-mono text-xs text-foreground/70">SHA-256 {asset.checksum || 'not recorded'}</p>
                </div>
              ))}
              {detailRelease.changelog && (
                <div>
                  <p className="mb-1 text-xs text-foreground/50">Notes</p>
                  <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-muted/30 p-3 font-mono text-xs">
                    {detailRelease.changelog}
                  </pre>
                </div>
              )}
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
