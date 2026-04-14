'use client';

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tag, GitBranch, Copy, Download, AlertCircle } from 'lucide-react';
import { formatNumber, formatUtcDate } from '@/lib/formatters';
import { useRuntimeSnapshot } from '@/lib/runtime-data';
import { downloadRuntimePayload, executeRuntimeAction, fetchRuntimeActionState, type RuntimeDownloadPayload } from '@/lib/runtime-actions';

type RuntimeTagRecord = {
  version: string;
  notes: string;
  createdAt: string;
};

const commitHash = 'abc123def456';

export default function VersionPage() {
  const { snapshot } = useRuntimeSnapshot();
  const [runtimeTags, setRuntimeTags] = React.useState<RuntimeTagRecord[]>([]);
  const [versionInput, setVersionInput] = React.useState('v2.5.0');
  const [releaseNotes, setReleaseNotes] = React.useState('');
  const [selectedVersion, setSelectedVersion] = React.useState<string | null>(null);
  const [busyAction, setBusyAction] = React.useState<string | null>(null);
  const [actionMessage, setActionMessage] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);

  React.useEffect(() => {
    const loadTags = async () => {
      try {
        const response = await fetchRuntimeActionState<{ tags?: RuntimeTagRecord[] }>();
        setRuntimeTags(response.data?.tags || []);
      } catch {
        setRuntimeTags([]);
      }
    };

    void loadTags();
  }, []);

  const currentRelease = snapshot.releases[0];

  const history = [
    ...snapshot.releases.map((release) => ({
      version: release.version,
      date: formatUtcDate(release.releaseDate),
      status: release.status === 'published' ? 'stable' : release.status,
      downloads: formatNumber(release.downloadCount),
      changes: release.changelog ? release.changelog.split('\n').length : 0,
      releaseId: release.id,
      notes: release.changelog,
      assetName: release.assets[0]?.name,
    })),
    ...runtimeTags.map((tag) => ({
      version: tag.version.replace(/^v/, ''),
      date: formatUtcDate(new Date(tag.createdAt)),
      status: 'tagged',
      downloads: '0',
      changes: tag.notes ? tag.notes.split('\n').length : 0,
      releaseId: tag.version,
      notes: tag.notes,
      assetName: undefined,
    })),
  ];

  const handleCopyCommit = async () => {
    try {
      await navigator.clipboard.writeText(commitHash);
      setActionError(null);
      setActionMessage('Commit hash copied to clipboard.');
    } catch {
      setActionError('Clipboard permission denied.');
    }
  };

  const handleDownload = async (assetName?: string) => {
    setBusyAction('download');
    setActionError(null);
    setActionMessage(null);

    try {
      const response = await executeRuntimeAction<RuntimeDownloadPayload>('releases.download', {
        fileName: assetName,
      });
      if (response.data) {
        downloadRuntimePayload(response.data);
      }
      setActionMessage(response.message || 'Release download prepared.');
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to download release asset.');
    } finally {
      setBusyAction(null);
    }
  };

  const handleCreateTag = async () => {
    setBusyAction('create-tag');
    setActionError(null);
    setActionMessage(null);

    try {
      const response = await executeRuntimeAction('version.create-tag', {
        version: versionInput,
        notes: releaseNotes,
      });

      const normalized = versionInput.startsWith('v') ? versionInput : `v${versionInput}`;
      setRuntimeTags((current) => [{
        version: normalized,
        notes: releaseNotes,
        createdAt: new Date().toISOString(),
      }, ...current]);
      setActionMessage(response.message || `Release tag ${normalized} created.`);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to create release tag.');
    } finally {
      setBusyAction(null);
    }
  };

  const handleViewNotes = (version: string, notes: string) => {
    setSelectedVersion(version);
    setActionError(null);
    setActionMessage(notes ? `Notes for ${version}: ${notes.slice(0, 140)}` : `No notes available for ${version}.`);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-8">
        <div className="p-3 rounded-lg bg-primary/20 text-primary">
          <Tag className="w-6 h-6" />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-foreground">Version Management</h1>
          <p className="text-foreground/70 mt-1">Release versioning, tagging, and deployment history</p>
        </div>
      </div>
      {actionError && <p className="text-sm text-chart-4">{actionError}</p>}
      {actionMessage && !actionError && <p className="text-sm text-chart-1">{actionMessage}</p>}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="glass border-border/50 hover:border-primary/50 transition-all md:col-span-2">
          <CardHeader>
            <CardTitle className="text-2xl">Current Version</CardTitle>
            <CardDescription>Active OTA IDE version</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="flex items-baseline gap-4">
              <div className="text-5xl font-bold text-primary">{currentRelease?.version || '2.4.0'}</div>
              <Badge className="bg-chart-1/20 text-chart-1 text-base px-3 py-1">Latest</Badge>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="p-3 rounded-lg bg-muted/20 border border-border/20">
                <p className="text-xs text-foreground/60 uppercase tracking-wider mb-1">Released</p>
                <p className="font-semibold text-foreground">{currentRelease ? formatUtcDate(currentRelease.releaseDate) : 'n/a'}</p>
              </div>
              <div className="p-3 rounded-lg bg-muted/20 border border-border/20">
                <p className="text-xs text-foreground/60 uppercase tracking-wider mb-1">Build Hash</p>
                <p className="font-mono text-sm text-foreground">{commitHash.slice(0, 8)}</p>
              </div>
            </div>
            <div className="p-4 rounded-lg bg-chart-1/5 border border-chart-1/20">
              <p className="text-sm text-foreground/80">
                <span className="font-semibold">Latest release notes:</span> {currentRelease?.description || 'Improved performance, security patches, and compatibility enhancements.'}
              </p>
            </div>
          </CardContent>
        </Card>

        <Card className="glass border-border/50 hover:border-border/80 transition-all">
          <CardHeader>
            <CardTitle>Git Information</CardTitle>
            <CardDescription>Repository details</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-3">
              <div>
                <p className="text-xs text-foreground/60 uppercase tracking-wider mb-1">Branch</p>
                <div className="flex items-center gap-2 p-2 bg-muted/20 rounded border border-border/20">
                  <GitBranch className="w-4 h-4 text-primary" />
                  <span className="text-sm font-mono text-foreground">main</span>
                </div>
              </div>
              <div>
                <p className="text-xs text-foreground/60 uppercase tracking-wider mb-1">Commit</p>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-mono text-foreground/80">{commitHash}</span>
                  <Button size="sm" variant="ghost" className="h-6 w-6 p-0" onClick={() => void handleCopyCommit()}>
                    <Copy className="w-3 h-3" />
                  </Button>
                </div>
              </div>
              <div>
                <p className="text-xs text-foreground/60 uppercase tracking-wider mb-1">Author</p>
                <p className="text-sm text-foreground">DevOps Team</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card className="glass border-border/50 hover:border-border/80 transition-all">
        <CardHeader>
          <CardTitle>Release History</CardTitle>
          <CardDescription>Previous versions and releases</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {history.map((entry) => (
              <div
                key={`${entry.version}-${entry.releaseId}`}
                className={`p-4 rounded-lg border border-border/50 hover:border-border/80 hover:bg-muted/20 transition-all group ${
                  selectedVersion === entry.version ? 'ring-1 ring-primary/40' : ''
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4 flex-1">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <Tag className="w-4 h-4 text-muted-foreground" />
                        <p className="font-bold text-foreground">v{entry.version.replace(/^v/, '')}</p>
                        <Badge variant="outline" className={`text-xs ${
                          entry.status === 'latest'
                            ? 'bg-chart-1/20 text-chart-1'
                            : entry.status === 'stable' || entry.status === 'published'
                              ? 'bg-primary/20 text-primary'
                              : 'bg-muted text-muted-foreground'
                        }`}>
                          {entry.status}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-4 text-xs text-foreground/50">
                        <span>{entry.date}</span>
                        <span className="text-foreground/30">|</span>
                        <span>{entry.changes} changes</span>
                        <span className="text-foreground/30">|</span>
                        <span>{entry.downloads} downloads</span>
                      </div>
                    </div>
                  </div>
                  <div className="flex gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-border"
                      onClick={() => void handleDownload(entry.assetName)}
                      disabled={busyAction === 'download'}
                    >
                      <Download className="w-3 h-3 mr-1" />
                      Download
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-border"
                      onClick={() => handleViewNotes(entry.version, entry.notes)}
                    >
                      View Notes
                    </Button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card className="glass border-border/50 hover:border-border/80 transition-all">
        <CardHeader>
          <CardTitle>Create New Release Tag</CardTitle>
          <CardDescription>Tag current commit as a new release version</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-foreground mb-2">Version Number</label>
              <input
                value={versionInput}
                onChange={(event) => setVersionInput(event.target.value)}
                placeholder="e.g., v2.5.0"
                className="w-full px-3 py-2 bg-muted/50 border border-border/50 rounded-lg text-sm text-foreground placeholder-foreground/40 focus:outline-none focus:border-primary/50"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-foreground mb-2">Release Date</label>
              <input
                type="date"
                className="w-full px-3 py-2 bg-muted/50 border border-border/50 rounded-lg text-sm text-foreground focus:outline-none focus:border-primary/50"
                defaultValue={new Date().toISOString().slice(0, 10)}
              />
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-foreground mb-2">Release Notes</label>
            <textarea
              value={releaseNotes}
              onChange={(event) => setReleaseNotes(event.target.value)}
              placeholder="Document new features, improvements, and bug fixes..."
              className="w-full px-3 py-2 bg-muted/50 border border-border/50 rounded-lg text-sm text-foreground placeholder-foreground/40 resize-none focus:outline-none focus:border-primary/50"
              rows={4}
            />
          </div>
          <Button
            className="bg-primary hover:bg-primary/90 text-primary-foreground w-full"
            onClick={() => void handleCreateTag()}
            disabled={busyAction === 'create-tag'}
          >
            <Tag className="w-4 h-4 mr-2" />
            {busyAction === 'create-tag' ? 'Creating...' : 'Create Release Tag'}
          </Button>
        </CardContent>
      </Card>

      <Card className="glass border-border/50">
        <CardHeader>
          <div className="flex items-center gap-2">
            <AlertCircle className="w-5 h-5 text-chart-3" />
            <div>
              <CardTitle>Version Compatibility</CardTitle>
              <CardDescription>Device and firmware compatibility information</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {[
              { device: 'ESP32', compat: 'v2.0+', note: 'Fully supported' },
              { device: 'ESP8266', compat: 'v2.2+', note: 'Limited features' },
              { device: 'ATmega328P', compat: 'v1.8+', note: 'Basic support' },
              { device: 'STM32F103', compat: 'v2.3+', note: 'Full support' },
            ].map((item) => (
              <div key={item.device} className="p-3 rounded-lg bg-muted/20 border border-border/20">
                <div className="flex items-center justify-between mb-1">
                  <p className="font-medium text-foreground">{item.device}</p>
                  <Badge variant="outline" className="bg-chart-1/20 text-chart-1 text-xs">
                    {item.compat}
                  </Badge>
                </div>
                <p className="text-xs text-foreground/60">{item.note}</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
