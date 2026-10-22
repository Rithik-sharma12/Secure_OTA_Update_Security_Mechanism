'use client';

import React from 'react';
import { ChevronDown, ChevronRight, Download, Tag } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { EmptyState, SkeletonRows } from '@/components/ui/empty-state';
import { formatNumber, formatUtcDate } from '@/lib/formatters';
import { useRuntimeSnapshot } from '@/lib/runtime-data';
import { downloadReleaseFile } from '@/lib/runtime-actions';

/** Set at build time when the deploy knows its commit; otherwise nothing is shown. */
const BUILD_SHA = process.env.NEXT_PUBLIC_GIT_SHA?.trim() || '';

export default function VersionPage() {
  const { snapshot, isLoading } = useRuntimeSnapshot();
  const [expanded, setExpanded] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState<string | null>(null);
  const [message, setMessage] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  const releases = snapshot.releases;
  const current = releases.find((release) => release.status === 'published') || null;

  // Newest published version per architecture, from the releases themselves.
  const perArch = React.useMemo(() => {
    const map = new Map<string, string>();
    releases.forEach((release) => {
      if (release.status !== 'published') return;
      const targets = release.compatible.length > 0 ? release.compatible : ['All architectures'];
      targets.forEach((target) => {
        if (!map.has(target)) map.set(target, release.version);
      });
    });
    return [...map.entries()];
  }, [releases]);

  const handleDownload = async (releaseId: string, fileName: string | undefined) => {
    if (!fileName) return;
    setBusy(releaseId);
    setError(null);
    setMessage(null);
    try {
      await downloadReleaseFile(fileName);
      setMessage(`Downloaded ${fileName}.`);
    } catch (downloadError) {
      setError(downloadError instanceof Error ? downloadError.message : 'Download failed.');
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="rounded-lg bg-primary/20 p-3 text-primary">
          <Tag className="h-6 w-6" />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-foreground">Version</h1>
          <p className="mt-1 text-foreground/70">Firmware release history from the gateway.</p>
        </div>
      </div>
      {error && <p className="text-sm text-chart-4">{error}</p>}
      {message && !error && <p className="text-sm text-chart-1">{message}</p>}

      <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
        <Card className="md:col-span-2">
          <CardHeader>
            <CardTitle>Current firmware</CardTitle>
            <CardDescription>The newest release the gateway offers to devices.</CardDescription>
          </CardHeader>
          <CardContent>
            {current ? (
              <div className="space-y-3">
                <div className="flex items-baseline gap-3">
                  <span className="text-4xl font-bold text-primary">v{current.version}</span>
                  <Badge variant="outline">Published</Badge>
                </div>
                <p className="text-sm text-foreground/70">
                  Released {formatUtcDate(current.releaseDate)} for{' '}
                  {current.compatible.length > 0 ? current.compatible.join(', ') : 'all architectures'}.
                </p>
                {current.description && <p className="text-sm text-foreground/80">{current.description}</p>}
              </div>
            ) : isLoading ? (
              <SkeletonRows rows={2} columns={2} />
            ) : (
              <p className="text-sm text-muted-foreground">No release is published.</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>By architecture</CardTitle>
            <CardDescription>Newest published version for each target.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            {perArch.length === 0 ? (
              <p className="text-muted-foreground">Nothing published yet.</p>
            ) : (
              perArch.map(([arch, version]) => (
                <div key={arch} className="flex items-center justify-between">
                  <span>{arch}</span>
                  <span className="font-mono">v{version}</span>
                </div>
              ))
            )}
            {BUILD_SHA && (
              <p className="pt-3 text-xs text-muted-foreground">
                Console build <span className="font-mono">{BUILD_SHA.slice(0, 12)}</span>
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Release history</CardTitle>
          <CardDescription>Every release the gateway holds, newest first.</CardDescription>
        </CardHeader>
        <CardContent>
          {releases.length === 0 ? (
            isLoading ? (
              <SkeletonRows rows={3} columns={4} />
            ) : (
              <EmptyState icon={<Tag className="h-5 w-5" />} title="No releases have been published yet.">
                Publish a compiled .bin on the Releases page.
              </EmptyState>
            )
          ) : (
            <div className="space-y-3">
              {releases.map((release) => {
                const open = expanded === release.id;
                const asset = release.assets[0];
                return (
                  <div key={release.id} className="rounded-lg border border-border/50 p-4">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <div className="mb-1 flex items-center gap-2">
                          <p className="font-bold text-foreground">v{release.version}</p>
                          <Badge variant="outline" className="capitalize">{release.status}</Badge>
                        </div>
                        <p className="text-xs text-foreground/50">
                          {formatUtcDate(release.releaseDate)} · {formatNumber(release.downloadCount)} downloads
                        </p>
                      </div>
                      <div className="flex gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={!asset || busy === release.id}
                          onClick={() => void handleDownload(release.id, asset?.name)}
                        >
                          <Download className="mr-1 h-3 w-3" />
                          {busy === release.id ? 'Downloading...' : 'Download'}
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => setExpanded(open ? null : release.id)} aria-expanded={open}>
                          {open ? <ChevronDown className="mr-1 h-3 w-3" /> : <ChevronRight className="mr-1 h-3 w-3" />}
                          Notes
                        </Button>
                      </div>
                    </div>
                    {open && (
                      <pre className="mt-3 whitespace-pre-wrap break-words rounded-lg bg-muted/30 p-3 font-mono text-xs text-foreground/80">
                        {release.changelog || 'No notes were published with this release.'}
                      </pre>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
