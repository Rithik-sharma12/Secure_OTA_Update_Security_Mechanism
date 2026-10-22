'use client';

import React from 'react';
import { Copy, FileJson } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { EmptyState, SkeletonRows } from '@/components/ui/empty-state';
import { formatBytes, formatUtcDateTime } from '@/lib/formatters';
import { useRuntimeSnapshot } from '@/lib/runtime-data';

/**
 * The gateway's signed manifest, read-only. This is exactly what a device
 * that polls without identifying itself receives from
 * GET /releases/latest/manifest. It is signed by the gateway, so it cannot be
 * edited here: publish or archive a release to change it.
 */
export default function ManifestPage() {
  const { snapshot, isLoading } = useRuntimeSnapshot();
  const [copied, setCopied] = React.useState<string | null>(null);
  const manifest = snapshot.manifest;
  const manifestJson = manifest ? JSON.stringify(manifest.raw, null, 2) : '';

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(manifestJson);
      setCopied('Manifest copied to clipboard.');
    } catch {
      setCopied('The browser did not allow clipboard access.');
    }
  };

  const fields: Array<[string, string]> = manifest
    ? [
        ['Version', manifest.version ? `v${manifest.version}` : 'Not set'],
        ['File', manifest.filename || 'Not set'],
        ['Size', formatBytes(manifest.size)],
        ['Generated', manifest.generatedAt ? `${formatUtcDateTime(manifest.generatedAt)} UTC` : 'Not recorded'],
        ['Targets', manifest.compatible.length > 0 ? manifest.compatible.join(', ') : 'All architectures'],
        ['Package', manifest.securePackage ? 'Encrypted package' : 'Plain image'],
      ]
    : [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-foreground">Manifest</h1>
        <p className="mt-1 text-foreground/70">
          The signed manifest the gateway serves for its newest published release. Publish or archive a release to change it.
        </p>
        {!snapshot.connection.reachable && snapshot.connection.error && (
          <p className="mt-2 text-sm text-chart-4">{snapshot.connection.error}</p>
        )}
      </div>

      {isLoading && !manifest ? (
        <Card>
          <CardContent>
            <SkeletonRows rows={6} columns={2} />
          </CardContent>
        </Card>
      ) : !manifest ? (
        <Card>
          <CardContent>
            <EmptyState icon={<FileJson className="h-5 w-5" />} title="No manifest is being served.">
              The gateway has no published release. Publish one on the Releases page and its signed manifest appears here.
            </EmptyState>
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle className="text-base">Release</CardTitle>
              </CardHeader>
              <CardContent className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                {fields.map(([label, value]) => (
                  <div key={label}>
                    <p className="mb-1 text-xs text-foreground/50">{label}</p>
                    <p className="break-all text-sm text-foreground">{value}</p>
                  </div>
                ))}
                <div className="sm:col-span-2">
                  <p className="mb-1 text-xs text-foreground/50">SHA-256 of the served file</p>
                  <p className="break-all font-mono text-xs text-foreground/80">{manifest.sha256 || 'Not set'}</p>
                </div>
                {manifest.imageSha256 && manifest.imageSha256 !== manifest.sha256 && (
                  <div className="sm:col-span-2">
                    <p className="mb-1 text-xs text-foreground/50">SHA-256 of the decrypted image</p>
                    <p className="break-all font-mono text-xs text-foreground/80">{manifest.imageSha256}</p>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Signature</CardTitle>
                <CardDescription>
                  {manifest.signatureAlgorithm || 'Unknown algorithm'}
                  {manifest.signatureKeyId ? `, key ${manifest.signatureKeyId}` : ''}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <Badge variant={manifest.signature ? 'default' : 'destructive'}>
                  {manifest.signature ? 'Signed' : 'No signature'}
                </Badge>
                <p className="break-all font-mono text-xs text-foreground/60">{manifest.signature || 'The manifest carries no signature.'}</p>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <div className="flex items-center justify-between gap-3">
                <div>
                  <CardTitle>Manifest JSON</CardTitle>
                  <CardDescription>As served by the gateway.</CardDescription>
                </div>
                <Button size="sm" variant="outline" onClick={handleCopy}>
                  <Copy className="mr-2 h-4 w-4" />
                  Copy
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {copied && <p className="mb-2 text-sm text-muted-foreground">{copied}</p>}
              <pre className="max-h-96 overflow-auto rounded-lg border border-border/40 bg-muted/30 p-4 font-mono text-xs text-foreground/80">
                {manifestJson}
              </pre>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
