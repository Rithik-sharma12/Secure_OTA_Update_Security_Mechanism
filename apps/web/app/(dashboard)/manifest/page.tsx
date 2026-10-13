'use client';

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Save, Copy, RefreshCw } from 'lucide-react';
import { formatUtcDate } from '@/lib/formatters';
import { useRuntimeSnapshot } from '@/lib/runtime-data';
import { executeRuntimeAction } from '@/lib/runtime-actions';

export default function ManifestPage() {
  const { snapshot, isLoading } = useRuntimeSnapshot();
  const [manifestDraft, setManifestDraft] = React.useState('');
  const [isSaving, setIsSaving] = React.useState(false);
  const [isResetting, setIsResetting] = React.useState(false);
  const [actionMessage, setActionMessage] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);

  const serializableManifest = snapshot.manifest
    ? {
        ...snapshot.manifest,
        createdAt:
          snapshot.manifest.createdAt instanceof Date
            ? snapshot.manifest.createdAt.toISOString()
            : snapshot.manifest.createdAt,
      }
    : null;

  const manifestJson = serializableManifest
    ? JSON.stringify(serializableManifest, null, 2)
    : '{\n  "message": "No live manifest available."\n}';

  React.useEffect(() => {
    setManifestDraft(manifestJson);
  }, [manifestJson]);

  const handleSaveManifest = async () => {
    setIsSaving(true);
    setActionError(null);
    setActionMessage(null);

    try {
      const response = await executeRuntimeAction('manifest.save', {
        manifestJson: manifestDraft,
      });
      setActionMessage(response.message || 'Manifest saved successfully.');
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Failed to save manifest.');
    } finally {
      setIsSaving(false);
    }
  };

  const handleResetManifest = async () => {
    setIsResetting(true);
    setActionError(null);
    setActionMessage(null);

    try {
      const response = await executeRuntimeAction('manifest.reset');
      setManifestDraft(manifestJson);
      setActionMessage(response.message || 'Manifest reset to gateway default.');
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Failed to reset manifest.');
    } finally {
      setIsResetting(false);
    }
  };

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(manifestDraft);
      setActionError(null);
      setActionMessage('Manifest copied to clipboard.');
    } catch {
      setActionError('Clipboard permission denied.');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Manifest Editor</h1>
          <p className="text-foreground/70 mt-1">Manage firmware manifest configurations</p>
          {!snapshot.connection.reachable && snapshot.connection.error && (
            <p className="text-sm text-chart-4 mt-2">{snapshot.connection.error}</p>
          )}
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            className="border-border"
            onClick={handleResetManifest}
            disabled={isResetting}
          >
            <RefreshCw className="w-4 h-4 mr-2" />
            {isResetting ? 'Resetting...' : 'Reset'}
          </Button>
          <Button
            className="bg-primary hover:bg-primary/90 text-primary-foreground"
            onClick={handleSaveManifest}
            disabled={isSaving}
          >
            <Save className="w-4 h-4 mr-2" />
            {isSaving ? 'Saving...' : 'Save'}
          </Button>
        </div>
      </div>
      {actionError && <p className="text-sm text-chart-4">{actionError}</p>}
      {actionMessage && !actionError && <p className="text-sm text-chart-1">{actionMessage}</p>}

      <Card className="glass border-border/50">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Release Manifest</CardTitle>
              <CardDescription>
                {isLoading
                  ? 'Loading live manifest...'
                  : snapshot.manifest
                    ? `JSON configuration for v${snapshot.manifest.entries[0]?.version || 'unknown'}`
                    : 'No live manifest published'}
              </CardDescription>
            </div>
            <Button size="sm" variant="outline" className="border-border" onClick={handleCopy}>
              <Copy className="w-4 h-4 mr-2" />
              Copy
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <textarea
            value={manifestDraft}
            onChange={(event) => setManifestDraft(event.target.value)}
            className="w-full bg-muted/30 rounded-lg p-4 text-sm text-foreground/80 font-mono max-h-96 min-h-72 overflow-y-auto border border-border/40 focus:outline-none focus:border-primary/60"
          />
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="glass border-border/50">
          <CardHeader>
            <CardTitle className="text-base">Manifest Info</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <p className="text-xs text-foreground/50 mb-1">ID</p>
              <p className="text-sm font-mono text-foreground">{snapshot.manifest?.id || 'n/a'}</p>
            </div>
            <div>
              <p className="text-xs text-foreground/50 mb-1">Entries</p>
              <p className="text-sm font-semibold text-foreground">{snapshot.manifest?.entries.length || 0}</p>
            </div>
            <div>
              <p className="text-xs text-foreground/50 mb-1">Created</p>
              <p className="text-sm text-foreground">
                {snapshot.manifest?.createdAt ? formatUtcDate(snapshot.manifest.createdAt) : 'n/a'}
              </p>
            </div>
          </CardContent>
        </Card>

        <Card className="glass border-border/50">
          <CardHeader>
            <CardTitle className="text-base">Signature</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-foreground/50 mb-2">RSA-2048</p>
            <p className="text-xs font-mono text-foreground/60 break-all">{snapshot.manifest?.signature || 'n/a'}</p>
          </CardContent>
        </Card>

        <Card className="glass border-border/50">
          <CardHeader>
            <CardTitle className="text-base">Validation</CardTitle>
          </CardHeader>
          <CardContent>
            {snapshot.manifest ? (
              <>
                <Badge className="bg-chart-1/20 text-chart-1 w-full text-center justify-center">
                  Live
                </Badge>
                <p className="text-xs text-foreground/50 mt-2 text-center">Manifest received from gateway runtime</p>
              </>
            ) : (
              <>
                <Badge className="bg-chart-3/20 text-chart-3 w-full text-center justify-center">
                  Waiting
                </Badge>
                <p className="text-xs text-foreground/50 mt-2 text-center">No manifest has been published yet</p>
              </>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
