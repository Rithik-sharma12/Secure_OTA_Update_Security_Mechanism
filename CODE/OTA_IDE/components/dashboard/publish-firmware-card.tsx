'use client';

import React from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { UploadCloud, CheckCircle2, AlertCircle, Loader2, FileUp } from 'lucide-react';
import { apiFetch } from '@/lib/client-auth';

const DEVICE_TYPES = ['ESP32', 'ESP8266', 'ATmega328P', 'STM32F103'] as const;

type PublishResult = {
  version: string;
  filename: string;
  sha256: string;
  size: number;
};

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/**
 * Upload a compiled firmware .bin and publish it as the latest release.
 *
 * Once published, the gateway signs a fresh manifest and every compatible
 * device picks the build up on its next manifest poll.
 */
export function PublishFirmwareCard({ onPublished }: { onPublished?: () => void }) {
  const fileInputRef = React.useRef<HTMLInputElement>(null);
  const [file, setFile] = React.useState<File | null>(null);
  const [version, setVersion] = React.useState('');
  const [changelog, setChangelog] = React.useState('');
  const [targets, setTargets] = React.useState<string[]>(['ESP32']);
  const [isPublishing, setIsPublishing] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [result, setResult] = React.useState<PublishResult | null>(null);

  const versionIsValid = /^\d+(\.\d+)*$/.test(version.trim().replace(/^v/i, ''));
  const canPublish = Boolean(file) && versionIsValid && !isPublishing;

  const handleFile = (selected: File | null) => {
    setError(null);
    setResult(null);

    if (selected && !selected.name.toLowerCase().endsWith('.bin')) {
      setFile(null);
      setError(`"${selected.name}" is not a .bin file. Pick the compiled firmware binary.`);
      return;
    }

    setFile(selected);

    // Infer the version from names like firmware_v2.5.0.bin so the common case
    // needs no typing.
    if (selected && !version) {
      const match = selected.name.match(/v?(\d+\.\d+(?:\.\d+)?)/);
      if (match) {
        setVersion(match[1]);
      }
    }
  };

  const toggleTarget = (deviceType: string) => {
    setTargets((current) =>
      current.includes(deviceType)
        ? current.filter((entry) => entry !== deviceType)
        : [...current, deviceType]
    );
  };

  const handlePublish = async () => {
    if (!file) return;

    setIsPublishing(true);
    setError(null);
    setResult(null);

    try {
      const form = new FormData();
      form.set('file', file, file.name);
      form.set('version', version.trim().replace(/^v/i, ''));
      form.set('changelog', changelog.trim());
      form.set('compatible', targets.join(','));

      const response = await apiFetch('/api/firmware/publish', { method: 'POST', body: form });
      const payload = await response.json().catch(() => null);

      if (!response.ok || !payload?.ok) {
        throw new Error(payload?.error || `Publish failed (${response.status}).`);
      }

      setResult({
        version: payload.release?.version || version,
        filename: payload.manifest?.filename || '',
        sha256: payload.manifest?.sha256 || '',
        size: payload.manifest?.size || file.size,
      });

      setFile(null);
      setVersion('');
      setChangelog('');
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }

      onPublished?.();
    } catch (publishError) {
      setError(publishError instanceof Error ? publishError.message : 'Publish failed.');
    } finally {
      setIsPublishing(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <UploadCloud className="w-5 h-5 text-primary" />
          Publish Firmware Update
        </CardTitle>
        <CardDescription>
          Upload a compiled <code>.bin</code> and publish it as the latest release. Devices flash it
          on their next check-in.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="firmware-file">Firmware binary</Label>
          <label
            htmlFor="firmware-file"
            className="flex items-center gap-3 rounded-md border border-dashed border-border px-4 py-6 cursor-pointer hover:border-primary/60 hover:bg-muted/40 transition-colors"
          >
            <FileUp className="w-5 h-5 text-muted-foreground shrink-0" />
            <span className="text-sm text-foreground/80 truncate">
              {file ? `${file.name} — ${formatBytes(file.size)}` : 'Choose a .bin file…'}
            </span>
          </label>
          <input
            id="firmware-file"
            ref={fileInputRef}
            type="file"
            accept=".bin"
            className="sr-only"
            onChange={(event) => handleFile(event.target.files?.[0] || null)}
          />
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2">
            <Label htmlFor="firmware-version">Version</Label>
            <Input
              id="firmware-version"
              placeholder="2.5.0"
              value={version}
              onChange={(event) => setVersion(event.target.value)}
              aria-invalid={version.length > 0 && !versionIsValid}
            />
            {version.length > 0 && !versionIsValid && (
              <p className="text-xs text-destructive">Use numeric dot-separated form, e.g. 2.5.0.</p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="firmware-changelog">Changelog</Label>
            <Input
              id="firmware-changelog"
              placeholder="What changed in this build?"
              value={changelog}
              onChange={(event) => setChangelog(event.target.value)}
            />
          </div>
        </div>

        <div className="space-y-2">
          <Label>Compatible devices</Label>
          <div className="flex flex-wrap gap-2">
            {DEVICE_TYPES.map((deviceType) => {
              const active = targets.includes(deviceType);
              return (
                <button
                  key={deviceType}
                  type="button"
                  onClick={() => toggleTarget(deviceType)}
                  aria-pressed={active}
                  className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
                    active
                      ? 'border-primary bg-primary/15 text-primary'
                      : 'border-border text-muted-foreground hover:border-primary/40'
                  }`}
                >
                  {deviceType}
                </button>
              );
            })}
          </div>
        </div>

        {error && (
          <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {result && (
          <div className="rounded-md border border-chart-1/40 bg-chart-1/10 px-3 py-2 text-sm">
            <div className="flex items-center gap-2 font-medium text-chart-1">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              Published v{result.version} — devices will update on their next check.
            </div>
            <dl className="mt-2 space-y-1 text-xs text-foreground/70">
              <div className="flex gap-2">
                <dt className="w-16 shrink-0">File</dt>
                <dd className="font-mono truncate">{result.filename}</dd>
              </div>
              <div className="flex gap-2">
                <dt className="w-16 shrink-0">Size</dt>
                <dd className="font-mono">{formatBytes(result.size)}</dd>
              </div>
              <div className="flex gap-2">
                <dt className="w-16 shrink-0">SHA-256</dt>
                <dd className="font-mono truncate">{result.sha256}</dd>
              </div>
            </dl>
          </div>
        )}

        <Button onClick={() => void handlePublish()} disabled={!canPublish} className="w-full sm:w-auto">
          {isPublishing ? (
            <>
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              Publishing…
            </>
          ) : (
            <>
              <UploadCloud className="w-4 h-4 mr-2" />
              Publish Release
            </>
          )}
        </Button>
      </CardContent>
    </Card>
  );
}
