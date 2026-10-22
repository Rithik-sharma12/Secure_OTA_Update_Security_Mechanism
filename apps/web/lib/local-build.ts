'use client';

import React from 'react';
import { apiFetch } from '@/lib/client-auth';

/** A firmware build in firmware/dist/<env>/ on the computer running the console. */
export type LocalBuild = {
  env: string;
  version: string;
  chip: string;
  secure: boolean;
  generic: boolean;
  toolchain: string;
  imageSha256: string;
  builtAt: string;
  /** Absolute folder, for example E:\repo\firmware\dist\esp32dev */
  directory: string;
  files: Array<{ name: string; bytes: number; sha256: string; path: string }>;
};

export type LocalBuildList = {
  available: boolean;
  distDir: string | null;
  buildCommand: string | null;
  builds: LocalBuild[];
};

const EMPTY: LocalBuildList = { available: false, distDir: null, buildCommand: null, builds: [] };

/** Lists the local builds once, with a reload for after a new build. */
export function useLocalBuilds() {
  const [data, setData] = React.useState<LocalBuildList>(EMPTY);
  const [loaded, setLoaded] = React.useState(false);

  const reload = React.useCallback(async () => {
    try {
      const response = await apiFetch('/api/firmware/local-build', { cache: 'no-store' });
      const payload = (await response.json().catch(() => null)) as (LocalBuildList & { ok?: boolean }) | null;
      setData(response.ok && payload ? payload : EMPTY);
    } catch {
      setData(EMPTY);
    } finally {
      setLoaded(true);
    }
  }, []);

  React.useEffect(() => {
    void reload();
  }, [reload]);

  return { ...data, loaded, reload };
}

/** Downloads one output file of a local build and checks it against its digest. */
export async function fetchLocalBuildFile(env: string, file: string) {
  const response = await apiFetch(
    `/api/firmware/local-build?env=${encodeURIComponent(env)}&file=${encodeURIComponent(file)}`,
    { cache: 'no-store' }
  );
  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as { error?: string } | null;
    throw new Error(payload?.error || `Could not read ${file} (${response.status}).`);
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  return {
    bytes,
    sha256: (response.headers.get('X-Firmware-Sha256') || '').toLowerCase(),
    version: response.headers.get('X-Firmware-Version') || '',
    path: response.headers.get('X-Firmware-Path') || file,
  };
}

/** Publishes a local build (OTA package plus factory image) as a release. */
export async function publishLocalBuild(env: string) {
  const response = await apiFetch('/api/firmware/local-build', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ env }),
  });
  const payload = (await response.json().catch(() => null)) as { ok?: boolean; error?: string; message?: string } | null;
  if (!response.ok || !payload?.ok) throw new Error(payload?.error || `Publishing failed (${response.status}).`);
  return payload.message || 'Published.';
}

export function formatBytes(bytes: number) {
  return bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}
