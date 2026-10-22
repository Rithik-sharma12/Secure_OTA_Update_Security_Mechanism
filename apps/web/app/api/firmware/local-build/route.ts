import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { NextResponse } from 'next/server';
import { OPERATOR_ROLES, withSecureApi } from '@/lib/api-security';
import { actorHeader } from '@/lib/gateway-proxy';
import { logger } from '@/lib/logger';
import type { LocalBuild } from '@/lib/local-build';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * The firmware built on this computer by scripts\build-firmware.cmd
 * (firmware/tools/build_firmware.py), read straight from firmware/dist/<env>/.
 *
 *   GET                              list the builds, with their absolute paths
 *   GET ?env=esp32dev&file=<name>    one file's bytes (for Flash over USB)
 *   POST { env }                     publish that build as a release, with its
 *                                    factory image, in one step
 *
 * Only the fixed output file names are served, never an arbitrary path. On a
 * hosted deployment there is no firmware folder and the list is empty.
 */

const gatewayUrl = (process.env.EDGE_GATEWAY_URL || 'http://localhost:5000').replace(/\/$/, '');
const gatewayApiKey = process.env.EDGE_GATEWAY_API_KEY?.trim();
const UPLOAD_TIMEOUT_MS = 60_000;

const ENV_PATTERN = /^(esp32dev|esp32s3|esp32c3)$/;
const SERVED_FILES = new Set(['firmware-full.bin', 'firmware.bin', 'firmware-ota.bin']);

type BuildInfo = {
  version?: string;
  environment?: string;
  chip?: string;
  generic?: boolean;
  secure?: boolean;
  toolchain?: string;
  imageSha256?: string;
  files?: Record<string, { bytes?: number; sha256?: string; flashAddress?: string }>;
};



/**
 * Where the files are on the computer, for display. In Docker the folder is
 * mounted at SECUREOTA_FIRMWARE_DIST and SECUREOTA_FIRMWARE_HOST_DIR names the
 * same folder on the host (for example E:\repo\firmware\dist), so the
 * console shows the path the operator can open in Explorer.
 */
function displayPath(serverPath: string): string {
  const mounted = process.env.SECUREOTA_FIRMWARE_DIST?.trim();
  const host = process.env.SECUREOTA_FIRMWARE_HOST_DIR?.trim();
  if (!mounted || !host || !serverPath.startsWith(path.resolve(mounted))) return serverPath;
  const rest = serverPath.slice(path.resolve(mounted).length).replace(/^[\\/]+/, '');
  const windows = /^[A-Za-z]:[\\/]/.test(host) || host.includes('\\');
  const sep = windows ? '\\' : '/';
  const base = host.replace(/[\\/]+$/, '').replace(/[\\/]/g, sep);
  return rest ? `${base}${sep}${rest.split(/[\\/]/).join(sep)}` : base;
}

/** The build script, as the operator runs it on the computer. */
function buildCommandFor(distDir: string): string {
  const shown = displayPath(distDir);
  const windows = /^[A-Za-z]:[\\/]/.test(shown) || shown.includes('\\');
  const sep = windows ? '\\' : '/';
  const root = shown.replace(/[\\/]+$/, '').split(/[\\/]/).slice(0, -2).join(sep);
  return root && root !== '.' ? `${root}${sep}scripts${sep}build-firmware.cmd` : 'scripts\\build-firmware.cmd';
}

/** Walk up from the server's working directory to the repository root. */
function findDistDir(): string | null {
  const override = process.env.SECUREOTA_FIRMWARE_DIST?.trim();
  if (override) return existsSync(override) ? path.resolve(override) : null;
  let dir = process.cwd();
  for (let depth = 0; depth < 5; depth += 1) {
    if (existsSync(path.join(dir, 'firmware', 'platformio.ini'))) {
      return path.join(dir, 'firmware', 'dist');
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

async function readBuild(distDir: string, env: string): Promise<LocalBuild | null> {
  const directory = path.join(distDir, env);
  const infoPath = path.join(directory, 'build-info.json');
  if (!existsSync(infoPath)) return null;
  let info: BuildInfo;
  try {
    info = JSON.parse(await readFile(infoPath, 'utf8')) as BuildInfo;
  } catch {
    return null;
  }
  const files: LocalBuild['files'] = [];
  for (const name of SERVED_FILES) {
    const filePath = path.join(directory, name);
    if (!existsSync(filePath)) continue;
    const meta = info.files?.[name];
    files.push({ name, bytes: (await stat(filePath)).size, sha256: meta?.sha256 ?? '', path: displayPath(filePath) });
  }
  return {
    env,
    version: info.version ?? 'unknown',
    chip: info.chip ?? '',
    secure: Boolean(info.secure),
    generic: Boolean(info.generic),
    toolchain: info.toolchain ?? 'platformio',
    imageSha256: info.imageSha256 ?? '',
    builtAt: (await stat(infoPath)).mtime.toISOString(),
    directory: displayPath(directory),
    files,
  };
}

async function listBuilds(distDir: string): Promise<LocalBuild[]> {
  if (!existsSync(distDir)) return [];
  const entries = await readdir(distDir, { withFileTypes: true });
  const builds: LocalBuild[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory() || !ENV_PATTERN.test(entry.name)) continue;
    const build = await readBuild(distDir, entry.name);
    if (build) builds.push(build);
  }
  return builds.sort((a, b) => b.builtAt.localeCompare(a.builtAt));
}

export async function GET(request: Request) {
  return withSecureApi(
    request,
    '/api/firmware/local-build',
    async () => {
      const distDir = findDistDir();
      const params = new URL(request.url).searchParams;
      const env = params.get('env');
      const file = params.get('file');

      if (env === null && file === null) {
        return NextResponse.json({
          ok: true,
          available: Boolean(distDir),
          distDir: distDir ? displayPath(distDir) : null,
          buildCommand: distDir ? buildCommandFor(distDir) : null,
          builds: distDir ? await listBuilds(distDir) : [],
        });
      }

      if (!distDir) {
        return NextResponse.json(
          { ok: false, error: 'This server has no firmware folder. Local builds are only available when the console runs from the repository.' },
          { status: 404 }
        );
      }
      if (!env || !ENV_PATTERN.test(env) || !file || !SERVED_FILES.has(file)) {
        return NextResponse.json({ ok: false, error: 'Unknown build or file.' }, { status: 400 });
      }
      const filePath = path.join(distDir, env, file);
      if (!existsSync(filePath)) {
        return NextResponse.json(
          { ok: false, error: `${file} has not been built for ${env}. Run scripts\\build-firmware.cmd ${env}.` },
          { status: 404 }
        );
      }
      const bytes = await readFile(filePath);
      const build = await readBuild(distDir, env);
      return new NextResponse(new Uint8Array(bytes), {
        status: 200,
        headers: {
          'Content-Type': 'application/octet-stream',
          'Content-Length': String(bytes.byteLength),
          'Content-Disposition': `attachment; filename="${file}"`,
          'Cache-Control': 'no-store',
          'X-Firmware-Sha256': createHash('sha256').update(bytes).digest('hex'),
          'X-Firmware-Version': build?.version ?? '',
          'X-Firmware-Path': displayPath(filePath),
        },
      });
    },
    { requireRole: OPERATOR_ROLES }
  );
}

export async function POST(request: Request) {
  return withSecureApi(
    request,
    '/api/firmware/local-build',
    async ({ auth }) => {
      const distDir = findDistDir();
      if (!distDir) {
        return NextResponse.json({ ok: false, error: 'This server has no firmware folder.' }, { status: 404 });
      }
      const body = (await request.json().catch(() => null)) as { env?: string } | null;
      const env = body?.env ?? 'esp32dev';
      if (!ENV_PATTERN.test(env)) {
        return NextResponse.json({ ok: false, error: 'Unknown build environment.' }, { status: 400 });
      }
      const build = await readBuild(distDir, env);
      if (!build) {
        return NextResponse.json(
          { ok: false, error: `No build for ${env}. Run scripts\\build-firmware.cmd ${env} first.` },
          { status: 404 }
        );
      }
      if (!/^\d+(\.\d+)*$/.test(build.version)) {
        return NextResponse.json({ ok: false, error: `The build reports version "${build.version}", which is not publishable.` }, { status: 400 });
      }

      // Secure builds publish the signed, encrypted package; others the plain app.
      const artifactName = build.files.some((entry) => entry.name === 'firmware-ota.bin') ? 'firmware-ota.bin' : 'firmware.bin';
      // build.directory is the display path; read from the server's own path.
      const serverDir = path.join(distDir, env);
      const artifact = await readFile(path.join(serverDir, artifactName));
      const fullPath = path.join(serverDir, 'firmware-full.bin');

      const outbound = new FormData();
      outbound.set('file', new Blob([new Uint8Array(artifact)]), `firmware_v${build.version}.bin`);
      outbound.set('version', build.version);
      outbound.set('description', `SecureOTA firmware v${build.version} (${build.env}, local ${build.toolchain} build).`);
      outbound.set('changelog', `Built on this computer; image SHA-256 ${build.imageSha256}.`);
      outbound.set('compatible', 'ESP32');
      if (artifactName === 'firmware-ota.bin') {
        outbound.set('imageSha256', build.imageSha256);
        outbound.set('securePackage', 'true');
      }
      if (existsSync(fullPath)) {
        outbound.set('factoryImage', new Blob([new Uint8Array(await readFile(fullPath))]), `firmware_v${build.version}_full.bin`);
      }

      const headers: Record<string, string> = { ...actorHeader(auth) };
      if (gatewayApiKey) headers['x-api-key'] = gatewayApiKey;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), UPLOAD_TIMEOUT_MS);
      try {
        const response = await fetch(`${gatewayUrl}/api/releases/upload`, {
          method: 'POST',
          body: outbound,
          headers,
          signal: controller.signal,
        });
        const parsed = (await response.json().catch(() => null)) as { detail?: string; error?: string } | null;
        if (!response.ok) {
          const detail = parsed?.detail || parsed?.error || `Gateway responded ${response.status}`;
          logger.error('LocalBuildPublish', `Gateway rejected v${build.version}`, detail);
          return NextResponse.json({ ok: false, error: detail }, { status: response.status });
        }
        logger.info('LocalBuildPublish', `Published local build v${build.version} (${build.env})`);
        return NextResponse.json({
          ok: true,
          message: `v${build.version} published with its factory image. New boards can be set up from it and existing boards update over the air.`,
          version: build.version,
        });
      } catch (error) {
        const aborted = error instanceof Error && error.name === 'AbortError';
        return NextResponse.json(
          { ok: false, error: aborted ? 'Upload to the gateway timed out.' : `Could not reach the gateway at ${gatewayUrl}.` },
          { status: 502 }
        );
      } finally {
        clearTimeout(timeout);
      }
    },
    { requireRole: OPERATOR_ROLES }
  );
}
