import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// In the repository the dependencies are hoisted to the workspace root two
// levels up. In the Docker image the app sits alone in /app, and "two levels
// up" is "/", which made Turbopack treat the whole container filesystem as the
// project. Use the workspace root only when it really is one.
const workspaceRoot = path.resolve(__dirname, '../..');
const repoRoot = fs.existsSync(path.join(workspaceRoot, 'package.json')) && workspaceRoot !== path.parse(workspaceRoot).root
  ? workspaceRoot
  : __dirname;

/** @type {import('next').NextConfig} */
const configuredOrigins = (process.env.OTA_ALLOWED_DEV_ORIGINS || '')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);

const allowedDevOrigins = Array.from(new Set([
  'localhost',
  '127.0.0.1',
  '192.168.127.1',
  '10.81.51.70',
  ...configuredOrigins,
]));

const nextConfig = {
  // No "X-Powered-By: Next.js" header: it advertises the stack and is a
  // "made with" tag in every response.
  poweredByHeader: false,
  // Keep gzip on: through the tunnel every uncached response crosses this
  // computer's upload link, so smaller is faster. The live-update stream
  // sends Cache-Control: no-transform, which the compressor honours, so it is
  // never buffered.
  compress: true,
  // Was `ignoreBuildErrors: true`, which shipped whatever tsc complained
  // about. The tree is clean as of this commit, so the suppression is gone and
  // a type error fails the build again.
  typescript: {
    ignoreBuildErrors: false,
  },
  turbopack: {
    root: repoRoot,
  },
  images: {
    unoptimized: true,
  },
  allowedDevOrigins,
}

export default nextConfig
