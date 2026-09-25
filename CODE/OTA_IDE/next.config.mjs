import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');

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
