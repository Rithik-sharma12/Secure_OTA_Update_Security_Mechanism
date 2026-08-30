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
  typescript: {
    ignoreBuildErrors: true,
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
