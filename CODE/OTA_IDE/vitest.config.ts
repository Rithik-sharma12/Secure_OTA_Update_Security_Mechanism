import { defineConfig } from 'vitest/config';
import path from 'node:path';

export default defineConfig({
  test: {
    // Node environment: this suite covers lib/ — validation, formatting and the
    // auth helpers — not React rendering. Add a jsdom project alongside this
    // one when component tests arrive.
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['lib/**/*.ts'],
      reporter: ['text-summary'],
    },
  },
  resolve: {
    alias: { '@': path.resolve(__dirname, '.') },
  },
});
