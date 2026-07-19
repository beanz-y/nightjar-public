import { defineConfig } from 'vitest/config'

// Test config only (see vite.config.ts for the app build). Node environment: the
// P0 suite is pure crypto/storage with no DOM or JSX, so no React plugin is
// needed. keystore.test.ts brings its own IndexedDB via `fake-indexeddb/auto`.
// worker/*.test.ts covers the DO-free worker helpers (e.g. the /canary.json
// handler) that use only web-standard Request/Response, at node speed; the
// miniflare suite (vitest.workers.config.ts) covers the real Durable Objects.
export default defineConfig({
  test: {
    environment: 'node',
    globals: true,
    include: ['src/**/*.test.ts', 'worker/canary.test.ts'],
  },
})
