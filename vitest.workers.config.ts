import { defineConfig } from 'vitest/config'
import { cloudflareTest } from '@cloudflare/vitest-pool-workers'

// Integration tests for the relay Worker + Durable Objects (DESIGN 7), run in
// the real workerd runtime via miniflare (option A, hybrid testing). The pure
// protocol logic is covered by the node suite (vitest.config.ts); this suite
// exercises the DO storage, hibernation WebSockets, and cross-inbox routing that
// only a real Workers environment can.
//
// Wiring note (vitest 4 / pool-workers 0.20): this was `defineWorkersConfig` from
// the now-removed `@cloudflare/vitest-pool-workers/config` subpath, with the
// runtime options nested under `test.poolOptions.workers`. Vitest 4 reworked
// pools, so the integration is now a Vite PLUGIN taking those same options
// directly. The options themselves are unchanged; only the wiring moved.
export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.jsonc' },
      miniflare: {
        compatibilityDate: '2025-09-06',
        // Bootstrap admin token, so the invite-mint endpoint is live in tests.
        bindings: { ADMIN_TOKEN: 'test-admin-token' },
      },
    }),
  ],
  test: {
    include: ['test/worker/**/*.test.ts'],
  },
})
