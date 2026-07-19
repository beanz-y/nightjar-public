import { defineWorkersConfig } from '@cloudflare/vitest-pool-workers/config'

// Integration tests for the relay Worker + Durable Objects (DESIGN 7), run in
// the real workerd runtime via miniflare (option A, hybrid testing). The pure
// protocol logic is covered by the node suite (vitest.config.ts); this suite
// exercises the DO storage, hibernation WebSockets, and cross-inbox routing that
// only a real Workers environment can.
export default defineWorkersConfig({
  test: {
    include: ['test/worker/**/*.test.ts'],
    poolOptions: {
      workers: {
        wrangler: { configPath: './wrangler.jsonc' },
        miniflare: {
          compatibilityDate: '2025-09-06',
          // Bootstrap admin token, so the invite-mint endpoint is live in tests.
          bindings: { ADMIN_TOKEN: 'test-admin-token' },
        },
      },
    },
  },
})
