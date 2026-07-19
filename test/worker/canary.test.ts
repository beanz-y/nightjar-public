import { SELF } from 'cloudflare:test'
import { describe, expect, it } from 'vitest'

// Integration coverage for the /canary.json route (P7, DESIGN 10.3). The full
// branchy logic is unit-tested in worker/canary.test.ts (node); here we prove the
// two things only the real workerd + assets pipeline can show, and that need no
// per-test binding (env mutation does not propagate to SELF in this pool):
//  1. with CANARY_JSON unset (the default), the route returns a REAL 404, NOT the
//     SPA index.html fallback that env.ASSETS serves for unknown paths (MF2) --
//     the client relies on this to tell "signal removed" from a routine build.
//  2. the route is owned by the Worker (a non-GET reaches it and gets 405), so it
//     is matched ahead of the static-asset fallthrough.

const BASE = 'http://example.com'

describe('/canary.json (integration)', () => {
  it('unset -> a real 404, never the SPA HTML fallback', async () => {
    const res = await SELF.fetch(`${BASE}/canary.json`)
    expect(res.status).toBe(404)
    expect((await res.text()).trimStart().startsWith('<')).toBe(false)
  })

  it('is worker-owned: a non-GET method gets 405 (matched before ASSETS)', async () => {
    const res = await SELF.fetch(`${BASE}/canary.json`, { method: 'POST' })
    expect(res.status).toBe(405)
    expect(res.headers.get('allow')).toContain('GET')
  })
})
