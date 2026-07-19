import { describe, expect, it } from 'vitest'
import { handleCanary } from './canary'
import type { Env } from './shared'

// Full logic of the /canary.json handler, unit-tested in node with web-standard
// Request/Response (env-binding mutation does not propagate to SELF in the
// miniflare pool, so the branchy logic lives here; the integration suite proves
// the route is wired ahead of the asset fallthrough).

const env = (canary?: string): Env => ({ CANARY_JSON: canary }) as unknown as Env
const req = (method = 'GET') => new Request('https://x/canary.json', { method })
const BLOB = JSON.stringify({ v: 1, version: 'v0.7.0', sig: 'x' })

describe('handleCanary', () => {
  it('404 (off-until-configured) when CANARY_JSON is unset', async () => {
    const res = handleCanary(req('GET'), env(undefined))
    expect(res.status).toBe(404)
  })

  it('200 + JSON + short cache when set', async () => {
    const res = handleCanary(req('GET'), env(BLOB))
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toContain('application/json')
    expect(res.headers.get('cache-control')).toMatch(/max-age=\d+/)
    expect(await res.text()).toBe(BLOB)
  })

  it('HEAD set: 200 with an empty body', async () => {
    const res = handleCanary(req('HEAD'), env(BLOB))
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('')
  })

  it('HEAD unset: 404', () => {
    expect(handleCanary(req('HEAD'), env(undefined)).status).toBe(404)
  })

  it('405 for non-GET/HEAD, with an Allow header', () => {
    for (const m of ['POST', 'PUT', 'DELETE']) {
      const res = handleCanary(req(m), env(BLOB))
      expect(res.status).toBe(405)
      expect(res.headers.get('allow')).toContain('GET')
    }
  })
})
