import { afterEach, describe, expect, it, vi } from 'vitest'
import { ed25519Generate, ed25519Sign } from '../crypto/primitives'
import { b64encode } from '../wire/codec'
import { CANARY_FRESH_DAYS, CANARY_STALE_DAYS } from './constants'
import {
  type CanaryDoc,
  canarySignedMessage,
  fetchCanary,
  verifyCanary,
} from './canary'

const DAY = 24 * 60 * 60 * 1000
const NOW = Date.UTC(2026, 6, 18) // fixed clock for determinism
const HASH = 'a'.repeat(64)
const VERSION = 'v0.7.0'

const kp = ed25519Generate()
const PIN = b64encode(kp.publicKey)

function sign(fields: {
  version?: string
  releaseHash?: string
  statement?: string
  signedAt?: string
}): CanaryDoc {
  const base: CanaryDoc = {
    v: 1,
    version: fields.version ?? VERSION,
    releaseHash: fields.releaseHash ?? HASH,
    statement: fields.statement ?? 'operator statement',
    signedAt: fields.signedAt ?? new Date(NOW).toISOString(),
    sig: '',
  }
  return { ...base, sig: b64encode(ed25519Sign(canarySignedMessage(base), kp.privateKey)) }
}

const doc = (d: unknown) => ({ kind: 'doc' as const, doc: d })

describe('verifyCanary: quiet (never a banner)', () => {
  it('unconfigured when no key is pinned', () => {
    const r = verifyCanary(doc(sign({})), '', VERSION, NOW)
    expect(r.status).toBe('unconfigured')
    expect(r.configured).toBe(false)
    expect(r.alarming).toBe(false)
  })

  it('unreachable transport is quiet even with a pin set (offline must not alarm)', () => {
    const r = verifyCanary({ kind: 'unreachable' }, PIN, VERSION, NOW)
    expect(r.status).toBe('unreachable')
    expect(r.alarming).toBe(false)
  })

  it('ok when the signature is valid and fresh', () => {
    const r = verifyCanary(doc(sign({})), PIN, VERSION, NOW)
    expect(r.status).toBe('ok')
    expect(r.alarming).toBe(false)
    expect(r.attestsVersion).toBe(VERSION)
    expect(r.attestsHash).toBe(HASH)
    expect(r.ageDays).toBe(0)
  })

  it('aging between the fresh and stale thresholds (subtle, not a banner)', () => {
    const signedAt = new Date(NOW - (CANARY_FRESH_DAYS + 5) * DAY).toISOString()
    const r = verifyCanary(doc(sign({ signedAt })), PIN, VERSION, NOW)
    expect(r.status).toBe('aging')
    expect(r.alarming).toBe(false)
  })
})

describe('verifyCanary: warning (a banner)', () => {
  it('absent when the server is reachable but returns 404 and a key is pinned', () => {
    const r = verifyCanary({ kind: 'absent' }, PIN, VERSION, NOW)
    expect(r.status).toBe('absent')
    expect(r.alarming).toBe(true)
  })

  it('stale past the stale threshold', () => {
    const signedAt = new Date(NOW - (CANARY_STALE_DAYS + 2) * DAY).toISOString()
    const r = verifyCanary(doc(sign({ signedAt })), PIN, VERSION, NOW)
    expect(r.status).toBe('stale')
    expect(r.alarming).toBe(true)
    expect(r.ageDays).toBe(CANARY_STALE_DAYS + 2)
  })

  it('invalid on a bad signature', () => {
    const d = sign({})
    const other = ed25519Generate()
    const forged = { ...d, sig: b64encode(ed25519Sign(canarySignedMessage(d), other.privateKey)) }
    const r = verifyCanary(doc(forged), PIN, VERSION, NOW)
    expect(r.status).toBe('invalid')
    expect(r.alarming).toBe(true)
  })

  it('invalid when any signed field is tampered after signing', () => {
    const d = sign({})
    const r = verifyCanary(doc({ ...d, releaseHash: 'b'.repeat(64) }), PIN, VERSION, NOW)
    expect(r.status).toBe('invalid')
  })

  it('invalid when verified with the wrong pinned key', () => {
    const wrongPin = b64encode(ed25519Generate().publicKey)
    const r = verifyCanary(doc(sign({})), wrongPin, VERSION, NOW)
    expect(r.status).toBe('invalid')
  })

  it('invalid (not fresh) when signedAt is materially in the future: MF3', () => {
    const signedAt = new Date(NOW + 10 * 60 * 1000).toISOString() // 10 min ahead
    const r = verifyCanary(doc(sign({ signedAt })), PIN, VERSION, NOW)
    expect(r.status).toBe('invalid')
    expect(r.alarming).toBe(true)
  })
})

describe('verifyCanary: structural fail-closed', () => {
  const cases: Array<[string, unknown]> = [
    ['not an object', 42],
    ['null', null],
    ['wrong v tag', { v: 2 }],
    ['missing fields', { v: 1, version: VERSION }],
    ['non-hex releaseHash', { v: 1, version: VERSION, releaseHash: 'z'.repeat(64), statement: 's', signedAt: new Date(NOW).toISOString(), sig: b64encode(new Uint8Array(64)) }],
    ['short releaseHash', { v: 1, version: VERSION, releaseHash: 'ab', statement: 's', signedAt: new Date(NOW).toISOString(), sig: b64encode(new Uint8Array(64)) }],
    ['bad base64 sig', { v: 1, version: VERSION, releaseHash: HASH, statement: 's', signedAt: new Date(NOW).toISOString(), sig: '!!!!' }],
    ['unparseable date', sign({ signedAt: 'not-a-date' })],
  ]
  for (const [name, body] of cases) {
    it(`invalid: ${name}`, () => {
      const r = verifyCanary(doc(body), PIN, VERSION, NOW)
      expect(r.status).toBe('invalid')
    })
  }
})

describe('verifyCanary: version-mismatch (neutral, not a banner)', () => {
  it('reports version-mismatch when the canary vouches for another release', () => {
    const r = verifyCanary(doc(sign({ version: 'v0.6.0' })), PIN, VERSION, NOW)
    expect(r.status).toBe('version-mismatch')
    expect(r.alarming).toBe(false)
    expect(r.attestsVersion).toBe('v0.6.0')
  })

  it('staleness wins over version-mismatch: an ancient mismatched canary is stale, not a quiet note', () => {
    const signedAt = new Date(NOW - (CANARY_STALE_DAYS + 5) * DAY).toISOString()
    const r = verifyCanary(doc(sign({ version: 'v0.6.0', signedAt })), PIN, VERSION, NOW)
    expect(r.status).toBe('stale')
    expect(r.alarming).toBe(true)
  })
})

describe('verifyCanary: malformed body warns (does not go quiet)', () => {
  it('a reachable 200 that claimed JSON but did not parse is invalid, not unreachable', () => {
    const r = verifyCanary({ kind: 'malformed' }, PIN, VERSION, NOW)
    expect(r.status).toBe('invalid')
    expect(r.alarming).toBe(true)
  })
})

describe('fetchCanary: transport taxonomy (MF2)', () => {
  afterEach(() => vi.unstubAllGlobals())

  const res = (status: number, body: string, contentType: string) =>
    new Response(body, { status, headers: { 'content-type': contentType } })

  it('maps a 404 to absent', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => res(404, 'nope', 'text/plain')))
    expect((await fetchCanary('https://x')).kind).toBe('absent')
  })

  it('maps a 5xx to unreachable', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => res(500, 'err', 'text/plain')))
    expect((await fetchCanary('https://x')).kind).toBe('unreachable')
  })

  it('maps a 200 non-JSON (SPA index.html fallback) to unreachable, not a doc', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => res(200, '<!doctype html>', 'text/html')))
    expect((await fetchCanary('https://x')).kind).toBe('unreachable')
  })

  it('maps a 200 that claims application/json but is garbage to malformed (warns)', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => res(200, 'not json {{{', 'application/json')))
    const f = await fetchCanary('https://x')
    expect(f.kind).toBe('malformed')
    expect(verifyCanary(f, PIN, VERSION, NOW).status).toBe('invalid')
  })

  it('maps a rejected fetch (offline) to unreachable', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('failed to fetch') }))
    expect((await fetchCanary('https://x')).kind).toBe('unreachable')
  })

  it('returns the parsed doc on a JSON 200', async () => {
    const d = sign({})
    vi.stubGlobal('fetch', vi.fn(async () => res(200, JSON.stringify(d), 'application/json; charset=utf-8')))
    const f = await fetchCanary('https://x')
    expect(f.kind).toBe('doc')
    if (f.kind === 'doc') expect(verifyCanary(f, PIN, VERSION, NOW).status).toBe('ok')
  })
})
