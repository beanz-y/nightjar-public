import { describe, expect, it } from 'vitest'
import { ed25519Generate } from '../crypto/primitives'
import { b64encode } from '../wire/codec'
// The signing tool is a bare-node .mjs; import its pure core to prove it produces
// exactly what the in-app verifier accepts (same domain-separated message + key).
import { buildCanary } from '../../tools/canary-sign.mjs'
import { verifyCanary } from './canary'

const kp = ed25519Generate()
const PRIV = b64encode(kp.privateKey)
const PIN = b64encode(kp.publicKey)
const HASH = 'c'.repeat(64)
const VERSION = 'v0.7.0'
const NOW = Date.UTC(2026, 6, 18)

describe('canary-sign <-> verifyCanary round-trip', () => {
  it('a freshly signed canary verifies as ok', () => {
    const doc = buildCanary({ version: VERSION, releaseHash: HASH, privateKeyB64: PRIV, now: NOW })
    const r = verifyCanary({ kind: 'doc', doc }, PIN, VERSION, NOW)
    expect(r.status).toBe('ok')
    expect(r.attestsHash).toBe(HASH)
  })

  it('the default statement is first-person and non-empty', () => {
    const doc = buildCanary({ version: VERSION, releaseHash: HASH, privateKeyB64: PRIV, now: NOW })
    expect(doc.statement.length).toBeGreaterThan(20)
    expect(doc.v).toBe(1)
  })

  it('refuses to sign a future-dated canary (MF3)', () => {
    expect(() =>
      buildCanary({ version: VERSION, releaseHash: HASH, privateKeyB64: PRIV, now: NOW, signedAt: new Date(NOW + 60 * 60 * 1000).toISOString() }),
    ).toThrow(/future/)
  })

  it('allows an explicit backdate override (test-only escape hatch)', () => {
    const doc = buildCanary({
      version: VERSION,
      releaseHash: HASH,
      privateKeyB64: PRIV,
      now: NOW,
      signedAt: new Date(NOW + 60 * 60 * 1000).toISOString(),
      allowBackdate: true,
    })
    // It signs, but the verifier still treats a future date as invalid, never fresh.
    expect(verifyCanary({ kind: 'doc', doc }, PIN, VERSION, NOW).status).toBe('invalid')
  })

  it('rejects a bad release hash', () => {
    expect(() => buildCanary({ version: VERSION, releaseHash: 'nothex', privateKeyB64: PRIV, now: NOW })).toThrow(/hash/)
  })
})
