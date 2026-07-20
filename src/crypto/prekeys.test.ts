import { describe, it, expect } from 'vitest'
import { TAG_SPK, SPK_MAX_AGE_MS, SPK_ROTATION_MS } from './constants'
import { type Identity, generateIdentity } from './identity'
import {
  domainSeparate,
  ed25519Sign,
  u32be,
  u64be,
  x25519Generate,
} from './primitives'
import {
  type FetchedBundle,
  OWN_BUNDLE_VERSION,
  buildOwnBundle,
  generateOneTimePrekeys,
  generateSignedPrekey,
  verifyFetchedBundle,
} from './prekeys'

const NOW = 1_700_000_000_000
const DAY = 86_400_000

function bundleFor(bob: Identity, now: number, opkCount = 2): FetchedBundle {
  const own = buildOwnBundle(bob, now, { opkCount })
  return {
    version: OWN_BUNDLE_VERSION,
    ikSigPub: own.ikSigPub,
    ikDhPub: own.ikDhPub,
    idkbindSig: own.idkbindSig,
    spk: own.spk,
    opk: opkCount > 0 ? own.opks[0] : null,
  }
}

function flip(b: Uint8Array): Uint8Array {
  const c = b.slice()
  c[0] ^= 1
  return c
}

function signSpk(bob: Identity, id: number, createdAt: number, expiry: number, pub: Uint8Array): Uint8Array {
  return ed25519Sign(domainSeparate(TAG_SPK, u32be(id), u64be(createdAt), u64be(expiry), pub), bob.ikSig.privateKey)
}

describe('prekey generation', () => {
  it('builds a bundle whose signed prekey verifies', () => {
    expect(() => verifyFetchedBundle(bundleFor(generateIdentity(), NOW), NOW)).not.toThrow()
  })
  it('generates a one-time prekey batch with sequential ids and 32-byte keys', () => {
    const batch = generateOneTimePrekeys(5, 3)
    expect(batch.map((b) => b.opk.id)).toEqual([5, 6, 7])
    expect(batch[0].opk.pub.length).toBe(32)
    expect(batch[0].priv.length).toBe(32)
  })
  it('sets signed-prekey expiry to createdAt + the max-age acceptance window', () => {
    const { spk } = generateSignedPrekey(generateIdentity(), 1, NOW)
    expect(spk.createdAt).toBe(NOW)
    expect(spk.expiry).toBe(NOW + SPK_MAX_AGE_MS)
    expect(SPK_MAX_AGE_MS).toBeGreaterThan(SPK_ROTATION_MS) // window outlasts a rotation
  })
})

describe('bundle verification (fails closed)', () => {
  it('rejects a version below the floor (downgrade)', () => {
    const b = { ...bundleFor(generateIdentity(), NOW), version: 0 }
    expect(() => verifyFetchedBundle(b, NOW)).toThrow(/floor/)
  })

  it('rejects a changed identity key when a pin is supplied, accepts a matching pin', () => {
    const bob = generateIdentity()
    const b = bundleFor(bob, NOW)
    expect(() => verifyFetchedBundle(b, NOW, generateIdentity().ikSig.publicKey)).toThrow(/changed/)
    expect(() => verifyFetchedBundle(b, NOW, bob.ikSig.publicKey)).not.toThrow()
  })

  it('rejects a tampered idkbind signature', () => {
    const b = bundleFor(generateIdentity(), NOW)
    expect(() => verifyFetchedBundle({ ...b, idkbindSig: flip(b.idkbindSig) }, NOW)).toThrow(/binding/)
  })

  it('rejects a substituted IK_dh (unknown-key-share)', () => {
    const b = bundleFor(generateIdentity(), NOW)
    expect(() => verifyFetchedBundle({ ...b, ikDhPub: generateIdentity().ikDh.publicKey }, NOW)).toThrow(/binding/)
  })

  it('rejects a tampered signed-prekey signature and a swapped signed-prekey key', () => {
    const b = bundleFor(generateIdentity(), NOW)
    expect(() => verifyFetchedBundle({ ...b, spk: { ...b.spk, sig: flip(b.spk.sig) } }, NOW)).toThrow(/signed-prekey/)
    expect(() => verifyFetchedBundle({ ...b, spk: { ...b.spk, pub: flip(b.spk.pub) } }, NOW)).toThrow(/signed-prekey/)
  })

  it('rejects an expired signed prekey', () => {
    const b = bundleFor(generateIdentity(), NOW)
    expect(() => verifyFetchedBundle(b, NOW + 15 * DAY)).toThrow(/expired/)
  })

  it('rejects a signed prekey signed by a different identity key', () => {
    const bob = generateIdentity()
    const b = bundleFor(bob, NOW)
    // An attacker signs the exact same SPK input, but the bundle still advertises
    // Bob's IK_sig: the SPK must be BOUND to the advertised identity, so this
    // must be rejected (not merely "some valid signature exists").
    const attacker = generateIdentity()
    const sig = signSpk(attacker, b.spk.id, b.spk.createdAt, b.spk.expiry, b.spk.pub)
    expect(() => verifyFetchedBundle({ ...b, spk: { ...b.spk, sig } }, NOW)).toThrow(/signed-prekey/)
  })

  it('rejects a future-dated signed prekey (beyond clock skew)', () => {
    const bob = generateIdentity()
    const b = bundleFor(bob, NOW)
    const kp = x25519Generate()
    const createdAt = NOW + 10 * 60 * 1000
    const expiry = createdAt + SPK_ROTATION_MS
    const spk = { id: b.spk.id, createdAt, expiry, pub: kp.publicKey, sig: signSpk(bob, b.spk.id, createdAt, expiry, kp.publicKey) }
    expect(() => verifyFetchedBundle({ ...b, spk }, NOW)).toThrow(/future/)
  })

  it('rejects a too-old signed prekey even if not yet expired', () => {
    const bob = generateIdentity()
    const b = bundleFor(bob, NOW)
    const kp = x25519Generate()
    // createdAt 15 days ago, but expiry still in the future: age check must catch it.
    const createdAt = NOW - 15 * DAY
    const expiry = NOW + DAY
    const spk = { id: b.spk.id, createdAt, expiry, pub: kp.publicKey, sig: signSpk(bob, b.spk.id, createdAt, expiry, kp.publicKey) }
    expect(() => verifyFetchedBundle({ ...b, spk }, NOW)).toThrow(/too old/)
  })
})

describe('version ceiling and timestamp sanity (P8 hardening)', () => {
  it('rejects a bundle advertising a version newer than this client speaks', () => {
    const b = { ...bundleFor(generateIdentity(), NOW), version: 2 }
    expect(() => verifyFetchedBundle(b, NOW)).toThrow(/newer/)
  })

  it('rejects an SPK whose timestamps are non-finite (NaN passes every comparison)', () => {
    const bob = generateIdentity()
    const b = bundleFor(bob, NOW)
    // Re-sign so only the freshness guards are in play, not the signature check.
    const spkNaN = {
      ...b.spk,
      createdAt: Number.NaN,
      expiry: Number.NaN,
      sig: signSpk(bob, b.spk.id, Number.NaN, Number.NaN, b.spk.pub),
    }
    expect(() => verifyFetchedBundle({ ...b, spk: spkNaN }, NOW)).toThrow(/malformed/)
  })
})
