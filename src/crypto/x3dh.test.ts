import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils'
import { SPK_MAX_AGE_MS, TAG_IDKBIND, TAG_SPK } from './constants'
import { type Identity, deriveUserId, generateIdentity } from './identity'
import {
  type KeyPair,
  bytesEqual,
  domainSeparate,
  ed25519Public,
  ed25519Sign,
  u32be,
  u64be,
  x25519Public,
} from './primitives'
import { type FetchedBundle, type SignedPrekey, OWN_BUNDLE_VERSION, buildOwnBundle } from './prekeys'
import {
  type InitialHeader,
  type ResponderKeys,
  InitialMessageReplayGuard,
  initialMessageId,
  x3dhInitiate,
  x3dhRespond,
} from './x3dh'

const NOW = 1_700_000_000_000

interface Scenario {
  alice: Identity
  bob: Identity
  bundle: FetchedBundle
  bobKeys: ResponderKeys
  firstOpkId: number
}

function scenario(now = NOW, withOpk = true): Scenario {
  const alice = generateIdentity()
  const bob = generateIdentity()
  const own = buildOwnBundle(bob, now, { spkId: 1, opkStartId: 7, opkCount: withOpk ? 3 : 0 })
  const bundle: FetchedBundle = {
    version: OWN_BUNDLE_VERSION,
    ikSigPub: own.ikSigPub,
    ikDhPub: own.ikDhPub,
    idkbindSig: own.idkbindSig,
    spk: own.spk,
    opk: withOpk ? own.opks[0] : null,
  }
  return { alice, bob, bundle, bobKeys: { spkPrivById: own.spkPrivById, opkPrivById: own.opkPrivById }, firstOpkId: 7 }
}

function flip(b: Uint8Array): Uint8Array {
  const c = b.slice()
  c[0] ^= 1
  return c
}

const SEED = (n: number): Uint8Array => new Uint8Array(32).fill(n)

function fixedIdentity(sigSeed: Uint8Array, dhSeed: Uint8Array): Identity {
  const ikSig = { privateKey: sigSeed, publicKey: ed25519Public(sigSeed) }
  const ikDh = { privateKey: dhSeed, publicKey: x25519Public(dhSeed) }
  const idkbindSig = ed25519Sign(domainSeparate(TAG_IDKBIND, ikDh.publicKey), ikSig.privateKey)
  return { ikSig, ikDh, idkbindSig, userId: deriveUserId(ikSig.publicKey) }
}

describe('X3DH agreement', () => {
  it('initiator and responder derive identical SK and AD (with a one-time prekey)', () => {
    const s = scenario()
    const ini = x3dhInitiate(s.alice, s.bundle, NOW)
    const res = x3dhRespond(s.bob, ini.header, s.bobKeys, NOW)
    expect(ini.sk.length).toBe(32)
    expect(bytesEqual(ini.sk, res.sk)).toBe(true)
    expect(bytesEqual(ini.ad, res.ad)).toBe(true)
    expect(ini.header.opkId).toBe(s.firstOpkId)
  })

  it('agrees on SK and AD with no one-time prekey (fallback path)', () => {
    const s = scenario(NOW, false)
    const ini = x3dhInitiate(s.alice, s.bundle, NOW)
    const res = x3dhRespond(s.bob, ini.header, s.bobKeys, NOW)
    expect(bytesEqual(ini.sk, res.sk)).toBe(true)
    expect(bytesEqual(ini.ad, res.ad)).toBe(true)
    expect(ini.header.opkId).toBeNull()
  })

  it('produces a fresh SK per session (ephemeral key)', () => {
    const s = scenario()
    const a = x3dhInitiate(s.alice, s.bundle, NOW)
    const b = x3dhInitiate(s.alice, s.bundle, NOW)
    expect(bytesEqual(a.sk, b.sk)).toBe(false)
  })

  it('responder rejects a tampered idkbind in the initial header', () => {
    const s = scenario()
    const ini = x3dhInitiate(s.alice, s.bundle, NOW)
    const bad: InitialHeader = { ...ini.header, idkbindSig: flip(ini.header.idkbindSig) }
    expect(() => x3dhRespond(s.bob, bad, s.bobKeys, NOW)).toThrow(/binding/)
  })

  it('responder rejects a substituted IK_dh in the initial header', () => {
    const s = scenario()
    const ini = x3dhInitiate(s.alice, s.bundle, NOW)
    const bad: InitialHeader = { ...ini.header, ikDhPub: generateIdentity().ikDh.publicKey }
    expect(() => x3dhRespond(s.bob, bad, s.bobKeys, NOW)).toThrow(/binding/)
  })

  it('responder rejects a changed initiator identity when pinned', () => {
    const s = scenario()
    const ini = x3dhInitiate(s.alice, s.bundle, NOW)
    expect(() => x3dhRespond(s.bob, ini.header, s.bobKeys, NOW, generateIdentity().ikSig.publicKey)).toThrow(/changed/)
    expect(() => x3dhRespond(s.bob, ini.header, s.bobKeys, NOW, s.alice.ikSig.publicKey)).not.toThrow()
  })

  it('responder fails closed on an unknown signed-prekey id', () => {
    const s = scenario()
    const ini = x3dhInitiate(s.alice, s.bundle, NOW)
    expect(() => x3dhRespond(s.bob, { ...ini.header, spkId: 999 }, s.bobKeys, NOW)).toThrow(/signed-prekey id/)
  })

  it('responder fails closed on an unknown one-time-prekey id', () => {
    const s = scenario()
    const ini = x3dhInitiate(s.alice, s.bundle, NOW)
    expect(() => x3dhRespond(s.bob, { ...ini.header, opkId: 999 }, s.bobKeys, NOW)).toThrow(/one-time-prekey id/)
  })

  it('responder rejects a version below the floor', () => {
    const s = scenario()
    const ini = x3dhInitiate(s.alice, s.bundle, NOW)
    expect(() => x3dhRespond(s.bob, { ...ini.header, version: 0 }, s.bobKeys, NOW)).toThrow(/floor/)
  })
})

// Independently-computed vectors (see the compute step in the P1 review): these
// pin the WHOLE construction (DH1..DH4 assignment, the 0xFF prefix, the HKDF
// salt/info, and the AD field order), so a change applied symmetrically to both
// x3dhInitiate and x3dhRespond can no longer pass silently.
describe('X3DH known-answer vectors (independently computed)', () => {
  const alice = fixedIdentity(SEED(0x11), SEED(0x12))
  const bob = fixedIdentity(SEED(0x21), SEED(0x22))
  const ek: KeyPair = { privateKey: SEED(0x13), publicKey: x25519Public(SEED(0x13)) }
  const spkSeed = SEED(0x23)
  const spkPub = x25519Public(spkSeed)
  const spk: SignedPrekey = {
    id: 1,
    createdAt: NOW,
    expiry: NOW + SPK_MAX_AGE_MS,
    pub: spkPub,
    sig: ed25519Sign(
      domainSeparate(TAG_SPK, u32be(1), u64be(NOW), u64be(NOW + SPK_MAX_AGE_MS), spkPub),
      bob.ikSig.privateKey,
    ),
  }
  const opkSeed = SEED(0x24)
  const opkPub = x25519Public(opkSeed)
  const bobKeys: ResponderKeys = {
    spkPrivById: new Map([[1, spkSeed]]),
    opkPrivById: new Map([[7, opkSeed]]),
  }
  const makeBundle = (withOpk: boolean): FetchedBundle => ({
    version: OWN_BUNDLE_VERSION,
    ikSigPub: bob.ikSig.publicKey,
    ikDhPub: bob.ikDh.publicKey,
    idkbindSig: bob.idkbindSig,
    spk,
    opk: withOpk ? { id: 7, pub: opkPub } : null,
  })

  it('with a one-time prekey: SK and AD match the pinned vector', () => {
    const ini = x3dhInitiate(alice, makeBundle(true), NOW, undefined, ek)
    const res = x3dhRespond(bob, ini.header, bobKeys, NOW)
    expect(bytesToHex(ini.sk)).toBe('538c5c575dcc440e5a0699e9ff88a2d397c7963adedd285a6f2e1251d6328df8')
    expect(bytesToHex(ini.ad)).toBe(
      '01d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737052a50773ac8d91773f2dc9662e12f0defe915e415b8a1c8e20a5a3d6ab2b843884b8857f4eaa1613c61504db34d4beaf346517a0e31de3cddd4d9b4201d9d0b0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20',
    )
    expect(bytesEqual(ini.sk, res.sk)).toBe(true)
    expect(bytesEqual(ini.ad, res.ad)).toBe(true)
  })

  it('without a one-time prekey: SK matches the pinned vector', () => {
    const ini = x3dhInitiate(alice, makeBundle(false), NOW, undefined, ek)
    const res = x3dhRespond(bob, ini.header, bobKeys, NOW)
    expect(bytesToHex(ini.sk)).toBe('9bd5a9db1abf86f17bdbebc56cdfd808d7d9d4b549acf35a135f7a9b84dbeace')
    expect(bytesEqual(ini.sk, res.sk)).toBe(true)
  })
})

describe('initial-message replay guard', () => {
  it('computes a deterministic id and detects a replay', () => {
    const s = scenario()
    const ini = x3dhInitiate(s.alice, s.bundle, NOW)
    const id = initialMessageId(ini.header)
    expect(bytesEqual(id, initialMessageId(ini.header))).toBe(true)

    const guard = new InitialMessageReplayGuard()
    expect(guard.check(id)).toBe(true) // first sighting
    expect(guard.check(id)).toBe(false) // replay rejected

    // A genuinely new initial message (fresh ephemeral key) is still accepted.
    const ini2 = x3dhInitiate(s.alice, s.bundle, NOW)
    expect(guard.check(initialMessageId(ini2.header))).toBe(true)
  })

  it('detects a replay on the no-OPK path (the deterministic-SK threat)', () => {
    const s = scenario(NOW, false)
    const ini = x3dhInitiate(s.alice, s.bundle, NOW)
    const guard = new InitialMessageReplayGuard()
    const id = initialMessageId(ini.header)
    expect(guard.check(id)).toBe(true)
    expect(guard.check(id)).toBe(false)
  })

  it('changes the id when any hashed header field changes', () => {
    const s = scenario()
    const ini = x3dhInitiate(s.alice, s.bundle, NOW)
    const base = initialMessageId(ini.header)
    const variants: InitialHeader[] = [
      { ...ini.header, version: ini.header.version ^ 1 },
      { ...ini.header, ikSigPub: flip(ini.header.ikSigPub) },
      { ...ini.header, ikDhPub: flip(ini.header.ikDhPub) },
      { ...ini.header, ekPub: flip(ini.header.ekPub) },
      { ...ini.header, spkId: ini.header.spkId + 1 },
      { ...ini.header, opkId: (ini.header.opkId ?? 0) + 1 },
    ]
    for (const v of variants) expect(bytesEqual(base, initialMessageId(v))).toBe(false)
    const ini2 = x3dhInitiate(s.alice, s.bundle, NOW)
    expect(bytesEqual(base, initialMessageId(ini2.header))).toBe(false)
  })
})
