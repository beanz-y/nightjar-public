import { describe, it, expect } from 'vitest'
import { generateIdentity } from '../crypto/identity'
import { utf8 } from '../crypto/primitives'
import { type FetchedBundle, OWN_BUNDLE_VERSION, buildOwnBundle } from '../crypto/prekeys'
import { type RatchetState, initRatchetInitiator, initRatchetResponder } from '../crypto/ratchet'
import { x3dhInitiate, x3dhRespond } from '../crypto/x3dh'
import { InMemoryLock } from '../storage/lock'
import { MemorySessionStore } from '../storage/sessionStore'
import { RatchetSession } from './ratchetSession'

const NOW = 1_700_000_000_000
const B = (s: string): Uint8Array => utf8(s)
const S = (b: Uint8Array): string => new TextDecoder().decode(b)

function establishStates(): { aliceState: RatchetState; bobState: RatchetState } {
  const aliceId = generateIdentity()
  const bobId = generateIdentity()
  const own = buildOwnBundle(bobId, NOW, { spkId: 1, opkStartId: 1, opkCount: 1 })
  const bundle: FetchedBundle = {
    version: OWN_BUNDLE_VERSION,
    ikSigPub: own.ikSigPub,
    ikDhPub: own.ikDhPub,
    idkbindSig: own.idkbindSig,
    spk: own.spk,
    opk: own.opks[0],
  }
  const ini = x3dhInitiate(aliceId, bundle, NOW)
  const res = x3dhRespond(bobId, ini.header, { spkPrivById: own.spkPrivById, opkPrivById: own.opkPrivById }, NOW)
  const bobSpkPriv = own.spkPrivById.get(1)
  if (!bobSpkPriv) throw new Error('missing spk priv')
  return {
    aliceState: initRatchetInitiator(ini.sk, ini.ad, bundle.spk.pub),
    bobState: initRatchetResponder(res.sk, res.ad, { privateKey: bobSpkPriv, publicKey: bundle.spk.pub }),
  }
}

async function pair() {
  const store = new MemorySessionStore()
  const lock = new InMemoryLock()
  const { aliceState, bobState } = establishStates()
  const alice = await RatchetSession.create('bob', aliceState, store, lock)
  const bob = await RatchetSession.create('alice', bobState, store, lock)
  return { store, lock, alice, bob }
}

describe('RatchetSession', () => {
  it('round-trips messages in both directions through storage', async () => {
    const { alice, bob } = await pair()
    const e = await alice.encrypt(B('hi bob'))
    expect(S(await bob.decrypt(e.header, e.ciphertext))).toBe('hi bob')
    const r = await bob.encrypt(B('hi alice'))
    expect(S(await alice.decrypt(r.header, r.ciphertext))).toBe('hi alice')
  })

  it('does not persist state when decrypt fails (crash-safe: commit only on success)', async () => {
    const { store, alice, bob } = await pair()
    const e = await alice.encrypt(B('real'))
    const before = JSON.stringify(await store.load('alice'))
    const tampered = e.ciphertext.slice()
    tampered[0] ^= 1
    await expect(bob.decrypt(e.header, tampered)).rejects.toThrow()
    expect(JSON.stringify(await store.load('alice'))).toBe(before) // unchanged
    // the genuine message still decrypts against the un-advanced state
    expect(S(await bob.decrypt(e.header, e.ciphertext))).toBe('real')
  })

  it('serializes concurrent encrypts so message numbers do not collide', async () => {
    const { alice, bob } = await pair()
    const [e1, e2, e3] = await Promise.all([alice.encrypt(B('a')), alice.encrypt(B('b')), alice.encrypt(B('c'))])
    expect(e1.header.n).toBe(0)
    expect(e2.header.n).toBe(1)
    expect(e3.header.n).toBe(2)
    // all three still decrypt at the receiver (out-of-order tolerated)
    expect(S(await bob.decrypt(e3.header, e3.ciphertext))).toBe('c')
    expect(S(await bob.decrypt(e1.header, e1.ciphertext))).toBe('a')
    expect(S(await bob.decrypt(e2.header, e2.ciphertext))).toBe('b')
  })

  it('resumes from storage: a session re-opened as a fresh instance continues the ratchet', async () => {
    const { store, lock, bob } = await pair()
    const e1 = await RatchetSession.open('bob', store, lock).encrypt(B('m0'))
    const e2 = await RatchetSession.open('bob', store, lock).encrypt(B('m1'))
    expect(e2.header.n).toBe(e1.header.n + 1) // continued, not restarted from n=0
    expect(S(await bob.decrypt(e1.header, e1.ciphertext))).toBe('m0')
    expect(S(await bob.decrypt(e2.header, e2.ciphertext))).toBe('m1')
  })

  it('throws when operating on a peer with no stored session', async () => {
    const store = new MemorySessionStore()
    const lock = new InMemoryLock()
    await expect(RatchetSession.open('ghost', store, lock).encrypt(B('x'))).rejects.toThrow(/no ratchet session/)
  })

  it('serializes an interleaved decrypt and encrypt on one session (no lost update across fields)', async () => {
    const { alice, bob } = await pair()
    // Prime: Bob receives one message so his sending chain exists.
    const m0 = await alice.encrypt(B('m0'))
    expect(S(await bob.decrypt(m0.header, m0.ciphertext))).toBe('m0')
    // Interleave a decrypt (advances nr/ckr) and an encrypt (advances ns/cks).
    const m1 = await alice.encrypt(B('m1'))
    const [plain, sent] = await Promise.all([bob.decrypt(m1.header, m1.ciphertext), bob.encrypt(B('reply'))])
    expect(S(plain)).toBe('m1')
    // Both advances persisted; follow-up traffic in both directions continues.
    expect(S(await alice.decrypt(sent.header, sent.ciphertext))).toBe('reply')
    const m2 = await alice.encrypt(B('m2'))
    expect(S(await bob.decrypt(m2.header, m2.ciphertext))).toBe('m2')
    const reply2 = await bob.encrypt(B('reply2'))
    expect(S(await alice.decrypt(reply2.header, reply2.ciphertext))).toBe('reply2')
  })

  it('decrypts the same message at most once (replay throws)', async () => {
    // Pins the at-most-once tradeoff: the advance commits before plaintext is
    // returned, so a redelivery fails. Idempotent reprocessing / dedup is a P4
    // app-layer responsibility (see RatchetSession.decrypt).
    const { alice, bob } = await pair()
    const e = await alice.encrypt(B('once'))
    expect(S(await bob.decrypt(e.header, e.ciphertext))).toBe('once')
    await expect(bob.decrypt(e.header, e.ciphertext)).rejects.toThrow()
  })
})
