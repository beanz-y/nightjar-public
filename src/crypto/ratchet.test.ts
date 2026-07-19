import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils'
import { MAX_SKIP } from './constants'
import { generateIdentity } from './identity'
import { type KeyPair, bytesEqual, utf8, x25519Public } from './primitives'
import { type FetchedBundle, OWN_BUNDLE_VERSION, buildOwnBundle } from './prekeys'
import { x3dhInitiate, x3dhRespond } from './x3dh'
import {
  type MessageHeader,
  type RatchetState,
  deserializeRatchet,
  expandMk,
  initRatchetInitiator,
  initRatchetResponder,
  kdfCk,
  kdfRk,
  ratchetDecrypt,
  ratchetEncrypt,
  serializeRatchet,
} from './ratchet'

const NOW = 1_700_000_000_000
const SEED = (n: number): Uint8Array => new Uint8Array(32).fill(n)
const B = (s: string): Uint8Array => utf8(s)
const S = (b: Uint8Array): string => new TextDecoder().decode(b)

/** Run a full X3DH and initialise both ratchets, as the real session setup will. */
function establish(): { alice: RatchetState; bob: RatchetState } {
  const aliceId = generateIdentity()
  const bobId = generateIdentity()
  const own = buildOwnBundle(bobId, NOW, { spkId: 1, opkStartId: 7, opkCount: 3 })
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
  const alice = initRatchetInitiator(ini.sk, ini.ad, bundle.spk.pub)
  const bobSpkPriv = own.spkPrivById.get(1)
  if (!bobSpkPriv) throw new Error('missing spk priv')
  const bob = initRatchetResponder(res.sk, res.ad, { privateKey: bobSpkPriv, publicKey: bundle.spk.pub })
  return { alice, bob }
}

/** Encrypt from -> to, decrypt, and return the advanced states plus plaintext. */
function deliver(from: RatchetState, to: RatchetState, msg: string): { from: RatchetState; to: RatchetState; text: string } {
  const e = ratchetEncrypt(from, B(msg))
  const d = ratchetDecrypt(to, e.header, e.ciphertext)
  return { from: e.state, to: d.state, text: S(d.plaintext) }
}

describe('ratchet KDF known-answer vectors', () => {
  it('kdfCk (chain step)', () => {
    const { mk, ck } = kdfCk(SEED(0x42))
    expect(bytesToHex(mk)).toBe('0b175bca3524cc7301c33946d7e00d3f008cb14632b72855b3442a7365403893')
    expect(bytesToHex(ck)).toBe('4fa923f5d122080142716bf80fec4930203815c6b10199d1a871e09fe0a3c720')
  })
  it('expandMk (message-key expansion)', () => {
    const { key, nonce } = expandMk(SEED(0x43))
    expect(bytesToHex(key)).toBe('8b6128242fdfb0c74ae4b82af1a576d2ad7d119a14a591fa67b15117c297c5f8')
    expect(bytesToHex(nonce)).toBe('4439a3cd672a837be89862c8de7d94e801c7d22e4e2440e1')
  })
  it('kdfRk (root/DH-ratchet step)', () => {
    const { rk, ck } = kdfRk(SEED(0x44), SEED(0x45))
    expect(bytesToHex(rk)).toBe('9f6527fc7eddf95be9524e41d3533052775af17b8f101615b6b73a8b37bfb170')
    expect(bytesToHex(ck)).toBe('8b649c2fc36493a1a9576dd9aecb933467ba9a7b1e1b9b4584171452e122c18b')
  })
})

describe('ratchet full-message known-answer vector', () => {
  it('pins the first message wire format (header + ciphertext, independently computed)', () => {
    // Fixed SK/AD (opaque to the ratchet) + an injected first ratchet key make
    // the whole envelope deterministic, pinning encodeHeader field order, the
    // AD||header AAD assembly, u32be endianness, the version octet, and the
    // key/nonce wiring. A symmetric change to any of these would fail here.
    const sk = SEED(0x51)
    const ad = SEED(0x52)
    const aliceRatchet: KeyPair = { privateKey: SEED(0x53), publicKey: x25519Public(SEED(0x53)) }
    const bobSpkPub = x25519Public(SEED(0x54))
    const alice = initRatchetInitiator(sk, ad, bobSpkPub, aliceRatchet)
    const e = ratchetEncrypt(alice, B('ratchet-kat-msg-0'))
    expect(e.header.version).toBe(1)
    expect(e.header.pn).toBe(0)
    expect(e.header.n).toBe(0)
    expect(bytesToHex(e.header.dhPub)).toBe('261cd9cd2e935f9c2455876a80f02a4d6786b8ab877f07227737ca0b577bf161')
    expect(bytesToHex(e.ciphertext)).toBe('9c52a9a6d06062074986a916b3692aed24d3e5fca7f98002879be568742ac2ba50')
  })
})

describe('ratchet round-trips', () => {
  it('carries a message in each direction', () => {
    let { alice, bob } = establish()
    let r = deliver(alice, bob, 'hi bob')
    alice = r.from
    bob = r.to
    expect(r.text).toBe('hi bob')
    r = deliver(bob, alice, 'hi alice')
    bob = r.from
    alice = r.to
    expect(r.text).toBe('hi alice')
  })

  it('handles a longer back-and-forth conversation', () => {
    let { alice, bob } = establish()
    const step = (fromAlice: boolean, msg: string) => {
      const r = fromAlice ? deliver(alice, bob, msg) : deliver(bob, alice, msg)
      if (fromAlice) {
        alice = r.from
        bob = r.to
      } else {
        bob = r.from
        alice = r.to
      }
      expect(r.text).toBe(msg)
    }
    step(true, 'a1')
    step(true, 'a2')
    step(false, 'b1')
    step(false, 'b2')
    step(true, 'a3')
    step(false, 'b3')
    step(true, 'a4')
  })
})

describe('ratchet out-of-order and loss', () => {
  it('decrypts messages received out of order using skipped keys', () => {
    let { alice, bob } = establish()
    const msgs = ['m0', 'm1', 'm2', 'm3'].map((m) => {
      const e = ratchetEncrypt(alice, B(m))
      alice = e.state
      return e
    })
    for (const i of [3, 1, 0, 2]) {
      const d = ratchetDecrypt(bob, msgs[i].header, msgs[i].ciphertext)
      bob = d.state
      expect(S(d.plaintext)).toBe(`m${i}`)
    }
  })

  it('decrypts a dropped message that finally arrives', () => {
    let { alice, bob } = establish()
    const m = ['m0', 'm1', 'm2'].map((x) => {
      const e = ratchetEncrypt(alice, B(x))
      alice = e.state
      return e
    })
    let d = ratchetDecrypt(bob, m[0].header, m[0].ciphertext)
    bob = d.state
    expect(S(d.plaintext)).toBe('m0')
    d = ratchetDecrypt(bob, m[2].header, m[2].ciphertext) // m1 skipped
    bob = d.state
    expect(S(d.plaintext)).toBe('m2')
    d = ratchetDecrypt(bob, m[1].header, m[1].ciphertext) // late m1
    bob = d.state
    expect(S(d.plaintext)).toBe('m1')
  })

  it('recovers pre-ratchet messages skipped across a DH-ratchet step (pn > 0)', () => {
    let { alice, bob } = establish()
    // Alice sends a1,a2,a3; Bob receives only a1.
    const a1 = ratchetEncrypt(alice, B('a1'))
    alice = a1.state
    const a2 = ratchetEncrypt(alice, B('a2'))
    alice = a2.state
    const a3 = ratchetEncrypt(alice, B('a3'))
    alice = a3.state
    let d = ratchetDecrypt(bob, a1.header, a1.ciphertext)
    bob = d.state
    expect(S(d.plaintext)).toBe('a1')
    // Bob replies; Alice receives it and DH-ratchets.
    const b1 = ratchetEncrypt(bob, B('b1'))
    bob = b1.state
    d = ratchetDecrypt(alice, b1.header, b1.ciphertext)
    alice = d.state
    expect(S(d.plaintext)).toBe('b1')
    // Alice's next message is in a NEW chain, carrying pn = 3 (old chain length).
    const a4 = ratchetEncrypt(alice, B('a4'))
    alice = a4.state
    expect(a4.header.pn).toBe(3)
    // Bob receives a4: must skip the tail (a2,a3) of the OLD chain across the ratchet.
    d = ratchetDecrypt(bob, a4.header, a4.ciphertext)
    bob = d.state
    expect(S(d.plaintext)).toBe('a4')
    // The late a2,a3 now decrypt from keys stored under the OLD dhr during the skip.
    d = ratchetDecrypt(bob, a2.header, a2.ciphertext)
    bob = d.state
    expect(S(d.plaintext)).toBe('a2')
    d = ratchetDecrypt(bob, a3.header, a3.ciphertext)
    bob = d.state
    expect(S(d.plaintext)).toBe('a3')
  })

  it('evicts the oldest skipped key past the storage cap (MAX_SKIP)', () => {
    let { alice, bob } = establish()
    const msgs: Array<{ header: MessageHeader; ciphertext: Uint8Array }> = []
    for (let i = 0; i <= 1002; i++) {
      const e = ratchetEncrypt(alice, B(`m${i}`))
      alice = e.state
      msgs.push({ header: e.header, ciphertext: e.ciphertext })
    }
    // Receive m1000 (stores skipped keys for 0..999, filling the cap), then m1002
    // (stores 1001, which evicts the oldest, n=0).
    let d = ratchetDecrypt(bob, msgs[1000].header, msgs[1000].ciphertext)
    bob = d.state
    expect(S(d.plaintext)).toBe('m1000')
    d = ratchetDecrypt(bob, msgs[1002].header, msgs[1002].ciphertext)
    bob = d.state
    expect(S(d.plaintext)).toBe('m1002')
    // m0's key was evicted (oldest) -> unrecoverable; a mid-range key survives.
    expect(() => ratchetDecrypt(bob, msgs[0].header, msgs[0].ciphertext)).toThrow()
    const dmid = ratchetDecrypt(bob, msgs[500].header, msgs[500].ciphertext)
    bob = dmid.state
    expect(S(dmid.plaintext)).toBe('m500')
  })
})

describe('ratchet security discipline', () => {
  it('rejects a replayed message (consumed key is gone)', () => {
    let { alice, bob } = establish()
    const e = ratchetEncrypt(alice, B('once'))
    alice = e.state
    const d = ratchetDecrypt(bob, e.header, e.ciphertext)
    bob = d.state
    expect(S(d.plaintext)).toBe('once')
    expect(() => ratchetDecrypt(bob, e.header, e.ciphertext)).toThrow()
  })

  it('a forged ciphertext throws and does not corrupt the receiver state', () => {
    let { alice, bob } = establish()
    const e1 = ratchetEncrypt(alice, B('real1'))
    alice = e1.state
    const tampered = e1.ciphertext.slice()
    tampered[0] ^= 1
    expect(() => ratchetDecrypt(bob, e1.header, tampered)).toThrow()
    // Bob's state is untouched: the genuine message still decrypts.
    const d1 = ratchetDecrypt(bob, e1.header, e1.ciphertext)
    bob = d1.state
    expect(S(d1.plaintext)).toBe('real1')
    const e2 = ratchetEncrypt(alice, B('real2'))
    alice = e2.state
    const d2 = ratchetDecrypt(bob, e2.header, e2.ciphertext)
    bob = d2.state
    expect(S(d2.plaintext)).toBe('real2')
  })

  it('rejects a message whose header was tampered (header is authenticated)', () => {
    let { alice, bob } = establish()
    const e = ratchetEncrypt(alice, B('x'))
    alice = e.state
    expect(() => ratchetDecrypt(bob, { ...e.header, n: e.header.n + 5 }, e.ciphertext)).toThrow()
  })

  it('rejects a new-chain header that would skip more than MAX_SKIP (compute bound)', () => {
    const { alice, bob } = establish()
    const e = ratchetEncrypt(alice, B('x'))
    expect(() => ratchetDecrypt(bob, { ...e.header, n: MAX_SKIP + 5 }, e.ciphertext)).toThrow(/skip bound/)
  })

  it('rejects a same-chain header that would skip more than MAX_SKIP', () => {
    let { alice, bob } = establish()
    const e0 = ratchetEncrypt(alice, B('m0'))
    alice = e0.state
    const d0 = ratchetDecrypt(bob, e0.header, e0.ciphertext)
    bob = d0.state
    expect(() => ratchetDecrypt(bob, { ...e0.header, n: MAX_SKIP + 2 }, e0.ciphertext)).toThrow(/skip bound/)
  })

  it('a responder cannot send before receiving the first message', () => {
    const { bob } = establish()
    expect(() => ratchetEncrypt(bob, B('too early'))).toThrow(/before receiving/)
  })

  it('encrypting twice from the same state reuses the key (caller MUST persist)', () => {
    const { alice } = establish()
    const e1 = ratchetEncrypt(alice, B('dup'))
    const e2 = ratchetEncrypt(alice, B('dup'))
    expect(e1.header.n).toBe(e2.header.n)
    expect(bytesEqual(e1.ciphertext, e2.ciphertext)).toBe(true) // identical: send once, persist the returned state
    const e3 = ratchetEncrypt(e1.state, B('next'))
    expect(e3.header.n).toBe(e1.header.n + 1)
  })

  it('authenticates the whole header (AAD binds fields not used for key derivation)', () => {
    let { alice, bob } = establish()
    const e0 = ratchetEncrypt(alice, B('m0'))
    alice = e0.state
    const d0 = ratchetDecrypt(bob, e0.header, e0.ciphertext) // Bob adopts Alice's chain
    bob = d0.state
    expect(S(d0.plaintext)).toBe('m0')
    // Same-chain second message: pn and version are NOT consulted for key
    // derivation here, so a throw proves the AEAD tag binds the header bytes. If
    // the AAD dropped the header, these would decrypt anyway.
    const e1 = ratchetEncrypt(alice, B('m1'))
    alice = e1.state
    expect(() => ratchetDecrypt(bob, { ...e1.header, pn: e1.header.pn + 7 }, e1.ciphertext)).toThrow()
    expect(() => ratchetDecrypt(bob, { ...e1.header, version: e1.header.version ^ 1 }, e1.ciphertext)).toThrow()
    // The genuine header still decrypts (the throws never advanced Bob's state).
    const d1 = ratchetDecrypt(bob, e1.header, e1.ciphertext)
    bob = d1.state
    expect(S(d1.plaintext)).toBe('m1')
  })

  it('never mutates the input state (thrown decrypt, and a successful skipped-key decrypt)', () => {
    let { alice, bob } = establish()
    const m0 = ratchetEncrypt(alice, B('m0'))
    alice = m0.state
    const m1 = ratchetEncrypt(alice, B('m1'))
    alice = m1.state
    const d1 = ratchetDecrypt(bob, m1.header, m1.ciphertext) // stores m0's key as skipped
    bob = d1.state
    const before = JSON.stringify(serializeRatchet(bob))

    // (a) a thrown decrypt leaves the input byte-identical
    const bad = m0.ciphertext.slice()
    bad[0] ^= 1
    expect(() => ratchetDecrypt(bob, m0.header, bad)).toThrow()
    expect(JSON.stringify(serializeRatchet(bob))).toBe(before)

    // (b) a SUCCESSFUL decrypt that consumes a skipped key still does not mutate
    //     the input; the advance lives only in the returned state.
    const d0 = ratchetDecrypt(bob, m0.header, m0.ciphertext)
    expect(S(d0.plaintext)).toBe('m0')
    expect(JSON.stringify(serializeRatchet(bob))).toBe(before)
    expect(JSON.stringify(serializeRatchet(d0.state))).not.toBe(before)
  })
})

describe('ratchet serialization', () => {
  it('survives serialization mid-conversation, including a stored skipped key', () => {
    let { alice, bob } = establish()
    let r = deliver(alice, bob, 'before')
    alice = r.from
    bob = r.to
    expect(r.text).toBe('before')

    // Round-trip Bob's state, then carry a skipped key across another round-trip.
    bob = deserializeRatchet(serializeRatchet(bob))
    const e1 = ratchetEncrypt(alice, B('s1'))
    alice = e1.state
    const e2 = ratchetEncrypt(alice, B('s2'))
    alice = e2.state
    const d2 = ratchetDecrypt(bob, e2.header, e2.ciphertext) // s1's key gets stored as skipped
    bob = d2.state
    expect(S(d2.plaintext)).toBe('s2')
    bob = deserializeRatchet(serializeRatchet(bob)) // serialize WITH a skipped key present
    const d1 = ratchetDecrypt(bob, e1.header, e1.ciphertext) // recover via the persisted skipped key
    bob = d1.state
    expect(S(d1.plaintext)).toBe('s1')
  })
})
