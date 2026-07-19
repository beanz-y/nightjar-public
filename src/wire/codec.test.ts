import { describe, expect, it } from 'vitest'
import { generateIdentity } from '../crypto/identity'
import { OWN_BUNDLE_VERSION, buildOwnBundle } from '../crypto/prekeys'
import { x3dhInitiate } from '../crypto/x3dh'
import type { FetchedBundle } from '../crypto/prekeys'
import {
  type Envelope,
  b64decode,
  b64encode,
  decodeEnvelope,
  decodeFetchedBundle,
  decodeInitialHeader,
  decodeMessageHeaderWire,
  decodePublishedBundle,
  decodeSignedPrekey,
  encodeEnvelope,
  encodeFetchedBundle,
  encodeInitialHeader,
  encodeMessageHeaderWire,
  encodePublishedBundle,
  encodeSignedPrekey,
} from './codec'

const NOW = 1_700_000_000_000
const seq = (n: number) => Uint8Array.from({ length: n }, (_, i) => i & 0xff)

// Independently-computed base64url of 0..31 (locks the base64url variant: note
// the url-safe alphabet and no padding). If this changes, the wire format did.
const B64_0_31 = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'

describe('base64url helpers', () => {
  it('encodes to the pinned url-safe, unpadded form', () => {
    expect(b64encode(seq(32))).toBe(B64_0_31)
  })

  it('round-trips arbitrary byte lengths', () => {
    for (const n of [0, 1, 16, 32, 63, 64, 100]) {
      expect(b64decode(b64encode(seq(n)))).toEqual(seq(n))
    }
  })

  it('rejects a non-base64 string', () => {
    expect(() => b64decode('*** not b64 ***')).toThrow()
  })

  it('rejects a wrong expected length (fail-closed)', () => {
    expect(() => b64decode(B64_0_31, 31)).toThrow(/expected 31 bytes/)
  })
})

describe('message header codec', () => {
  it('encodes to the pinned wire shape', () => {
    const w = encodeMessageHeaderWire({ version: 1, dhPub: seq(32), pn: 5, n: 258 })
    expect(w).toEqual({ version: 1, dhPub: B64_0_31, pn: 5, n: 258 })
  })

  it('round-trips', () => {
    const h = { version: 1, dhPub: seq(32), pn: 7, n: 4_000_000_000 }
    expect(decodeMessageHeaderWire(encodeMessageHeaderWire(h))).toEqual(h)
  })

  it('rejects a short dhPub', () => {
    expect(() => decodeMessageHeaderWire({ version: 1, dhPub: b64encode(seq(31)), pn: 0, n: 0 })).toThrow()
  })

  it('rejects a non-integer counter', () => {
    expect(() => decodeMessageHeaderWire({ version: 1, dhPub: B64_0_31, pn: 0, n: 1.5 })).toThrow()
  })

  it('rejects a negative counter', () => {
    expect(() => decodeMessageHeaderWire({ version: 1, dhPub: B64_0_31, pn: -1, n: 0 })).toThrow()
  })
})

describe('prekey + bundle codecs', () => {
  it('round-trips a fetched bundle (with and without OPK)', () => {
    const id = generateIdentity()
    const own = buildOwnBundle(id, NOW, { spkId: 1, opkStartId: 1, opkCount: 1 })
    const withOpk: FetchedBundle = {
      version: OWN_BUNDLE_VERSION,
      ikSigPub: own.ikSigPub,
      ikDhPub: own.ikDhPub,
      idkbindSig: own.idkbindSig,
      spk: own.spk,
      opk: own.opks[0],
    }
    expect(decodeFetchedBundle(encodeFetchedBundle(withOpk))).toEqual(withOpk)

    const noOpk: FetchedBundle = { ...withOpk, opk: null }
    expect(decodeFetchedBundle(encodeFetchedBundle(noOpk))).toEqual(noOpk)
  })

  it('round-trips a published bundle with a full OPK batch', () => {
    const id = generateIdentity()
    const own = buildOwnBundle(id, NOW, { spkId: 2, opkStartId: 10, opkCount: 5 })
    const pub = {
      version: OWN_BUNDLE_VERSION,
      ikSigPub: own.ikSigPub,
      ikDhPub: own.ikDhPub,
      idkbindSig: own.idkbindSig,
      spk: own.spk,
      opks: own.opks,
    }
    const back = decodePublishedBundle(encodePublishedBundle(pub))
    expect(back).toEqual(pub)
    expect(back.opks).toHaveLength(5)
  })

  it('round-trips a signed prekey', () => {
    const id = generateIdentity()
    const own = buildOwnBundle(id, NOW, { spkId: 3 })
    expect(decodeSignedPrekey(encodeSignedPrekey(own.spk))).toEqual(own.spk)
  })

  it('rejects a signed prekey with a bad signature length', () => {
    const id = generateIdentity()
    const own = buildOwnBundle(id, NOW, { spkId: 1 })
    const w = encodeSignedPrekey(own.spk)
    w.sig = b64encode(seq(63)) // one byte short of an Ed25519 signature
    expect(() => decodeSignedPrekey(w)).toThrow()
  })
})

describe('initial header + envelope codecs', () => {
  function makeInitial() {
    const alice = generateIdentity()
    const bob = generateIdentity()
    const own = buildOwnBundle(bob, NOW, { spkId: 1, opkStartId: 1, opkCount: 1 })
    const bundle: FetchedBundle = {
      version: OWN_BUNDLE_VERSION,
      ikSigPub: own.ikSigPub,
      ikDhPub: own.ikDhPub,
      idkbindSig: own.idkbindSig,
      spk: own.spk,
      opk: own.opks[0],
    }
    return x3dhInitiate(alice, bundle, NOW)
  }

  it('round-trips an initial header', () => {
    const ini = makeInitial()
    expect(decodeInitialHeader(encodeInitialHeader(ini.header))).toEqual(ini.header)
  })

  it('round-trips a normal envelope', () => {
    const e: Envelope = {
      id: 'msg-1',
      kind: 'normal',
      header: { version: 1, dhPub: seq(32), pn: 0, n: 3 },
      ciphertext: seq(48),
    }
    expect(decodeEnvelope(encodeEnvelope(e))).toEqual(e)
  })

  it('round-trips an initial envelope carrying the X3DH header', () => {
    const ini = makeInitial()
    const e: Envelope = {
      id: 'msg-init',
      kind: 'initial',
      header: { version: 1, dhPub: seq(32), pn: 0, n: 0 },
      ciphertext: seq(80),
      initialHeader: ini.header,
    }
    expect(decodeEnvelope(encodeEnvelope(e))).toEqual(e)
  })

  it('rejects an initial envelope missing its initial header', () => {
    const w = {
      id: 'x',
      kind: 'initial' as const,
      header: { version: 1, dhPub: B64_0_31, pn: 0, n: 0 },
      ciphertext: b64encode(seq(10)),
    }
    expect(() => decodeEnvelope(w)).toThrow(/missing initialHeader/)
  })

  it('rejects an unknown envelope kind', () => {
    const w = {
      id: 'x',
      kind: 'weird' as unknown as 'normal',
      header: { version: 1, dhPub: B64_0_31, pn: 0, n: 0 },
      ciphertext: b64encode(seq(10)),
    }
    expect(() => decodeEnvelope(w)).toThrow(/bad envelope kind/)
  })

  it('rejects an empty or over-long id', () => {
    const base = {
      kind: 'normal' as const,
      header: { version: 1, dhPub: B64_0_31, pn: 0, n: 0 },
      ciphertext: b64encode(seq(10)),
    }
    expect(() => decodeEnvelope({ ...base, id: '' })).toThrow(/bad envelope id/)
    expect(() => decodeEnvelope({ ...base, id: 'x'.repeat(200) })).toThrow(/bad envelope id/)
  })
})
