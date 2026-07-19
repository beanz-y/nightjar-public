import { describe, it, expect } from 'vitest'
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils'
import {
  aeadOpen,
  aeadSeal,
  base32lower,
  bytesEqual,
  compareBytes,
  concatBytes,
  domainSeparate,
  ed25519Generate,
  ed25519Sign,
  ed25519Verify,
  hash256,
  hash512,
  hkdfSha256,
  hmacSha256,
  randomBytes,
  utf8,
  x25519Dh,
  x25519Generate,
  XCHACHA_KEY_BYTES,
  XCHACHA_NONCE_BYTES,
} from './primitives'

describe('hashes (RFC known-answer)', () => {
  it('sha256("abc")', () => {
    expect(bytesToHex(hash256(utf8ToBytes('abc')))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    )
  })
  it('sha512("abc")', () => {
    expect(bytesToHex(hash512(utf8ToBytes('abc')))).toBe(
      'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a' +
        '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
    )
  })
})

describe('HKDF-SHA256 (RFC 5869 test case 1)', () => {
  it('derives the published OKM', () => {
    const ikm = hexToBytes('0b'.repeat(22))
    const salt = hexToBytes('000102030405060708090a0b0c')
    const info = hexToBytes('f0f1f2f3f4f5f6f7f8f9')
    expect(bytesToHex(hkdfSha256(ikm, salt, info, 42))).toBe(
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    )
  })
})

describe('HMAC-SHA256 (RFC 4231 test case 2)', () => {
  it('matches the published MAC', () => {
    expect(
      bytesToHex(hmacSha256(utf8ToBytes('Jefe'), utf8ToBytes('what do ya want for nothing?'))),
    ).toBe('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843')
  })
})

describe('X25519 (RFC 7748 section 5.2)', () => {
  it('scalar-mult matches the published output', () => {
    const scalar = hexToBytes('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4')
    const u = hexToBytes('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c')
    expect(bytesToHex(x25519Dh(scalar, u))).toBe(
      'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552',
    )
  })
  it('two parties derive the same shared secret', () => {
    const a = x25519Generate()
    const b = x25519Generate()
    expect(bytesEqual(x25519Dh(a.privateKey, b.publicKey), x25519Dh(b.privateKey, a.publicKey))).toBe(true)
  })
  it('throws on an all-zero / low-order public key (contributory-key guard)', () => {
    // A predictable all-zero shared secret must fail closed, since X3DH (P1)
    // builds directly on this DH.
    expect(() => x25519Dh(x25519Generate().privateKey, new Uint8Array(32))).toThrow()
    const one = new Uint8Array(32)
    one[0] = 1
    expect(() => x25519Dh(x25519Generate().privateKey, one)).toThrow()
  })
})

describe('Ed25519', () => {
  it('sign/verify round-trips and rejects tampering', () => {
    const k = ed25519Generate()
    const msg = utf8('hello nightjar')
    const sig = ed25519Sign(msg, k.privateKey)
    expect(ed25519Verify(sig, msg, k.publicKey)).toBe(true)
    expect(ed25519Verify(sig, utf8('hello nightjas'), k.publicKey)).toBe(false)
    expect(ed25519Verify(sig, msg, ed25519Generate().publicKey)).toBe(false)
  })
  it('is deterministic', () => {
    const k = ed25519Generate()
    const msg = utf8('deterministic')
    expect(bytesEqual(ed25519Sign(msg, k.privateKey), ed25519Sign(msg, k.privateKey))).toBe(true)
  })
})

describe('XChaCha20-Poly1305 AEAD', () => {
  it('round-trips with AAD and rejects tamper / wrong AAD', () => {
    const key = randomBytes(XCHACHA_KEY_BYTES)
    const nonce = randomBytes(XCHACHA_NONCE_BYTES)
    const pt = utf8('secret message')
    const aad = utf8('associated')
    const ct = aeadSeal(key, nonce, pt, aad)
    expect(bytesEqual(aeadOpen(key, nonce, ct, aad), pt)).toBe(true)
    expect(() => aeadOpen(key, nonce, ct, utf8('wrong'))).toThrow()
    const tampered = ct.slice()
    tampered[0] ^= 1
    expect(() => aeadOpen(key, nonce, tampered, aad)).toThrow()
  })
  it('rejects a wrong key and a wrong nonce, and round-trips with no AAD', () => {
    const key = randomBytes(XCHACHA_KEY_BYTES)
    const nonce = randomBytes(XCHACHA_NONCE_BYTES)
    const pt = utf8('no aad here')
    const ctNoAad = aeadSeal(key, nonce, pt)
    expect(bytesEqual(aeadOpen(key, nonce, ctNoAad), pt)).toBe(true)
    const ct = aeadSeal(key, nonce, pt, utf8('x'))
    expect(() => aeadOpen(randomBytes(XCHACHA_KEY_BYTES), nonce, ct, utf8('x'))).toThrow()
    expect(() => aeadOpen(key, randomBytes(XCHACHA_NONCE_BYTES), ct, utf8('x'))).toThrow()
  })
})

describe('domainSeparate', () => {
  it('matches the pinned byte layout (u32be(taglen)||tag||u32be(len)||part)', () => {
    expect(bytesToHex(domainSeparate('T', utf8('ab')))).toBe('0000000154000000026162')
  })
  it('is unambiguous: one part [ab] != two parts [a],[b]', () => {
    const a = utf8('a')
    const b = utf8('b')
    expect(bytesEqual(domainSeparate('T', concatBytes(a, b)), domainSeparate('T', a, b))).toBe(false)
  })
  it('different tags produce different encodings', () => {
    const x = utf8('x')
    expect(bytesEqual(domainSeparate('T1', x), domainSeparate('T2', x))).toBe(false)
  })
  it('is injective even when one tag is a byte-prefix of another', () => {
    const x = utf8('x')
    expect(bytesEqual(domainSeparate('spk', x), domainSeparate('spk-v1', x))).toBe(false)
  })
})

describe('base32lower (encoding KAT)', () => {
  it('encodes fixed inputs, lowercase and unpadded', () => {
    expect(base32lower(Uint8Array.from([0]))).toBe('aa')
    expect(base32lower(Uint8Array.from([0, 1, 2, 3, 4]))).toBe('aaaqeaye')
  })
})

describe('compareBytes / concatBytes edges', () => {
  it('compareBytes orders lexicographically with length tiebreak', () => {
    expect(compareBytes(utf8('abc'), utf8('abc'))).toBe(0)
    expect(compareBytes(utf8('ab'), utf8('abc'))).toBeLessThan(0)
    expect(compareBytes(utf8('abd'), utf8('abc'))).toBeGreaterThan(0)
    expect(compareBytes(new Uint8Array(0), utf8('a'))).toBeLessThan(0)
  })
  it('concatBytes handles no-arg and empty middle', () => {
    expect(concatBytes().length).toBe(0)
    expect(bytesEqual(concatBytes(utf8('a'), new Uint8Array(0), utf8('b')), utf8('ab'))).toBe(true)
  })
})

describe('bytesEqual', () => {
  it('true only for equal length and content', () => {
    expect(bytesEqual(utf8('abc'), utf8('abc'))).toBe(true)
    expect(bytesEqual(utf8('abc'), utf8('abd'))).toBe(false)
    expect(bytesEqual(utf8('abc'), utf8('ab'))).toBe(false)
  })
})
