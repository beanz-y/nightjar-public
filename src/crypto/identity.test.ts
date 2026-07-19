import { describe, it, expect } from 'vitest'
import {
  deriveUserId,
  deserializeIdentity,
  generateIdentity,
  serializeIdentity,
  verifyIdkbind,
} from './identity'
import { bytesEqual } from './primitives'

describe('identity', () => {
  it('generates a valid IK_sig -> IK_dh binding', () => {
    const id = generateIdentity()
    expect(verifyIdkbind(id.ikSig.publicKey, id.ikDh.publicKey, id.idkbindSig)).toBe(true)
  })

  it('rejects a substituted IK_dh (unknown-key-share guard)', () => {
    const id = generateIdentity()
    const other = generateIdentity()
    expect(verifyIdkbind(id.ikSig.publicKey, other.ikDh.publicKey, id.idkbindSig)).toBe(false)
  })

  it('rejects a wrong IK_sig', () => {
    const id = generateIdentity()
    const other = generateIdentity()
    expect(verifyIdkbind(other.ikSig.publicKey, id.ikDh.publicKey, id.idkbindSig)).toBe(false)
  })

  it('derives a deterministic, full-width user id', () => {
    const id = generateIdentity()
    expect(id.userId).toBe(deriveUserId(id.ikSig.publicKey))
    // base32 of a 32-byte hash, unpadded lowercase, is 52 chars
    expect(id.userId).toMatch(/^[a-z2-7]{52}$/)
  })

  it('gives distinct identities distinct ids', () => {
    expect(generateIdentity().userId).not.toBe(generateIdentity().userId)
  })

  it('serializes and deserializes losslessly, binding still valid', () => {
    const id = generateIdentity()
    const round = deserializeIdentity(serializeIdentity(id))
    expect(bytesEqual(round.ikSig.privateKey, id.ikSig.privateKey)).toBe(true)
    expect(bytesEqual(round.ikSig.publicKey, id.ikSig.publicKey)).toBe(true)
    expect(bytesEqual(round.ikDh.privateKey, id.ikDh.privateKey)).toBe(true)
    expect(bytesEqual(round.ikDh.publicKey, id.ikDh.publicKey)).toBe(true)
    expect(bytesEqual(round.idkbindSig, id.idkbindSig)).toBe(true)
    expect(round.userId).toBe(id.userId)
    expect(verifyIdkbind(round.ikSig.publicKey, round.ikDh.publicKey, round.idkbindSig)).toBe(true)
  })

  it('rejects a wrong-length blob', () => {
    expect(() => deserializeIdentity(new Uint8Array(10))).toThrow()
  })

  it('user id matches a pinned known-answer vector', () => {
    // Locks the base32(SHA-256(pub)) construction against silent change.
    const pub = Uint8Array.from({ length: 32 }, (_, i) => i)
    expect(deriveUserId(pub)).toBe('mmg42klgyqzwneiskrelxms3j72bfje4omw3fsflyg4fqg6xcdoq')
  })

  it('rejects a right-length but tampered blob (fails closed)', () => {
    // Flip a byte inside the idkbind signature: length is still 192, but the
    // binding no longer verifies.
    const sigTampered = serializeIdentity(generateIdentity())
    sigTampered[130] ^= 1
    expect(() => deserializeIdentity(sigTampered)).toThrow()

    // Flip a byte of the stored IK_sig public half: it no longer matches its
    // private half.
    const pubTampered = serializeIdentity(generateIdentity())
    pubTampered[32] ^= 1
    expect(() => deserializeIdentity(pubTampered)).toThrow()
  })
})
