// Account-key rotation (Sesame, roadmap 7b). A rotation moves a whole
// relationship from one key to another, so every check here is one that stops
// somebody being moved somewhere they did not agree to go: a statement signed by
// the wrong key, one naming a key its author does not hold, one lifted from
// another account, or one whose id and key disagree.

import { describe, expect, it } from 'vitest'
import { CLOCK_SKEW_MS, TAG_ROSTER, TAG_ROTATION } from './constants'
import { accountIdOf } from './identity'
import {
  concatBytes,
  domainSeparate,
  ed25519Public,
  ed25519Sign,
  ed25519Verify,
  u32be,
  u64be,
  utf8,
} from './primitives'
import { RotationError, rotationSigningBytes, signRotation, verifyRotation } from './rotation'

const NOW = 1_700_000_000_000

/** Deterministic keys, so the layout test below pins actual bytes. */
function keyPair(fill: number) {
  const privateKey = new Uint8Array(32).fill(fill)
  return { privateKey, publicKey: ed25519Public(privateKey) }
}

const oldKey = keyPair(1)
const newKey = keyPair(2)
const oldId = accountIdOf(oldKey.publicKey)
const newId = accountIdOf(newKey.publicKey)

describe('rotation signing bytes', () => {
  it('are length-framed field by field, in a pinned order', () => {
    // Built here WITHOUT domainSeparate, so this fails if either the framing or
    // the field order changes. Both are wire-format changes: every statement
    // anyone ever signed stops verifying.
    const frame = (b: Uint8Array) => concatBytes(u32be(b.length), b)
    const expected = concatBytes(
      frame(utf8(TAG_ROTATION)),
      frame(utf8(oldId)),
      frame(utf8(newId)),
      frame(newKey.publicKey),
      frame(u64be(NOW)),
    )
    expect(rotationSigningBytes(oldId, newId, newKey.publicKey, NOW)).toEqual(expected)
  })

  it('cannot be confused with a roster signed by the same key', () => {
    // On a first device one key signs rosters, prekeys, auth challenges and this.
    // The tag is what stops any of those being an oracle for another.
    const asRoster = domainSeparate(TAG_ROSTER, utf8(oldId), utf8(newId), newKey.publicKey, u64be(NOW))
    expect(rotationSigningBytes(oldId, newId, newKey.publicKey, NOW)).not.toEqual(asRoster)
  })
})

describe('signing a rotation', () => {
  it('round-trips under the key the contact already holds', () => {
    const st = signRotation(oldId, oldKey.privateKey, newKey, NOW)
    expect(st.oldAccountId).toBe(oldId)
    expect(st.newAccountId).toBe(newId)
    expect(() => verifyRotation(st, oldKey.publicKey, NOW)).not.toThrow()
  })

  it('refuses to sign with a key that is not the account being rotated', () => {
    // A rotation is irreversible for that key and the Directory records the first
    // valid one, so a mismatch fails here rather than producing a statement that
    // quietly verifies nowhere.
    expect(() => signRotation(oldId, keyPair(9).privateKey, newKey, NOW)).toThrow(RotationError)
  })

  it('refuses to rotate an account to the key it already has', () => {
    expect(() => signRotation(oldId, oldKey.privateKey, oldKey, NOW)).toThrow(RotationError)
  })
})

describe('verifying a rotation', () => {
  const good = signRotation(oldId, oldKey.privateKey, newKey, NOW)

  it('refuses a statement presented under a key that is not the account it names', () => {
    // The caller supplies the key it already holds for that contact. A statement
    // about somebody else is not a statement about them.
    expect(() => verifyRotation(good, keyPair(3).publicKey, NOW)).toThrow(/does not match the account id/)
  })

  it('refuses a statement the old key did not sign', () => {
    const impostor = keyPair(4)
    const bytes = rotationSigningBytes(oldId, newId, newKey.publicKey, NOW)
    const forged = { ...good, oldSig: ed25519Sign(bytes, impostor.privateKey) }
    expect(() => verifyRotation(forged, oldKey.publicKey, NOW)).toThrow(/old account key did not sign/)
  })

  it('refuses a rotation to a key its author does not hold', () => {
    // The attack the counter-signature exists for. Mallory rotates "to" a
    // contact's published account key: her contacts would re-file her
    // conversation under the victim's id and inherit the victim's trust, and her
    // mail would go to the victim's devices. She cannot sign as the victim, so
    // the second signature is the thing that makes this unproducible.
    const mallory = keyPair(5)
    const malloryId = accountIdOf(mallory.publicKey)
    const victim = keyPair(6)
    const bytes = rotationSigningBytes(malloryId, accountIdOf(victim.publicKey), victim.publicKey, NOW)
    const transplant = {
      oldAccountId: malloryId,
      newAccountId: accountIdOf(victim.publicKey),
      newAccountKey: victim.publicKey,
      rotatedAt: NOW,
      oldSig: ed25519Sign(bytes, mallory.privateKey), // genuine: it IS her account
      newSig: ed25519Sign(bytes, mallory.privateKey), // the half she cannot produce
    }
    expect(() => verifyRotation(transplant, mallory.publicKey, NOW)).toThrow(/new account key did not sign/)
  })

  it('refuses a rotation onto a key nobody can hold', () => {
    // A small-order key verifies a signature of all zeros, so the counter-
    // signature below is one ANYBODY could produce. Worse than a weak proof: the
    // successor account would be world-writable, since every roster it ever
    // published would verify under zeros too, letting anyone redirect the
    // contacts that followed the rotation.
    const zeroKey = new Uint8Array(32)
    const zeroSig = new Uint8Array(64)
    const zeroId = accountIdOf(zeroKey)
    const bytes = rotationSigningBytes(oldId, zeroId, zeroKey, NOW)
    const degenerate = {
      oldAccountId: oldId,
      newAccountId: zeroId,
      newAccountKey: zeroKey,
      rotatedAt: NOW,
      oldSig: ed25519Sign(bytes, oldKey.privateKey),
      newSig: zeroSig,
    }
    // The signature really does verify; the key check is the only thing between
    // that and a hijacked account.
    expect(ed25519Verify(zeroSig, bytes, zeroKey)).toBe(true)
    expect(() => verifyRotation(degenerate, oldKey.publicKey, NOW)).toThrow(/not a key anybody can hold/)
  })

  it('refuses a new id that does not match the key given with it', () => {
    const swapped = { ...good, newAccountId: accountIdOf(keyPair(7).publicKey) }
    expect(() => verifyRotation(swapped, oldKey.publicKey, NOW)).toThrow(/does not match the key given/)
  })

  it('refuses a signature made under another tag', () => {
    // Same fields, same key, wrong tag: a roster signature must never be
    // reusable as a rotation.
    const asRoster = domainSeparate(TAG_ROSTER, utf8(oldId), utf8(newId), newKey.publicKey, u64be(NOW))
    const crossed = {
      ...good,
      oldSig: ed25519Sign(asRoster, oldKey.privateKey),
      newSig: ed25519Sign(asRoster, newKey.privateKey),
    }
    expect(() => verifyRotation(crossed, oldKey.publicKey, NOW)).toThrow(RotationError)
  })

  it('refuses a statement whose time was changed after signing', () => {
    expect(() => verifyRotation({ ...good, rotatedAt: NOW - 1 }, oldKey.publicKey, NOW)).toThrow(RotationError)
  })

  it('tolerates clock skew but not a rotation from the future', () => {
    const skewed = signRotation(oldId, oldKey.privateKey, newKey, NOW + CLOCK_SKEW_MS - 1)
    expect(() => verifyRotation(skewed, oldKey.publicKey, NOW)).not.toThrow()
    const ahead = signRotation(oldId, oldKey.privateKey, newKey, NOW + CLOCK_SKEW_MS + 1000)
    expect(() => verifyRotation(ahead, oldKey.publicKey, NOW)).toThrow(/implausible time/)
  })

  it('accepts a statement from long ago', () => {
    // Somebody offline for a year still has to be able to catch up, so age is
    // never a reason to refuse.
    const old = signRotation(oldId, oldKey.privateKey, newKey, NOW - 365 * 24 * 60 * 60 * 1000)
    expect(() => verifyRotation(old, oldKey.publicKey, NOW)).not.toThrow()
  })

  it('refuses wrong-width keys and signatures before looking at them', () => {
    expect(() => verifyRotation({ ...good, newAccountKey: new Uint8Array(31) }, oldKey.publicKey, NOW)).toThrow(
      /not 32 bytes/,
    )
    expect(() => verifyRotation({ ...good, oldSig: new Uint8Array(63) }, oldKey.publicKey, NOW)).toThrow(
      /not 64 bytes/,
    )
    expect(() => verifyRotation({ ...good, newSig: new Uint8Array(0) }, oldKey.publicKey, NOW)).toThrow(
      /not 64 bytes/,
    )
  })

  it('chains: each hop verifies under the key the hop before it introduced', () => {
    // Never under a key that arrived with the statement, which is the whole
    // reason the caller passes the key in.
    const third = keyPair(8)
    const first = signRotation(oldId, oldKey.privateKey, newKey, NOW)
    const second = signRotation(newId, newKey.privateKey, third, NOW + 1000)
    expect(() => verifyRotation(first, oldKey.publicKey, NOW + 2000)).not.toThrow()
    expect(() => verifyRotation(second, newKey.publicKey, NOW + 2000)).not.toThrow()
    // And the second hop is meaningless to somebody still holding the first key.
    expect(() => verifyRotation(second, oldKey.publicKey, NOW + 2000)).toThrow(/does not match the account id/)
  })
})
