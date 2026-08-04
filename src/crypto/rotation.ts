// Account-key rotation (Sesame, roadmap 7b).
//
// An account id IS base32(SHA-256(account key)) (DESIGN 3), so a new key is a new
// id, and a new id is a stranger to everybody. Rotation is the one statement that
// carries a relationship across that gap: the OLD account key says "the account
// you know as X is now Y", and the NEW key signs the same words back.
//
// What it is honestly for, and what it is not:
//
//   It helps when the old key is GONE but not in use: a phone that was lost or
//   handed on, a key whose storage you no longer trust. Contacts keep the
//   conversation, the history and the name they gave you instead of starting
//   again with somebody they have never met.
//
//   It does NOT beat an attacker who is actively USING the stolen key. They hold
//   the same key, so they can sign a competing rotation that is exactly as valid
//   as yours, and nothing in these bytes tells the two apart. Rotation preserves
//   the RELATIONSHIP; it never preserves the TRUST. Every contact lands on the new
//   key as unverified and re-does the safety-number comparison, and the screens
//   that present this have to say so rather than reading as "revoke a stolen
//   device", which is not what it is.
//
// TWO signatures, and the second is load-bearing rather than ceremony:
//
//   The OLD key attests the new one. That is the continuity, and only the account
//   being rotated can produce it.
//
//   The NEW key signs the same bytes to prove somebody holds its private half.
//   Without that, a statement could name a key its author does not own: Mallory
//   rotates "to" a contact's published account key, and every one of Mallory's
//   contacts re-files that conversation under the victim's account id, inheriting
//   whatever trust and whatever safety number the victim had earned, and sending
//   Mallory's mail to the victim's devices. The counter-signature is what makes
//   that unproducible rather than merely unlikely.
//
// Replay is a no-op by construction rather than by a counter. A statement names
// the account it starts FROM, and a client applies one only when that is the
// account it currently holds for that contact, so re-presenting an old statement
// to somebody who has already moved past it changes nothing. A chain (X -> Y -> Z)
// is a chain of statements, each verified under the key the previous one
// introduced, never under a key that came with it.
//
// Rollback is not solved here, for the same reason it is not solved in roster.ts:
// a valid signature over stale facts is still a valid signature. The defence is
// the caller's memory of which account it currently holds for a contact, plus the
// re-verification the new binding demands anyway.

import { CLOCK_SKEW_MS, TAG_ROTATION } from './constants'
import { accountIdOf } from './identity'
import {
  type KeyPair,
  domainSeparate,
  ed25519KeyUsable,
  ed25519Public,
  ed25519Sign,
  ed25519Verify,
  u64be,
  utf8,
} from './primitives'

/** One account saying which key replaces it. */
export interface RotationStatement {
  /** The account this rotates away from. */
  readonly oldAccountId: string
  /** base32(SHA-256(newAccountKey)); recomputed on verify, never trusted as given. */
  readonly newAccountId: string
  /** The Ed25519 account key taking over (32 bytes). */
  readonly newAccountKey: Uint8Array
  /** When it was signed, in ms. Shown to the user; never a security input. */
  readonly rotatedAt: number
  /** Signature by the OLD account key over `rotationSigningBytes`. The continuity. */
  readonly oldSig: Uint8Array
  /** Signature by the NEW account key over the SAME bytes. The proof of possession. */
  readonly newSig: Uint8Array
}

/** Thrown by `verifyRotation`. Distinct so a caller can tell a bad statement from
 *  a network or storage failure and surface it as the security event it is. */
export class RotationError extends Error {
  constructor(message: string) {
    super(`rotation: ${message}`)
    this.name = 'RotationError'
  }
}

/**
 * The exact bytes both keys sign. Canonical and injective by construction:
 * `domainSeparate` length-frames the tag and every field, so no field can absorb
 * its neighbour and a statement cannot be reinterpreted under another tag.
 *
 * Field order is pinned by a known-answer test. Changing anything here changes
 * every signature, so it is a wire-format change.
 */
export function rotationSigningBytes(
  oldAccountId: string,
  newAccountId: string,
  newAccountKey: Uint8Array,
  rotatedAt: number,
): Uint8Array {
  return domainSeparate(TAG_ROTATION, utf8(oldAccountId), utf8(newAccountId), newAccountKey, u64be(rotatedAt))
}

/**
 * Sign a rotation. Needs BOTH private halves, which is the point: it is a
 * statement two keys make together.
 *
 * The old private half is checked against the account id it claims before
 * anything is signed. A rotation is rare, irreversible for that key, and the
 * Directory records the first valid one, so a mismatch here has to fail loudly
 * now rather than produce a statement that quietly verifies nowhere.
 */
export function signRotation(
  oldAccountId: string,
  oldAccountPriv: Uint8Array,
  newAccountKey: KeyPair,
  rotatedAt: number,
): RotationStatement {
  if (accountIdOf(ed25519Public(oldAccountPriv)) !== oldAccountId) {
    throw new RotationError('the signing key is not the account being rotated')
  }
  const newAccountId = accountIdOf(newAccountKey.publicKey)
  if (newAccountId === oldAccountId) {
    throw new RotationError('an account cannot rotate to the key it already has')
  }
  const bytes = rotationSigningBytes(oldAccountId, newAccountId, newAccountKey.publicKey, rotatedAt)
  return {
    oldAccountId,
    newAccountId,
    newAccountKey: newAccountKey.publicKey,
    rotatedAt,
    oldSig: ed25519Sign(bytes, oldAccountPriv),
    newSig: ed25519Sign(bytes, newAccountKey.privateKey),
  }
}

/**
 * Check a rotation, fail-closed. Throws `RotationError` on anything wrong and
 * returns nothing on success, so there is no truthy value to misuse.
 *
 * `oldAccountKeyPub` is the key the caller ALREADY holds for the account being
 * rotated: a contact record, this device's own account key, or the key a previous
 * statement in the chain introduced. It is never taken from the statement, which
 * would only prove the statement was signed by whoever wrote it.
 *
 * The `now` bound on `rotatedAt` is presentation integrity, not a security
 * control, which is why skew is tolerated and old statements are fine: somebody
 * who has been offline for a year still has to be able to catch up.
 */
export function verifyRotation(st: RotationStatement, oldAccountKeyPub: Uint8Array, now: number): void {
  if (accountIdOf(oldAccountKeyPub) !== st.oldAccountId) {
    throw new RotationError('the account key does not match the account id it claims to rotate')
  }
  if (st.newAccountKey.length !== 32) throw new RotationError('the new account key is not 32 bytes')
  // Both keys have to be able to MEAN a signature. A small-order key verifies an
  // all-zero signature, so a rotation onto one would be a statement anybody could
  // have made, and worse, it would hand the successor account to everybody at
  // once: every future roster for it would verify under a signature of zeros.
  // The new key is chosen by whoever wrote the statement, so this is exactly the
  // place that check has to happen.
  if (!ed25519KeyUsable(st.newAccountKey)) {
    throw new RotationError('the new account key is not a key anybody can hold')
  }
  if (!ed25519KeyUsable(oldAccountKeyPub)) {
    throw new RotationError('the old account key is not a key anybody can hold')
  }
  // The binding that makes the new id mean anything: an account id IS the hash of
  // its key, so it is recomputed rather than believed.
  if (accountIdOf(st.newAccountKey) !== st.newAccountId) {
    throw new RotationError('the new account id does not match the key given with it')
  }
  if (st.newAccountId === st.oldAccountId) {
    throw new RotationError('an account cannot rotate to the key it already has')
  }
  if (!Number.isSafeInteger(st.rotatedAt) || st.rotatedAt < 0 || st.rotatedAt > now + CLOCK_SKEW_MS) {
    throw new RotationError('the rotation has an implausible time')
  }
  if (st.oldSig.length !== 64 || st.newSig.length !== 64) throw new RotationError('a signature is not 64 bytes')
  const bytes = rotationSigningBytes(st.oldAccountId, st.newAccountId, st.newAccountKey, st.rotatedAt)
  if (!ed25519Verify(st.oldSig, bytes, oldAccountKeyPub)) {
    throw new RotationError('the old account key did not sign this')
  }
  // Proof of possession. See the module header: this is what stops a rotation
  // naming somebody else's key.
  if (!ed25519Verify(st.newSig, bytes, st.newAccountKey)) {
    throw new RotationError('the new account key did not sign this')
  }
}
