// Prekeys and prekey-bundle verification (DESIGN 4.1, 4.2). A bundle is the
// public material a responder publishes so an initiator can start a session
// while the responder is offline. Generation is here; the server-side directory
// that stores bundles and vends one-time prekeys is P4.

import {
  CLOCK_SKEW_MS,
  SPK_MAX_AGE_MS,
  TAG_SPK,
  VERSION,
  VERSION_FLOOR,
} from './constants'
import { type Identity, verifyIdkbind } from './identity'
import {
  bytesEqual,
  domainSeparate,
  ed25519Sign,
  ed25519Verify,
  u32be,
  u64be,
  x25519Generate,
} from './primitives'

/** A signed prekey: medium-term, rotated ~weekly, signed by IK_sig. The signed
 *  blob binds the id and timestamps so a stale or swapped SPK is detectable. */
export interface SignedPrekey {
  readonly id: number
  readonly createdAt: number // ms
  readonly expiry: number // ms, = createdAt + SPK_MAX_AGE_MS (acceptance window)
  readonly pub: Uint8Array
  readonly sig: Uint8Array // Sig(IK_sig, TAG_SPK || id || createdAt || expiry || pub)
}

/** A one-time prekey: single-use, unsigned (DESIGN 4.1). Substitution degrades
 *  only to a session-setup DoS, which the responder fails closed on. */
export interface OneTimePrekey {
  readonly id: number
  readonly pub: Uint8Array
}

/** What an initiator fetches: the identity, one signed prekey, and at most one
 *  one-time prekey (the server hands out a single OPK and deletes it). */
export interface FetchedBundle {
  readonly version: number
  readonly ikSigPub: Uint8Array
  readonly ikDhPub: Uint8Array
  readonly idkbindSig: Uint8Array
  readonly spk: SignedPrekey
  readonly opk: OneTimePrekey | null
}

function spkSigningInput(id: number, createdAt: number, expiry: number, pub: Uint8Array): Uint8Array {
  return domainSeparate(TAG_SPK, u32be(id), u64be(createdAt), u64be(expiry), pub)
}

/** Generate and sign a fresh signed prekey. Returns the public SignedPrekey and
 *  its private key (kept by the owner, looked up by id when responding). */
export function generateSignedPrekey(
  identity: Identity,
  id: number,
  now: number,
): { spk: SignedPrekey; priv: Uint8Array } {
  const kp = x25519Generate()
  const createdAt = now
  // The acceptance window is the 14-day max age, not the ~7-day rotation cadence,
  // so a key stays usable while the owner is briefly offline (DESIGN 4.2, 14).
  // The client rotates on connect once the current SPK passes SPK_ROTATION_MS
  // (client.ts maybeRotateSpk), producing overlapping valid prekeys.
  const expiry = now + SPK_MAX_AGE_MS
  const sig = ed25519Sign(spkSigningInput(id, createdAt, expiry, kp.publicKey), identity.ikSig.privateKey)
  return { spk: { id, createdAt, expiry, pub: kp.publicKey, sig }, priv: kp.privateKey }
}

/** Generate a batch of one-time prekeys with sequential ids from startId. */
export function generateOneTimePrekeys(
  startId: number,
  count: number,
): Array<{ opk: OneTimePrekey; priv: Uint8Array }> {
  return Array.from({ length: count }, (_, i) => {
    const kp = x25519Generate()
    return { opk: { id: startId + i, pub: kp.publicKey }, priv: kp.privateKey }
  })
}

/**
 * Verify a fetched bundle BEFORE any key in it is used (DESIGN 4.2 step 1).
 * Throws on any failure. `knownPeerIkSig`, if supplied, is the pinned identity
 * key for a previously-verified contact: a mismatch is a loud key-change error,
 * not a silent accept (DESIGN 6.4).
 */
export function verifyFetchedBundle(
  bundle: FetchedBundle,
  now: number,
  knownPeerIkSig?: Uint8Array,
): void {
  if (bundle.version < VERSION_FLOOR) {
    throw new Error('x3dh: peer version below floor (possible downgrade)')
  }
  // Ceiling as well as floor: a version we do not speak has semantics we cannot
  // assume, so it is rejected rather than processed with v1 rules.
  if (bundle.version > VERSION) {
    throw new Error('x3dh: peer version newer than this client speaks')
  }
  if (knownPeerIkSig && !bytesEqual(knownPeerIkSig, bundle.ikSigPub)) {
    throw new Error('x3dh: peer identity key changed; verify the safety number')
  }
  // IK_dh authenticity rests entirely on this binding (DESIGN 3, 4.2): check it
  // before the DH that uses IK_dh.
  if (!verifyIdkbind(bundle.ikSigPub, bundle.ikDhPub, bundle.idkbindSig)) {
    throw new Error('x3dh: IK_dh binding signature invalid')
  }
  const { spk } = bundle
  // Fail closed on non-finite timestamps BEFORE the comparisons below: every
  // one of them is false for NaN, so without this a NaN-stamped SPK would pass
  // all three freshness checks.
  if (!Number.isFinite(spk.createdAt) || !Number.isFinite(spk.expiry) || !Number.isInteger(spk.id)) {
    throw new Error('x3dh: signed prekey has malformed id or timestamps')
  }
  if (!ed25519Verify(spk.sig, spkSigningInput(spk.id, spk.createdAt, spk.expiry, spk.pub), bundle.ikSigPub)) {
    throw new Error('x3dh: signed-prekey signature invalid')
  }
  if (now >= spk.expiry) throw new Error('x3dh: signed prekey has expired')
  if (spk.createdAt > now + CLOCK_SKEW_MS) throw new Error('x3dh: signed prekey created in the future')
  if (now - spk.createdAt > SPK_MAX_AGE_MS) throw new Error('x3dh: signed prekey too old')
}

/** Convenience for tests/callers: assemble a full published bundle plus the
 *  private material needed to respond, from an identity. */
export function buildOwnBundle(
  identity: Identity,
  now: number,
  opts: { spkId?: number; opkStartId?: number; opkCount?: number } = {},
): {
  ikSigPub: Uint8Array
  ikDhPub: Uint8Array
  idkbindSig: Uint8Array
  spk: SignedPrekey
  opks: OneTimePrekey[]
  spkPrivById: Map<number, Uint8Array>
  opkPrivById: Map<number, Uint8Array>
} {
  const spkId = opts.spkId ?? 1
  const { spk, priv: spkPriv } = generateSignedPrekey(identity, spkId, now)
  const opkPairs = generateOneTimePrekeys(opts.opkStartId ?? 1, opts.opkCount ?? 0)
  return {
    ikSigPub: identity.ikSig.publicKey,
    ikDhPub: identity.ikDh.publicKey,
    idkbindSig: identity.idkbindSig,
    spk,
    opks: opkPairs.map((p) => p.opk),
    spkPrivById: new Map([[spkId, spkPriv]]),
    opkPrivById: new Map(opkPairs.map((p) => [p.opk.id, p.priv])),
  }
}

/** The version an owner stamps into its own published bundle. */
export const OWN_BUNDLE_VERSION = VERSION
