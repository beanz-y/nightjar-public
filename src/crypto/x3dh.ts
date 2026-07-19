// X3DH key agreement (DESIGN 4.2). Produces a shared secret SK and associated
// data AD that the Double Ratchet (P2) will seed from. Both parties must derive
// byte-identical SK and AD; the tests assert exactly that.
//
// This module is transport-agnostic: the initiator produces an InitialHeader,
// the responder consumes one. Moving them over the wire is P4.

import { bytesToHex } from '@noble/hashes/utils'
import { INFO_X3DH, VERSION_FLOOR } from './constants'
import { type Identity, verifyIdkbind } from './identity'
import {
  type KeyPair,
  bytesEqual,
  concatBytes,
  hash256,
  hkdfSha256,
  u32be,
  utf8,
  x25519Dh,
  x25519Generate,
} from './primitives'
import { type FetchedBundle, verifyFetchedBundle } from './prekeys'

/** The first message's header, carrying everything the responder needs to run
 *  the matching X3DH (DESIGN 4.2 step 6). */
export interface InitialHeader {
  readonly version: number
  readonly ikSigPub: Uint8Array // initiator IK_sig
  readonly ikDhPub: Uint8Array // initiator IK_dh
  readonly idkbindSig: Uint8Array // Sig(IK_sig_a, TAG_IDKBIND || IK_dh_a)
  readonly ekPub: Uint8Array // initiator ephemeral
  readonly spkId: number // which of the responder's signed prekeys was used
  readonly opkId: number | null // which one-time prekey was consumed, or none
}

/** The responder's private material, looked up by id (DESIGN 4.2). */
export interface ResponderKeys {
  readonly spkPrivById: ReadonlyMap<number, Uint8Array>
  readonly opkPrivById: ReadonlyMap<number, Uint8Array>
}

export interface InitiateResult {
  readonly sk: Uint8Array
  readonly ad: Uint8Array
  readonly header: InitialHeader
}

// 32 0xFF bytes prefixed to the DH concatenation (DESIGN 4.2 step 4): domain
// separates the KDF input from a raw curve encoding.
const X3DH_F = new Uint8Array(32).fill(0xff)

function deriveSK(dhs: readonly Uint8Array[], version: number): Uint8Array {
  const ikm = concatBytes(X3DH_F, ...dhs)
  const info = concatBytes(utf8(INFO_X3DH), Uint8Array.from([version]))
  return hkdfSha256(ikm, new Uint8Array(32), info, 32)
}

// AD = version || IK_sig_a || IK_dh_a || IK_sig_b || IK_dh_b, initiator first,
// all fixed-length so the concatenation is unambiguous (DESIGN 4.2 step 5).
function buildAD(
  version: number,
  ikSigA: Uint8Array,
  ikDhA: Uint8Array,
  ikSigB: Uint8Array,
  ikDhB: Uint8Array,
): Uint8Array {
  return concatBytes(Uint8Array.from([version]), ikSigA, ikDhA, ikSigB, ikDhB)
}

/**
 * Initiator side. Verifies the fetched bundle, runs the four (or three) DHs,
 * derives SK and AD, and returns the InitialHeader to send.
 *
 * PRECONDITION (key<->userId binding, DESIGN 3/6.1): this function trusts the
 * presented `bundle.ikSigPub`. The caller MUST have already checked that
 * deriveUserId(bundle.ikSigPub) equals the userId it intends to talk to (the
 * client send path does this), or pass that key as `knownPeerIkSig`. Without it,
 * a directory that served a substituted key would not be caught here.
 */
export function x3dhInitiate(
  me: Identity,
  bundle: FetchedBundle,
  now: number,
  knownPeerIkSig?: Uint8Array,
  ephemeral?: KeyPair,
): InitiateResult {
  verifyFetchedBundle(bundle, now, knownPeerIkSig)

  // `ephemeral` is a test-only seam for deterministic known-answer vectors;
  // production omits it and a fresh ephemeral key is generated per session.
  const ek = ephemeral ?? x25519Generate()
  const dhs: Uint8Array[] = [
    x25519Dh(me.ikDh.privateKey, bundle.spk.pub), // DH1
    x25519Dh(ek.privateKey, bundle.ikDhPub), // DH2
    x25519Dh(ek.privateKey, bundle.spk.pub), // DH3
  ]
  let opkId: number | null = null
  if (bundle.opk) {
    dhs.push(x25519Dh(ek.privateKey, bundle.opk.pub)) // DH4
    opkId = bundle.opk.id
  }

  const sk = deriveSK(dhs, bundle.version)
  const ad = buildAD(bundle.version, me.ikSig.publicKey, me.ikDh.publicKey, bundle.ikSigPub, bundle.ikDhPub)
  const header: InitialHeader = {
    version: bundle.version,
    ikSigPub: me.ikSig.publicKey,
    ikDhPub: me.ikDh.publicKey,
    idkbindSig: me.idkbindSig,
    ekPub: ek.publicKey,
    spkId: bundle.spk.id,
    opkId,
  }
  return { sk, ad, header }
}

/**
 * Responder side. Verifies the initiator's identity binding BEFORE any DH that
 * uses their IK_dh (DESIGN 4.2 step 6), looks up the referenced private prekeys,
 * runs the matching DHs, and derives the same SK and AD.
 *
 * PRECONDITION (key<->userId binding, DESIGN 3/6.1): the caller MUST have checked
 * deriveUserId(header.ikSigPub) equals the sender's routing userId (the inbound
 * path does this) before trusting the session; this function does not.
 */
export function x3dhRespond(
  me: Identity,
  header: InitialHeader,
  keys: ResponderKeys,
  now: number,
  knownPeerIkSig?: Uint8Array,
): { sk: Uint8Array; ad: Uint8Array } {
  // `now` is accepted for symmetry and future initial-message freshness checks;
  // the responder trusts its own prekey lifetimes.
  void now
  if (header.version < VERSION_FLOOR) {
    throw new Error('x3dh: initiator version below floor (possible downgrade)')
  }
  if (knownPeerIkSig && !bytesEqual(knownPeerIkSig, header.ikSigPub)) {
    throw new Error('x3dh: peer identity key changed; verify the safety number')
  }
  if (!verifyIdkbind(header.ikSigPub, header.ikDhPub, header.idkbindSig)) {
    throw new Error('x3dh: initiator IK_dh binding invalid')
  }

  const spkPriv = keys.spkPrivById.get(header.spkId)
  if (!spkPriv) throw new Error('x3dh: unknown signed-prekey id (rotated out?)')

  const dhs: Uint8Array[] = [
    x25519Dh(spkPriv, header.ikDhPub), // DH1
    x25519Dh(me.ikDh.privateKey, header.ekPub), // DH2
    x25519Dh(spkPriv, header.ekPub), // DH3
  ]
  if (header.opkId !== null) {
    const opkPriv = keys.opkPrivById.get(header.opkId)
    if (!opkPriv) throw new Error('x3dh: unknown one-time-prekey id')
    dhs.push(x25519Dh(opkPriv, header.ekPub)) // DH4
  }

  const sk = deriveSK(dhs, header.version)
  const ad = buildAD(header.version, header.ikSigPub, header.ikDhPub, me.ikSig.publicKey, me.ikDh.publicKey)
  return { sk, ad }
}

// --- initial-message replay protection (DESIGN 4.3) ----------------------
// Without an OPK, SK is deterministic from long/medium-term keys plus EK, so a
// captured initial message would re-derive the same SK forever. This id lets a
// responder reject a replayed initial message. Full integration (write only on
// AEAD success; commit no durable ratchet state until the first genuine ratchet
// response) lands with the ratchet in P2; the persisted, bounded cache is P4.

export function initialMessageId(header: InitialHeader): Uint8Array {
  return hash256(
    concatBytes(
      Uint8Array.from([header.version]),
      header.ikSigPub,
      header.ikDhPub,
      header.ekPub,
      u32be(header.spkId),
      // A 1-byte has-OPK flag then the id, so a null OPK cannot alias a real id.
      Uint8Array.from([header.opkId === null ? 0 : 1]),
      u32be(header.opkId ?? 0),
    ),
  )
}

/** In-memory replay guard. Returns true if the id is fresh (and records it),
 *  false if it has been seen. P4 replaces the Set with a bounded, persisted,
 *  never-time-evicting store (DESIGN 4.3). */
export class InitialMessageReplayGuard {
  private readonly seen = new Set<string>()

  check(id: Uint8Array): boolean {
    const key = bytesToHex(id)
    if (this.seen.has(key)) return false
    this.seen.add(key)
    return true
  }
}
