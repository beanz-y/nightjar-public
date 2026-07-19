// Identity (DESIGN 3): two keypairs generated on-device.
//   IK_sig (Ed25519) is THE identity; the user id and safety number derive from
//   its public key. It signs everything else.
//   IK_dh  (X25519)  is the DH key for X3DH, bound to IK_sig by a signature that
//   MUST be verified before any DH involving IK_dh (DESIGN 4.2).

import { TAG_IDKBIND } from './constants'
import {
  type KeyPair,
  base32lower,
  bytesEqual,
  domainSeparate,
  ed25519Generate,
  ed25519Public,
  ed25519Sign,
  ed25519Verify,
  hash256,
  x25519Generate,
  x25519Public,
} from './primitives'

export interface Identity {
  readonly ikSig: KeyPair // Ed25519, the identity
  readonly ikDh: KeyPair // X25519, DH key
  readonly idkbindSig: Uint8Array // Sig(ikSig, TAG_IDKBIND || ikDh.pub)
  readonly userId: string
}

/** The public half others need to open a session with us (DESIGN 4.1). */
export interface PublicIdentity {
  readonly ikSigPub: Uint8Array
  readonly ikDhPub: Uint8Array
  readonly idkbindSig: Uint8Array
  readonly userId: string
}

/** user id = full-width, untruncated base32(SHA-256(IK_sig_pub)) (DESIGN 3, 14).
 *  Never truncate: a short id is grindable to a routing-hijack collision. */
export function deriveUserId(ikSigPub: Uint8Array): string {
  return base32lower(hash256(ikSigPub))
}

function bindIkDh(ikDhPub: Uint8Array, ikSigPriv: Uint8Array): Uint8Array {
  return ed25519Sign(domainSeparate(TAG_IDKBIND, ikDhPub), ikSigPriv)
}

export function generateIdentity(): Identity {
  const ikSig = ed25519Generate()
  const ikDh = x25519Generate()
  return {
    ikSig,
    ikDh,
    idkbindSig: bindIkDh(ikDh.publicKey, ikSig.privateKey),
    userId: deriveUserId(ikSig.publicKey),
  }
}

/** Verify the IK_sig -> IK_dh binding. Callers MUST run this before using a
 *  fetched IK_dh in any DH (DESIGN 4.2). */
export function verifyIdkbind(
  ikSigPub: Uint8Array,
  ikDhPub: Uint8Array,
  idkbindSig: Uint8Array,
): boolean {
  return ed25519Verify(idkbindSig, domainSeparate(TAG_IDKBIND, ikDhPub), ikSigPub)
}

export function publicIdentity(id: Identity): PublicIdentity {
  return {
    ikSigPub: id.ikSig.publicKey,
    ikDhPub: id.ikDh.publicKey,
    idkbindSig: id.idkbindSig,
    userId: id.userId,
  }
}

// --- durable serialization (fixed 192-byte layout) -----------------------
// ikSigPriv(32) ikSigPub(32) ikDhPriv(32) ikDhPub(32) idkbindSig(64)
// The user id is recomputed from ikSigPub on load, never trusted from storage.

const SER_LEN = 32 + 32 + 32 + 32 + 64

export function serializeIdentity(id: Identity): Uint8Array {
  const out = new Uint8Array(SER_LEN)
  out.set(id.ikSig.privateKey, 0)
  out.set(id.ikSig.publicKey, 32)
  out.set(id.ikDh.privateKey, 64)
  out.set(id.ikDh.publicKey, 96)
  out.set(id.idkbindSig, 128)
  return out
}

export function deserializeIdentity(bytes: Uint8Array): Identity {
  if (bytes.length !== SER_LEN) {
    throw new Error(`identity blob is ${bytes.length} bytes, expected ${SER_LEN}`)
  }
  const ikSig: KeyPair = { privateKey: bytes.slice(0, 32), publicKey: bytes.slice(32, 64) }
  const ikDh: KeyPair = { privateKey: bytes.slice(64, 96), publicKey: bytes.slice(96, 128) }
  const idkbindSig = bytes.slice(128, 192)
  // Fail closed on a corrupted or tampered local blob: the stored public halves
  // must match their private halves, and the idkbind binding must verify. This
  // is self-corruption/DoS defence; remote-key verification still happens at
  // X3DH (DESIGN 4.2).
  if (!bytesEqual(ed25519Public(ikSig.privateKey), ikSig.publicKey)) {
    throw new Error('identity blob: IK_sig public/private mismatch')
  }
  if (!bytesEqual(x25519Public(ikDh.privateKey), ikDh.publicKey)) {
    throw new Error('identity blob: IK_dh public/private mismatch')
  }
  if (!verifyIdkbind(ikSig.publicKey, ikDh.publicKey, idkbindSig)) {
    throw new Error('identity blob: idkbind signature invalid')
  }
  return { ikSig, ikDh, idkbindSig, userId: deriveUserId(ikSig.publicKey) }
}
