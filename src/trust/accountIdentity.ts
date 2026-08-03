// Account identity (Sesame, multi-device).
//
// Nightjar has always had exactly one kind of identity. Multi-device splits it in
// two, and being precise about which is which is the whole of this module:
//
//   An ACCOUNT is a person. Its key signs the device roster, its id is what a
//   conversation is filed under, and it is the key a safety number covers. This
//   is what a contact verifies out of band, and it does not change when devices
//   come and go.
//
//   A DEVICE is one of the things that person reads Nightjar on. Its key is the
//   credential the relay authenticates, its id addresses an inbox, and it is the
//   key a ratchet session actually runs between.
//
// On an account's FIRST device these are the same key, and that is a deliberate
// choice rather than a simplification to be cleaned up later. It is what lets
// every existing single-device user become a one-device account with nothing
// moving at all: same id, same inbox, same published prekeys, same sessions, and
// above all the same safety numbers, so nobody has to verify anybody again.
//
// The honest cost of that choice, recorded here because this is where somebody
// will come looking: the first device cannot be removed from its own account,
// because its device key IS the account key. Retiring it means moving to a new
// device (DESIGN 8.3) or rotating the account key, which is a re-verify event for
// every contact.

import type { KeyPair } from '../crypto/primitives'
import { type Identity, accountIdOf } from '../crypto/identity'

export interface AccountIdentity {
  /** base32(SHA-256(account key)). Equal to the user id every build has used. */
  readonly accountId: string
  /** Ed25519. Signs device rosters, and nothing else signs those. */
  readonly accountKey: KeyPair
}

/**
 * This device's account identity.
 *
 * Today it is derived from the device identity, because a first device's account
 * key is its own signing key. A LINKED device will hold an account key it was
 * given during linking, alongside a device key that is entirely its own, and will
 * load it rather than derive it. That is the one seam this function exists to
 * mark: callers ask for the account identity instead of reaching for
 * `identity.ikSig`, so the day a linked device exists, only this changes.
 */
export function accountIdentityOf(device: Identity): AccountIdentity {
  return { accountId: accountIdOf(device.ikSig.publicKey), accountKey: device.ikSig }
}
