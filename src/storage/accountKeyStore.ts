// Where a LINKED device keeps its account key (Sesame).
//
// A first device has no use for this: its account key IS its device identity, so
// `accountIdentityOf` derives it and nothing is stored. A device that was linked
// into an existing account holds two keys, its own and the account's, and this is
// where the second one lives.
//
// It is sealed under its own app-lock sub-key. That is deliberate rather than
// tidy: this key signs device rosters, so whoever holds it can add a device to
// the account, which is the one thing an operator cannot do. It is the most
// consequential secret on the device after the device identity itself, and unlike
// the device identity it does NOT have to be readable before unlock (nothing at
// start-up needs it), so there is no reason to leave it in the clear.

import { openBlob, sealBlob } from '../crypto/appLock'
import { ed25519Public } from '../crypto/primitives'
import type { KeyPair } from '../crypto/primitives'
import type { AppLockStore } from './appLockStore'
import type { KeyStore } from './keystore'

const ACCOUNT_KEY = 'account.key.v1'

/** Store the account key's private half. The public half is derived on read, so
 *  the two can never disagree on disk. Requires an unlocked app-lock. */
export async function saveAccountKey(keys: KeyStore, lock: AppLockStore, privateKey: Uint8Array): Promise<void> {
  if (privateKey.length !== 32) throw new Error('account key: private half must be 32 bytes')
  await keys.put(ACCOUNT_KEY, sealBlob(lock.accountKey(), ACCOUNT_KEY, privateKey))
}

/**
 * This device's stored account key, or null if it has none (which is every device
 * that was not linked into an existing account).
 *
 * Fails CLOSED: a blob that will not open is an error rather than a null, because
 * "no account key" and "an account key this device cannot read" mean opposite
 * things. The first says derive it from the device identity; the second would
 * silently make a linked device start signing rosters as an account of one.
 */
export async function loadAccountKey(keys: KeyStore, lock: AppLockStore): Promise<KeyPair | null> {
  const raw = await keys.get(ACCOUNT_KEY)
  if (raw == null) return null
  const privateKey = openBlob(lock.accountKey(), ACCOUNT_KEY, raw)
  if (privateKey.length !== 32) throw new Error('account key: stored blob is the wrong size')
  return { privateKey, publicKey: ed25519Public(privateKey) }
}

/** Forget the account key. Used by the reset paths, which discard the key that
 *  seals it and so must clear what it sealed. */
export async function clearAccountKey(keys: KeyStore): Promise<void> {
  await keys.delete(ACCOUNT_KEY)
}
