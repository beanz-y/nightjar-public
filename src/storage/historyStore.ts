// Message history at-rest sealing (P10c). The WHOLE message record (content id,
// peer, direction, timestamp, and text), not just the body, is encrypted under the
// Local Data Key (LDK, held by the AppLockStore), so a device image without the
// unlock secret reveals NOTHING about who you talked to or when. The storage key
// is an opaque HMAC of (peer, dir, id) under an LDK-derived index key, so even the
// row's existence-pattern leaks no peer/id.
//
// Fail-closed: seal/open derive their keys from the LDK via the AppLockStore,
// which throws AppLockedError while locked. There is NO unwrapped-key path and no
// key generation here (the LDK is born, wrapped, and unwrapped only in
// appLockStore); the P10b plaintext-HMK behaviour is gone. A seal reached while
// locked simply throws, and the caller (inbound) turns that into a retry, not a
// silent plaintext write.
//
// `failed` (an outbound send that permanently failed) is a plain boolean on the
// stored blob, not inside the ciphertext: it is not sensitive (it reveals only
// that some row is a failed send) and keeping it out lets a status update avoid a
// re-seal.

import { bytesToHex } from '@noble/hashes/utils'
import { HISTORY_FORMAT_VERSION, HISTORY_SALT_BYTES, INFO_HISTORY } from '../crypto/constants'
import {
  XCHACHA_KEY_BYTES,
  XCHACHA_NONCE_BYTES,
  aeadOpen,
  aeadSeal,
  domainSeparate,
  hkdfSha256,
  hmacSha256,
  randomBytes,
  utf8,
} from '../crypto/primitives'
import type { AppLockStore } from './appLockStore'
import type { HistoryRecord } from './sessionStore'

const ROW_AAD_TAG = 'Nightjar-histrow-v1'
const KEY_TAG = 'Nightjar-histkey-v1'
const decoder = new TextDecoder()

/** A message as history holds it (all fields are sealed at rest). */
export interface HistoryMessage {
  id: string
  peerId: string
  dir: 'in' | 'out'
  ts: number
  text: string
}

export class HistoryStore {
  constructor(private readonly lock: AppLockStore) {}

  get isUnlocked(): boolean {
    return this.lock.isUnlocked
  }

  /** The opaque IndexedDB key for a message: hex(HMAC(indexKey, peer|dir|id)).
   *  One-way, so the key reveals no peer/dir/id; deterministic, so a redelivery
   *  upserts the same row and a delete/mark can target it. Requires the LDK. */
  storageKey(peerId: string, dir: 'in' | 'out', id: string): string {
    const mac = hmacSha256(this.lock.historyIndexKey(), domainSeparate(KEY_TAG, utf8(peerId), utf8(dir), utf8(id)))
    return bytesToHex(mac)
  }

  private bodyKeyNonce(salt: Uint8Array): { key: Uint8Array; nonce: Uint8Array } {
    const out = hkdfSha256(this.lock.historyBodyKey(), salt, utf8(INFO_HISTORY), XCHACHA_KEY_BYTES + XCHACHA_NONCE_BYTES)
    return { key: out.slice(0, XCHACHA_KEY_BYTES), nonce: out.slice(XCHACHA_KEY_BYTES) }
  }

  // AAD binds the ciphertext to its storage key + format version, so a sealed row
  // cannot be moved to another key slot and still open.
  private aad(storageKey: string): Uint8Array {
    return domainSeparate(ROW_AAD_TAG, utf8(storageKey), Uint8Array.from([HISTORY_FORMAT_VERSION]))
  }

  /** Seal a full message into a storable record. Throws AppLockedError if locked. */
  seal(msg: HistoryMessage, failed?: boolean): HistoryRecord {
    const key = this.storageKey(msg.peerId, msg.dir, msg.id)
    const salt = randomBytes(HISTORY_SALT_BYTES)
    const { key: k, nonce } = this.bodyKeyNonce(salt)
    // Compact JSON: i=id, p=peer, d=dir, t=ts, x=text.
    const plain = utf8(JSON.stringify({ i: msg.id, p: msg.peerId, d: msg.dir, t: msg.ts, x: msg.text }))
    const ct = aeadSeal(k, nonce, plain, this.aad(key))
    return failed ? { key, salt, ct, failed: true } : { key, salt, ct }
  }

  /** Open a stored record. Throws if it does not authenticate (locked, wrong LDK,
   *  corruption, or a relabelled key). */
  open(rec: HistoryRecord): HistoryMessage {
    const { key: k, nonce } = this.bodyKeyNonce(rec.salt)
    const plain = aeadOpen(k, nonce, rec.ct, this.aad(rec.key))
    const o = JSON.parse(decoder.decode(plain)) as { i: string; p: string; d: 'in' | 'out'; t: number; x: string }
    return { id: o.i, peerId: o.p, dir: o.d, ts: o.t, text: o.x }
  }
}
