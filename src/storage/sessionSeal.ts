// Ratchet sessions and the send queue, sealed at rest (P11).
//
// Until this, the `sessions` store was keyed by the peer's userId in CLEARTEXT with
// the serialized ratchet state beside it. A forensic image of a LOCKED device
// therefore listed everyone the user talks to, when each was last used, and held
// the root and chain keys needed to decrypt everything those conversations went on
// to say. Sealing closes both, and it is possible only because the client is never
// constructed while locked (useNightjar.activate), so nothing needs to read a
// session without the Local Data Key.
//
// Shape follows historyStore.ts (8.5): opaque HMAC storage key, fresh per-record
// salt, AEAD with the AAD binding the row to its slot and a dedicated format
// version. ONE deliberate divergence, and it matters:
//
//   HistoryStore.open rebuilds its AAD from `rec.key`, a field carried inside the
//   VALUE, because history is enumerated by a keyless full scan and the opener has
//   no key in hand. Sessions are not like that: every read has the peerId. So the
//   sealed record here carries NO key field, and open() recomputes the key from the
//   peerId the CALLER asked for. A row copied into another peer's slot then fails
//   to authenticate, instead of opening cleanly and handing one peer's ratchet to
//   another conversation, which would encrypt two peers from one chain key.
//
// Outbox rows keep `id` and `createdAt` in cleartext: the id is a random transport
// id that names nobody and removeOutbox() addresses rows by it, and createdAt dates
// a queued send without naming anyone, so the retry horizon and the oldest-first
// ordering keep working on a row that will not open. Only {to, env, silent} is
// sealed, which is the part that identifies a peer.

import { bytesToHex } from '@noble/hashes/utils.js'
import { INFO_SESSION, SESSION_FORMAT_VERSION, SESSION_SALT_BYTES } from '../crypto/constants'
import {
  XCHACHA_KEY_BYTES,
  XCHACHA_NONCE_BYTES,
  aeadOpen,
  aeadSeal,
  domainSeparate,
  hkdfSha256,
  hmacSha256,
  randomBytes,
  u32be,
  utf8,
} from '../crypto/primitives'
import type { AppLockStore } from './appLockStore'
import type { OutboxEntry, SealedOutboxRecord, SealedSessionRecord, SessionBook } from './sessionStore'

const SESSION_KEY_TAG = 'Nightjar-sesskey-v1'
const SESSION_ROW_AAD_TAG = 'Nightjar-sessrow-v1'
const OUTBOX_ROW_AAD_TAG = 'Nightjar-obxrow-v1'
const decoder = new TextDecoder()

/** A stored row exists but will not open. Distinct from "no row", and routed AWAY
 *  from the inbound poison counter: an idle-lock landing mid-receive must not burn
 *  drop attempts against a perfectly healthy conversation. */
export class SessionSealError extends Error {
  constructor(what: string) {
    super(`the stored keys for ${what} could not be read on this device`)
    this.name = 'SessionSealError'
  }
}

export class SessionSealer {
  constructor(private readonly lock: AppLockStore) {}

  get isUnlocked(): boolean {
    return this.lock.isUnlocked
  }

  /** The opaque IndexedDB key for a peer's session book: one-way, so the key names
   *  nobody, and deterministic, so every read and write addresses the same row.
   *  Computing it needs the LDK, so a guessed userId cannot be confirmed against
   *  the database without the unlock secret. */
  sessionKey(peerId: string): string {
    return bytesToHex(hmacSha256(this.lock.sessionIndexKey(), domainSeparate(SESSION_KEY_TAG, utf8(peerId))))
  }

  private keyNonce(salt: Uint8Array): { key: Uint8Array; nonce: Uint8Array } {
    const out = hkdfSha256(this.lock.sessionBodyKey(), salt, utf8(INFO_SESSION), XCHACHA_KEY_BYTES + XCHACHA_NONCE_BYTES)
    return { key: out.slice(0, XCHACHA_KEY_BYTES), nonce: out.slice(XCHACHA_KEY_BYTES) }
  }

  private sessionAad(storageKey: string): Uint8Array {
    return domainSeparate(SESSION_ROW_AAD_TAG, utf8(storageKey), Uint8Array.from([SESSION_FORMAT_VERSION]))
  }

  // The outbox AAD binds the plaintext fields that stay outside the ciphertext, so
  // neither the row's identity nor its age can be edited without breaking the seal.
  private outboxAad(id: string, createdAt: number): Uint8Array {
    return domainSeparate(
      OUTBOX_ROW_AAD_TAG,
      utf8(id),
      u32be(Math.floor(createdAt / 1000)),
      Uint8Array.from([SESSION_FORMAT_VERSION]),
    )
  }

  /** Seal a session book for storage under `sessionKey(peerId)`. A re-seal (every
   *  message advances the ratchet) draws a FRESH salt, so it is a new key+nonce and
   *  never a keystream reuse against the row it replaces. */
  sealSession(peerId: string, book: SessionBook): SealedSessionRecord {
    const salt = randomBytes(SESSION_SALT_BYTES)
    const { key, nonce } = this.keyNonce(salt)
    const ct = aeadSeal(key, nonce, utf8(JSON.stringify(book)), this.sessionAad(this.sessionKey(peerId)))
    return { salt, ct }
  }

  /** Open a session row. `peerId` is the peer the CALLER asked for; the AAD is
   *  rebuilt from it, so a row sitting in the wrong slot cannot authenticate. */
  openSession(peerId: string, rec: SealedSessionRecord): SessionBook {
    const { key, nonce } = this.keyNonce(rec.salt)
    try {
      const plain = aeadOpen(key, nonce, rec.ct, this.sessionAad(this.sessionKey(peerId)))
      return JSON.parse(decoder.decode(plain)) as SessionBook
    } catch {
      throw new SessionSealError('this conversation')
    }
  }

  sealOutbox(entry: OutboxEntry): SealedOutboxRecord {
    const salt = randomBytes(SESSION_SALT_BYTES)
    const { key, nonce } = this.keyNonce(salt)
    const body: Record<string, unknown> = { to: entry.to, env: entry.env }
    if (entry.silent) body.silent = true
    // The two fields multi-device added, and they have to survive the round trip:
    // once a message is fanned out to several devices the entry id is a per-copy
    // TRANSPORT id, so `contentId` is the only remaining link to the logical
    // message and `account` the only link to the conversation. Without them a
    // queued copy read back from disk cannot be cancelled by a delete, marked
    // delivered, or marked failed, because every one of those looks the message
    // up by (account, contentId).
    //
    // They go INSIDE the sealed body rather than beside it: `account` names a
    // peer, which is exactly what this seal exists to hide (see the header).
    if (entry.contentId) body.contentId = entry.contentId
    if (entry.account) body.account = entry.account
    const ct = aeadSeal(key, nonce, utf8(JSON.stringify(body)), this.outboxAad(entry.id, entry.createdAt))
    return { id: entry.id, createdAt: entry.createdAt, salt, ct }
  }

  openOutbox(rec: SealedOutboxRecord): OutboxEntry {
    const { key, nonce } = this.keyNonce(rec.salt)
    let body: { to: string; env: unknown; silent?: boolean; contentId?: string; account?: string }
    try {
      const plain = aeadOpen(key, nonce, rec.ct, this.outboxAad(rec.id, rec.createdAt))
      body = JSON.parse(decoder.decode(plain)) as typeof body
    } catch {
      throw new SessionSealError('a queued message')
    }
    const e: OutboxEntry = { id: rec.id, to: body.to, env: body.env as OutboxEntry['env'], createdAt: rec.createdAt }
    if (body.silent) e.silent = true
    // Absent on rows sealed before this fix, which is why every reader falls back
    // to the single-device meaning (`e.account ?? e.to`, `e.contentId ?? e.id`).
    if (body.contentId) e.contentId = body.contentId
    if (body.account) e.account = body.account
    return e
  }
}
