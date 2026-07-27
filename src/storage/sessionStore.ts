// Durable per-conversation ratchet-state storage (DESIGN 5.3, 8.1).
//
// P5 change (the session-glare fix): a peer slot no longer holds ONE ratchet
// snapshot but a SESSION BOOK: a `currentId` plus a small, bounded set of
// sessions. This is what lets simultaneous first-contact ("glare") and
// re-establishment (restore, 8.3) work without one side silently clobbering a
// live session (see docs/SESSION-GLARE.md). Sends use the current session;
// receives try each session and keep whichever authenticates.
//
// Alongside the book, the store holds the dedup/guard structures the receive
// path needs:
//   - seen:     message ids already durably consumed (or poison-dropped), so a
//               redelivered envelope is ack-and-dropped, not reprocessed.
//   - replay:   initial-message ids (H(initial header)) already accepted, so a
//               replayed X3DH initial is rejected (DESIGN 4.3).
//   - failures: per-envelope decrypt-failure counts, so a permanently
//               undecryptable envelope is dropped after a bounded number of
//               retries instead of being redelivered forever (DESIGN 5.3).
//   - outbox:   queued outgoing envelopes, kept byte-identical for retransmit.
//
// The load-bearing property is ATOMICITY: a dedup/guard entry MUST be written in
// the SAME IndexedDB transaction as the session book, or a crash between the two
// could reprocess a message (key reuse) or lose a marker. The saveBookWith*
// methods do exactly that. The single-writer ordering (load -> compute -> save)
// is still enforced one layer up by the inbound processor / client holding the
// per-peer lock.

import { ENVELOPE_TTL_MS, SESSION_SEAL_VERSION, TOMBSTONE_TTL_MS } from '../crypto/constants'
import type { RatchetSnapshot } from '../crypto/ratchet'
import type { SessionSealer } from './sessionSeal'

/** One ratchet session inside a peer's book. `id` is a stable local handle
 *  (a UUID minted at creation); it never crosses the wire. */
export interface StoredSession {
  id: string
  snapshot: RatchetSnapshot
  createdAt: number
  /** Updated whenever the session is used (send or successful decrypt); drives
   *  LRU eviction so an actively-used glare session is never evicted. */
  lastUsedAt: number
}

/** All ratchet sessions currently held for one peer. `currentId` is the session
 *  new outgoing messages use; the full set is tried on inbound decrypt. */
export interface SessionBook {
  currentId: string
  sessions: StoredSession[]
}

/** A queued outgoing message. `env` is the already-encrypted WireEnvelope, kept
 *  verbatim so a retransmission is byte-identical (encrypt exactly once, DESIGN
 *  5.3). Stored alongside the session book so the advance and the outbox entry
 *  commit in one transaction (commit before release). */
export interface OutboxEntry {
  id: string
  to: string
  env: unknown
  createdAt: number
  /** A delete-for-everyone control (P10d) is delivered WITHOUT a push nudge so it
   *  never notifies the recipient. Persisted so retransmits stay silent too. */
  silent?: boolean
}

/** One persisted message (P10c). The WHOLE message (id, peer, dir, ts, text) is
 *  sealed into `ct` under the Local Data Key (see historyStore.ts); `salt` is the
 *  fresh per-record HKDF salt; `key` is the opaque HMAC storage key (also the
 *  IndexedDB key) that reveals no peer/dir/id at rest. A record is written in the
 *  SAME transaction as the ratchet advance + dedup marker, so an acked message is
 *  always durably in history. The storage layer treats it as opaque bytes; only
 *  the (unlocked) HistoryStore can compute keys and open ciphertext. */
export interface HistoryRecord {
  key: string
  salt: Uint8Array
  ct: Uint8Array
  /** Set on an outbound message whose delivery permanently failed or timed out, so
   *  a reload re-renders it as "not sent". A plain flag (not inside the AEAD, and
   *  not sensitive); absent means not failed. */
  failed?: boolean
}

/** A session book as it sits on disk (P11): sealed under the LDK, at an opaque
 *  HMAC storage key. Deliberately carries NO copy of that key, unlike a
 *  HistoryRecord: the opener always knows which peer it asked for, so the AAD is
 *  rebuilt from that rather than trusted from the value (see sessionSeal.ts). */
export interface SealedSessionRecord {
  salt: Uint8Array
  ct: Uint8Array
}

/** A queued outgoing message as it sits on disk (P11). `id` and `createdAt` stay in
 *  cleartext on purpose: the id is a random transport id that names nobody and
 *  addresses the row for removal, and the age drives the retry horizon and the
 *  oldest-first flush, both of which must keep working on a row that will not open.
 *  Only the peer and the envelope are sealed. Both plaintext fields are bound into
 *  the AAD, so neither can be edited without breaking the seal. */
export interface SealedOutboxRecord {
  id: string
  createdAt: number
  salt: Uint8Array
  ct: Uint8Array
}

/** What `pendingOutbox` found. `unreadable` counts rows that exist but will not
 *  open; they are KEPT and reported rather than skipped, because an outbox entry
 *  committed in the same transaction as its ratchet advance can never be
 *  re-encrypted, so silently dropping one is a message lost with no trace. */
export interface PendingOutbox {
  entries: OutboxEntry[]
  unreadable: string[]
}

/** A delete-for-everyone (P10d) applied inside a receive commit: remove the target
 *  history row at `key` AND record a tombstone at the same `key`, so a target that
 *  arrives AFTER its delete (reorder / redelivery) is later suppressed instead of
 *  persisted. Both live in the sessions DB so they ride the SAME transaction as the
 *  ratchet advance + dedup marker (an acked delete always durably removes). `key`
 *  is the opaque HMAC storage key of (peer, 'in', targetContentId). */
export interface HistoryDelete {
  key: string
}


export interface SessionStore {
  // --- session book ------------------------------------------------------
  /** The peer's whole session book, or null if none exists yet. */
  loadBook(peerId: string): Promise<SessionBook | null>
  /** Overwrite the peer's book (non-atomic convenience; tests + resend paths). */
  saveBook(peerId: string, book: SessionBook): Promise<void>
  /** Persist the book AND the consumed message id atomically (normal receive).
   *  An optional history record is written in the SAME transaction, so an acked
   *  inbound message is always durably in history (omitted for an ephemeral or
   *  unpersistable message). `del`, when the inbound message was a delete-for-
   *  everyone control, removes the target history row and records its tombstone in
   *  that SAME transaction (P10d). `history` and `del` are mutually exclusive (a
   *  delete control is not itself persisted). */
  saveBookWithSeen(
    peerId: string,
    book: SessionBook,
    msgId: string,
    history?: HistoryRecord,
    del?: HistoryDelete,
  ): Promise<void>
  /** Persist the book (with a freshly-promoted session), the consumed message id,
   *  AND the initial-message id, all atomically (the initial accept path), plus an
   *  optional history record OR delete (P10d) in the same transaction. */
  saveBookWithSeenReplay(
    peerId: string,
    book: SessionBook,
    msgId: string,
    initId: string,
    history?: HistoryRecord,
    del?: HistoryDelete,
  ): Promise<void>
  /** Persist the advanced book AND the outbox entry atomically, BEFORE the
   *  envelope is handed to the socket (commit before release), plus an optional
   *  history record for the sent message in the same transaction. */
  saveBookWithOutbox(peerId: string, book: SessionBook, entry: OutboxEntry, history?: HistoryRecord): Promise<void>

  // --- single-session convenience (the P3 RatchetSession wrapper + tests) --
  /** The CURRENT session's snapshot, or null. */
  load(peerId: string): Promise<RatchetSnapshot | null>
  /** Replace the peer's current session snapshot (keeps a one-session book). */
  save(peerId: string, snap: RatchetSnapshot): Promise<void>
  delete(peerId: string): Promise<void>
  /** The OPAQUE storage keys of every stored session book. Deliberately not named
   *  `list()` returning peer ids any more: once rows are sealed (P11) the keys are
   *  HMAC hex and cannot be mapped back to a peer, and a method typed `string[]`
   *  that silently changed meaning is exactly the kind of trap the type system
   *  cannot catch. Used for counting and for the migration; nothing routes on it. */
  listKeys(): Promise<string[]>

  // --- dedup / guards ----------------------------------------------------
  hasSeen(msgId: string): Promise<boolean>
  /** Mark a message id consumed without advancing any session (poison drop). */
  markSeen(msgId: string): Promise<void>
  hasReplayedInitial(initId: string): Promise<boolean>
  /** Record one more decrypt failure for a message id; returns the new count. */
  bumpFailure(msgId: string): Promise<number>
  /** Drop a failure counter (best-effort cleanup once an id is resolved). */
  clearFailure(msgId: string): Promise<void>

  // --- outbox ------------------------------------------------------------
  removeOutbox(id: string): Promise<void>
  /** Queued sends, oldest first, PLUS the ids of any rows that exist but will not
   *  open. Two lists rather than one, so no caller can read "could not read it" as
   *  "there is nothing there": an outbox row committed in the same transaction as
   *  its ratchet advance can never be re-encrypted, so a silent skip is a message
   *  destroyed without a trace, and a throw would take the whole connect path down
   *  because of one bad row. */
  pendingOutbox(): Promise<PendingOutbox>

  // --- history (P10c) ----------------------------------------------------
  /** Every persisted record across all peers (boot hydration). Opaque; the caller
   *  decrypts + groups + sorts. Storage keys are HMACs, so a per-peer range query
   *  is not possible (by design: the DB reveals no peer); a full scan is the only
   *  reader, which the app does once at unlock. */
  historyLoadAll(): Promise<HistoryRecord[]>
  /** One record by its opaque storage key, or null. */
  historyGet(key: string): Promise<HistoryRecord | null>
  /** Overwrite one record in place, ONLY if it already exists (never resurrects a
   *  deleted row: a status update racing a delete-for-everyone must not put the
   *  message back). Used to re-seal a row whose delivery status changed, which is a
   *  post-commit annotation on an existing message, not message content, so it does
   *  not ride the ratchet commit. Callers hold the per-peer lock so a row still has
   *  exactly one writer. */
  historyUpdate(rec: HistoryRecord): Promise<void>
  /** Remove exactly one record by its opaque storage key (delete / ephemeral). */
  historyRemove(key: string): Promise<void>
  /** Mark one record failed by its opaque storage key. No-op if the row is gone. */
  historyMarkFailed(key: string): Promise<void>
  /** Clear the saved-history row classes, meaning messages AND their delete
   *  tombstones (the forgot-secret app-lock reset: erase saved messages while
   *  keeping sessions/dedup/outbox so live messaging still works). */
  historyClear(): Promise<void>

  // --- delete tombstones (P10d) ------------------------------------------
  /** Whether a delete-for-everyone has already been applied for this opaque
   *  history key, so a target message arriving after its delete is suppressed. */
  hasTombstone(key: string): Promise<boolean>
  /** All tombstoned history keys (boot hydration defence-in-depth: a row that
   *  somehow coexists with a tombstone for it is dropped rather than shown). */
  tombstoneKeys(): Promise<string[]>

  // --- maintenance (P8) ----------------------------------------------------
  /** Age out dedup + failure rows past ENVELOPE_TTL_MS: the relay redelivers an
   *  unacked envelope for up to that long, so a `seen` row must outlive the whole
   *  redelivery window (pruning at the shorter seen-id TTL would let a late
   *  redelivery skip dedup and burn poison-drop attempts). `failures` age out on
   *  the same bound (the envelope they count no longer exists past it). The
   *  REPLAY store is never pruned, by design (DESIGN 4.3). Delete tombstones age
   *  out on the same envelope-TTL bound (past it their target can no longer be in
   *  flight); they are not counted in the returned tally. */
  pruneExpired(now: number): Promise<{ seen: number; failures: number }>
  /** Erase every store (restore, DESIGN 8.3): a restored identity starts with
   *  no sessions, dedup state, failure counters, queued outbox, history, or
   *  delete tombstones. */
  wipeAll(): Promise<void>
}


// --- helpers shared by both implementations --------------------------------

let idCounter = 0
/** A stable local session id. crypto.randomUUID where available (browser +
 *  workerd + modern node), else a monotonic fallback so tests never collide. */
export function newSessionId(): string {
  const c = (globalThis as { crypto?: Crypto }).crypto
  if (c && typeof c.randomUUID === 'function') return c.randomUUID()
  return `sid-${Date.now().toString(36)}-${(idCounter++).toString(36)}`
}

/** Wrap a single snapshot as a fresh one-session book. */
export function singleSessionBook(snap: RatchetSnapshot, now = 0): SessionBook {
  const id = newSessionId()
  return { currentId: id, sessions: [{ id, snapshot: snap, createdAt: now, lastUsedAt: now }] }
}

const clone = <T>(v: T): T => structuredClone(v) as T

// --- in-memory implementation ---------------------------------------------

export class MemorySessionStore implements SessionStore {
  private readonly books = new Map<string, SessionBook>()
  private readonly seen = new Map<string, number>() // msgId -> seen-at ms
  private readonly replay = new Set<string>()
  private readonly failures = new Map<string, { count: number; ts: number }>()
  private readonly outbox = new Map<string, OutboxEntry>()
  private readonly history = new Map<string, HistoryRecord>() // opaque storage key -> record
  private readonly tombstones = new Map<string, number>() // opaque history key -> tombstoned-at ms

  async loadBook(peerId: string): Promise<SessionBook | null> {
    const b = this.books.get(peerId)
    return b ? clone(b) : null
  }

  async saveBook(peerId: string, book: SessionBook): Promise<void> {
    this.books.set(peerId, clone(book))
  }

  async saveBookWithSeen(
    peerId: string,
    book: SessionBook,
    msgId: string,
    history?: HistoryRecord,
    del?: HistoryDelete,
  ): Promise<void> {
    this.books.set(peerId, clone(book))
    this.seen.set(msgId, Date.now())
    if (history) this.history.set(history.key, clone(history))
    if (del) this.applyDelete(del)
  }

  async saveBookWithSeenReplay(
    peerId: string,
    book: SessionBook,
    msgId: string,
    initId: string,
    history?: HistoryRecord,
    del?: HistoryDelete,
  ): Promise<void> {
    this.books.set(peerId, clone(book))
    this.seen.set(msgId, Date.now())
    this.replay.add(initId)
    if (history) this.history.set(history.key, clone(history))
    if (del) this.applyDelete(del)
  }

  private applyDelete(del: HistoryDelete): void {
    this.history.delete(del.key)
    this.tombstones.set(del.key, Date.now())
  }

  async saveBookWithOutbox(peerId: string, book: SessionBook, entry: OutboxEntry, history?: HistoryRecord): Promise<void> {
    this.books.set(peerId, clone(book))
    this.outbox.set(entry.id, clone(entry))
    if (history) this.history.set(history.key, clone(history))
  }

  async load(peerId: string): Promise<RatchetSnapshot | null> {
    const b = this.books.get(peerId)
    if (!b) return null
    const cur = b.sessions.find((s) => s.id === b.currentId)
    return cur ? clone(cur.snapshot) : null
  }

  async save(peerId: string, snap: RatchetSnapshot): Promise<void> {
    const b = this.books.get(peerId)
    if (b) {
      const cur = b.sessions.find((s) => s.id === b.currentId)
      if (cur) {
        cur.snapshot = clone(snap)
        return
      }
    }
    this.books.set(peerId, singleSessionBook(clone(snap)))
  }

  async delete(peerId: string): Promise<void> {
    this.books.delete(peerId)
  }

  async listKeys(): Promise<string[]> {
    return [...this.books.keys()]
  }

  async hasSeen(msgId: string): Promise<boolean> {
    return this.seen.has(msgId)
  }

  async markSeen(msgId: string): Promise<void> {
    this.seen.set(msgId, Date.now())
  }

  async hasReplayedInitial(initId: string): Promise<boolean> {
    return this.replay.has(initId)
  }

  async bumpFailure(msgId: string): Promise<number> {
    const prev = this.failures.get(msgId)
    const next = { count: (prev?.count ?? 0) + 1, ts: prev?.ts ?? Date.now() }
    this.failures.set(msgId, next)
    return next.count
  }

  async clearFailure(msgId: string): Promise<void> {
    this.failures.delete(msgId)
  }

  async removeOutbox(id: string): Promise<void> {
    this.outbox.delete(id)
  }

  // Sorted like the IndexedDB implementation. Map iteration is already insertion
  // order here, so without this an ordering test would pass in memory and fail
  // only in production, where the backing order is by random key.
  async pendingOutbox(): Promise<PendingOutbox> {
    return { entries: [...this.outbox.values()].map(clone).sort((a, b) => a.createdAt - b.createdAt), unreadable: [] }
  }

  async historyLoadAll(): Promise<HistoryRecord[]> {
    return [...this.history.values()].map(clone)
  }

  async historyGet(key: string): Promise<HistoryRecord | null> {
    const r = this.history.get(key)
    return r ? clone(r) : null
  }

  async historyUpdate(rec: HistoryRecord): Promise<void> {
    const current = this.history.get(rec.key)
    if (!current) return
    // Preserve a `failed` flag set since the caller read the row (see the IndexedDB
    // implementation for why).
    this.history.set(rec.key, clone(current.failed ? { ...rec, failed: true } : rec))
  }

  async historyRemove(key: string): Promise<void> {
    this.history.delete(key)
  }

  async historyMarkFailed(key: string): Promise<void> {
    const r = this.history.get(key)
    if (r) r.failed = true
  }

  async historyClear(): Promise<void> {
    this.history.clear()
    this.tombstones.clear()
  }

  async hasTombstone(key: string): Promise<boolean> {
    return this.tombstones.has(key)
  }

  async tombstoneKeys(): Promise<string[]> {
    return [...this.tombstones.keys()]
  }

  async pruneExpired(now: number): Promise<{ seen: number; failures: number }> {
    let seen = 0
    for (const [id, ts] of this.seen) {
      if (now - ts > ENVELOPE_TTL_MS) {
        this.seen.delete(id)
        seen += 1
      }
    }
    let failures = 0
    for (const [id, f] of this.failures) {
      if (now - f.ts > ENVELOPE_TTL_MS) {
        this.failures.delete(id)
        failures += 1
      }
    }
    for (const [key, ts] of this.tombstones) {
      if (now - ts > TOMBSTONE_TTL_MS) this.tombstones.delete(key)
    }
    return { seen, failures }
  }

  async wipeAll(): Promise<void> {
    this.books.clear()
    this.seen.clear()
    this.replay.clear()
    this.failures.clear()
    this.outbox.clear()
    this.history.clear()
    this.tombstones.clear()
  }
}

// --- IndexedDB implementation ---------------------------------------------

const DB_NAME = 'nightjar-sessions'
const SESSIONS = 'sessions'
const SEEN = 'seen'
const REPLAY = 'replay'
const FAILURES = 'failures'
const OUTBOX = 'outbox'
const HISTORY = 'history'
const TOMBSTONES = 'tombstones'
const META = 'meta'
const SEAL_MARKER = 'sealVersion'
// STANDING RULE: any change to the ON-DISK shape of SESSIONS or OUTBOX needs its own
// version bump, and for one reason only. The bump is not how data gets migrated (see
// migrateToSealed; onupgradeneeded fires before unlock and cannot await, so it can
// never seal anything). It is the only mechanism that stops a stale bundle, still
// running in another PWA window after a deploy, from writing rows in the OLD shape
// beside the new ones. Two shapes for one peer means two forked ratchet copies that
// both believe they hold the per-peer lock, which emits the same message key and
// nonce twice: catastrophic, and far worse than whatever the change was fixing.
// `onblocked` below rejects the new tab's open, and `onversionchange` makes the old
// tab step aside, which together make the overlap impossible rather than unlikely.
const DB_VERSION = 7

// A delete-for-everyone inside a receive transaction: remove the target history
// row and record its tombstone, both keyed by the same opaque history key. The
// caller has already added HISTORY + TOMBSTONES to the transaction's scope.
function applyDeleteTx(t: IDBTransaction, del: HistoryDelete): void {
  t.objectStore(HISTORY).delete(del.key)
  t.objectStore(TOMBSTONES).put(Date.now(), del.key)
}

export class IdbSessionStore implements SessionStore {
  private dbPromise: Promise<IDBDatabase> | null = null

  /** Set once the app-lock is unlocked, via `useSealer`. While it is null the store
   *  reads and writes the pre-P11 plaintext shape, which is what the tests use and
   *  what a database looks like before its one-time migration has run. */
  private sealer: SessionSealer | null = null

  /** Wire the LDK-backed sealer in. Called from activate(), after unlock and BEFORE
   *  the migration and the client, so nothing ever touches a session row through a
   *  half-configured store. */
  useSealer(sealer: SessionSealer): void {
    this.sealer = sealer
  }

  /**
   * Rewrite every session and outbox row into the sealed format, ONCE, in ONE
   * transaction. Call after unlock (the sealer needs the LDK) and before the client
   * exists, so there is no concurrent writer.
   *
   * The single transaction is the whole safety argument, and it is why this does not
   * use the `tx()` helper: that takes exactly one request and returns a promise, and
   * ANY await between reading the old rows and writing the new ones ends the
   * transaction, reopening the window where a kill or a quota abort leaves the store
   * emptied but not yet rewritten. Every primitive here is synchronous (@noble HMAC,
   * HKDF, XChaCha), so read, seal, clear and write all fit inside one transaction
   * with no yield, and "partially migrated" is not a state that can exist. An abort
   * at any point leaves the store byte-identical with the marker unset, and the next
   * unlock simply runs the whole thing again.
   *
   * Idempotence is the marker, read and written INSIDE the same transaction, so it
   * can never disagree with the rows it describes.
   */
  async migrateToSealed(): Promise<void> {
    const sealer = this.sealer
    if (!sealer) throw new Error('sessions: cannot migrate without an unlocked app-lock')
    const db = await this.open() // the ONLY await; everything below is one transaction
    await new Promise<void>((resolve, reject) => {
      const t = db.transaction([SESSIONS, OUTBOX, META], 'readwrite')
      t.oncomplete = () => resolve()
      t.onabort = () => reject(t.error ?? new Error('sessions: seal migration aborted'))
      t.onerror = () => reject(t.error ?? new Error('sessions: seal migration failed'))
      const sessions = t.objectStore(SESSIONS)
      const outbox = t.objectStore(OUTBOX)
      const meta = t.objectStore(META)

      const markerReq = meta.get(SEAL_MARKER)
      markerReq.onsuccess = () => {
        if (markerReq.result === SESSION_SEAL_VERSION) return // already sealed: commit a no-op
        // Requests issued from inside this handler keep the transaction alive.
        const sKeys = sessions.getAllKeys()
        const sVals = sessions.getAll()
        const oVals = outbox.getAll()
        oVals.onsuccess = () => {
          try {
            const peers = (sKeys.result ?? []).map(String)
            const books = (sVals.result ?? []) as SessionBook[]
            const sealedSessions: Array<{ slot: string; row: SealedSessionRecord }> = []
            for (let i = 0; i < peers.length; i++) {
              const peer = peers[i]
              const book = books[i]
              if (!peer || !book) continue
              sealedSessions.push({ slot: sealer.sessionKey(peer), row: sealer.sealSession(peer, book) })
            }
            const sealedOutbox = ((oVals.result ?? []) as OutboxEntry[]).map((e) => sealer.sealOutbox(e))
            // Only now, with every seal computed and nothing left that can throw,
            // does anything get destroyed.
            sessions.clear()
            outbox.clear()
            for (const s of sealedSessions) sessions.put(s.row, s.slot)
            for (const o of sealedOutbox) outbox.put(o, o.id)
            meta.put(SESSION_SEAL_VERSION, SEAL_MARKER)
          } catch (e) {
            // A seal that throws part-way aborts the whole transaction, so the
            // original plaintext rows survive untouched and this retries next unlock.
            t.abort()
            reject(e)
          }
        }
      }
    })
  }

  private open(): Promise<IDBDatabase> {
    if (!this.dbPromise) {
      this.dbPromise = new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, DB_VERSION)
        req.onupgradeneeded = (ev) => {
          const db = req.result
          if (!db.objectStoreNames.contains(SESSIONS)) db.createObjectStore(SESSIONS)
          if (!db.objectStoreNames.contains(SEEN)) db.createObjectStore(SEEN)
          if (!db.objectStoreNames.contains(REPLAY)) db.createObjectStore(REPLAY)
          if (!db.objectStoreNames.contains(FAILURES)) db.createObjectStore(FAILURES)
          if (!db.objectStoreNames.contains(OUTBOX)) db.createObjectStore(OUTBOX)
          // v4 -> v5 (P10b): a `history` store keyed by `${peerId}:${id}`. The
          // createObjectStore-if-absent above already handles a brand-new DB; an
          // upgrade from v4 just adds the empty store (no data to migrate).
          if (!db.objectStoreNames.contains(HISTORY)) db.createObjectStore(HISTORY)
          // v5 -> v6 (P10d): a `tombstones` store keyed by an opaque history key,
          // recording a delete-for-everyone so a target arriving after its delete is
          // suppressed. New empty store; nothing to migrate.
          if (!db.objectStoreNames.contains(TOMBSTONES)) db.createObjectStore(TOMBSTONES)
          // v6 -> v7 (P11): a `meta` store holding the seal-migration marker. New
          // empty store; the actual sealing happens in migrateToSealed after unlock,
          // because the Local Data Key does not exist yet at this point.
          if (!db.objectStoreNames.contains(META)) db.createObjectStore(META)
          // v2 -> v3: a v2 `sessions` value was a bare RatchetSnapshot; wrap each
          // as a one-session book so a pre-P5 conversation is not lost. (Prod has
          // none yet: the only durable sessions before P5 were isolated dev
          // self-tests using the in-memory store.)
          const from = (ev as IDBVersionChangeEvent).oldVersion
          const tx = req.transaction
          if (from >= 1 && from < 3 && tx) migrateSessionsToBooks(tx.objectStore(SESSIONS))
          // v3 -> v4: `seen` values become the seen-at timestamp and `failures`
          // values become {count, ts}, so both can be TTL-pruned. Existing rows
          // are stamped at migration time (their clocks start now; pruning a
          // dedup row EARLY is the only unsafe direction, so never stamp 0).
          if (from >= 1 && from < 4 && tx) migrateRetentionStamps(tx.objectStore(SEEN), tx.objectStore(FAILURES))
        }
        req.onsuccess = () => {
          const db = req.result
          // Another tab later opens this DB at a HIGHER version: step aside so its
          // upgrade is not blocked forever. Without this, the newer tab's open sits
          // in `blocked` until this connection closes, which for a PWA left open in
          // a background tab is "never".
          db.onversionchange = () => {
            this.dbPromise = null
            db.close()
          }
          resolve(db)
        }
        // An open that needs an upgrade while ANOTHER tab still holds the old
        // version fires `blocked` and then never fires success or error. Failing
        // here is what stops the caller awaiting a promise that can never settle:
        // an unsettled promise cannot be caught, so the UI would hang on the unlock
        // spinner with no error at all (the bootstrap try/catch never runs).
        req.onblocked = () => {
          this.dbPromise = null
          reject(new Error('storage is open in another tab running an older version of Nightjar: close it, or reload this tab'))
        }
        req.onerror = () => {
          this.dbPromise = null // a failed open must not wedge every later call
          reject(req.error)
        }
      })
    }
    return this.dbPromise
  }

  // Single-request helper. Resolves on COMMIT (transaction.oncomplete), not on
  // request success: a put can succeed while the transaction still aborts at
  // commit time (quota/disk), which would let a caller act on a non-durable write.
  private async tx<T>(
    stores: string | string[],
    mode: IDBTransactionMode,
    fn: (tx: IDBTransaction) => IDBRequest<T> | null,
  ): Promise<T | undefined> {
    const db = await this.open()
    return new Promise<T | undefined>((resolve, reject) => {
      const transaction = db.transaction(stores, mode)
      let result: T | undefined
      const request = fn(transaction)
      if (request) {
        request.onsuccess = () => {
          result = request.result
        }
        request.onerror = () => reject(request.error)
      }
      transaction.oncomplete = () => resolve(result)
      transaction.onabort = () => reject(transaction.error)
      transaction.onerror = () => reject(transaction.error)
    })
  }

  // Sealing (P11). Every session read and write goes through these two, so there is
  // exactly one place that knows the on-disk shape. With no sealer wired (tests,
  // pre-unlock) rows stay plaintext at the peerId key, which is the pre-P11 format.
  private sessionSlot(peerId: string): string {
    return this.sealer ? this.sealer.sessionKey(peerId) : peerId
  }

  private sealedBook(peerId: string, book: SessionBook): SealedSessionRecord | SessionBook {
    return this.sealer ? this.sealer.sealSession(peerId, book) : book
  }

  async loadBook(peerId: string): Promise<SessionBook | null> {
    const v = await this.tx<unknown>(SESSIONS, 'readonly', (t) => t.objectStore(SESSIONS).get(this.sessionSlot(peerId)))
    if (v == null) return null
    // Present-but-will-not-open is a THIRD outcome, never folded into null. A null
    // here would read as "no session yet", which sends the caller down the
    // first-contact path and overwrites a conversation that was merely unreadable
    // for a moment (an idle-lock landing mid-receive). openSession throws instead.
    return this.sealer ? this.sealer.openSession(peerId, v as SealedSessionRecord) : (v as SessionBook)
  }

  async saveBook(peerId: string, book: SessionBook): Promise<void> {
    const row = this.sealedBook(peerId, book)
    await this.tx(SESSIONS, 'readwrite', (t) => t.objectStore(SESSIONS).put(row, this.sessionSlot(peerId)))
  }

  async saveBookWithSeen(
    peerId: string,
    book: SessionBook,
    msgId: string,
    history?: HistoryRecord,
    del?: HistoryDelete,
  ): Promise<void> {
    // Seal BEFORE opening the transaction. Sealing is synchronous, but doing it
    // inside the callback would put a throw (app locked mid-operation) in the middle
    // of a half-built multi-store write; out here it aborts with nothing issued.
    const slot = this.sessionSlot(peerId)
    const row = this.sealedBook(peerId, book)
    const stores = history || del ? [SESSIONS, SEEN, HISTORY, TOMBSTONES] : [SESSIONS, SEEN]
    await this.tx(stores, 'readwrite', (t) => {
      t.objectStore(SESSIONS).put(row, slot)
      t.objectStore(SEEN).put(Date.now(), msgId)
      if (history) t.objectStore(HISTORY).put(history, history.key)
      if (del) applyDeleteTx(t, del)
      return null
    })
  }

  async saveBookWithSeenReplay(
    peerId: string,
    book: SessionBook,
    msgId: string,
    initId: string,
    history?: HistoryRecord,
    del?: HistoryDelete,
  ): Promise<void> {
    const slot = this.sessionSlot(peerId)
    const row = this.sealedBook(peerId, book)
    const stores = history || del ? [SESSIONS, SEEN, REPLAY, HISTORY, TOMBSTONES] : [SESSIONS, SEEN, REPLAY]
    await this.tx(stores, 'readwrite', (t) => {
      t.objectStore(SESSIONS).put(row, slot)
      t.objectStore(SEEN).put(Date.now(), msgId)
      t.objectStore(REPLAY).put(1, initId)
      if (history) t.objectStore(HISTORY).put(history, history.key)
      if (del) applyDeleteTx(t, del)
      return null
    })
  }

  async saveBookWithOutbox(peerId: string, book: SessionBook, entry: OutboxEntry, history?: HistoryRecord): Promise<void> {
    const slot = this.sessionSlot(peerId)
    const row = this.sealedBook(peerId, book)
    const obx = this.sealer ? this.sealer.sealOutbox(entry) : entry
    const stores = history ? [SESSIONS, OUTBOX, HISTORY] : [SESSIONS, OUTBOX]
    await this.tx(stores, 'readwrite', (t) => {
      t.objectStore(SESSIONS).put(row, slot)
      t.objectStore(OUTBOX).put(obx, entry.id)
      if (history) t.objectStore(HISTORY).put(history, history.key)
      return null
    })
  }

  async load(peerId: string): Promise<RatchetSnapshot | null> {
    const b = await this.loadBook(peerId)
    if (!b) return null
    const cur = b.sessions.find((s) => s.id === b.currentId)
    return cur ? cur.snapshot : null
  }

  async save(peerId: string, snap: RatchetSnapshot): Promise<void> {
    const b = await this.loadBook(peerId)
    if (b) {
      const cur = b.sessions.find((s) => s.id === b.currentId)
      if (cur) {
        cur.snapshot = snap
        await this.saveBook(peerId, b)
        return
      }
    }
    await this.saveBook(peerId, singleSessionBook(snap))
  }

  async delete(peerId: string): Promise<void> {
    await this.tx(SESSIONS, 'readwrite', (t) => t.objectStore(SESSIONS).delete(this.sessionSlot(peerId)))
  }

  async listKeys(): Promise<string[]> {
    const keys = await this.tx<IDBValidKey[]>(SESSIONS, 'readonly', (t) => t.objectStore(SESSIONS).getAllKeys())
    return (keys ?? []).map(String)
  }

  async hasSeen(msgId: string): Promise<boolean> {
    const v = await this.tx<unknown>(SEEN, 'readonly', (t) => t.objectStore(SEEN).get(msgId))
    return v !== undefined
  }

  async markSeen(msgId: string): Promise<void> {
    await this.tx(SEEN, 'readwrite', (t) => t.objectStore(SEEN).put(Date.now(), msgId))
  }

  async hasReplayedInitial(initId: string): Promise<boolean> {
    const v = await this.tx<unknown>(REPLAY, 'readonly', (t) => t.objectStore(REPLAY).get(initId))
    return v !== undefined
  }

  async bumpFailure(msgId: string): Promise<number> {
    const db = await this.open()
    return new Promise<number>((resolve, reject) => {
      const t = db.transaction(FAILURES, 'readwrite')
      const store = t.objectStore(FAILURES)
      const get = store.get(msgId)
      let next = 1
      get.onsuccess = () => {
        const prev = get.result as number | { count: number; ts: number } | undefined
        const count = typeof prev === 'number' ? prev : (prev?.count ?? 0)
        const ts = typeof prev === 'object' && prev ? prev.ts : Date.now()
        next = count + 1
        store.put({ count: next, ts }, msgId)
      }
      get.onerror = () => reject(get.error)
      t.oncomplete = () => resolve(next)
      t.onabort = () => reject(t.error)
      t.onerror = () => reject(t.error)
    })
  }

  async clearFailure(msgId: string): Promise<void> {
    await this.tx(FAILURES, 'readwrite', (t) => t.objectStore(FAILURES).delete(msgId))
  }

  async removeOutbox(id: string): Promise<void> {
    await this.tx(OUTBOX, 'readwrite', (t) => t.objectStore(OUTBOX).delete(id))
  }

  // Ordered oldest-FIRST by creation time. `getAll()` yields IndexedDB key order,
  // and the key is the entry id (a random 16-byte hex, see saveBookWithOutbox), so
  // the raw order is uncorrelated with the order the user actually did things. The
  // relay drains in arrival order, which is our flush order, so an unordered flush
  // lets a queued control (a delete, and anything later that targets an existing
  // message) overtake the message it refers to. Sorting here is the single place
  // that fixes it for every caller.
  async pendingOutbox(): Promise<PendingOutbox> {
    const rows = await this.tx<unknown[]>(OUTBOX, 'readonly', (t) => t.objectStore(OUTBOX).getAll())
    const entries: OutboxEntry[] = []
    const unreadable: string[] = []
    for (const row of rows ?? []) {
      if (!this.sealer) {
        entries.push(row as OutboxEntry)
        continue
      }
      // Per row, never per batch: one bad row must not stop every other queued
      // message from ever being retransmitted, and must not throw the whole connect
      // path into the error phase. It is reported, not skipped, and not deleted.
      try {
        entries.push(this.sealer.openOutbox(row as SealedOutboxRecord))
      } catch {
        unreadable.push(String((row as SealedOutboxRecord).id ?? ''))
      }
    }
    // createdAt stays in cleartext precisely so this ordering survives a row that
    // would not open (see SealedOutboxRecord).
    return { entries: entries.sort((a, b) => a.createdAt - b.createdAt), unreadable }
  }

  async historyLoadAll(): Promise<HistoryRecord[]> {
    const rows = await this.tx<HistoryRecord[]>(HISTORY, 'readonly', (t) => t.objectStore(HISTORY).getAll())
    return rows ?? []
  }

  async historyRemove(key: string): Promise<void> {
    await this.tx(HISTORY, 'readwrite', (t) => t.objectStore(HISTORY).delete(key))
  }

  async historyGet(key: string): Promise<HistoryRecord | null> {
    const r = await this.tx<HistoryRecord | undefined>(HISTORY, 'readonly', (t) => t.objectStore(HISTORY).get(key))
    return r ?? null
  }

  // Existence is re-checked inside the SAME transaction as the put, so a row
  // deleted in between (delete-for-everyone, an ephemeral cleanup) is not
  // resurrected by a status update that was already in flight.
  //
  // The `failed` flag is carried over from whatever is on disk NOW rather than from
  // the caller's snapshot. A status update is a read-modify-write across two
  // transactions, and historyMarkFailed writes the same row from outside the
  // per-peer lock, so a caller that read before that write would otherwise put back
  // a record with the flag cleared and a permanently rejected message would start
  // reading as delivered.
  async historyUpdate(rec: HistoryRecord): Promise<void> {
    const db = await this.open()
    await new Promise<void>((resolve, reject) => {
      const t = db.transaction(HISTORY, 'readwrite')
      const store = t.objectStore(HISTORY)
      const get = store.get(rec.key)
      get.onsuccess = () => {
        const current = get.result as HistoryRecord | undefined
        if (current !== undefined) store.put(current.failed ? { ...rec, failed: true } : rec, rec.key)
      }
      get.onerror = () => reject(get.error)
      t.oncomplete = () => resolve()
      t.onabort = () => reject(t.error)
      t.onerror = () => reject(t.error)
    })
  }

  async historyMarkFailed(key: string): Promise<void> {
    const db = await this.open()
    await new Promise<void>((resolve, reject) => {
      const t = db.transaction(HISTORY, 'readwrite')
      const store = t.objectStore(HISTORY)
      const get = store.get(key)
      get.onsuccess = () => {
        const row = get.result as HistoryRecord | undefined
        if (row) {
          row.failed = true
          store.put(row, key)
        }
      }
      get.onerror = () => reject(get.error)
      t.oncomplete = () => resolve()
      t.onabort = () => reject(t.error)
      t.onerror = () => reject(t.error)
    })
  }

  // Clears every row class that belongs to saved history, not just the messages.
  // Tombstones are keyed by the same opaque history key, so leaving them behind
  // survived the "forgot your secret" reset as a count of applied deletes, and
  // (since the reset discards the LDK) as rows nothing could ever open or attribute
  // again. DESIGN 8.5 says that reset erases the saved history, so it must.
  async historyClear(): Promise<void> {
    await this.tx([HISTORY, TOMBSTONES], 'readwrite', (t) => {
      t.objectStore(HISTORY).clear()
      t.objectStore(TOMBSTONES).clear()
      return null
    })
  }

  async hasTombstone(key: string): Promise<boolean> {
    const v = await this.tx<unknown>(TOMBSTONES, 'readonly', (t) => t.objectStore(TOMBSTONES).get(key))
    return v !== undefined
  }

  async tombstoneKeys(): Promise<string[]> {
    const keys = await this.tx<IDBValidKey[]>(TOMBSTONES, 'readonly', (t) => t.objectStore(TOMBSTONES).getAllKeys())
    return (keys ?? []).map(String)
  }

  async pruneExpired(now: number): Promise<{ seen: number; failures: number }> {
    const db = await this.open()
    return new Promise((resolve, reject) => {
      const t = db.transaction([SEEN, FAILURES, TOMBSTONES], 'readwrite')
      let seen = 0
      let failures = 0
      const sweep = (store: IDBObjectStore, expired: (v: unknown) => boolean, bump: () => void) => {
        const cur = store.openCursor()
        cur.onsuccess = () => {
          const c = cur.result
          if (!c) return
          if (expired(c.value)) {
            c.delete()
            bump()
          }
          c.continue()
        }
      }
      sweep(
        t.objectStore(SEEN),
        (v) => typeof v === 'number' && now - v > ENVELOPE_TTL_MS,
        () => (seen += 1),
      )
      sweep(
        t.objectStore(FAILURES),
        (v) => typeof v === 'object' && v !== null && now - (v as { ts: number }).ts > ENVELOPE_TTL_MS,
        () => (failures += 1),
      )
      // Tombstones age out on the envelope-TTL bound too; not counted in the tally.
      sweep(
        t.objectStore(TOMBSTONES),
        (v) => typeof v === 'number' && now - v > TOMBSTONE_TTL_MS,
        () => {},
      )
      t.oncomplete = () => resolve({ seen, failures })
      t.onabort = () => reject(t.error)
      t.onerror = () => reject(t.error)
    })
  }

  async wipeAll(): Promise<void> {
    await this.tx([SESSIONS, SEEN, REPLAY, FAILURES, OUTBOX, HISTORY, TOMBSTONES, META], 'readwrite', (t) => {
      t.objectStore(SESSIONS).clear()
      t.objectStore(SEEN).clear()
      t.objectStore(REPLAY).clear()
      t.objectStore(FAILURES).clear()
      t.objectStore(OUTBOX).clear()
      t.objectStore(HISTORY).clear()
      t.objectStore(TOMBSTONES).clear()
      // An empty store is trivially sealed, so the marker is SET rather than
      // cleared: leaving it unset would make the next unlock run a migration over
      // nothing, and leaving a stale marker after a wipe would be a lie about rows
      // that no longer exist. Both are avoided by writing it in this transaction.
      t.objectStore(META).put(SESSION_SEAL_VERSION, SEAL_MARKER)
      return null
    })
  }

  /** Close the cached connection (restore: lets a wipe/reload proceed without a
   *  blocked-version dance). Subsequent calls reopen on demand. */
  close(): void {
    void this.dbPromise?.then((db) => db.close()).catch(() => {})
    this.dbPromise = null
  }
}

/** v2 -> v3 migration: rewrite each bare-snapshot session value as a one-session
 *  book. Runs inside the versionchange transaction via a cursor. */
function migrateSessionsToBooks(store: IDBObjectStore): void {
  const cursorReq = store.openCursor()
  cursorReq.onsuccess = () => {
    const cursor = cursorReq.result
    if (!cursor) return
    const value = cursor.value as unknown
    // Already a book (has `currentId`)? leave it. Else wrap the snapshot.
    if (!value || typeof value !== 'object' || !('currentId' in (value as object))) {
      cursor.update(singleSessionBook(value as RatchetSnapshot))
    }
    cursor.continue()
  }
}

/** v3 -> v4 migration: stamp legacy `seen` (value 1) and `failures` (bare count)
 *  rows with the migration-time clock so TTL pruning can never drop a dedup row
 *  early. Runs inside the versionchange transaction via cursors. */
function migrateRetentionStamps(seen: IDBObjectStore, failures: IDBObjectStore): void {
  const now = Date.now()
  const seenCur = seen.openCursor()
  seenCur.onsuccess = () => {
    const c = seenCur.result
    if (!c) return
    if (typeof c.value !== 'number' || c.value < 1_000_000_000_000) c.update(now)
    c.continue()
  }
  const failCur = failures.openCursor()
  failCur.onsuccess = () => {
    const c = failCur.result
    if (!c) return
    if (typeof c.value === 'number') c.update({ count: c.value, ts: now })
    c.continue()
  }
}
