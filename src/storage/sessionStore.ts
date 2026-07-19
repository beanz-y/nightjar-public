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

import type { RatchetSnapshot } from '../crypto/ratchet'

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
}

export interface SessionStore {
  // --- session book ------------------------------------------------------
  /** The peer's whole session book, or null if none exists yet. */
  loadBook(peerId: string): Promise<SessionBook | null>
  /** Overwrite the peer's book (non-atomic convenience; tests + resend paths). */
  saveBook(peerId: string, book: SessionBook): Promise<void>
  /** Persist the book AND the consumed message id atomically (normal receive). */
  saveBookWithSeen(peerId: string, book: SessionBook, msgId: string): Promise<void>
  /** Persist the book (with a freshly-promoted session), the consumed message id,
   *  AND the initial-message id, all atomically (the initial accept path). */
  saveBookWithSeenReplay(peerId: string, book: SessionBook, msgId: string, initId: string): Promise<void>
  /** Persist the advanced book AND the outbox entry atomically, BEFORE the
   *  envelope is handed to the socket (commit before release). */
  saveBookWithOutbox(peerId: string, book: SessionBook, entry: OutboxEntry): Promise<void>

  // --- single-session convenience (the P3 RatchetSession wrapper + tests) --
  /** The CURRENT session's snapshot, or null. */
  load(peerId: string): Promise<RatchetSnapshot | null>
  /** Replace the peer's current session snapshot (keeps a one-session book). */
  save(peerId: string, snap: RatchetSnapshot): Promise<void>
  delete(peerId: string): Promise<void>
  list(): Promise<string[]>

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
  pendingOutbox(): Promise<OutboxEntry[]>
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
  private readonly seen = new Set<string>()
  private readonly replay = new Set<string>()
  private readonly failures = new Map<string, number>()
  private readonly outbox = new Map<string, OutboxEntry>()

  async loadBook(peerId: string): Promise<SessionBook | null> {
    const b = this.books.get(peerId)
    return b ? clone(b) : null
  }

  async saveBook(peerId: string, book: SessionBook): Promise<void> {
    this.books.set(peerId, clone(book))
  }

  async saveBookWithSeen(peerId: string, book: SessionBook, msgId: string): Promise<void> {
    this.books.set(peerId, clone(book))
    this.seen.add(msgId)
  }

  async saveBookWithSeenReplay(peerId: string, book: SessionBook, msgId: string, initId: string): Promise<void> {
    this.books.set(peerId, clone(book))
    this.seen.add(msgId)
    this.replay.add(initId)
  }

  async saveBookWithOutbox(peerId: string, book: SessionBook, entry: OutboxEntry): Promise<void> {
    this.books.set(peerId, clone(book))
    this.outbox.set(entry.id, clone(entry))
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

  async list(): Promise<string[]> {
    return [...this.books.keys()]
  }

  async hasSeen(msgId: string): Promise<boolean> {
    return this.seen.has(msgId)
  }

  async markSeen(msgId: string): Promise<void> {
    this.seen.add(msgId)
  }

  async hasReplayedInitial(initId: string): Promise<boolean> {
    return this.replay.has(initId)
  }

  async bumpFailure(msgId: string): Promise<number> {
    const n = (this.failures.get(msgId) ?? 0) + 1
    this.failures.set(msgId, n)
    return n
  }

  async clearFailure(msgId: string): Promise<void> {
    this.failures.delete(msgId)
  }

  async removeOutbox(id: string): Promise<void> {
    this.outbox.delete(id)
  }

  async pendingOutbox(): Promise<OutboxEntry[]> {
    return [...this.outbox.values()].map(clone)
  }
}

// --- IndexedDB implementation ---------------------------------------------

const DB_NAME = 'nightjar-sessions'
const SESSIONS = 'sessions'
const SEEN = 'seen'
const REPLAY = 'replay'
const FAILURES = 'failures'
const OUTBOX = 'outbox'
const DB_VERSION = 3

export class IdbSessionStore implements SessionStore {
  private dbPromise: Promise<IDBDatabase> | null = null

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
          // v2 -> v3: a v2 `sessions` value was a bare RatchetSnapshot; wrap each
          // as a one-session book so a pre-P5 conversation is not lost. (Prod has
          // none yet: the only durable sessions before P5 were isolated dev
          // self-tests using the in-memory store.)
          const from = (ev as IDBVersionChangeEvent).oldVersion
          if (from >= 1 && from < 3) {
            const tx = req.transaction
            if (tx) migrateSessionsToBooks(tx.objectStore(SESSIONS))
          }
        }
        req.onsuccess = () => resolve(req.result)
        req.onerror = () => reject(req.error)
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

  async loadBook(peerId: string): Promise<SessionBook | null> {
    const v = await this.tx<unknown>(SESSIONS, 'readonly', (t) => t.objectStore(SESSIONS).get(peerId))
    return (v ?? null) as SessionBook | null
  }

  async saveBook(peerId: string, book: SessionBook): Promise<void> {
    await this.tx(SESSIONS, 'readwrite', (t) => t.objectStore(SESSIONS).put(book, peerId))
  }

  async saveBookWithSeen(peerId: string, book: SessionBook, msgId: string): Promise<void> {
    await this.tx([SESSIONS, SEEN], 'readwrite', (t) => {
      t.objectStore(SESSIONS).put(book, peerId)
      t.objectStore(SEEN).put(1, msgId)
      return null
    })
  }

  async saveBookWithSeenReplay(peerId: string, book: SessionBook, msgId: string, initId: string): Promise<void> {
    await this.tx([SESSIONS, SEEN, REPLAY], 'readwrite', (t) => {
      t.objectStore(SESSIONS).put(book, peerId)
      t.objectStore(SEEN).put(1, msgId)
      t.objectStore(REPLAY).put(1, initId)
      return null
    })
  }

  async saveBookWithOutbox(peerId: string, book: SessionBook, entry: OutboxEntry): Promise<void> {
    await this.tx([SESSIONS, OUTBOX], 'readwrite', (t) => {
      t.objectStore(SESSIONS).put(book, peerId)
      t.objectStore(OUTBOX).put(entry, entry.id)
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
    await this.tx(SESSIONS, 'readwrite', (t) => t.objectStore(SESSIONS).delete(peerId))
  }

  async list(): Promise<string[]> {
    const keys = await this.tx<IDBValidKey[]>(SESSIONS, 'readonly', (t) => t.objectStore(SESSIONS).getAllKeys())
    return (keys ?? []).map(String)
  }

  async hasSeen(msgId: string): Promise<boolean> {
    const v = await this.tx<unknown>(SEEN, 'readonly', (t) => t.objectStore(SEEN).get(msgId))
    return v !== undefined
  }

  async markSeen(msgId: string): Promise<void> {
    await this.tx(SEEN, 'readwrite', (t) => t.objectStore(SEEN).put(1, msgId))
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
        next = ((get.result as number | undefined) ?? 0) + 1
        store.put(next, msgId)
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

  async pendingOutbox(): Promise<OutboxEntry[]> {
    const entries = await this.tx<OutboxEntry[]>(OUTBOX, 'readonly', (t) => t.objectStore(OUTBOX).getAll())
    return entries ?? []
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
