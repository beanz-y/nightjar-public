// Pure helpers over a peer's SESSION BOOK (the P5 glare fix; see
// docs/SESSION-GLARE.md). A book holds a small, bounded set of ratchet sessions
// for one peer plus a `currentId` pointer:
//
//   - SEND uses the current session.
//   - RECEIVE (normal) tries the sessions in `decryptOrder` and keeps whichever
//     authenticates, so a message encrypted on a session that is no longer our
//     current one (the other arm of a glare, or a message in flight across a
//     re-establishment) still decrypts.
//   - Every accepted INITIAL promotes a new current and archives the rest;
//     `promoteSession` evicts the least-recently-used non-current session past
//     the cap so a peer cannot grow the book without bound.
//
// These functions never mutate their input book; they return a new one, matching
// the pure/immutable style of the ratchet itself.

import { MAX_SESSIONS_PER_PEER } from '../crypto/constants'
import type { RatchetSnapshot } from '../crypto/ratchet'
import { type SessionBook, type StoredSession, newSessionId } from '../storage/sessionStore'

/** The current (send) session, or null if the book is empty or its pointer is
 *  dangling (defensive; should not happen). */
export function currentSession(book: SessionBook | null): StoredSession | null {
  if (!book) return null
  return book.sessions.find((s) => s.id === book.currentId) ?? null
}

/** Add a freshly-created session, make it current, and evict the
 *  least-recently-used NON-current session while over the cap. Works for both a
 *  new initiator session (send path) and a new responder session (receive-initial
 *  path): either way the fresh session becomes current. */
export function promoteSession(book: SessionBook | null, snapshot: RatchetSnapshot, now: number): SessionBook {
  const fresh: StoredSession = { id: newSessionId(), snapshot, createdAt: now, lastUsedAt: now }
  let sessions = [...(book?.sessions ?? []), fresh]
  const currentId = fresh.id

  while (sessions.length > MAX_SESSIONS_PER_PEER) {
    // Evict the LRU among non-current sessions (ties broken by createdAt), so an
    // actively-used arm of a glare survives and only a stale session is dropped.
    let victim: StoredSession | null = null
    for (const s of sessions) {
      if (s.id === currentId) continue
      if (
        !victim ||
        s.lastUsedAt < victim.lastUsedAt ||
        (s.lastUsedAt === victim.lastUsedAt && s.createdAt < victim.createdAt)
      ) {
        victim = s
      }
    }
    if (!victim) break // only the current session remains
    sessions = sessions.filter((s) => s.id !== victim!.id)
  }

  return { currentId, sessions }
}

/** Sessions ordered for an inbound decrypt attempt: the current session first
 *  (the common case), then the rest most-recently-used first. */
export function decryptOrder(book: SessionBook): StoredSession[] {
  const current = currentSession(book)
  const rest = book.sessions
    .filter((s) => s.id !== book.currentId)
    .sort((a, b) => b.lastUsedAt - a.lastUsedAt)
  return current ? [current, ...rest] : rest
}

/** Replace a session's snapshot after an advance and stamp its lastUsedAt.
 *  Returns a new book; the current pointer is unchanged. */
export function updateSession(book: SessionBook, id: string, snapshot: RatchetSnapshot, now: number): SessionBook {
  return {
    currentId: book.currentId,
    sessions: book.sessions.map((s) => (s.id === id ? { ...s, snapshot, lastUsedAt: now } : s)),
  }
}
