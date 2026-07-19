import { describe, expect, it } from 'vitest'
import { MAX_SESSIONS_PER_PEER } from '../crypto/constants'
import type { RatchetSnapshot } from '../crypto/ratchet'
import { type SessionBook, singleSessionBook } from '../storage/sessionStore'
import { currentSession, decryptOrder, promoteSession, updateSession } from './sessionBook'

// A snapshot distinguishable by its root key, enough for book bookkeeping tests
// (the crypto is exercised elsewhere).
const snap = (rk: string): RatchetSnapshot => ({
  dhsPriv: null,
  dhsPub: null,
  dhr: null,
  rk,
  cks: null,
  ckr: null,
  ns: 0,
  nr: 0,
  pn: 0,
  skipped: [],
  ad: '00',
})

describe('sessionBook', () => {
  it('promotes a first session and makes it current', () => {
    const b = promoteSession(null, snap('a'), 1)
    expect(b.sessions).toHaveLength(1)
    expect(currentSession(b)?.snapshot.rk).toBe('a')
  })

  it('promoting a new session archives the old current (does not clobber it)', () => {
    let b = promoteSession(null, snap('a'), 1)
    const firstId = b.currentId
    b = promoteSession(b, snap('b'), 2)
    expect(b.sessions).toHaveLength(2)
    expect(currentSession(b)?.snapshot.rk).toBe('b')
    // The old session is still present (archived), reachable via decryptOrder.
    expect(b.sessions.some((s) => s.id === firstId)).toBe(true)
    expect(decryptOrder(b).map((s) => s.snapshot.rk)).toEqual(['b', 'a'])
  })

  it('decryptOrder puts the current session first, then most-recently-used', () => {
    let b = promoteSession(null, snap('a'), 1)
    b = promoteSession(b, snap('b'), 2)
    b = promoteSession(b, snap('c'), 3)
    // Touch 'a' so it becomes more-recently-used than 'b'.
    const aId = b.sessions.find((s) => s.snapshot.rk === 'a')!.id
    b = updateSession(b, aId, snap('a'), 10)
    // current is 'c'; then 'a' (lastUsedAt 10) before 'b' (lastUsedAt 2).
    expect(decryptOrder(b).map((s) => s.snapshot.rk)).toEqual(['c', 'a', 'b'])
  })

  it('updateSession replaces one snapshot and stamps lastUsedAt, current unchanged', () => {
    let b = promoteSession(null, snap('a'), 1)
    b = promoteSession(b, snap('b'), 2)
    const aId = b.sessions.find((s) => s.snapshot.rk === 'a')!.id
    const before = b.currentId
    b = updateSession(b, aId, snap('a2'), 99)
    expect(b.currentId).toBe(before)
    const a = b.sessions.find((s) => s.id === aId)!
    expect(a.snapshot.rk).toBe('a2')
    expect(a.lastUsedAt).toBe(99)
  })

  it('evicts the least-recently-used non-current session past the cap', () => {
    // Fill to the cap, each at a distinct createdAt/lastUsedAt.
    let b: SessionBook | null = null
    const ids: string[] = []
    for (let i = 0; i < MAX_SESSIONS_PER_PEER; i++) {
      b = promoteSession(b, snap(`s${i}`), i + 1)
      ids.push(b.currentId)
    }
    expect(b!.sessions).toHaveLength(MAX_SESSIONS_PER_PEER)
    // Touch every session EXCEPT s1 so s1 is the LRU non-current.
    for (const s of b!.sessions) {
      if (s.snapshot.rk !== 's1') b = updateSession(b!, s.id, s.snapshot, 100)
    }
    // One more promote overflows the cap; s1 (the LRU) is evicted.
    b = promoteSession(b!, snap('new'), 200)
    expect(b.sessions).toHaveLength(MAX_SESSIONS_PER_PEER)
    expect(b.sessions.some((s) => s.snapshot.rk === 's1')).toBe(false)
    expect(currentSession(b)?.snapshot.rk).toBe('new')
  })

  it('never evicts the current session', () => {
    let b: SessionBook | null = null
    for (let i = 0; i < MAX_SESSIONS_PER_PEER + 3; i++) b = promoteSession(b, snap(`s${i}`), i + 1)
    // The last promoted is always current and always present.
    expect(currentSession(b)?.snapshot.rk).toBe(`s${MAX_SESSIONS_PER_PEER + 2}`)
    expect(b!.sessions).toHaveLength(MAX_SESSIONS_PER_PEER)
  })

  it('singleSessionBook is a valid one-session book', () => {
    const b = singleSessionBook(snap('x'), 5)
    expect(currentSession(b)?.snapshot.rk).toBe('x')
    expect(decryptOrder(b)).toHaveLength(1)
  })
})
