import 'fake-indexeddb/auto'
import { IDBFactory } from 'fake-indexeddb'
import { beforeEach, describe, it, expect } from 'vitest'
import type { RatchetSnapshot } from '../crypto/ratchet'
import {
  type HistoryRow,
  IdbSessionStore,
  MemorySessionStore,
  type SessionStore,
  singleSessionBook,
} from './sessionStore'

beforeEach(() => {
  globalThis.indexedDB = new IDBFactory()
})

const snap: RatchetSnapshot = {
  dhsPriv: 'aa'.repeat(32),
  dhsPub: 'bb'.repeat(32),
  dhr: 'cc'.repeat(32),
  rk: 'dd'.repeat(32),
  cks: 'ee'.repeat(32),
  ckr: null,
  ns: 3,
  nr: 5,
  pn: 2,
  skipped: [{ dhr: 'cc'.repeat(32), n: 1, mk: 'ff'.repeat(32) }],
  ad: '11'.repeat(129),
}

function suite(name: string, make: () => SessionStore) {
  describe(name, () => {
    it('save/load round-trips a snapshot exactly', async () => {
      const s = make()
      expect(await s.load('bob')).toBeNull()
      await s.save('bob', snap)
      expect(await s.load('bob')).toEqual(snap)
    })

    it('lists and deletes', async () => {
      const s = make()
      await s.save('a', snap)
      await s.save('b', snap)
      expect((await s.list()).sort()).toEqual(['a', 'b'])
      await s.delete('a')
      expect(await s.load('a')).toBeNull()
      expect(await s.list()).toEqual(['b'])
    })

    it('stores an independent copy (mutating the input does not change stored bytes)', async () => {
      const s = make()
      const local = structuredClone(snap)
      await s.save('c', local)
      local.ns = 999
      const loaded = await s.load('c')
      expect(loaded?.ns).toBe(snap.ns)
    })
  })
}

suite('MemorySessionStore', () => new MemorySessionStore())
suite('IdbSessionStore', () => new IdbSessionStore())

describe('retention maintenance (P8)', () => {
  const DAY = 86_400_000

  it('MemorySessionStore prunes aged seen + failures rows, never replay', async () => {
    const store = new MemorySessionStore()
    await store.markSeen('old-msg')
    await store.bumpFailure('old-fail')
    await store.saveBookWithSeenReplay('peer', singleSessionBook(snap), 'msg-with-replay', 'init-1')

    // Nothing is old enough yet.
    let r = await store.pruneExpired(Date.now() + 1000)
    expect(r).toEqual({ seen: 0, failures: 0 })

    // Way past both TTLs: seen + failures go, replay stays.
    r = await store.pruneExpired(Date.now() + 40 * DAY)
    expect(r.seen).toBe(2)
    expect(r.failures).toBe(1)
    expect(await store.hasSeen('old-msg')).toBe(false)
    expect(await store.hasReplayedInitial('init-1')).toBe(true)
  })

  it('IdbSessionStore prunes on the same rules and wipeAll clears every store', async () => {
    const store = new IdbSessionStore()
    await store.markSeen('m1')
    await store.bumpFailure('f1')
    await store.saveBookWithSeenReplay('peer', singleSessionBook(snap), 'm2', 'i1')

    const r = await store.pruneExpired(Date.now() + 40 * DAY)
    expect(r.seen).toBe(2)
    expect(r.failures).toBe(1)
    expect(await store.hasReplayedInitial('i1')).toBe(true)

    await store.wipeAll()
    expect(await store.loadBook('peer')).toBeNull()
    expect(await store.hasReplayedInitial('i1')).toBe(false)
    expect(await store.pendingOutbox()).toEqual([])
  })

  it('failure timestamps anchor to the FIRST failure, so an envelope being retried is not kept alive forever', async () => {
    const store = new MemorySessionStore()
    await store.bumpFailure('f')
    await store.bumpFailure('f') // later bumps must not refresh ts
    const r = await store.pruneExpired(Date.now() + 40 * DAY)
    expect(r.failures).toBe(1)
  })
})

const PEER_A = 'a'.repeat(52)
const PEER_B = 'b'.repeat(52)
const hrow = (peerId: string, id: string, dir: 'in' | 'out' = 'in', ts = 1): HistoryRow => ({
  id,
  peerId,
  dir,
  ts,
  salt: new Uint8Array(16).fill(7),
  ct: Uint8Array.from([1, 2, 3, id.charCodeAt(0)]),
})

function historySuite(name: string, make: () => SessionStore) {
  describe(`history (P10b) — ${name}`, () => {
    it('writes a history row atomically with the seen marker (normal receive)', async () => {
      const s = make()
      await s.saveBookWithSeen(PEER_A, singleSessionBook(snap), 'env-1', hrow(PEER_A, 'c1'))
      expect(await s.hasSeen('env-1')).toBe(true)
      const rows = await s.historyLoad(PEER_A)
      expect(rows.map((r) => r.id)).toEqual(['c1'])
      expect(await s.load(PEER_A)).toEqual(snap) // the book landed too
    })

    it('writes a history row atomically with seen + replay (initial receive)', async () => {
      const s = make()
      await s.saveBookWithSeenReplay(PEER_A, singleSessionBook(snap), 'env-2', 'init-2', hrow(PEER_A, 'c2'))
      expect(await s.hasSeen('env-2')).toBe(true)
      expect(await s.hasReplayedInitial('init-2')).toBe(true)
      expect((await s.historyLoad(PEER_A)).map((r) => r.id)).toEqual(['c2'])
    })

    it('writes a history row atomically with the outbox entry (send)', async () => {
      const s = make()
      await s.saveBookWithOutbox(
        PEER_A,
        singleSessionBook(snap),
        { id: 'env-3', to: PEER_A, env: {}, createdAt: 1 },
        hrow(PEER_A, 'c3', 'out'),
      )
      expect((await s.pendingOutbox()).map((e) => e.id)).toEqual(['env-3'])
      expect((await s.historyLoad(PEER_A)).map((r) => r.id)).toEqual(['c3'])
    })

    it('omitting the history row persists the book + marker but no row', async () => {
      const s = make()
      await s.saveBookWithSeen(PEER_A, singleSessionBook(snap), 'env-4')
      expect(await s.hasSeen('env-4')).toBe(true)
      expect(await s.historyLoad(PEER_A)).toEqual([])
    })

    it('scopes historyLoad to one peer and returns all via historyLoadAll', async () => {
      const s = make()
      await s.saveBookWithSeen(PEER_A, singleSessionBook(snap), 'e1', hrow(PEER_A, 'a1'))
      await s.saveBookWithSeen(PEER_A, singleSessionBook(snap), 'e2', hrow(PEER_A, 'a2'))
      await s.saveBookWithSeen(PEER_B, singleSessionBook(snap), 'e3', hrow(PEER_B, 'b1'))
      expect((await s.historyLoad(PEER_A)).map((r) => r.id).sort()).toEqual(['a1', 'a2'])
      expect((await s.historyLoad(PEER_B)).map((r) => r.id)).toEqual(['b1'])
      expect((await s.historyLoadAll()).length).toBe(3)
    })

    it('upserts by (peer,id): a redelivered row does not duplicate', async () => {
      const s = make()
      await s.saveBookWithSeen(PEER_A, singleSessionBook(snap), 'e1', hrow(PEER_A, 'dup', 'in', 1))
      await s.saveBookWithSeen(PEER_A, singleSessionBook(snap), 'e1b', hrow(PEER_A, 'dup', 'in', 2))
      const rows = await s.historyLoad(PEER_A)
      expect(rows.length).toBe(1)
      expect(rows[0].ts).toBe(2) // last write wins
    })

    it('removes exactly one row and wipeAll clears history', async () => {
      const s = make()
      await s.saveBookWithSeen(PEER_A, singleSessionBook(snap), 'e1', hrow(PEER_A, 'a1'))
      await s.saveBookWithSeen(PEER_A, singleSessionBook(snap), 'e2', hrow(PEER_A, 'a2'))
      await s.historyRemove(PEER_A, 'in', 'a1')
      expect((await s.historyLoad(PEER_A)).map((r) => r.id)).toEqual(['a2'])
      await s.wipeAll()
      expect(await s.historyLoadAll()).toEqual([])
    })

    it('keys by (peer,dir,id): an inbound and outbound row with the SAME id coexist', async () => {
      const s = make()
      // The HIGH finding: a peer-chosen inbound id must not address an outbound slot.
      await s.saveBookWithOutbox(
        PEER_A,
        singleSessionBook(snap),
        { id: 'ex', to: PEER_A, env: {}, createdAt: 1 },
        hrow(PEER_A, 'SAME', 'out', 5),
      )
      await s.saveBookWithSeen(PEER_A, singleSessionBook(snap), 'ei', hrow(PEER_A, 'SAME', 'in', 6))
      const rows = await s.historyLoad(PEER_A)
      expect(rows.length).toBe(2) // both survive; neither overwrote the other
      expect(rows.map((r) => `${r.dir}:${r.ts}`).sort()).toEqual(['in:6', 'out:5'])
      // Removing the inbound one leaves the outbound one intact.
      await s.historyRemove(PEER_A, 'in', 'SAME')
      const left = await s.historyLoad(PEER_A)
      expect(left.map((r) => r.dir)).toEqual(['out'])
    })

    it('marks an outbound row failed (survives a reload as "not sent")', async () => {
      const s = make()
      await s.saveBookWithOutbox(
        PEER_A,
        singleSessionBook(snap),
        { id: 'ex', to: PEER_A, env: {}, createdAt: 1 },
        hrow(PEER_A, 'm1', 'out', 1),
      )
      expect((await s.historyLoad(PEER_A))[0].failed).toBeUndefined()
      await s.historyMarkFailed(PEER_A, 'out', 'm1')
      expect((await s.historyLoad(PEER_A))[0].failed).toBe(true)
      // A no-op when the row is absent (wrong dir / unknown id).
      await s.historyMarkFailed(PEER_A, 'in', 'm1')
      await s.historyMarkFailed(PEER_A, 'out', 'nope')
    })
  })
}

historySuite('MemorySessionStore', () => new MemorySessionStore())
historySuite('IdbSessionStore', () => new IdbSessionStore())

describe('v4 -> v5 history-store migration (P10b)', () => {
  it('adds the history store to a v4 DB while preserving existing sessions', async () => {
    const NAME = 'nightjar-sessions'
    // Build a v4 database by hand: the five pre-P10 stores, one session row.
    await new Promise<void>((resolve, reject) => {
      const req = indexedDB.open(NAME, 4)
      req.onupgradeneeded = () => {
        const db = req.result
        for (const st of ['sessions', 'seen', 'replay', 'failures', 'outbox']) {
          if (!db.objectStoreNames.contains(st)) db.createObjectStore(st)
        }
      }
      req.onsuccess = () => {
        const db = req.result
        const tx = db.transaction('sessions', 'readwrite')
        tx.objectStore('sessions').put(singleSessionBook(snap), PEER_A)
        tx.oncomplete = () => {
          db.close()
          resolve()
        }
        tx.onerror = () => reject(tx.error)
      }
      req.onerror = () => reject(req.error)
    })

    // Opening via IdbSessionStore triggers the v4 -> v5 upgrade (adds `history`).
    const store = new IdbSessionStore()
    expect(await store.load(PEER_A)).toEqual(snap) // pre-existing session preserved
    // The new history store is usable.
    await store.saveBookWithSeen(PEER_A, singleSessionBook(snap), 'e1', hrow(PEER_A, 'a1'))
    expect((await store.historyLoad(PEER_A)).map((r) => r.id)).toEqual(['a1'])
  })
})

describe('v3 -> v4 retention-stamp migration (P8)', () => {
  it('stamps legacy seen (value 1) and failures (bare count) rows so pruning does not drop them early', async () => {
    const NAME = 'nightjar-sessions'
    // Build a v3 database by hand: seen values were `1`, failures were bare counts.
    await new Promise<void>((resolve, reject) => {
      const req = indexedDB.open(NAME, 3)
      req.onupgradeneeded = () => {
        const db = req.result
        for (const s of ['sessions', 'seen', 'replay', 'failures', 'outbox']) {
          if (!db.objectStoreNames.contains(s)) db.createObjectStore(s)
        }
      }
      req.onsuccess = () => {
        const db = req.result
        const tx = db.transaction(['seen', 'failures'], 'readwrite')
        tx.objectStore('seen').put(1, 'legacy-seen')
        tx.objectStore('failures').put(3, 'legacy-fail')
        tx.oncomplete = () => { db.close(); resolve() }
        tx.onerror = () => reject(tx.error)
      }
      req.onerror = () => reject(req.error)
    })

    // Opening via IdbSessionStore triggers the v3 -> v4 migration.
    const store = new IdbSessionStore()
    expect(await store.hasSeen('legacy-seen')).toBe(true)
    // The migration stamps rows at migration time (~now), so a prune far in the
    // FUTURE relative to that (well past ENVELOPE_TTL) drops them, but a prune at
    // "now" keeps them: proves they were stamped, not left at 0 (which would drop
    // instantly) nor treated as never-expiring.
    const keepNow = await store.pruneExpired(Date.now())
    expect(keepNow.seen).toBe(0)
    expect(keepNow.failures).toBe(0)
    expect(await store.hasSeen('legacy-seen')).toBe(true)
    const dropFuture = await store.pruneExpired(Date.now() + 40 * 86_400_000)
    expect(dropFuture.seen).toBe(1)
    expect(dropFuture.failures).toBe(1)
  })
})
