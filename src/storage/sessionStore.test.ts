import 'fake-indexeddb/auto'
import { IDBFactory } from 'fake-indexeddb'
import { beforeEach, describe, it, expect } from 'vitest'
import type { RatchetSnapshot } from '../crypto/ratchet'
import { IdbSessionStore, MemorySessionStore, type SessionStore, singleSessionBook } from './sessionStore'

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
