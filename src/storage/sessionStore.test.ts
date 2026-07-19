import 'fake-indexeddb/auto'
import { IDBFactory } from 'fake-indexeddb'
import { beforeEach, describe, it, expect } from 'vitest'
import type { RatchetSnapshot } from '../crypto/ratchet'
import { IdbSessionStore, MemorySessionStore, type SessionStore } from './sessionStore'

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
