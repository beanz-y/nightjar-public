import 'fake-indexeddb/auto'
import { afterEach, describe, expect, it } from 'vitest'
import { IDBFactory } from 'fake-indexeddb'
import type { RatchetSnapshot } from '../crypto/ratchet'
import {
  IdbSessionStore,
  MemorySessionStore,
  type OutboxEntry,
  type SessionBook,
  type SessionStore,
  singleSessionBook,
} from './sessionStore'

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

const book = (rk: string): SessionBook => singleSessionBook(snap(rk), 1)

// Reset the fake IndexedDB between tests so the DB (and its version) start clean.
afterEach(() => {
  globalThis.indexedDB = new IDBFactory()
})

function suite(name: string, make: () => SessionStore) {
  describe(name, () => {
    it('round-trips a session book, and load() returns the current snapshot', async () => {
      const store = make()
      expect(await store.loadBook('bob')).toBeNull()
      const b = book('bb')
      await store.saveBook('bob', b)
      expect(await store.loadBook('bob')).toEqual(b)
      expect((await store.load('bob'))?.rk).toBe('bb')
    })

    it('records a seen message id atomically with the book', async () => {
      const store = make()
      expect(await store.hasSeen('m1')).toBe(false)
      await store.saveBookWithSeen('alice', book('aa'), 'm1')
      expect(await store.hasSeen('m1')).toBe(true)
      expect((await store.load('alice'))?.rk).toBe('aa')
    })

    it('records the replay-guard id and the seen id together on an initial accept', async () => {
      const store = make()
      expect(await store.hasReplayedInitial('init-1')).toBe(false)
      await store.saveBookWithSeenReplay('bob', book('bb'), 'm1', 'init-1')
      expect(await store.hasReplayedInitial('init-1')).toBe(true)
      expect(await store.hasSeen('m1')).toBe(true)
      expect((await store.load('bob'))?.rk).toBe('bb')
    })

    it('queues an outbox entry with the book and drains it on remove', async () => {
      const store = make()
      const entry: OutboxEntry = { id: 'o1', to: 'carol', env: { any: 'thing' }, createdAt: 123 }
      await store.saveBookWithOutbox('carol', book('cc'), entry)
      expect((await store.load('carol'))?.rk).toBe('cc')
      const pending = await store.pendingOutbox()
      expect(pending).toHaveLength(1)
      expect(pending[0].id).toBe('o1')
      await store.removeOutbox('o1')
      expect(await store.pendingOutbox()).toHaveLength(0)
    })

    it('keeps seen, replay, and outbox independent of each other', async () => {
      const store = make()
      await store.saveBookWithSeen('p', book('01'), 'seen-only')
      expect(await store.hasReplayedInitial('seen-only')).toBe(false)
      await store.saveBookWithOutbox('p', book('02'), { id: 'ob', to: 'p', env: {}, createdAt: 1 })
      expect(await store.hasSeen('ob')).toBe(false)
    })

    it('markSeen consumes an id without touching any session', async () => {
      const store = make()
      await store.markSeen('dropped-1')
      expect(await store.hasSeen('dropped-1')).toBe(true)
      expect(await store.loadBook('anyone')).toBeNull()
    })

    it('bumpFailure counts up per id and clearFailure resets it', async () => {
      const store = make()
      expect(await store.bumpFailure('x')).toBe(1)
      expect(await store.bumpFailure('x')).toBe(2)
      expect(await store.bumpFailure('y')).toBe(1) // independent per id
      await store.clearFailure('x')
      expect(await store.bumpFailure('x')).toBe(1) // reset
    })

    it('save() replaces the current session snapshot, keeping the book shape', async () => {
      const store = make()
      await store.save('d', snap('11'))
      const first = await store.loadBook('d')
      expect(first?.sessions).toHaveLength(1)
      await store.save('d', snap('22'))
      const second = await store.loadBook('d')
      expect(second?.sessions).toHaveLength(1)
      expect(second?.currentId).toBe(first?.currentId) // same slot, not a new session
      expect((await store.load('d'))?.rk).toBe('22')
    })

    it('lists and deletes peer slots', async () => {
      const store = make()
      await store.saveBook('a', book('aa'))
      await store.saveBook('b', book('bb'))
      expect((await store.list()).sort()).toEqual(['a', 'b'])
      await store.delete('a')
      expect(await store.loadBook('a')).toBeNull()
      expect(await store.list()).toEqual(['b'])
    })
  })
}

suite('MemorySessionStore', () => new MemorySessionStore())
suite('IdbSessionStore', () => new IdbSessionStore())
