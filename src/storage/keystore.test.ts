import 'fake-indexeddb/auto'
import { IDBFactory } from 'fake-indexeddb'
import { beforeEach, describe, it, expect } from 'vitest'
import { IdbKeyStore, type KeyStore, MemoryKeyStore } from './keystore'
import { bootstrapIdentity } from './identityStore'
import { InMemoryLock } from './lock'
import { MemorySentinel } from './persist'
import { verifyIdkbind } from '../crypto/identity'

// Reset the process-global fake IndexedDB before every test so the shared
// 'nightjar' db never leaks state (e.g. 'identity.v1') across tests.
beforeEach(() => {
  globalThis.indexedDB = new IDBFactory()
})

function suite(name: string, makeStore: () => KeyStore) {
  describe(name, () => {
    it('put / get / delete / keys', async () => {
      const s = makeStore()
      expect(await s.get('x')).toBeNull()
      await s.put('x', new Uint8Array([1, 2, 3]))
      const v = await s.get('x')
      expect(v).not.toBeNull()
      expect(Array.from(v!)).toEqual([1, 2, 3])
      expect(await s.keys()).toContain('x')
      await s.delete('x')
      expect(await s.get('x')).toBeNull()
    })

    it('stores an independent snapshot (mutating the input does not change stored bytes)', async () => {
      const s = makeStore()
      const buf = new Uint8Array([9])
      await s.put('k', buf)
      buf[0] = 0
      const v = await s.get('k')
      expect(v![0]).toBe(9)
    })

    it('bootstrapIdentity creates then loads the same identity', async () => {
      const s = makeStore()
      const sentinel = new MemorySentinel()
      const lock = new InMemoryLock()
      const first = await bootstrapIdentity(s, sentinel, lock)
      expect(first.state).toBe('first-run')
      const second = await bootstrapIdentity(s, sentinel, lock)
      expect(second.state).toBe('loaded')
      expect(second.identity?.userId).toBe(first.identity?.userId)
      expect(
        verifyIdkbind(
          second.identity!.ikSig.publicKey,
          second.identity!.ikDh.publicKey,
          second.identity!.idkbindSig,
        ),
      ).toBe(true)
    })
  })
}

suite('MemoryKeyStore', () => new MemoryKeyStore())
// Cross-test isolation is not needed here: the identity test uses first-create
// semantics on the 'identity.v1' key, which no other test writes.
suite('IdbKeyStore', () => new IdbKeyStore())
