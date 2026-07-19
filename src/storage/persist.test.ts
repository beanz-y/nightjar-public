import { describe, it, expect } from 'vitest'
import { generateIdentity, serializeIdentity } from '../crypto/identity'
import { MemoryKeyStore } from './keystore'
import { IDENTITY_KEY, bootstrapIdentity } from './identityStore'
import { InMemoryLock } from './lock'
import { MemorySentinel, detectStartupState, requestPersistentStorage } from './persist'

describe('detectStartupState', () => {
  it('classifies loaded / first-run / evicted', async () => {
    const s = new MemorySentinel()
    expect(await detectStartupState(true, s)).toBe('loaded')
    expect(await detectStartupState(false, s)).toBe('first-run')
    await s.mark()
    expect(await detectStartupState(false, s)).toBe('evicted-needs-restore')
    expect(await detectStartupState(true, s)).toBe('loaded') // identity present wins
  })
})

describe('bootstrapIdentity', () => {
  it('first run generates an identity and marks the sentinel', async () => {
    const store = new MemoryKeyStore()
    const sentinel = new MemorySentinel()
    const boot = await bootstrapIdentity(store, sentinel, new InMemoryLock())
    expect(boot.state).toBe('first-run')
    expect(boot.identity).not.toBeNull()
    expect(await sentinel.exists()).toBe(true)
  })

  it('a second start loads the same identity', async () => {
    const store = new MemoryKeyStore()
    const sentinel = new MemorySentinel()
    const lock = new InMemoryLock()
    const first = await bootstrapIdentity(store, sentinel, lock)
    const second = await bootstrapIdentity(store, sentinel, lock)
    expect(second.state).toBe('loaded')
    expect(second.identity?.userId).toBe(first.identity?.userId)
  })

  it('self-heals the sentinel for an existing identity, so a later eviction routes to restore', async () => {
    // Identity present but the sentinel is NOT yet marked: the 'loaded' path must
    // (re)mark it, otherwise a later eviction would misclassify as first-run.
    const store = new MemoryKeyStore()
    const sentinel = new MemorySentinel()
    await store.put(IDENTITY_KEY, serializeIdentity(generateIdentity()))
    expect(await sentinel.exists()).toBe(false)
    const boot = await bootstrapIdentity(store, sentinel, new InMemoryLock())
    expect(boot.state).toBe('loaded')
    expect(await sentinel.exists()).toBe(true) // self-healed
    // Simulate eviction of only the store: the (now-marked) sentinel routes to restore.
    await store.delete(IDENTITY_KEY)
    const after = await bootstrapIdentity(store, sentinel, new InMemoryLock())
    expect(after.state).toBe('evicted-needs-restore')
    expect(after.identity).toBeNull()
  })

  it('an evicted store with a marked sentinel routes to restore and does NOT regenerate', async () => {
    const store = new MemoryKeyStore()
    const sentinel = new MemorySentinel()
    await sentinel.mark() // we registered before...
    const boot = await bootstrapIdentity(store, sentinel, new InMemoryLock()) // ...but the store is empty
    expect(boot.state).toBe('evicted-needs-restore')
    expect(boot.identity).toBeNull()
  })
})

describe('requestPersistentStorage', () => {
  it('returns false when navigator.storage is unavailable (e.g. Node)', async () => {
    expect(await requestPersistentStorage()).toBe(false)
  })
})
