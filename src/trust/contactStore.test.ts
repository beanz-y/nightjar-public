import { describe, expect, it } from 'vitest'
import { generateIdentity } from '../crypto/identity'
import { MemoryKeyStore } from '../storage/keystore'
import { InMemoryLock } from '../storage/lock'
import { ContactStore, KeyConflictError } from './contactStore'

const NOW = 1_700_000_000_000

function fresh() {
  return new ContactStore(new MemoryKeyStore(), new InMemoryLock())
}

describe('ContactStore.assess', () => {
  it('reports first-contact, match, and a (collision-only) conflict', async () => {
    const store = fresh()
    const a = generateIdentity()
    const b = generateIdentity()
    expect((await store.assess(a.userId, a.ikSig.publicKey)).outcome).toBe('first-contact')
    await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW)
    expect((await store.assess(a.userId, a.ikSig.publicKey)).outcome).toBe('match')
    // A different key presented for the SAME userId (only possible via a hash
    // collision or corruption) fails closed.
    expect((await store.assess(a.userId, b.ikSig.publicKey)).outcome).toBe('conflict')
  })
})

describe('ContactStore.recordFirstContact', () => {
  it('records a new contact at unverified (TOFU) and is idempotent for the same key', async () => {
    const store = fresh()
    const a = generateIdentity()
    await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW)
    await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW + 1)
    const c = await store.get(a.userId)
    expect(c?.trust).toBe('unverified')
    expect(c?.firstSeen).toBe(NOW)
    expect(await store.list()).toHaveLength(1)
  })

  it('records an invite-sourced contact at invite trust and upgrades TOFU->invite', async () => {
    const store = fresh()
    const a = generateIdentity()
    await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW) // TOFU
    expect(await store.trustLevel(a.userId)).toBe('unverified')
    await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW, 'invite')
    expect(await store.trustLevel(a.userId)).toBe('invite')
  })

  it('rejects a key that does not hash to the peer id (substituted key)', async () => {
    const store = fresh()
    const a = generateIdentity()
    const b = generateIdentity()
    await expect(store.recordFirstContact(a.userId, b.ikSig.publicKey, NOW)).rejects.toThrow(/does not match/)
  })

  it('does not downgrade a verified contact on a later TOFU record', async () => {
    const store = fresh()
    const a = generateIdentity()
    await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW)
    await store.markVerified(a.userId, NOW)
    await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW + 1)
    expect(await store.trustLevel(a.userId)).toBe('verified')
  })
})

describe('ContactStore.markVerified', () => {
  it('promotes a contact to verified with a timestamp', async () => {
    const store = fresh()
    const a = generateIdentity()
    await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW)
    await store.markVerified(a.userId, NOW + 5)
    const c = await store.get(a.userId)
    expect(c?.trust).toBe('verified')
    expect(c?.verifiedAt).toBe(NOW + 5)
  })

  it('throws when verifying an unknown peer', async () => {
    const store = fresh()
    await expect(store.markVerified(generateIdentity().userId, NOW)).rejects.toThrow(/unknown peer/)
  })
})

describe('KeyConflictError', () => {
  it('carries the peer id', () => {
    const e = new KeyConflictError('peer-x')
    expect(e).toBeInstanceOf(Error)
    expect(e.peerId).toBe('peer-x')
  })
})

describe('chat aliases (P8+, local nicknames)', () => {
  it('sets, reads, updates, and clears a peer alias without touching contacts', async () => {
    const store = new ContactStore(new MemoryKeyStore(), new InMemoryLock())
    const peer = generateIdentity().userId
    expect(await store.getAliases()).toEqual({})

    await store.setAlias(peer, '  Alice  ') // trimmed
    expect((await store.getAliases())[peer]).toBe('Alice')

    await store.setAlias(peer, 'Alice at work')
    expect((await store.getAliases())[peer]).toBe('Alice at work')

    // Aliases are independent of the contact map (a chat can be named pre-contact).
    expect(await store.list()).toEqual([])

    await store.setAlias(peer, '') // clear
    expect(await store.getAliases()).toEqual({})
  })

  it('caps alias length', async () => {
    const store = new ContactStore(new MemoryKeyStore(), new InMemoryLock())
    const peer = generateIdentity().userId
    await store.setAlias(peer, 'x'.repeat(200))
    expect((await store.getAliases())[peer]?.length).toBe(60)
  })
})

describe('ContactStore at-rest encryption (P10c)', () => {
  it('seals the contact blob under the app-lock; a fresh store re-reads it; no plaintext at rest', async () => {
    const { AppLockStore } = await import('../storage/appLockStore')
    const { hash256 } = await import('../crypto/primitives')
    const stubKdf = (s: Uint8Array, salt: Uint8Array) => hash256(new Uint8Array([...s, ...salt]))
    const keys = new MemoryKeyStore()
    const lock = new InMemoryLock()
    const appLock = new AppLockStore(keys, lock, stubKdf)
    await appLock.enroll([{ kind: 'pass', secret: 'contacts-secret' }])

    const a = generateIdentity()
    const store = new ContactStore(keys, lock, appLock)
    await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW)

    // The raw keystore blob must NOT be readable plaintext JSON.
    const raw = await keys.get('contacts.v1')
    expect(raw).not.toBeNull()
    const asText = new TextDecoder().decode(raw!)
    expect(asText).not.toContain(a.userId)
    expect(asText).not.toContain('unverified')

    // A fresh store over the same keys + (unlocked) app-lock reads it back.
    const store2 = new ContactStore(keys, lock, appLock)
    expect((await store2.get(a.userId))?.peerId).toBe(a.userId)

    // Locked -> the contacts sub-key is unavailable -> reads fail closed.
    appLock.lockNow()
    await expect(new ContactStore(keys, lock, appLock).list()).rejects.toThrow()
  })
})

describe('ContactStore pre-P10c plaintext migration', () => {
  it('adopts a legacy plaintext contacts blob under a new app-lock and re-seals it', async () => {
    const { AppLockStore } = await import('../storage/appLockStore')
    const { hash256 } = await import('../crypto/primitives')
    const { b64encode } = await import('../wire/codec')
    const stubKdf = (s: Uint8Array, salt: Uint8Array) => hash256(new Uint8Array([...s, ...salt]))
    const keys = new MemoryKeyStore()
    const lock = new InMemoryLock()

    // Simulate a pre-P10c device: contacts stored as PLAINTEXT JSON.
    const a = generateIdentity()
    const plain = {
      [a.userId]: { peerId: a.userId, ikSig: b64encode(a.ikSig.publicKey), trust: 'unverified', firstSeen: NOW, verifiedAt: null },
    }
    await keys.put('contacts.v1', new TextEncoder().encode(JSON.stringify(plain)))

    // The user enrolls an app-lock and opens the store.
    const appLock = new AppLockStore(keys, lock, stubKdf)
    await appLock.enroll([{ kind: 'pass', secret: 'upgrade-secret' }])
    const store = new ContactStore(keys, lock, appLock)

    // The legacy contact is readable (migration), not a crash.
    expect((await store.get(a.userId))?.peerId).toBe(a.userId)
    // The on-disk blob is now sealed (no longer plaintext JSON).
    const raw = await keys.get('contacts.v1')
    const stillPlain = (() => {
      try {
        return typeof JSON.parse(new TextDecoder().decode(raw!)) === 'object'
      } catch {
        return false
      }
    })()
    expect(stillPlain).toBe(false)
    // A fresh store reads the now-sealed blob.
    expect((await new ContactStore(keys, lock, appLock).get(a.userId))?.peerId).toBe(a.userId)
  })
})

describe('ContactStore app-lock reset (forgot secret)', () => {
  it('wipeLocalData lets a re-enrolled lock (new LDK) start without a decrypt crash', async () => {
    const { AppLockStore } = await import('../storage/appLockStore')
    const { hash256 } = await import('../crypto/primitives')
    const stubKdf = (s: Uint8Array, salt: Uint8Array) => hash256(new Uint8Array([...s, ...salt]))
    const keys = new MemoryKeyStore()
    const lock = new InMemoryLock()

    // First lock + a sealed contact.
    const appLock = new AppLockStore(keys, lock, stubKdf)
    await appLock.enroll([{ kind: 'pass', secret: 'first-secret' }])
    const a = generateIdentity()
    const store = new ContactStore(keys, lock, appLock)
    await store.recordFirstContact(a.userId, a.ikSig.publicKey, NOW)
    expect((await store.get(a.userId))?.peerId).toBe(a.userId)

    // Forgot-secret reset: wipe local contact data, then reset the lock.
    await store.wipeLocalData()
    await appLock.reset()

    // Re-enroll a NEW lock (fresh LDK) and open the store: no crash, empty list.
    await appLock.enroll([{ kind: 'pin', secret: '445566' }])
    const store2 = new ContactStore(keys, lock, appLock)
    await expect(store2.list()).resolves.toEqual([])
    await expect(store2.getAliases()).resolves.toEqual({})
    // And the store is usable again (records under the new LDK).
    await store2.recordFirstContact(a.userId, a.ikSig.publicKey, NOW)
    expect((await store2.get(a.userId))?.peerId).toBe(a.userId)
  })
})
