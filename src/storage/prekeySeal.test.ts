// The prekey private halves, sealed at rest (P11).
//
// These are the signed-prekey and one-time-prekey PRIVATE keys, which is exactly
// what is needed to answer, and therefore decrypt, an X3DH initial message waiting
// at the relay. Leaving them in cleartext left a whole class of INCOMING
// conversation readable from an image of a locked device, and the sealed session
// store does not cover it: those messages have no session yet.
//
// Sealing needs no boot re-ordering, because PrekeyStore is only ever constructed
// inside activate(), after the Local Data Key is resident.

import { describe, expect, it } from 'vitest'
import { hash256 } from '../crypto/primitives'
import { AppLockStore } from './appLockStore'
import { MemoryKeyStore } from './keystore'
import { InMemoryLock } from './lock'
import { PREKEYS_KEY, PrekeyStore } from './prekeyStore'

const stubKdf = (s: Uint8Array, salt: Uint8Array) => hash256(new Uint8Array([...s, ...salt]))
const encoder = new TextEncoder()
const decoder = new TextDecoder()

async function unlocked() {
  const keys = new MemoryKeyStore()
  const lock = new InMemoryLock()
  const appLock = new AppLockStore(keys, lock, stubKdf)
  await appLock.enroll([{ kind: 'pass', secret: 'a good long passphrase' }])
  return { keys, lock, appLock }
}

const material = () => ({
  spk: {
    id: 1,
    createdAt: 1000,
    expiry: 2000,
    pub: new Uint8Array(32).fill(7),
    sig: new Uint8Array(64).fill(8),
  },
  spkPrivById: new Map([[1, new Uint8Array(32).fill(9)]]),
  opks: [{ id: 1, pub: new Uint8Array(32).fill(1) }],
  opkPrivById: new Map([[1, new Uint8Array(32).fill(2)]]),
})

describe('prekey privates at rest', () => {
  it('stores nothing readable, and round-trips through the seal', async () => {
    const { keys, lock, appLock } = await unlocked()
    const store = new PrekeyStore(keys, lock, appLock)
    await store.setFromRegistration(material())

    const raw = await keys.get(PREKEYS_KEY)
    expect(raw).not.toBeNull()
    // The give-away in the old format was that the blob was JSON.
    expect(() => JSON.parse(decoder.decode(raw!))).toThrow()

    const responder = await store.responderKeys()
    expect(responder.spkPrivById.get(1)).toEqual(new Uint8Array(32).fill(9))
    expect(responder.opkPrivById.get(1)).toEqual(new Uint8Array(32).fill(2))
  })

  it('adopts and re-seals a pre-P11 plaintext blob on first unlock', async () => {
    // A device upgrading into P11 has one of these. It must be adopted, not thrown
    // away and not left in the clear.
    const { keys, lock, appLock } = await unlocked()
    const legacy = new PrekeyStore(keys, lock) // no app-lock: writes plaintext JSON
    await legacy.setFromRegistration(material())
    const before = await keys.get(PREKEYS_KEY)
    expect(JSON.parse(decoder.decode(before!))).toBeTypeOf('object') // plaintext today

    const sealed = new PrekeyStore(keys, lock, appLock)
    const responder = await sealed.responderKeys()
    expect(responder.spkPrivById.get(1)).toEqual(new Uint8Array(32).fill(9)) // adopted

    const after = await keys.get(PREKEYS_KEY)
    expect(() => JSON.parse(decoder.decode(after!))).toThrow() // and re-sealed on disk
    // Still readable after the migration, through the seal this time.
    expect((await sealed.responderKeys()).opkPrivById.get(1)).toEqual(new Uint8Array(32).fill(2))
  })

  it('refuses a blob it cannot open rather than treating it as absent', async () => {
    // "No prekeys" would send the app down a re-registration path on what may be a
    // transient failure; a throw is recoverable, a silent purge is not.
    const { keys, lock, appLock } = await unlocked()
    const store = new PrekeyStore(keys, lock, appLock)
    await store.setFromRegistration(material())

    const other = await unlocked() // a different LDK
    const wrongKey = new PrekeyStore(keys, other.lock, other.appLock)
    await expect(wrongKey.responderKeys()).rejects.toThrow()

    // A blob that is neither valid JSON nor openable is also refused, not adopted.
    await keys.put(PREKEYS_KEY, encoder.encode('not json, not sealed'))
    await expect(new PrekeyStore(keys, lock, appLock).responderKeys()).rejects.toThrow()
  })
})
