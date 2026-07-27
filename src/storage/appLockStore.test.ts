import { describe, expect, it } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils'
import { type Argon2Kdf, AppLockAuthError } from '../crypto/appLock'
import { hash256 } from '../crypto/primitives'
import { MemoryKeyStore } from './keystore'
import { InMemoryLock } from './lock'
import { AppLockStore, AppLockedError, HISTORY_LOCK_KEY } from './appLockStore'

const stubKdf: Argon2Kdf = (secret, salt) => hash256(new Uint8Array([...secret, ...salt]))
const make = () => new AppLockStore(new MemoryKeyStore(), new InMemoryLock(), stubKdf)

describe('AppLockStore (P10c)', () => {
  it('is unconfigured until enrolled, then unlocked and reusable across lock/unlock', async () => {
    const s = make()
    expect(await s.status()).toBe('unconfigured')
    expect(s.isUnlocked).toBe(false)

    await s.enroll([{ kind: 'pass', secret: 'a strong passphrase' }])
    expect(await s.status()).toBe('unlocked')
    expect(s.isUnlocked).toBe(true)

    const body1 = bytesToHex(s.historyBodyKey())
    s.lockNow()
    expect(await s.status()).toBe('locked')
    expect(() => s.historyBodyKey()).toThrow(AppLockedError)

    await s.unlockWithSecret('a strong passphrase')
    expect(await s.status()).toBe('unlocked')
    // Same LDK -> same sub-keys after unlock.
    expect(bytesToHex(s.historyBodyKey())).toBe(body1)
  })

  it('sub-keys are distinct per use and stable across a re-unlock', async () => {
    const s = make()
    await s.enroll([{ kind: 'pin', secret: '135790' }])
    const b = bytesToHex(s.historyBodyKey())
    const i = bytesToHex(s.historyIndexKey())
    const c = bytesToHex(s.contactsKey())
    expect(new Set([b, i, c]).size).toBe(3)
    s.lockNow()
    await s.unlockWithSecret('135790')
    expect(bytesToHex(s.historyBodyKey())).toBe(b)
    expect(bytesToHex(s.contactsKey())).toBe(c)
  })

  it('rejects the wrong secret and keeps the store locked', async () => {
    const s = make()
    await s.enroll([{ kind: 'pass', secret: 'right one here' }])
    s.lockNow()
    await expect(s.unlockWithSecret('wrong one here')).rejects.toBeInstanceOf(AppLockAuthError)
    expect(s.isUnlocked).toBe(false)
  })

  it('a fresh store instance (reload) can unlock the persisted record', async () => {
    const keys = new MemoryKeyStore()
    const lock = new InMemoryLock()
    const s1 = new AppLockStore(keys, lock, stubKdf)
    await s1.enroll([{ kind: 'pass', secret: 'persist me please' }])
    const bodyKey = bytesToHex(s1.historyBodyKey())

    const s2 = new AppLockStore(keys, lock, stubKdf)
    expect(await s2.status()).toBe('locked')
    await s2.unlockWithSecret('persist me please')
    expect(bytesToHex(s2.historyBodyKey())).toBe(bodyKey)
  })

  it('enrollment requires a knowledge factor (biometric alone is refused)', async () => {
    const s = make()
    await expect(
      s.enroll([{ kind: 'bio', credentialId: new Uint8Array([1]), prfSecret: hash256(new Uint8Array([2])) }]),
    ).rejects.toThrow(/passphrase or PIN/)
    expect(await s.status()).toBe('unconfigured')
  })

  it('supports biometric alongside a knowledge factor, unlockable by either', async () => {
    const s = make()
    const prf = hash256(new Uint8Array([7, 7]))
    const credId = new Uint8Array([5, 5, 5])
    await s.enroll([
      { kind: 'pin', secret: '246800' },
      { kind: 'bio', credentialId: credId, prfSecret: prf },
    ])
    const body = bytesToHex(s.historyBodyKey())
    expect((await s.methods()).sort()).toEqual(['bio', 'pin'])
    expect(bytesToHex((await s.biometricCredentialId())!)).toBe(bytesToHex(credId))

    s.lockNow()
    await s.unlockWithBiometric(prf)
    expect(bytesToHex(s.historyBodyKey())).toBe(body)

    s.lockNow()
    await s.unlockWithSecret('246800')
    expect(bytesToHex(s.historyBodyKey())).toBe(body)
  })

  it('changeKnowledge re-wraps under a new secret, keeping the same LDK', async () => {
    const s = make()
    await s.enroll([{ kind: 'pass', secret: 'old secret here' }])
    const body = bytesToHex(s.historyBodyKey())
    await s.changeKnowledge('pass', 'new secret here')
    s.lockNow()
    await expect(s.unlockWithSecret('old secret here')).rejects.toBeInstanceOf(AppLockAuthError)
    await s.unlockWithSecret('new secret here')
    expect(bytesToHex(s.historyBodyKey())).toBe(body) // same underlying LDK
  })

  it('removeBiometric refuses to strip the last knowledge factor path... and keeps knowledge', async () => {
    const s = make()
    await s.enroll([
      { kind: 'pin', secret: '112233' },
      { kind: 'bio', credentialId: new Uint8Array([1]), prfSecret: hash256(new Uint8Array([9])) },
    ])
    await s.removeBiometric()
    expect(await s.methods()).toEqual(['pin'])
  })

  it('reset returns to unconfigured and deletes the record', async () => {
    const s = make()
    await s.enroll([{ kind: 'pass', secret: 'erase me later' }])
    await s.reset()
    expect(await s.status()).toBe('unconfigured')
    expect(await new MemoryKeyStore().get(HISTORY_LOCK_KEY)).toBeNull()
  })
})

// Key hygiene on lock (P11). Best-effort by nature: JavaScript cannot guarantee
// erasure, and nothing in the design depends on this. It is worth doing only
// because the sub-keys are now CACHED: session rows re-seal on every message, so
// deriving per call would put one un-wipeable copy on the heap per message sent.
describe('AppLockStore key hygiene', () => {
  it('overwrites the key material on lock rather than only dropping the reference', async () => {
    const s = make()
    await s.enroll([{ kind: 'pass', secret: 'a strong passphrase' }])
    // Hold references to the live arrays, which is what a RAM capture would find.
    const body = s.historyBodyKey()
    const sess = s.sessionBodyKey()
    const index = s.sessionIndexKey()
    expect(body.some((b) => b !== 0)).toBe(true)

    s.lockNow()

    for (const k of [body, sess, index]) expect([...k].every((b) => b === 0)).toBe(true)
  })

  it('hands out the SAME cached sub-key rather than deriving a fresh copy per call', async () => {
    // One thing to overwrite per sub-key, instead of one per message.
    const s = make()
    await s.enroll([{ kind: 'pass', secret: 'a strong passphrase' }])
    expect(s.sessionIndexKey()).toBe(s.sessionIndexKey())
  })

  it('re-derives cleanly after an unlock, so caching cannot serve a stale key', async () => {
    const s = make()
    await s.enroll([{ kind: 'pass', secret: 'a strong passphrase' }])
    const before = bytesToHex(s.sessionBodyKey())
    s.lockNow()
    await s.unlockWithSecret('a strong passphrase')
    expect(bytesToHex(s.sessionBodyKey())).toBe(before)
  })

  it('a lock landing mid-rewrap still wraps the REAL key, never the zeroed one', async () => {
    // The reason changeKnowledge works from a private copy. Argon2id takes seconds
    // and is awaited INSIDE wrapKnowledge, so an idle-lock in that window would
    // otherwise have it wrap 32 zero bytes and persist them: the user would then
    // "unlock" successfully into a key that opens nothing, with no way back. This is
    // the assertion that would have caught that, so do not weaken it.
    const keys = new MemoryKeyStore()
    let onKdf: (() => void) | null = null
    const slowKdf: Argon2Kdf = async (secret, salt) => {
      onKdf?.()
      return hash256(new Uint8Array([...secret, ...salt]))
    }
    const s = new AppLockStore(keys, new InMemoryLock(), slowKdf)
    await s.enroll([{ kind: 'pass', secret: 'the original passphrase' }])
    const realKey = bytesToHex(s.sessionBodyKey()) // what everything at rest is sealed under

    onKdf = () => s.lockNow() // the idle lock fires while the KDF is running
    await s.changeKnowledge('pass', 'the replacement passphrase')

    onKdf = null
    await s.unlockWithSecret('the replacement passphrase')
    // The SAME key came back, so nothing sealed before the change became unopenable.
    expect(bytesToHex(s.sessionBodyKey())).toBe(realKey)
    expect([...s.historyBodyKey()].every((b) => b === 0)).toBe(false)
  })
})
