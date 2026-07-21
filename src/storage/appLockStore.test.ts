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
