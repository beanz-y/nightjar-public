import { describe, expect, it } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils'
import { hash256 } from '../crypto/primitives'
import { AppLockStore, AppLockedError } from './appLockStore'
import { HistoryStore, type HistoryMessage } from './historyStore'
import { MemoryKeyStore } from './keystore'
import { InMemoryLock } from './lock'

const stubKdf = (s: Uint8Array, salt: Uint8Array) => hash256(new Uint8Array([...s, ...salt]))
const PEER = 'a'.repeat(52)
const OTHER = 'b'.repeat(52)

async function make(): Promise<{ appLock: AppLockStore; hist: HistoryStore }> {
  const keys = new MemoryKeyStore()
  const lock = new InMemoryLock()
  const appLock = new AppLockStore(keys, lock, stubKdf)
  await appLock.enroll([{ kind: 'pass', secret: 'test-passphrase' }])
  return { appLock, hist: new HistoryStore(appLock) }
}

const msg = (id: string, dir: 'in' | 'out', ts: number, text: string): HistoryMessage => ({ id, peerId: PEER, dir, ts, text })

describe('HistoryStore (P10c full-message at-rest)', () => {
  it('round-trips a full message (all metadata sealed)', async () => {
    const { hist } = await make()
    const m = hist.open(hist.seal(msg('c1', 'out', 100, 'hello 😀 world')))
    expect(m).toEqual({ id: 'c1', peerId: PEER, dir: 'out', ts: 100, text: 'hello 😀 world' })
  })

  it('storage key is opaque (64-hex), deterministic, and peer/dir/id-sensitive', async () => {
    const { hist } = await make()
    const k = hist.storageKey(PEER, 'in', 'content-id-one')
    expect(k).toMatch(/^[0-9a-f]{64}$/) // an HMAC digest, not a readable key
    expect(k).toBe(hist.storageKey(PEER, 'in', 'content-id-one')) // deterministic
    expect(k).not.toContain(PEER) // reveals no peer id
    expect(hist.storageKey(PEER, 'out', 'content-id-one')).not.toBe(k) // direction matters
    expect(hist.storageKey(PEER, 'in', 'content-id-two')).not.toBe(k) // id matters
    expect(hist.storageKey(OTHER, 'in', 'content-id-one')).not.toBe(k) // peer matters
  })

  it('uses a fresh salt per seal (same message -> same key, different ciphertext)', async () => {
    const { hist } = await make()
    const a = hist.seal(msg('c1', 'in', 1, 'x'))
    const b = hist.seal(msg('c1', 'in', 1, 'x'))
    expect(a.key).toBe(b.key)
    expect(bytesToHex(a.salt)).not.toBe(bytesToHex(b.salt))
    expect(bytesToHex(a.ct)).not.toBe(bytesToHex(b.ct))
    expect(hist.open(a).text).toBe('x')
    expect(hist.open(b).text).toBe('x')
  })

  it('does not open under a different LDK', async () => {
    const a = await make()
    const b = await make()
    const rec = a.hist.seal(msg('c1', 'in', 1, 'secret'))
    expect(() => b.hist.open(rec)).toThrow()
  })

  it('AAD binds the storage key: a relabelled or tampered record will not open', async () => {
    const { hist } = await make()
    const rec = hist.seal(msg('c1', 'in', 1, 'bound'))
    expect(() => hist.open({ ...rec, key: hist.storageKey(PEER, 'in', 'other') })).toThrow()
    const tampered = { ...rec, ct: rec.ct.slice() }
    tampered.ct[0] ^= 0xff
    expect(() => hist.open(tampered)).toThrow()
  })

  it('fails closed when locked: seal/open/storageKey throw, no plaintext path', async () => {
    const { appLock, hist } = await make()
    const rec = hist.seal(msg('c1', 'in', 1, 'x'))
    appLock.lockNow()
    expect(() => hist.seal(msg('c2', 'in', 1, 'y'))).toThrow(AppLockedError)
    expect(() => hist.storageKey(PEER, 'in', 'c1')).toThrow(AppLockedError)
    expect(() => hist.open(rec)).toThrow(AppLockedError)
    expect(hist.isUnlocked).toBe(false)
  })
})
