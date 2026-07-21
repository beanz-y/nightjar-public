import { describe, expect, it } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils'
import { MemoryKeyStore } from './keystore'
import { InMemoryLock } from './lock'
import {
  HISTORY_HMK_KEY,
  HistoryKeyFormatError,
  HistoryLockedError,
  HistoryStore,
} from './historyStore'
import type { HistoryRow } from './sessionStore'

const PEER = 'a'.repeat(52) // shape of a base32 userId
const OTHER = 'b'.repeat(52)
const idHex = (n: number) => bytesToHex(Uint8Array.from({ length: 16 }, () => n))

function make(): { store: HistoryStore; keys: MemoryKeyStore } {
  const keys = new MemoryKeyStore()
  return { store: new HistoryStore(keys, new InMemoryLock()), keys }
}

describe('HistoryStore (P10b at-rest history)', () => {
  it('round-trips a sealed message', async () => {
    const { store } = make()
    const row = await store.seal(idHex(1), PEER, 'out', 1700, 'hello 😀 world')
    const opened = await store.open(row)
    expect(opened).toEqual({ id: idHex(1), dir: 'out', text: 'hello 😀 world', ts: 1700 })
  })

  it('uses a FRESH salt (and thus fresh ciphertext) for every seal of the same body', async () => {
    const { store } = make()
    const a = await store.seal(idHex(1), PEER, 'in', 1, 'same body')
    const b = await store.seal(idHex(1), PEER, 'in', 1, 'same body')
    expect(bytesToHex(a.salt)).not.toBe(bytesToHex(b.salt))
    expect(bytesToHex(a.ct)).not.toBe(bytesToHex(b.ct))
    // Both still open to the same plaintext.
    expect((await store.open(a)).text).toBe('same body')
    expect((await store.open(b)).text).toBe('same body')
  })

  it('persists the HMK so a second store instance on the same keys opens the rows', async () => {
    const keys = new MemoryKeyStore()
    const s1 = new HistoryStore(keys, new InMemoryLock())
    const row = await s1.seal(idHex(2), PEER, 'in', 42, 'shared key')
    const s2 = new HistoryStore(keys, new InMemoryLock())
    expect((await s2.open(row)).text).toBe('shared key')
  })

  it('fails to open under a DIFFERENT key (independent stores)', async () => {
    const a = make()
    const b = make() // its own empty keystore -> its own generated HMK
    const row = await a.store.seal(idHex(3), PEER, 'in', 1, 'secret')
    await expect(b.store.open(row)).rejects.toThrow()
  })

  it('AAD binds the row to its peer, direction, and id: a relabelled row will not open', async () => {
    const { store } = make()
    const row = await store.seal(idHex(4), PEER, 'in', 1, 'bound')
    await expect(store.open({ ...row, peerId: OTHER })).rejects.toThrow()
    await expect(store.open({ ...row, id: idHex(5) })).rejects.toThrow()
    // Direction is bound (the HIGH finding): an 'in' row cannot be reopened as 'out'.
    await expect(store.open({ ...row, dir: 'out' })).rejects.toThrow()
    // A single flipped ciphertext byte also fails the tag.
    const tampered: HistoryRow = { ...row, ct: row.ct.slice() }
    tampered.ct[0] ^= 0xff
    await expect(store.open(tampered)).rejects.toThrow()
  })

  it('an inbound and outbound row with the SAME content id are independent ciphertexts', async () => {
    const { store } = make()
    const out = await store.seal(idHex(6), PEER, 'out', 1, 'i sent this')
    const inb = await store.seal(idHex(6), PEER, 'in', 2, 'they sent this')
    // Same id, different direction: each opens to its own body under its own dir.
    expect((await store.open(out)).text).toBe('i sent this')
    expect((await store.open(inb)).text).toBe('they sent this')
    // Cross-opening (swap the dir) fails, so one cannot masquerade as the other.
    await expect(store.open({ ...out, dir: 'in' })).rejects.toThrow()
  })

  it('generates + stores an unwrapped HMK record on first use', async () => {
    const { store, keys } = make()
    expect(await keys.get(HISTORY_HMK_KEY)).toBeNull()
    await store.ensureKey()
    const rec = await keys.get(HISTORY_HMK_KEY)
    expect(rec).not.toBeNull()
    expect(rec![0]).toBe(0x01) // plaintext tag
    expect(rec!.length).toBe(1 + 32)
  })

  it('reuses (never regenerates) an existing HMK across ensureKey calls', async () => {
    const { store, keys } = make()
    await store.ensureKey()
    const first = bytesToHex((await keys.get(HISTORY_HMK_KEY))!)
    store.lockNow() // drop from RAM
    await store.ensureKey() // must re-load, not regenerate
    expect(bytesToHex((await keys.get(HISTORY_HMK_KEY))!)).toBe(first)
  })

  it('fails closed on a wrapped HMK record (a newer app-lock build wrote it)', async () => {
    const keys = new MemoryKeyStore()
    await keys.put(HISTORY_HMK_KEY, Uint8Array.from([0x02, ...new Uint8Array(48)])) // WRAPPED tag
    const store = new HistoryStore(keys, new InMemoryLock())
    await expect(store.ensureKey()).rejects.toBeInstanceOf(HistoryLockedError)
    expect(store.isUnlocked).toBe(false)
  })

  it('rejects a malformed HMK record rather than silently regenerating', async () => {
    const keys = new MemoryKeyStore()
    await keys.put(HISTORY_HMK_KEY, Uint8Array.from([0x09, 1, 2, 3])) // unknown tag
    const store = new HistoryStore(keys, new InMemoryLock())
    await expect(store.ensureKey()).rejects.toBeInstanceOf(HistoryKeyFormatError)
  })
})
