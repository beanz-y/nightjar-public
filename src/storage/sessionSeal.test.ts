// Sealing the ratchet sessions and the send queue at rest (P11), and the one-time
// migration that gets an existing device there.
//
// The migration is the single most dangerous operation in the app. Ratchet state
// cannot be recovered or re-derived and there is no server-side copy, so a bug does
// not degrade, it permanently destroys every conversation on the device. The whole
// safety argument is that the rewrite happens in ONE IndexedDB transaction with no
// await inside it, which makes "partially migrated" a state that cannot exist. The
// abort tests below are what stop that being merely a claim about the code.

import 'fake-indexeddb/auto'
import { IDBFactory } from 'fake-indexeddb'
import { readFileSync } from 'node:fs'
import { beforeEach, describe, expect, it } from 'vitest'
import { SESSION_SEAL_VERSION } from '../crypto/constants'
import { hash256 } from '../crypto/primitives'
import type { RatchetSnapshot } from '../crypto/ratchet'
import { AppLockStore, AppLockedError } from './appLockStore'
import { MemoryKeyStore } from './keystore'
import { InMemoryLock } from './lock'
import { SessionSealError, SessionSealer } from './sessionSeal'
import { IdbSessionStore, type OutboxEntry, type SealedSessionRecord, singleSessionBook } from './sessionStore'

beforeEach(() => {
  globalThis.indexedDB = new IDBFactory()
})

const DB = 'nightjar-sessions'
const PEER_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
const PEER_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
const stubKdf = (s: Uint8Array, salt: Uint8Array) => hash256(new Uint8Array([...s, ...salt]))

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

const entry = (id: string, to: string, createdAt: number): OutboxEntry => ({ id, to, env: { k: id }, createdAt })

async function unlockedSealer(): Promise<{ sealer: SessionSealer; appLock: AppLockStore }> {
  const keys = new MemoryKeyStore()
  const lock = new InMemoryLock()
  const appLock = new AppLockStore(keys, lock, stubKdf)
  await appLock.enroll([{ kind: 'pass', secret: 'open sesame please' }])
  return { sealer: new SessionSealer(appLock), appLock }
}

/** Build a pre-P11 (v6) database by hand: cleartext session rows keyed by peerId,
 *  cleartext outbox entries. This is what a real device upgrading into P11 holds. */
async function legacyV6(rows: Array<[string, unknown]>, outbox: OutboxEntry[]): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const req = indexedDB.open(DB, 6)
    req.onupgradeneeded = () => {
      const db = req.result
      for (const st of ['sessions', 'seen', 'replay', 'failures', 'outbox', 'history', 'tombstones']) {
        if (!db.objectStoreNames.contains(st)) db.createObjectStore(st)
      }
    }
    req.onsuccess = () => {
      const db = req.result
      const tx = db.transaction(['sessions', 'outbox'], 'readwrite')
      for (const [k, v] of rows) tx.objectStore('sessions').put(v, k)
      for (const e of outbox) tx.objectStore('outbox').put(e, e.id)
      tx.oncomplete = () => {
        db.close()
        resolve()
      }
      tx.onerror = () => reject(tx.error)
    }
    req.onerror = () => reject(req.error)
  })
}

/** Read the raw sessions store, bypassing the store's own sealing. */
async function rawSessions(): Promise<{ keys: string[]; values: unknown[]; marker: unknown }> {
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const req = indexedDB.open(DB)
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
  const out = await new Promise<{ keys: string[]; values: unknown[]; marker: unknown }>((resolve, reject) => {
    const t = db.transaction(['sessions', 'meta'], 'readonly')
    const k = t.objectStore('sessions').getAllKeys()
    const v = t.objectStore('sessions').getAll()
    const m = t.objectStore('meta').get('sealVersion')
    t.oncomplete = () => resolve({ keys: (k.result ?? []).map(String), values: v.result ?? [], marker: m.result })
    t.onerror = () => reject(t.error)
  })
  db.close()
  return out
}

describe('session sealing at rest (P11)', () => {
  it('migrates a v6 device: every row sealed, opaque-keyed, and byte-for-byte recoverable', async () => {
    const bookA = singleSessionBook(snap, 1000)
    const bookB = singleSessionBook(snap, 2000)
    await legacyV6(
      [
        [PEER_A, bookA],
        [PEER_B, bookB],
      ],
      [entry('e1', PEER_A, 500), entry('e2', PEER_B, 400)],
    )

    const { sealer } = await unlockedSealer()
    const store = new IdbSessionStore()
    store.useSealer(sealer)
    await store.migrateToSealed()

    const raw = await rawSessions()
    expect(raw.marker).toBe(SESSION_SEAL_VERSION)
    // No key names anybody any more, and every key is an HMAC in hex.
    expect(raw.keys).toHaveLength(2)
    expect(raw.keys).not.toContain(PEER_A)
    expect(raw.keys).not.toContain(PEER_B)
    for (const k of raw.keys) expect(k).toMatch(/^[0-9a-f]{64}$/)
    // The value carries no copy of its own key: nothing authoritative-but-wrong to
    // trust, so a row moved to another slot cannot authenticate (see below).
    for (const v of raw.values) expect(v).not.toHaveProperty('key')
    // And it is genuinely the same data.
    expect(await store.loadBook(PEER_A)).toEqual(bookA)
    expect(await store.loadBook(PEER_B)).toEqual(bookB)
    const pending = await store.pendingOutbox()
    expect(pending.unreadable).toEqual([])
    expect(pending.entries.map((e) => e.id)).toEqual(['e2', 'e1']) // oldest first
    expect(pending.entries[1]).toEqual(entry('e1', PEER_A, 500))
  })

  it('is idempotent: a second run rewrites nothing', async () => {
    await legacyV6([[PEER_A, singleSessionBook(snap, 1000)]], [])
    const { sealer } = await unlockedSealer()
    const store = new IdbSessionStore()
    store.useSealer(sealer)
    await store.migrateToSealed()
    const first = await rawSessions()

    await store.migrateToSealed()

    const second = await rawSessions()
    // A re-seal would draw a fresh salt, so identical bytes prove nothing was
    // rewritten rather than merely that the data still round-trips.
    expect(second.values).toEqual(first.values)
    expect(second.keys).toEqual(first.keys)
  })

  it('ABORTS WHOLE on a seal failure, leaving every original row untouched', async () => {
    // The one that matters. A partial rewrite is the state that destroys a device.
    const bookA = singleSessionBook(snap, 1000)
    const bookB = singleSessionBook(snap, 2000)
    await legacyV6(
      [
        [PEER_A, bookA],
        [PEER_B, bookB],
      ],
      [entry('e1', PEER_A, 500)],
    )
    const { sealer } = await unlockedSealer()
    let calls = 0
    const original = sealer.sealSession.bind(sealer)
    sealer.sealSession = (peer: string, book) => {
      if (++calls === 2) throw new Error('simulated seal failure on row 2 of 2')
      return original(peer, book)
    }
    const store = new IdbSessionStore()
    store.useSealer(sealer)

    await expect(store.migrateToSealed()).rejects.toThrow(/simulated seal failure/)

    const raw = await rawSessions()
    expect(raw.marker).toBeUndefined() // not marked, so the next unlock retries
    expect(raw.keys.sort()).toEqual([PEER_A, PEER_B].sort()) // still the ORIGINAL plaintext
    expect(raw.values).toContainEqual(bookA)
    expect(raw.values).toContainEqual(bookB)

    // And the retry, once the fault clears, succeeds completely.
    sealer.sealSession = original
    await store.migrateToSealed()
    expect((await rawSessions()).marker).toBe(SESSION_SEAL_VERSION)
    expect(await store.loadBook(PEER_A)).toEqual(bookA)
    expect(await store.loadBook(PEER_B)).toEqual(bookB)
  })

  it('uses exactly ONE transaction, and its source contains no await', async () => {
    // Two guards for the same property. Any await between reading the old rows and
    // writing the new ones ends the transaction and reopens the destructive window.
    await legacyV6([[PEER_A, singleSessionBook(snap, 1000)]], [entry('e1', PEER_A, 500)])
    const { sealer } = await unlockedSealer()
    const store = new IdbSessionStore()
    store.useSealer(sealer)
    // Force the connection open first, so only the migration's own transaction counts.
    await store.loadBook(PEER_B).catch(() => null)

    const db = await (store as unknown as { open(): Promise<IDBDatabase> }).open()
    const real = db.transaction.bind(db)
    let opened = 0
    ;(db as unknown as { transaction: unknown }).transaction = (...args: unknown[]) => {
      opened++
      return (real as (...a: unknown[]) => IDBTransaction)(...args)
    }
    await store.migrateToSealed()
    expect(opened).toBe(1)

    // Everything after the transaction is opened must be synchronous. The two awaits
    // outside it are fine and necessary: one gets the connection, one waits for the
    // commit. What must not appear is an await BETWEEN reading the old rows and
    // writing the new ones, which would end the transaction mid-rewrite.
    const src = readFileSync(new URL('./sessionStore.ts', import.meta.url), 'utf8')
    const body = src.slice(src.indexOf('async migrateToSealed('), src.indexOf('private open('))
    const insideTx = body.slice(body.indexOf('const t = db.transaction('))
    expect(insideTx).not.toMatch(/\bawait\b/)
    expect(insideTx).not.toMatch(/\.then\(/)
  })

  it('refuses to open a row sitting in another peer slot', async () => {
    // The AAD is rebuilt from the peer the CALLER asked for, never from a field in
    // the value. Otherwise a row copied between slots would open cleanly and hand
    // one conversation's ratchet to another, encrypting two peers from one chain key.
    const { sealer } = await unlockedSealer()
    const store = new IdbSessionStore()
    store.useSealer(sealer)
    const bookA = singleSessionBook(snap, 1000) // session ids are random: capture once
    await store.saveBook(PEER_A, bookA)

    const raw = await rawSessions()
    const rowA = raw.values[0] as SealedSessionRecord
    const db = await new Promise<IDBDatabase>((resolve) => {
      const req = indexedDB.open(DB)
      req.onsuccess = () => resolve(req.result)
    })
    await new Promise<void>((resolve) => {
      const t = db.transaction('sessions', 'readwrite')
      t.objectStore('sessions').put(rowA, sealer.sessionKey(PEER_B)) // A's row, B's slot
      t.oncomplete = () => resolve()
    })
    db.close()

    await expect(store.loadBook(PEER_B)).rejects.toThrow(SessionSealError)
    expect(await store.loadBook(PEER_A)).toEqual(bookA) // A is fine
  })

  it('throws rather than reporting "no session" when the app locks mid-read', async () => {
    // Folding this into null would send the caller down the first-contact path and
    // overwrite a conversation that was only briefly unreadable, which is why inbound
    // routes both this and SessionSealError away from the poison counter.
    const { sealer, appLock } = await unlockedSealer()
    const store = new IdbSessionStore()
    store.useSealer(sealer)
    await store.saveBook(PEER_A, singleSessionBook(snap, 1000))

    appLock.lockNow()

    await expect(store.loadBook(PEER_A)).rejects.toThrow(AppLockedError) // never null
  })

  it('reads a DIFFERENT app-lock key as "no session", not as a broken one', async () => {
    // Worth pinning because it is the forgot-secret-reset shape. The storage key is
    // derived from the LDK, so a new LDK simply addresses a slot that does not exist:
    // the app opens a fresh session rather than bricking. The old rows are then
    // unreachable garbage, which is exactly why resetLock wipes the store outright
    // instead of relying on this.
    const { sealer } = await unlockedSealer()
    const store = new IdbSessionStore()
    store.useSealer(sealer)
    await store.saveBook(PEER_A, singleSessionBook(snap, 1000))

    const reEnrolled = await unlockedSealer() // a brand-new LDK, as after a reset
    store.useSealer(reEnrolled.sealer)

    expect(await store.loadBook(PEER_A)).toBeNull()
  })

  it('reports an unopenable queued send instead of hiding or throwing on it', async () => {
    // It can never be re-encrypted (its ratchet advance committed in the same
    // transaction), so a silent skip is a destroyed message and a throw takes the
    // whole connect path down over one bad row.
    const { sealer } = await unlockedSealer()
    const store = new IdbSessionStore()
    store.useSealer(sealer)
    await store.saveBookWithOutbox(PEER_A, singleSessionBook(snap, 1000), entry('good', PEER_A, 100))
    await store.saveBookWithOutbox(PEER_A, singleSessionBook(snap, 1000), entry('bad', PEER_A, 200))

    // Corrupt exactly one row's ciphertext.
    const db = await new Promise<IDBDatabase>((resolve) => {
      const req = indexedDB.open(DB)
      req.onsuccess = () => resolve(req.result)
    })
    await new Promise<void>((resolve) => {
      const t = db.transaction('outbox', 'readwrite')
      const g = t.objectStore('outbox').get('bad')
      g.onsuccess = () => {
        const row = g.result as { ct: Uint8Array }
        row.ct[0] ^= 0xff
        t.objectStore('outbox').put(row, 'bad')
      }
      t.oncomplete = () => resolve()
    })
    db.close()

    const pending = await store.pendingOutbox()
    expect(pending.entries.map((e) => e.id)).toEqual(['good']) // the good one still flushes
    expect(pending.unreadable).toEqual(['bad']) // and the bad one is reported, not dropped
  })

  it('marks an emptied store as sealed, so a wipe never leaves the marker lying', async () => {
    const { sealer } = await unlockedSealer()
    const store = new IdbSessionStore()
    store.useSealer(sealer)
    await store.saveBook(PEER_A, singleSessionBook(snap, 1000))

    await store.wipeAll()

    const raw = await rawSessions()
    expect(raw.keys).toEqual([])
    expect(raw.marker).toBe(SESSION_SEAL_VERSION) // an empty store IS sealed
  })

  it('locks a stale bundle out of the database rather than letting it write the old shape', async () => {
    // Two shapes for one peer means two forked ratchets that both think they hold
    // the per-peer lock, which emits the same message key and nonce twice.
    const { sealer } = await unlockedSealer()
    const store = new IdbSessionStore()
    store.useSealer(sealer)
    await store.saveBook(PEER_A, singleSessionBook(snap, 1000)) // opens at v7

    await expect(
      new Promise((resolve, reject) => {
        const req = indexedDB.open(DB, 6)
        req.onsuccess = () => resolve(req.result)
        req.onerror = () => reject(req.error)
      }),
    ).rejects.toBeTruthy()
  })
})
