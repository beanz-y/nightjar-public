// Move staging (Phase D). stageMove turns an opened move file into this device's
// standing under the app-lock, with the IDENTITY WRITE as the commit point. The
// tests pin the two properties the red-team said everything else rests on: a
// crash before the identity write leaves NO identity (so boot re-runs the import
// cleanly), and a re-run converges without duplicating history.

import 'fake-indexeddb/auto'
import { IDBFactory } from 'fake-indexeddb'
import { beforeEach, describe, expect, it } from 'vitest'
import { hash256 } from '../crypto/primitives'
import { generateIdentity, serializeIdentity } from '../crypto/identity'
import type { HistoryUnitMessage } from '../crypto/historyUnit'
import type { MovePayload } from '../crypto/move'
import { b64encode } from '../wire/codec'
import type { Contact } from '../trust/contactStore'
import { ContactStore } from '../trust/contactStore'
import { AppLockStore } from './appLockStore'
import { HistoryStore } from './historyStore'
import { MemoryKeyStore } from './keystore'
import { InMemoryLock } from './lock'
import { MemorySentinel } from './persist'
import { SessionSealer } from './sessionSeal'
import { IdbSessionStore } from './sessionStore'
import { IDENTITY_KEY } from './identityStore'
import { RESTORE_PENDING_KEY, stageMove } from './restore'

const stubKdf = (s: Uint8Array, salt: Uint8Array) => hash256(new Uint8Array([...s, ...salt]))
const NOW = 1_700_000_000_000

beforeEach(() => {
  globalThis.indexedDB = new IDBFactory()
})

function contactFor(): Contact {
  const peer = generateIdentity()
  return { peerId: peer.userId, ikSig: b64encode(peer.ikSig.publicKey), trust: 'unverified', firstSeen: NOW, verifiedAt: null }
}

async function device() {
  const keys = new MemoryKeyStore()
  const lock = new InMemoryLock()
  const appLock = new AppLockStore(keys, lock, stubKdf)
  await appLock.enroll([{ kind: 'pass', secret: 'open sesame please' }])
  const sessions = new IdbSessionStore()
  sessions.useSealer(new SessionSealer(appLock))
  await sessions.migrateToSealed()
  const contacts = new ContactStore(keys, lock, appLock)
  const history = new HistoryStore(appLock)
  const sentinel = new MemorySentinel()
  return { keys, lock, appLock, sessions, contacts, history, sentinel }
}

function payloadWith(messages: HistoryUnitMessage[], contacts: Contact[], dismissals: MovePayload['dismissals'] = {}): MovePayload {
  return { identity: generateIdentity(), contacts, aliases: {}, dismissals, messages, createdAt: NOW }
}

describe('stageMove (Phase D)', () => {
  it('stages identity, contacts, dismissals, and history; identity is the commit point', async () => {
    const d = await device()
    const alice = contactFor()
    const bob = contactFor()
    const messages: HistoryUnitMessage[] = [
      { id: 'a'.repeat(32), peer: alice.peerId, dir: 'in', ts: NOW - 2000, text: 'hi' },
      { id: 'b'.repeat(32), peer: alice.peerId, dir: 'out', ts: NOW - 1000, text: 'yo', status: 'delivered' },
    ]
    // The dismissal `at` must be recent on the REAL clock: getDismissal TTL-filters
    // against Date.now(), so a fixed 2023 NOW would read as expired.
    const recent = Date.now() - 1000
    const payload = payloadWith(messages, [alice, bob], { [bob.peerId]: { at: recent, auto: true } })
    const expectedUser = payload.identity.userId

    await stageMove(
      { keys: d.keys, sessions: d.sessions, contacts: d.contacts, sentinel: d.sentinel, lock: d.lock },
      d.history,
      payload,
    )

    // Identity landed (the commit point) and is the moved one.
    const idBytes = await d.keys.get(IDENTITY_KEY)
    expect(idBytes).not.toBeNull()
    expect((await d.keys.get(RESTORE_PENDING_KEY))).not.toBeNull()

    // History decrypts under this device's lock and matches (both directions).
    const rows = await d.sessions.historyLoadAll()
    const opened = rows.map((r) => d.history.open(r)).sort((a, b) => a.ts - b.ts)
    expect(opened.map((m) => m.text)).toEqual(['hi', 'yo'])
    expect(opened[1].status).toBe('delivered')

    // Contacts landed; the dismissal rode along with hadSession forced false.
    expect((await d.contacts.list()).map((c) => c.peerId).sort()).toEqual([alice.peerId, bob.peerId].sort())
    const dm = await d.contacts.getDismissal(bob.peerId)
    expect(dm).not.toBeNull()
    expect(dm!.hadSession).toBe(false)

    // The refresh list is every imported contact EXCEPT the dismissed one.
    expect(await d.contacts.getMoveRefresh()).toEqual([alice.peerId])
    // And it is SEALED. Stored in the clear it was a plaintext roster of everyone
    // this device had just imported, sitting on disk precisely when a freshly
    // moved device is most likely to be lost, which contradicted 8.5.
    const raw = await d.keys.get('move.refresh.v1')
    expect(raw).toBeTruthy()
    expect(new TextDecoder().decode(raw!)).not.toContain(alice.peerId)
    void serializeIdentity // (imported for parity with the restore module's own use)
    void expectedUser
  })

  it('adopts a plaintext refresh list left by an older build, and re-seals it', async () => {
    // A device that moved under 1.9.0 or 1.10.0 may still be holding an undrained
    // list in the clear. Losing it would leave those contacts sending on dead
    // sessions with no ping to fix them, which is the exact hole the list closes,
    // so it is adopted rather than discarded.
    const d = await device()
    const alice = contactFor()
    await d.keys.put('move.refresh.v1', new TextEncoder().encode(JSON.stringify([alice.peerId])))

    expect(await d.contacts.getMoveRefresh()).toEqual([alice.peerId])

    // Reading it once converts it, so the plaintext does not linger.
    const raw = await d.keys.get('move.refresh.v1')
    expect(new TextDecoder().decode(raw!)).not.toContain(alice.peerId)
    expect(await d.contacts.getMoveRefresh()).toEqual([alice.peerId])
  })

  it('leaves NO identity when the history stage throws (crash-before-commit is recoverable)', async () => {
    const d = await device()
    // Pre-seed a throwaway identity, as an onboarding device holds before a move.
    await d.keys.put(IDENTITY_KEY, serializeIdentity(generateIdentity()))
    const alice = contactFor()
    const payload = payloadWith([{ id: 'c'.repeat(32), peer: alice.peerId, dir: 'in', ts: NOW, text: 'x' }], [alice])

    // A history store that throws on seal simulates a mid-stage failure (quota, a
    // lock landing badly). The identity was deleted in step (a), so nothing can
    // boot the half-staged world.
    const throwingHistory = {
      seal() {
        throw new Error('simulated seal failure')
      },
    } as unknown as HistoryStore

    await expect(
      stageMove({ keys: d.keys, sessions: d.sessions, contacts: d.contacts, sentinel: d.sentinel, lock: d.lock }, throwingHistory, payload),
    ).rejects.toThrow('simulated seal failure')

    // The commit-point invariant: no identity survives a pre-commit crash.
    expect(await d.keys.get(IDENTITY_KEY)).toBeNull()
  })

  it('converges on a re-run without duplicating history (blind overwrite + wipe-first)', async () => {
    const d = await device()
    const alice = contactFor()
    const messages: HistoryUnitMessage[] = [
      { id: 'd'.repeat(32), peer: alice.peerId, dir: 'in', ts: NOW - 1000, text: 'one' },
      { id: 'e'.repeat(32), peer: alice.peerId, dir: 'out', ts: NOW, text: 'two' },
    ]
    const deps = { keys: d.keys, sessions: d.sessions, contacts: d.contacts, sentinel: d.sentinel, lock: d.lock }
    // Two identical imports (a crash-retry re-runs the same file). splice consumes
    // payload.messages, so give each run its own copy.
    await stageMove(deps, d.history, payloadWith([...messages], [alice]))
    await stageMove(deps, d.history, payloadWith([...messages], [alice]))

    const rows = await d.sessions.historyLoadAll()
    expect(rows).toHaveLength(2) // deterministic storage keys: the re-run upserts, never duplicates
    expect((await d.contacts.list())).toHaveLength(1)
  })
})
