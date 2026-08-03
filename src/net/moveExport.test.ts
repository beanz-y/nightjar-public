// Move EXPORT gather (Phase D): NightjarClient.exportMoveData, without a live
// relay. Asserts the properties the red-team said the gather must hold:
//   - a readable row for a real contact rides, with direction + delivery status;
//   - a history row whose peer has no contact row is dropped and COUNTED
//     (orphaned), never turned into a contactless conversation on the new device;
//   - it REFUSES (MoveBlockedError) rather than exporting while a send is queued.

import { describe, expect, it } from 'vitest'
import { type Identity, generateIdentity } from '../crypto/identity'
import { hash256 } from '../crypto/primitives'
import { type FetchedBundle, OWN_BUNDLE_VERSION, buildOwnBundle } from '../crypto/prekeys'
import { initRatchetInitiator, serializeRatchet } from '../crypto/ratchet'
import { x3dhInitiate } from '../crypto/x3dh'
import { AppLockStore } from '../storage/appLockStore'
import { HistoryStore } from '../storage/historyStore'
import { InMemoryLock } from '../storage/lock'
import { MemoryKeyStore } from '../storage/keystore'
import { PrekeyStore } from '../storage/prekeyStore'
import { MemorySessionStore, type OutboxEntry, singleSessionBook } from '../storage/sessionStore'
import { ContactStore } from '../trust/contactStore'
import { MoveBlockedError, NightjarClient } from './client'

const NOW = 1_700_000_000_000
const stubKdf = (s: Uint8Array, salt: Uint8Array) => hash256(new Uint8Array([...s, ...salt]))

function peerBundle(): { id: Identity; bundle: FetchedBundle } {
  const id = generateIdentity()
  const own = buildOwnBundle(id, NOW, { spkId: 1, opkStartId: 1, opkCount: 1 })
  return {
    id,
    bundle: {
      version: OWN_BUNDLE_VERSION,
      ikSigPub: own.ikSigPub,
      ikDhPub: own.ikDhPub,
      idkbindSig: own.idkbindSig,
      spk: own.spk,
      opk: own.opks[0],
    },
  }
}

async function harness() {
  const identity = generateIdentity()
  const keys = new MemoryKeyStore()
  const lock = new InMemoryLock()
  const store = new MemorySessionStore()
  const prekeys = new PrekeyStore(keys, lock)
  const contacts = new ContactStore(keys, lock)
  const appLock = new AppLockStore(keys, lock, stubKdf)
  await appLock.enroll([{ kind: 'pass', secret: 'open sesame please' }])
  const history = new HistoryStore(appLock)
  const client = new NightjarClient(identity, store, prekeys, contacts, lock, { onMessage: () => {} }, history)

  // Record a contact AND seed a current session to them (so an outbox entry has a book).
  const addContactWithSession = async (): Promise<string> => {
    const { id: peer, bundle } = peerBundle()
    await contacts.recordFirstContact(peer.userId, bundle.ikSigPub, NOW)
    const ini = x3dhInitiate(identity, bundle, NOW)
    const state = initRatchetInitiator(ini.sk, ini.ad, bundle.spk.pub)
    await store.saveBook(peer.userId, singleSessionBook(serializeRatchet(state), NOW))
    return peer.userId
  }

  return { identity, store, contacts, history, client, addContactWithSession }
}

describe('exportMoveData (Phase D)', () => {
  it('gathers a real contact and its readable rows with direction + status intact', async () => {
    const h = await harness()
    const peer = await h.addContactWithSession()
    const inRow = h.history.seal({ id: 'a'.repeat(32), peerId: peer, dir: 'in', ts: NOW - 1000, text: 'from them' })
    const outRow = h.history.seal({ id: 'b'.repeat(32), peerId: peer, dir: 'out', ts: NOW, text: 'from me', status: 'delivered' })
    await h.store.historyPutMany([inRow, outRow])

    const data = await h.client.exportMoveData()
    expect(data.contacts.map((c) => c.peerId)).toEqual([peer])
    expect(data.messages).toHaveLength(2)
    const out = data.messages.find((m) => m.dir === 'out')!
    expect(out.text).toBe('from me')
    expect(out.status).toBe('delivered')
    expect(data.orphaned).toBe(0)
    expect(data.unreadable).toBe(0)
  })

  it('drops (and counts) a history row whose peer is not a contact', async () => {
    const h = await harness()
    const stranger = generateIdentity().userId // never recorded as a contact
    await h.store.historyPutMany([h.history.seal({ id: 'c'.repeat(32), peerId: stranger, dir: 'in', ts: NOW, text: 'ghost' })])

    const data = await h.client.exportMoveData()
    expect(data.messages).toHaveLength(0)
    expect(data.orphaned).toBe(1)
  })

  it('refuses to gather while a send is still queued', async () => {
    const h = await harness()
    const peer = await h.addContactWithSession()
    const book = (await h.store.loadBook(peer))!
    const entry: OutboxEntry = {
      id: 'q'.repeat(32),
      to: peer,
      env: { id: 'q'.repeat(32), kind: 'normal', header: 'x', ciphertext: 'y' },
      createdAt: NOW,
    }
    await h.store.saveBookWithOutbox(peer, book, entry)
    await expect(h.client.exportMoveData()).rejects.toBeInstanceOf(MoveBlockedError)
  })
})
