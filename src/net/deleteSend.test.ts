// Delete-for-everyone SEND side (P10d): NightjarClient.deleteForEveryone. The
// receive side (a delete removing + tombstoning the target, and the reorder
// suppression) is covered in inbound.test.ts; here we assert the sender's local
// effects without a live relay:
//   - a DELIVERED message (not in the outbox) -> the local copy is removed and a
//     delete control is queued with its OWN fresh transport id (never the target
//     content id);
//   - a still-QUEUED message -> the send is cancelled (outbox entry dropped) and no
//     delete control is transmitted;
//   - a never-delivered FAILED message is removed locally only (the UI path).
//
// The client's transport is never connected, so fire() throws internally and is
// swallowed (the envelope stays queued) exactly as on a real dropped socket.

import { beforeEach, describe, expect, it } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils'
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
import { MemorySessionStore, singleSessionBook } from '../storage/sessionStore'
import { ContactStore } from '../trust/contactStore'
import { NightjarClient } from './client'

const NOW = 1_700_000_000_000
const stubKdf = (s: Uint8Array, salt: Uint8Array) => hash256(new Uint8Array([...s, ...salt]))

// A peer to delete toward: its bundle lets us seed a real initiator session.
async function makePeerBundle(): Promise<{ id: Identity; bundle: FetchedBundle }> {
  const id = generateIdentity()
  const own = buildOwnBundle(id, NOW, { spkId: 1, opkStartId: 1, opkCount: 3 })
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
  await appLock.enroll([{ kind: 'pass', secret: 'x' }])
  const history = new HistoryStore(appLock)
  const client = new NightjarClient(identity, store, prekeys, contacts, lock, { onMessage: () => {} }, history)

  // Seed a current initiator session to `peer`, so sendDeleteControl can encrypt.
  const seedSession = async (peer: Identity, bundle: FetchedBundle) => {
    const ini = x3dhInitiate(identity, bundle, NOW)
    const state = initRatchetInitiator(ini.sk, ini.ad, bundle.spk.pub)
    await store.saveBook(peer.userId, singleSessionBook(serializeRatchet(state), NOW))
  }
  // Persist an outbound history row as if we had sent `id` to `peer`.
  const seedSentRow = async (peer: string, id: string) => {
    const row = history.seal({ id, peerId: peer, dir: 'out', ts: NOW, text: 'secret' })
    const book = (await store.loadBook(peer))!
    await store.saveBookWithSeen(peer, book, `seed-${id}`, row)
  }

  return { client, store, history, seedSession, seedSentRow }
}

describe('NightjarClient.deleteForEveryone (P10d)', () => {
  let peer: Identity
  let bundle: FetchedBundle
  beforeEach(async () => {
    const p = await makePeerBundle()
    peer = p.id
    bundle = p.bundle
  })

  it('a delivered message: removes the local copy and queues a delete control with a FRESH id', async () => {
    const h = await harness()
    await h.seedSession(peer, bundle)
    const id = bytesToHex(new Uint8Array(16).fill(9))
    await h.seedSentRow(peer.userId, id)
    // Sanity: the row is present, and nothing is queued.
    expect((await h.store.historyLoadAll()).length).toBe(1)
    expect(await h.store.pendingOutbox()).toEqual([])

    const { requested } = await h.client.deleteForEveryone(peer.userId, id)
    expect(requested).toBe(true)
    // The local sent copy is gone.
    expect(await h.store.historyLoadAll()).toEqual([])
    // Exactly one delete control is queued, with a FRESH transport id (never the
    // target content id) and no history row of its own.
    const out = await h.store.pendingOutbox()
    expect(out).toHaveLength(1)
    expect(out[0].id).not.toBe(id)
    expect(out[0].to).toBe(peer.userId)
    expect((out[0].env as { kind: string }).kind).toBe('normal')
  })

  it('a still-queued message: cancels the send, transmits no delete control', async () => {
    const h = await harness()
    await h.seedSession(peer, bundle)
    const id = bytesToHex(new Uint8Array(16).fill(5))
    await h.seedSentRow(peer.userId, id)
    // The message is still in the outbox (not yet acked/delivered).
    const book = (await h.store.loadBook(peer.userId))!
    await h.store.saveBookWithOutbox(peer.userId, book, { id, to: peer.userId, env: { id, kind: 'normal' }, createdAt: NOW })
    expect((await h.store.pendingOutbox()).map((e) => e.id)).toEqual([id])

    const { requested } = await h.client.deleteForEveryone(peer.userId, id)
    expect(requested).toBe(false)
    // The queued send was cancelled and NO delete control was queued in its place.
    expect(await h.store.pendingOutbox()).toEqual([])
    // The local copy is removed as well.
    expect(await h.store.historyLoadAll()).toEqual([])
  })

  it('with no session to the peer: removes locally, requests nothing (nothing was delivered)', async () => {
    const h = await harness()
    // No seedSession: there is no session, so the target was never delivered.
    const id = bytesToHex(new Uint8Array(16).fill(3))
    await h.seedSession(peer, bundle) // needed only to persist a row against a book
    await h.seedSentRow(peer.userId, id)
    await h.store.delete(peer.userId) // now drop the session, keep the row
    const { requested } = await h.client.deleteForEveryone(peer.userId, id)
    expect(requested).toBe(false)
    expect(await h.store.historyLoadAll()).toEqual([])
    expect(await h.store.pendingOutbox()).toEqual([])
  })
})
