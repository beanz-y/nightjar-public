// Deleting a conversation, at the client level. The load-bearing assertion here is
// the one that looks like an omission: the ratchet SESSION SURVIVES.
//
// Destroying it would black-hole the peer. Their app keeps sending on the session it
// still holds; those messages reach a device with no session, fail to decrypt, and
// are acked-and-dropped, which the relay reports back to them as delivered. Silent
// one-way loss, with the sender told it worked. For an audience wider than friends
// and family that is the wrong failure, and Nightjar has no block to offer instead.
// So a delete removes what is yours (messages, contact, verification, nickname,
// queued sends) and leaves the channel they can reach you on.

import { describe, expect, it } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { type Identity, generateIdentity } from '../crypto/identity'
import { type FetchedBundle, OWN_BUNDLE_VERSION, buildOwnBundle } from '../crypto/prekeys'
import { hash256 } from '../crypto/primitives'
import type { RatchetSnapshot } from '../crypto/ratchet'
import { AppLockStore } from '../storage/appLockStore'
import { HistoryStore } from '../storage/historyStore'
import { MemoryKeyStore } from '../storage/keystore'
import { InMemoryLock } from '../storage/lock'
import { PrekeyStore } from '../storage/prekeyStore'
import { MemorySessionStore, singleSessionBook } from '../storage/sessionStore'
import { ContactStore } from '../trust/contactStore'
import { NightjarClient } from './client'

const NOW = Date.now()
const stubKdf = (s: Uint8Array, salt: Uint8Array) => hash256(new Uint8Array([...s, ...salt]))
const snap = 'bb'.repeat(32) as unknown as RatchetSnapshot

function bundleFor(id: Identity): FetchedBundle {
  const own = buildOwnBundle(id, NOW, { spkId: 1, opkStartId: 1, opkCount: 3 })
  return {
    version: OWN_BUNDLE_VERSION,
    ikSigPub: own.ikSigPub,
    ikDhPub: own.ikDhPub,
    idkbindSig: own.idkbindSig,
    spk: own.spk,
    opk: own.opks[0],
  }
}

/** What client.handleDeliver calls after a delivered message from someone we hold
 *  no contact record for. Private, so reached the way the other client tests do. */
function recover(client: NightjarClient, peer: string, seenAt: number): Promise<void> {
  return (client as unknown as { recoverContact(p: string, t: number): Promise<void> }).recoverContact(peer, seenAt)
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

  const peer = generateIdentity()
  ;(client as unknown as { directory: unknown }).directory = {
    fetchBundle: async (id: string) => ({ bundle: id === peer.userId ? bundleFor(peer) : null }),
  }

  const seed = async () => {
    await store.saveBook(peer.userId, singleSessionBook(snap, NOW))
    for (const [i, text] of ['one', 'two'].entries()) {
      const id = bytesToHex(new Uint8Array(16).fill(i + 1))
      const row = history.seal({ id, peerId: peer.userId, dir: 'out', ts: NOW, text })
      await store.saveBookWithSeen(peer.userId, singleSessionBook(snap, NOW), `env-${id}`, row)
    }
    await contacts.recordFirstContact(peer.userId, peer.ikSig.publicKey, NOW)
    await contacts.markVerified(peer.userId, NOW)
    await contacts.setAlias(peer.userId, 'Gran')
    await store.saveBookWithOutbox(peer.userId, singleSessionBook(snap, NOW), {
      id: 'queued-1',
      to: peer.userId,
      env: {},
      createdAt: NOW,
    })
  }
  return { client, store, contacts, history, peer, seed }
}

describe('deleteConversation', () => {
  it('removes the messages, contact, verification, nickname and queued sends', async () => {
    const h = await harness()
    await h.seed()

    const res = await h.client.deleteConversation(h.peer.userId)

    expect(res.removed).toBe(2)
    expect(res.cancelled).toBe(1)
    expect(res.unreadable).toBe(0)
    expect(await h.store.historyLoadAll()).toEqual([])
    expect((await h.store.pendingOutbox()).entries).toEqual([])
    expect(await h.contacts.get(h.peer.userId)).toBeNull()
    expect(await h.contacts.trustLevel(h.peer.userId)).toBeNull()
    expect(await h.contacts.getAliases()).toEqual({})
  })

  it('KEEPS the ratchet session, so the peer can still reach you', async () => {
    // If this ever starts failing because someone "finished" the delete, read the
    // file header first: removing the session is what silently destroys their
    // messages while their app reports them delivered.
    const h = await harness()
    await h.seed()

    await h.client.deleteConversation(h.peer.userId)

    const book = await h.store.loadBook(h.peer.userId)
    expect(book).not.toBeNull()
    expect(book?.sessions.length).toBeGreaterThan(0)
  })

  it('arms the marker, so the app never re-adds them on its own initiative', async () => {
    const h = await harness()
    await h.seed()

    await h.client.deleteConversation(h.peer.userId)

    expect(await h.contacts.dismissedAt(h.peer.userId)).not.toBeNull()
    // A relay-driven re-add (the mutual-invite sync) is refused...
    expect(
      await h.contacts.recordFirstContact(h.peer.userId, h.peer.ikSig.publicKey, NOW + 1, 'unverified', true),
    ).toBe(false)
    // ...while the peer messaging, or the user re-adding, is not.
    expect(await h.contacts.recordFirstContact(h.peer.userId, h.peer.ikSig.publicKey, NOW + 2)).toBe(true)
  })

  it('clearMessages keeps the contact, the verification and the session', async () => {
    const h = await harness()
    await h.seed()

    const res = await h.client.clearMessages(h.peer.userId)

    expect(res.removed).toBe(2)
    expect(await h.store.historyLoadAll()).toEqual([])
    expect(await h.contacts.trustLevel(h.peer.userId)).toBe('verified')
    expect(await h.contacts.getAliases()).toEqual({ [h.peer.userId]: 'Gran' })
    expect(await h.store.loadBook(h.peer.userId)).not.toBeNull()
    expect(await h.contacts.dismissedAt(h.peer.userId)).toBeNull() // not a deletion
  })

  it('records that a session existed, which is what the stale-prekey guard needs', async () => {
    // Captured while the book is still readable. A peer deleted with no session
    // consumed no one-time prekey, and must not be pushed onto the degraded path.
    const h = await harness()
    await h.seed()

    await h.client.deleteConversation(h.peer.userId)

    expect(await h.contacts.getDismissal(h.peer.userId)).toMatchObject({ hadSession: true })
  })

  it('records hadSession false for a peer that never had one', async () => {
    const h = await harness()
    const stranger = generateIdentity()
    await h.contacts.recordFirstContact(stranger.userId, stranger.ikSig.publicKey, NOW)

    await h.client.deleteConversation(stranger.userId)

    expect(await h.contacts.getDismissal(stranger.userId)).toMatchObject({ hadSession: false })
  })

  it('re-records the peer when a message reaches you on the kept session', async () => {
    // The other half of keeping the session. Their app keeps sending `normal`
    // messages, which never reach the first-contact path an `initial` takes, so
    // without this the chat reopens with no stored key and therefore NO SAFETY
    // NUMBER: the priority-1 control, silently missing from a live conversation.
    const h = await harness()
    await h.seed()
    await h.client.deleteConversation(h.peer.userId)
    expect(await h.contacts.get(h.peer.userId)).toBeNull()

    await recover(h.client, h.peer.userId, Date.now())

    expect((await h.contacts.get(h.peer.userId))?.trust).toBe('unverified')
    // Verification is NOT restored: it has to be redone in person (DESIGN 6.2).
    expect(await h.contacts.trustLevel(h.peer.userId)).toBe('unverified')
    // ...and the deletion marker is lifted, so the mutual invite stops refusing them.
    expect(
      await h.contacts.recordFirstContact(h.peer.userId, h.peer.ikSig.publicKey, Date.now(), 'unverified', true),
    ).toBe(true)
  })

  it('refuses to re-record when the delete landed while the key was in flight', async () => {
    // The fetch takes long enough for a user to press delete part-way through. A
    // delete that lands after the message arrived has to win, or the recovery would
    // quietly undo it.
    const h = await harness()
    await h.seed()
    const seenAt = Date.now() - 5000 // their message arrived, THEN the user deleted

    await h.client.deleteConversation(h.peer.userId)
    await recover(h.client, h.peer.userId, seenAt)

    expect(await h.contacts.get(h.peer.userId)).toBeNull()
  })

  it('leaves an existing contact alone', async () => {
    // The common case by far: recovery must be a no-op, and must not cost a fetch.
    const h = await harness()
    await h.seed()

    await recover(h.client, h.peer.userId, Date.now())

    expect(await h.contacts.trustLevel(h.peer.userId)).toBe('verified') // not downgraded
  })

  it('touches nothing belonging to another peer', async () => {
    const h = await harness()
    await h.seed()
    const other = generateIdentity()
    const row = h.history.seal({ id: 'ff'.repeat(8), peerId: other.userId, dir: 'in', ts: NOW, text: 'theirs' })
    await h.store.saveBookWithSeen(other.userId, singleSessionBook(snap, NOW), 'env-other', row)
    await h.contacts.recordFirstContact(other.userId, other.ikSig.publicKey, NOW)

    await h.client.deleteConversation(h.peer.userId)

    expect((await h.store.historyLoadAll()).length).toBe(1)
    expect(await h.contacts.get(other.userId)).not.toBeNull()
    expect(await h.store.loadBook(other.userId)).not.toBeNull()
  })
})
