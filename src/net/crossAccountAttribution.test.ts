// Which conversation a message belongs in, when somebody is lying about it.
//
// A device list is signed, but signing it proves only that the account SAID it.
// A device id is the hash of a public key and every key here is public, so any
// account can name any device in its own list. Attribution therefore needs BOTH
// halves: the account claims the device, and the device claims the account.
//
// The defect this file exists for was found by an adversarial review and had two
// consequences. The obvious one is attribution theft: a hostile contact captures
// a third party's messages into their own conversation, inheriting the trust
// badge and safety number the user checked for THEM. The worse one, which no
// lens named until the completeness critic, is that the same primitive silently
// switches off the VICTIM'S OWN cross-device sync, because the account resolved
// for a device feeds the self-only gates on synced records. Unlike the prekey
// wipe it never self-heals.
//
// Every other client suite is single-account by construction, which is exactly
// why none of them could express this.

import { describe, expect, it } from 'vitest'
import { type Identity, deviceIdOf, generateIdentity } from '../crypto/identity'
import { hash256 } from '../crypto/primitives'
import { type RosterDevice, signRoster } from '../crypto/roster'
import { AppLockStore } from '../storage/appLockStore'
import { HistoryStore } from '../storage/historyStore'
import { InMemoryLock } from '../storage/lock'
import { MemoryKeyStore } from '../storage/keystore'
import { PrekeyStore } from '../storage/prekeyStore'
import { MemorySessionStore } from '../storage/sessionStore'
import { ContactStore } from '../trust/contactStore'
import { NightjarClient } from './client'

const stubKdf = (s: Uint8Array, salt: Uint8Array) => hash256(new Uint8Array([...s, ...salt]))

interface Internals {
  handleHello(fromDeviceId: string, accountId: string): Promise<void>
}

function deviceOf(id: Identity): RosterDevice {
  return { deviceId: deviceIdOf(id.ikSig.publicKey), dkSigPub: id.ikSig.publicKey, addedAt: Date.now() }
}

async function harness() {
  const identity = generateIdentity()
  const keys = new MemoryKeyStore()
  const lock = new InMemoryLock()
  const contacts = new ContactStore(keys, lock)
  const appLock = new AppLockStore(keys, lock, stubKdf)
  await appLock.enroll([{ kind: 'pass', secret: 'x' }])
  const security: string[] = []
  const client = new NightjarClient(
    identity,
    new MemorySessionStore(),
    new PrekeyStore(keys, lock),
    contacts,
    lock,
    { onMessage: () => {}, onSecurity: (d) => security.push(d) },
    new HistoryStore(appLock),
  )
  /** Rosters this relay will serve, by account id. */
  const rosters = new Map<string, ReturnType<typeof signRoster>>()
  ;(client as unknown as { directory: unknown }).directory = {
    fetchRosterWithRotation: async (accountId: string) => ({
      roster: rosters.get(accountId) ?? null,
      rotation: null,
    }),
  }
  return {
    client,
    contacts,
    security,
    serve: (accountId: string, r: ReturnType<typeof signRoster>) => rosters.set(accountId, r),
    know: async (peer: Identity) => {
      await contacts.recordFirstContact(peer.userId, peer.ikSig.publicKey, Date.now())
    },
    hello: (fromDeviceId: string, accountId: string) =>
      (client as unknown as Internals).handleHello(fromDeviceId, accountId),
  }
}

describe('attributing a device when another account claims it', () => {
  it('does not file a victim’s messages under the account that merely named them', async () => {
    // Mallory lists the victim's device in her own validly signed list. Before
    // corroboration this captured the victim outright, because the lookup took
    // the first account whose cached list named the device.
    const h = await harness()
    const mallory = generateIdentity()
    const victim = generateIdentity()
    const victimDevice = generateIdentity() // a device of the victim's, id and key public
    const victimDeviceId = deviceIdOf(victimDevice.ikSig.publicKey)
    await h.know(mallory)
    await h.know(victim)

    h.serve(
      mallory.userId,
      signRoster(
        mallory.userId,
        1,
        [deviceOf(mallory), { deviceId: victimDeviceId, dkSigPub: victimDevice.ikSig.publicKey, addedAt: Date.now() }],
        mallory.ikSig.privateKey,
      ),
    )
    await h.client.resolveDevices(mallory.userId) // caches the hostile list

    // Named by Mallory, corroborated by nobody: not hers.
    expect(await h.client.accountForDevice(victimDeviceId)).toBe(victimDeviceId)
  })

  it('files it under the account once the device itself says so', async () => {
    // The legitimate path, and the proof that corroboration is not simply a
    // refusal to attribute anything.
    const h = await harness()
    const peer = generateIdentity()
    const laptop = generateIdentity()
    const laptopId = deviceIdOf(laptop.ikSig.publicKey)
    await h.know(peer)
    h.serve(peer.userId, signRoster(peer.userId, 1, [deviceOf(peer), deviceOf(laptop)], peer.ikSig.privateKey))

    expect(await h.client.accountForDevice(laptopId)).toBe(laptopId) // not yet introduced
    await h.hello(laptopId, peer.userId) // the device's own half, over its own session
    expect(await h.client.accountForDevice(laptopId)).toBe(peer.userId)
  })

  it('refuses BOTH when two accounts claim one device, and says so', async () => {
    // Insertion order used to decide this silently, which is what made the
    // capture permanent: whoever named the device first won for good.
    const h = await harness()
    const mallory = generateIdentity()
    const peer = generateIdentity()
    const laptop = generateIdentity()
    const laptopId = deviceIdOf(laptop.ikSig.publicKey)
    await h.know(mallory)
    await h.know(peer)

    // The real owner, corroborated.
    h.serve(peer.userId, signRoster(peer.userId, 1, [deviceOf(peer), deviceOf(laptop)], peer.ikSig.privateKey))
    await h.hello(laptopId, peer.userId)
    expect(await h.client.accountForDevice(laptopId)).toBe(peer.userId)

    // Then Mallory names the same device in hers.
    h.serve(
      mallory.userId,
      signRoster(mallory.userId, 1, [deviceOf(mallory), deviceOf(laptop)], mallory.ikSig.privateKey),
    )
    await h.client.resolveDevices(mallory.userId)

    expect(await h.client.accountForDevice(laptopId)).toBe(laptopId)
    expect(h.security.join(' ')).toMatch(/both claim the same device/)
  })

  it('still attributes a first device, which never introduces itself', async () => {
    // The exemption that must not be forgotten: an account's own first device has
    // the account key as its device key, so the ids are the same string and it has
    // nothing to announce. Requiring corroboration from it would un-attribute the
    // primary device of every multi-device account.
    const h = await harness()
    const peer = generateIdentity()
    const laptop = generateIdentity()
    await h.know(peer)
    h.serve(peer.userId, signRoster(peer.userId, 1, [deviceOf(peer), deviceOf(laptop)], peer.ikSig.privateKey))
    await h.client.resolveDevices(peer.userId)

    expect(await h.client.accountForDevice(peer.userId)).toBe(peer.userId)
  })

  it('does not let a stranger’s list take a device away from the account that owns it', async () => {
    // The victim-own-sync case in miniature: once corroborated, a later hostile
    // list must not be able to move the answer. Here it produces a conflict
    // rather than a capture, which is refusal plus a notice rather than silence.
    const h = await harness()
    const peer = generateIdentity()
    const laptop = generateIdentity()
    const laptopId = deviceIdOf(laptop.ikSig.publicKey)
    const mallory = generateIdentity()
    await h.know(peer)
    await h.know(mallory)
    h.serve(peer.userId, signRoster(peer.userId, 1, [deviceOf(peer), deviceOf(laptop)], peer.ikSig.privateKey))
    await h.hello(laptopId, peer.userId)

    h.serve(
      mallory.userId,
      signRoster(mallory.userId, 1, [deviceOf(mallory), deviceOf(laptop)], mallory.ikSig.privateKey),
    )
    await h.client.resolveDevices(mallory.userId)

    // Never Mallory's, whichever way the cache happens to be ordered.
    expect(await h.client.accountForDevice(laptopId)).not.toBe(mallory.userId)
  })

  it('deletes a conversation atomically against a write from a SECOND device', async () => {
    // The race no existing suite could express, because every other client suite
    // is single-account and an account id EQUALS its first device's id: the sweep
    // happened to hold the one lock that covered the contact's original device, so
    // the hole was invisible unless a SECOND device wrote during the sweep.
    //
    // The sweep is one transaction now, so a write lands either entirely before it
    // (and is removed) or entirely after it (a message arriving after a delete,
    // which DESIGN 8.9 covers by re-opening the conversation). What must never
    // happen again is the middle case: a row surviving a delete that counted it.
    const h = await harness()
    const peer = generateIdentity()
    const laptop = generateIdentity()
    const laptopId = deviceIdOf(laptop.ikSig.publicKey)
    await h.know(peer)
    h.serve(peer.userId, signRoster(peer.userId, 1, [deviceOf(peer), deviceOf(laptop)], peer.ikSig.privateKey))
    await h.hello(laptopId, peer.userId)

    const store = (h.client as unknown as { store: MemorySessionStore }).store
    const history = (h.client as unknown as { history: HistoryStore }).history
    for (let i = 0; i < 8; i++) {
      await store.historyPutMany([
        history.seal({ id: `m${i}`, peerId: peer.userId, dir: 'in', ts: 1000 + i, text: `msg ${i}` }),
      ])
    }

    const result = await h.client.deleteConversation(peer.userId)

    // Whatever it reported gone IS gone: the count and the store agree.
    const left = (await store.historyLoadAll()).map((r) => history.open(r)).filter((m) => m.peerId === peer.userId)
    expect(result.removed).toBe(8)
    expect(left).toHaveLength(0)
  })

  it('removes the contact before the messages, and finishes the sweep after a crash', async () => {
    // The order is the point. The sweep is one transaction and cannot half-finish,
    // so messages-first only bought a window in which a message arriving mid-sweep
    // survived a delete whose contact record was about to be destroyed: a nameless
    // populated thread at the next launch, with the verification already gone.
    // Contact first means the worst case is an EMPTY named thread instead.
    const h = await harness()
    const peer = generateIdentity()
    await h.know(peer)
    const store = (h.client as unknown as { store: MemorySessionStore }).store
    const history = (h.client as unknown as { history: HistoryStore }).history
    await store.historyPutMany([
      history.seal({ id: 'm1', peerId: peer.userId, dir: 'in', ts: 1000, text: 'one' }),
    ])

    // Simulate the crash: mark the delete as started, remove the contact, and never
    // sweep, which is exactly the state an interruption leaves behind.
    const startedAt = Date.now()
    await h.contacts.setPendingDelete(peer.userId, startedAt)
    await h.contacts.remove(peer.userId, Date.now())
    expect((await store.historyLoadAll()).length).toBe(1)

    await h.client.resumePendingDeletes()

    expect((await store.historyLoadAll()).length).toBe(0)
    expect(await h.contacts.pendingDeletes()).toEqual([])
  })

  it('resuming a delete does not remove what the peer sent after it', async () => {
    // A marker can sit through several connects if the sweep keeps failing, and a
    // message arriving in the meantime re-opens the conversation (DESIGN 8.9). If
    // the resume swept to NOW it would destroy that message, silently, on every
    // connect until it happened to succeed, while its sender was told delivered.
    // The stamp is what keeps this a record of one past request.
    const h = await harness()
    const peer = generateIdentity()
    await h.know(peer)
    const store = (h.client as unknown as { store: MemorySessionStore }).store
    const history = (h.client as unknown as { history: HistoryStore }).history

    const startedAt = Date.now()
    await store.historyPutMany([
      history.seal({ id: 'old', peerId: peer.userId, dir: 'in', ts: startedAt - 1000, text: 'before the delete' }),
    ])
    await h.contacts.setPendingDelete(peer.userId, startedAt)
    await h.contacts.remove(peer.userId, Date.now())
    // ... and then they write again, which re-opens the conversation.
    await store.historyPutMany([
      history.seal({ id: 'new', peerId: peer.userId, dir: 'in', ts: startedAt + 1000, text: 'after the delete' }),
    ])

    await h.client.resumePendingDeletes()

    const left = (await store.historyLoadAll()).map((r) => history.open(r))
    expect(left.map((m) => m.id)).toEqual(['new'])
    expect(await h.contacts.pendingDeletes()).toEqual([])
  })

  it('does not let a sibling’s copy overwrite the message already on disk', async () => {
    // A forward from one of your own devices and the direct copy from the sender
    // describe the SAME message with different timestamps, and both now arrive on
    // every multi-device conversation because a sender no longer claims to have
    // reached every device. Whoever got there first is kept, so the message does
    // not move in the thread on the next reload.
    const h = await harness()
    const peer = generateIdentity()
    const store = (h.client as unknown as { store: MemorySessionStore }).store
    const history = (h.client as unknown as { history: HistoryStore }).history
    const key = history.storageKey(peer.userId, 'in', 'm1')
    const direct = history.seal({ id: 'm1', peerId: peer.userId, dir: 'in', ts: 5000, text: 'hello' })
    await store.saveBookWithSeen('dev', { currentId: '', sessions: [] }, 'seen1', direct)

    // The sibling's forward, carrying the ORIGINAL timestamp, arrives second.
    const forwarded = history.seal({ id: 'm1', peerId: peer.userId, dir: 'in', ts: 1000, text: 'hello' })
    await store.saveBookWithSeen('dev', { currentId: '', sessions: [] }, 'seen2', forwarded, undefined, true)

    const row = await store.historyGet(key)
    expect(row).not.toBeNull()
    expect(history.open(row!).ts).toBe(5000) // the first one stands
  })

  it('refuses a device that claims an account which has not listed it', async () => {
    // The other direction: the device's word alone is worth nothing either.
    const h = await harness()
    const peer = generateIdentity()
    const stranger = generateIdentity()
    const strangerId = deviceIdOf(stranger.ikSig.publicKey)
    await h.know(peer)
    h.serve(peer.userId, signRoster(peer.userId, 1, [deviceOf(peer)], peer.ikSig.privateKey))

    await h.hello(strangerId, peer.userId)

    expect(await h.client.accountForDevice(strangerId)).toBe(strangerId)
    expect(h.security.join(' ')).toMatch(/has not listed it/)
  })
})
