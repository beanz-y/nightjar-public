// Sending saved messages to another of your own devices (DESIGN 8.12), at the
// level the app actually calls it.
//
// The envelope's own tests cover what the seal is worth. These are about the
// decisions either side of it, which is where this could quietly do harm: handing
// every message you have to a screen that is not yours, writing somebody else's
// conversations into your history, or undoing a delete by importing a copy from a
// device that never heard about it.

import { describe, expect, it } from 'vitest'
import { type Identity, generateIdentity } from '../crypto/identity'
import { hash256 } from '../crypto/primitives'
import { type RosterDevice, signRoster } from '../crypto/roster'
import { sealHistoryTransfer } from '../crypto/historyTransfer'
import type { HistoryUnitMessage } from '../crypto/historyUnit'
import { LINK_SECRET_BYTES } from '../crypto/constants'
import { randomBytes } from '../crypto/primitives'
import { deviceIdOf } from '../crypto/identity'
import { AppLockStore } from '../storage/appLockStore'
import { HistoryStore } from '../storage/historyStore'
import { InMemoryLock } from '../storage/lock'
import { MemoryKeyStore } from '../storage/keystore'
import { PrekeyStore } from '../storage/prekeyStore'
import { MemorySessionStore } from '../storage/sessionStore'
import { ContactStore } from '../trust/contactStore'
import { NightjarClient } from './client'

const stubKdf = (s: Uint8Array, salt: Uint8Array) => hash256(new Uint8Array([...s, ...salt]))
const NOW = Date.now()

function deviceOf(id: Identity): RosterDevice {
  return { deviceId: deviceIdOf(id.ikSig.publicKey), dkSigPub: id.ikSig.publicKey, addedAt: NOW }
}

async function harness() {
  const identity = generateIdentity()
  const keys = new MemoryKeyStore()
  const lock = new InMemoryLock()
  const store = new MemorySessionStore()
  const contacts = new ContactStore(keys, lock)
  const appLock = new AppLockStore(keys, lock, stubKdf)
  await appLock.enroll([{ kind: 'pass', secret: 'x' }])
  const history = new HistoryStore(appLock)
  const client = new NightjarClient(
    identity,
    store,
    new PrekeyStore(keys, lock),
    contacts,
    lock,
    { onMessage: () => {} },
    history,
  )
  const rosters = new Map<string, ReturnType<typeof signRoster>>()
  ;(client as unknown as { directory: unknown }).directory = {
    fetchRosterWithRotation: async (a: string) => ({ roster: rosters.get(a) ?? null, rotation: null }),
    fetchBundle: async () => ({ bundle: null }),
  }
  return {
    client,
    identity,
    store,
    history,
    contacts,
    serve: (r: ReturnType<typeof signRoster>) => rosters.set(r.accountId, r),
    know: async (peer: Identity) => {
      await contacts.recordFirstContact(peer.userId, peer.ikSig.publicKey, NOW)
    },
    /** A saved message, as if it had been sent or received here. */
    seed: async (peer: string, id: string, opts: { dir?: 'in' | 'out'; ts?: number; text?: string } = {}) => {
      const row = history.seal({
        id,
        peerId: peer,
        dir: opts.dir ?? 'out',
        ts: opts.ts ?? NOW - 1000,
        text: opts.text ?? `body-${id}`,
      })
      await store.historyPutMany([row])
      return row
    },
    rows: async () => {
      const out = []
      for (const r of await store.historyLoadAll()) out.push(history.open(r))
      return out
    },
  }
}

const idOf = (n: number) => n.toString(16).padStart(32, '0')

describe('deciding what to send, and to whom', () => {
  it('refuses a device that is not on this account', async () => {
    // The seal proves the sender photographed a screen. It says nothing about
    // whose screen, so without this check, holding a phone in front of someone
    // walks away with every message they have.
    const h = await harness()
    const stranger = generateIdentity()
    h.serve(signRoster(h.client.account.accountId, 1, [deviceOf(h.identity)], h.identity.ikSig.privateKey))

    await expect(
      h.client.sealHistoryFor(deviceIdOf(stranger.ikSig.publicKey), randomBytes(LINK_SECRET_BYTES)),
    ).rejects.toThrow(/not on your account/)
  })

  it('refuses this device own code', async () => {
    const h = await harness()
    await expect(h.client.sealHistoryFor(h.client.deviceId, randomBytes(LINK_SECRET_BYTES))).rejects.toThrow(/own code/)
  })

  it('sends to a device that IS on this account', async () => {
    const h = await harness()
    const laptop = generateIdentity()
    const peer = generateIdentity()
    await h.know(peer)
    await h.seed(peer.userId, idOf(1))
    h.serve(
      signRoster(
        h.client.account.accountId,
        1,
        [deviceOf(h.identity), deviceOf(laptop)],
        h.identity.ikSig.privateKey,
      ),
    )
    const blob = await h.client.sealHistoryFor(deviceIdOf(laptop.ikSig.publicKey), randomBytes(LINK_SECRET_BYTES))
    expect(blob.length).toBeGreaterThan(0)
  })

  it('leaves out messages whose peer this device holds no contact for', async () => {
    // The receiving device would have no key for them, so no safety number and a
    // conversation it could never verify. The move export refuses these too.
    const h = await harness()
    const known = generateIdentity()
    const unknown = generateIdentity()
    await h.know(known)
    await h.seed(known.userId, idOf(1))
    await h.seed(unknown.userId, idOf(2))

    const prep = await h.client.prepareHistoryTransfer()
    expect(prep.messages.map((m) => m.peer)).toEqual([known.userId])
    expect(prep.orphaned).toBe(1)
  })

  it('bounds by time, so a long history can be sent as a recent slice', async () => {
    // The size ceiling is really a time budget: this is what lets someone send
    // something that will actually finish.
    const h = await harness()
    const peer = generateIdentity()
    await h.know(peer)
    await h.seed(peer.userId, idOf(1), { ts: NOW - 90 * 24 * 3600 * 1000 })
    await h.seed(peer.userId, idOf(2), { ts: NOW - 1000 })

    const all = await h.client.prepareHistoryTransfer()
    expect(all.messages).toHaveLength(2)
    const recent = await h.client.prepareHistoryTransfer(NOW - 7 * 24 * 3600 * 1000)
    expect(recent.messages.map((m) => m.id)).toEqual([idOf(2)])
  })

  it('never carries a message whose delete already arrived', async () => {
    const h = await harness()
    const peer = generateIdentity()
    await h.know(peer)
    const row = await h.seed(peer.userId, idOf(1))
    await h.seed(peer.userId, idOf(2))
    await h.store.saveBookWithSeen(peer.userId, { currentId: '', sessions: [] }, 'seen-x', undefined, {
      key: row.key,
    })

    const prep = await h.client.prepareHistoryTransfer()
    expect(prep.messages.map((m) => m.id)).toEqual([idOf(2)])
  })
})

describe('taking saved messages in', () => {
  /** Seal a transfer as some account would have. */
  const transferFrom = (accountId: string, messages: HistoryUnitMessage[], secret: Uint8Array) =>
    sealHistoryTransfer({ accountId, messages, createdAt: NOW }, secret)

  it('merges them in, keyed so a message already here is not duplicated', async () => {
    const h = await harness()
    const peer = generateIdentity()
    await h.know(peer)
    // This device already holds one of them.
    await h.seed(peer.userId, idOf(1), { text: 'already here' })

    const secret = randomBytes(LINK_SECRET_BYTES)
    const messages: HistoryUnitMessage[] = [
      { id: idOf(1), peer: peer.userId, dir: 'out', ts: NOW - 1000, text: 'already here' },
      { id: idOf(2), peer: peer.userId, dir: 'in', ts: NOW - 500, text: 'new one' },
    ]
    const res = await h.client.importHistoryTransfer(
      transferFrom(h.client.account.accountId, messages, secret),
      secret,
    )
    expect(res.imported).toBe(2)
    // Two rows, not three: the one already here was written over itself.
    const rows = await h.rows()
    expect(rows).toHaveLength(2)
    expect(rows.map((r) => r.id).sort()).toEqual([idOf(1), idOf(2)])
  })

  it('is safe to run twice, which is what makes retrying it safe', async () => {
    const h = await harness()
    const peer = generateIdentity()
    await h.know(peer)
    const secret = randomBytes(LINK_SECRET_BYTES)
    const messages: HistoryUnitMessage[] = [
      { id: idOf(3), peer: peer.userId, dir: 'in', ts: NOW - 200, text: 'once' },
    ]
    const blob = transferFrom(h.client.account.accountId, messages, secret)
    await h.client.importHistoryTransfer(blob, secret)
    await h.client.importHistoryTransfer(blob, secret)
    expect(await h.rows()).toHaveLength(1)
  })

  it('refuses a transfer belonging to a different account', async () => {
    // Sealed under our code proves somebody was standing here, not that they are
    // us. Writing their conversations in under their peer ids would put words in
    // contacts' mouths exactly as a forged forwarded copy would.
    const h = await harness()
    const peer = generateIdentity()
    await h.know(peer)
    const secret = randomBytes(LINK_SECRET_BYTES)
    const messages: HistoryUnitMessage[] = [
      { id: idOf(4), peer: peer.userId, dir: 'in', ts: NOW - 100, text: 'not yours' },
    ]
    await expect(
      h.client.importHistoryTransfer(transferFrom(generateIdentity().userId, messages, secret), secret),
    ).rejects.toThrow(/different account/)
    expect(await h.rows()).toHaveLength(0)
  })

  it('skips messages with a peer this device does not hold, and says how many', async () => {
    const h = await harness()
    const known = generateIdentity()
    const unknown = generateIdentity()
    await h.know(known)
    const secret = randomBytes(LINK_SECRET_BYTES)
    const messages: HistoryUnitMessage[] = [
      { id: idOf(5), peer: known.userId, dir: 'in', ts: NOW - 100, text: 'fine' },
      { id: idOf(6), peer: unknown.userId, dir: 'in', ts: NOW - 100, text: 'nobody here' },
    ]
    const res = await h.client.importHistoryTransfer(
      transferFrom(h.client.account.accountId, messages, secret),
      secret,
    )
    expect(res.imported).toBe(1)
    expect(res.skippedUnknownPeer).toBe(1)
  })

  it('does not resurrect a message this device was told to delete', async () => {
    // The sending device may never have heard about that delete, and importing
    // must not become a way to undo one.
    const h = await harness()
    const peer = generateIdentity()
    await h.know(peer)
    const key = h.history.storageKey(peer.userId, 'in', idOf(7))
    await h.store.saveBookWithSeen(peer.userId, { currentId: '', sessions: [] }, 'seen-y', undefined, { key })

    const secret = randomBytes(LINK_SECRET_BYTES)
    const messages: HistoryUnitMessage[] = [
      { id: idOf(7), peer: peer.userId, dir: 'in', ts: NOW - 100, text: 'deleted here' },
    ]
    const res = await h.client.importHistoryTransfer(
      transferFrom(h.client.account.accountId, messages, secret),
      secret,
    )
    expect(res.imported).toBe(0)
    expect(res.skippedDeleted).toBe(1)
    expect(await h.rows()).toHaveLength(0)
  })
})
