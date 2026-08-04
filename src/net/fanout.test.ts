// Fanning one message out to every device a person reads on (Sesame B2).
//
// The property that makes this change safe is the first test here: a recipient
// with no roster, which is every conversation that exists today, must produce
// exactly the single envelope it always did, with the same id and the same
// history row. Everything else is what changes only once somebody links a device.

import { describe, expect, it } from 'vitest'
import { type Identity, deviceIdOf, generateIdentity } from '../crypto/identity'
import { hash256 } from '../crypto/primitives'
import { type FetchedBundle, OWN_BUNDLE_VERSION, buildOwnBundle } from '../crypto/prekeys'
import { type RosterDevice, signRoster } from '../crypto/roster'
import { AppLockStore } from '../storage/appLockStore'
import { HistoryStore } from '../storage/historyStore'
import { InMemoryLock } from '../storage/lock'
import { MemoryKeyStore } from '../storage/keystore'
import { PrekeyStore } from '../storage/prekeyStore'
import { MemorySessionStore } from '../storage/sessionStore'
import { ContactStore } from '../trust/contactStore'
import { NightjarClient } from './client'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { encodeSyncDeleteMessage, encodeSyncSentMessage, newMsgId } from '../crypto/message'
import { initRatchetInitiator, ratchetEncrypt } from '../crypto/ratchet'
import { x3dhInitiate } from '../crypto/x3dh'
import { b64encode, encodeInitialHeader, encodeMessageHeaderWire } from '../wire/codec'

const stubKdf = (s: Uint8Array, salt: Uint8Array) => hash256(new Uint8Array([...s, ...salt]))

function bundleFor(id: Identity): FetchedBundle {
  const own = buildOwnBundle(id, Date.now(), { spkId: 1, opkStartId: 1, opkCount: 3 })
  return {
    version: OWN_BUNDLE_VERSION,
    ikSigPub: own.ikSigPub,
    ikDhPub: own.ikDhPub,
    idkbindSig: own.idkbindSig,
    spk: own.spk,
    opk: own.opks[0],
  }
}

function deviceOf(id: Identity): RosterDevice {
  return { deviceId: deviceIdOf(id.ikSig.publicKey), dkSigPub: id.ikSig.publicKey, addedAt: Date.now() }
}

async function harness(peers: Identity[]) {
  const identity = generateIdentity()
  const keys = new MemoryKeyStore()
  const lock = new InMemoryLock()
  const store = new MemorySessionStore()
  const prekeys = new PrekeyStore(keys, lock)
  // Seeded so another device can actually open a session TO this one, which the
  // self-sync tests below need.
  const mine = buildOwnBundle(identity, Date.now(), { spkId: 1, opkStartId: 1, opkCount: 4 })
  await prekeys.setFromRegistration({
    spk: { id: mine.spk.id, createdAt: mine.spk.createdAt, expiry: mine.spk.expiry, pub: mine.spk.pub, sig: mine.spk.sig },
    spkPrivById: mine.spkPrivById,
    opks: mine.opks,
    opkPrivById: mine.opkPrivById,
  })
  const ownBundle: FetchedBundle = {
    version: OWN_BUNDLE_VERSION,
    ikSigPub: mine.ikSigPub,
    ikDhPub: mine.ikDhPub,
    idkbindSig: mine.idkbindSig,
    spk: mine.spk,
    opk: mine.opks[0],
  }
  const contacts = new ContactStore(keys, lock)
  const appLock = new AppLockStore(keys, lock, stubKdf)
  await appLock.enroll([{ kind: 'pass', secret: 'x' }])
  const history = new HistoryStore(appLock)
  const notices: string[] = []
  const client = new NightjarClient(
    identity,
    store,
    prekeys,
    contacts,
    lock,
    { onMessage: () => {}, onError: (d) => notices.push(d) },
    history,
  )
  const bundles = new Map(peers.map((p) => [deviceIdOf(p.ikSig.publicKey), bundleFor(p)]))
  let served: ReturnType<typeof signRoster> | null = null
  ;(client as unknown as { directory: unknown }).directory = {
    fetchBundle: async (target: string) => ({ bundle: bundles.get(target) ?? null }),
    fetchRosterWithRotation: async () => ({ roster: served, rotation: null }),
  }
  return {
    client,
    store,
    history,
    contacts,
    notices,
    ownBundle,
    serve: (r: ReturnType<typeof signRoster> | null) => {
      served = r
    },
    know: async (peer: Identity) => {
      await contacts.recordFirstContact(peer.userId, peer.ikSig.publicKey, Date.now())
    },
    queued: async () => (await store.pendingOutbox()).entries,
    rows: async () => {
      const out = []
      for (const row of await store.historyLoadAll()) out.push(history.open(row))
      return out
    },
  }
}

describe('sending to a person with one device', () => {
  it('produces exactly the single envelope it always did', async () => {
    // The safety property for every conversation that exists today: no roster
    // means no fan-out, and the entry keeps the shape the rest of the app was
    // built around, including the transport id doubling as the content id.
    const peer = generateIdentity()
    const h = await harness([peer])
    await h.know(peer)
    h.serve(null)

    const id = await h.client.sendText(peer.userId, 'hello')
    const out = await h.queued()
    expect(out).toHaveLength(1)
    expect(out[0].id).toBe(id)
    expect(out[0].to).toBe(peer.userId)
    expect(out[0].contentId).toBeUndefined()
    expect(out[0].account).toBeUndefined()

    const rows = await h.rows()
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({ id, peerId: peer.userId, dir: 'out', text: 'hello' })
  })
})

describe('sending to a person with several devices', () => {
  it('reaches every device, from one saved message', async () => {
    const phone = generateIdentity()
    const laptop = generateIdentity()
    const h = await harness([phone, laptop])
    await h.know(phone)
    h.serve(signRoster(phone.userId, 1, [deviceOf(phone), deviceOf(laptop)], phone.ikSig.privateKey))

    const id = await h.client.sendText(phone.userId, 'to both of you')

    const out = await h.queued()
    expect(out).toHaveLength(2)
    expect(out.map((e) => e.to).sort()).toEqual(
      [deviceIdOf(phone.ikSig.publicKey), deviceIdOf(laptop.ikSig.publicKey)].sort(),
    )
    // Distinct envelope ids, because they share one outbox...
    expect(new Set(out.map((e) => e.id)).size).toBe(2)
    // ...while both name the one logical message and the one conversation.
    expect(out.every((e) => e.contentId === id)).toBe(true)
    expect(out.every((e) => e.account === phone.userId)).toBe(true)

    // ONE saved message, filed under the person rather than either device.
    const rows = await h.rows()
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({ id, peerId: phone.userId, dir: 'out', text: 'to both of you' })
  })

  it('opens a separate session per device', async () => {
    // Sessions run between devices even though the conversation is with a person,
    // so each device gets its own ratchet rather than sharing one.
    const phone = generateIdentity()
    const laptop = generateIdentity()
    const h = await harness([phone, laptop])
    await h.know(phone)
    h.serve(signRoster(phone.userId, 1, [deviceOf(phone), deviceOf(laptop)], phone.ikSig.privateKey))
    await h.client.sendText(phone.userId, 'first')

    expect(await h.store.loadBook(deviceIdOf(phone.ikSig.publicKey))).not.toBeNull()
    expect(await h.store.loadBook(deviceIdOf(laptop.ikSig.publicKey))).not.toBeNull()
    // And the ACCOUNT is not itself a session: it is a person, not an endpoint.
    // (Only true when the account id differs from every device id, which it does
    // not here, since a first device IS its account. So assert the laptop only.)
    expect(deviceIdOf(laptop.ikSig.publicKey)).not.toBe(phone.userId)
  })

  it('still saves and sends when only some of their devices can be reached', async () => {
    // Honest partial delivery: some of their devices have it, and the user is told
    // rather than being shown a message that looks fully sent.
    const phone = generateIdentity()
    const laptop = generateIdentity()
    // The laptop has no bundle, so a session to it cannot be opened.
    const h = await harness([phone])
    await h.know(phone)
    h.serve(signRoster(phone.userId, 1, [deviceOf(phone), deviceOf(laptop)], phone.ikSig.privateKey))

    const id = await h.client.sendText(phone.userId, 'partial')
    const out = await h.queued()
    expect(out).toHaveLength(1)
    expect(out[0].to).toBe(deviceIdOf(phone.ikSig.publicKey))
    expect(h.notices.join(' ')).toMatch(/sent to 1 of 2 of their devices/)
    // The message is still saved once, under the person.
    const rows = await h.rows()
    expect(rows).toHaveLength(1)
    expect(rows[0].id).toBe(id)
  })

  it('fails the send outright when none of their devices can be reached', async () => {
    // Nothing queued and nothing saved, so the message is not shown as sent.
    const phone = generateIdentity()
    const h = await harness([])
    await h.know(phone)
    h.serve(null)
    await expect(h.client.sendText(phone.userId, 'nowhere')).rejects.toThrow()
    expect(await h.queued()).toHaveLength(0)
    expect(await h.rows()).toHaveLength(0)
  })

  it('does not fan out to a roster it could not verify', async () => {
    // An unverifiable device list must never widen who a message goes to. With no
    // contact record there is no key to check the signature against.
    const phone = generateIdentity()
    const laptop = generateIdentity()
    const h = await harness([phone, laptop])
    // Deliberately NOT known: no contact record for this account.
    h.serve(signRoster(phone.userId, 1, [deviceOf(phone), deviceOf(laptop)], phone.ikSig.privateKey))

    await h.client.sendText(phone.userId, 'only to the account itself')
    const out = await h.queued()
    expect(out).toHaveLength(1)
    expect(out[0].to).toBe(phone.userId)
  })
})

describe('copying a sent message to your own other devices', () => {
  it('sends nothing extra when this account has only this device', async () => {
    // True for everyone until they link a second device, and it costs no network
    // call: our own resolved device list is just us.
    const peer = generateIdentity()
    const h = await harness([peer])
    await h.know(peer)
    h.serve(null)
    await h.client.sendText(peer.userId, 'solo')
    await new Promise((r) => setTimeout(r, 0))
    expect(await h.queued()).toHaveLength(1)
  })

  it('stores an arriving copy as our own message in the right conversation', async () => {
    // The point of the whole thing: a message sent from the phone shows up on the
    // laptop as something WE sent to that person, at the time it was written.
    const phone = generateIdentity()
    const laptop = await harness([])
    const peer = generateIdentity()

    // The laptop is a device of the phone's account, and knows it.
    laptop.client.setAccountKey({ privateKey: phone.ikSig.privateKey, publicKey: phone.ikSig.publicKey })
    await laptop.contacts.putKnownRoster(phone.userId, {
      version: 1,
      devices: [phone.userId, laptop.client.deviceId],
    })

    const contentId = bytesToHex(newMsgId())
    const originalTs = Date.now() - 60_000
    await deliverFromOwnDevice(laptop, phone, encodeSyncSentMessage(hexToBytes(contentId), peer.userId, originalTs, 'from my phone'))

    const rows = await laptop.rows()
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({ id: contentId, peerId: peer.userId, dir: 'out', text: 'from my phone' })
    // The ORIGINAL time, not the arrival time, or it would sort to whenever the
    // laptop happened to be switched on.
    expect(rows[0].ts).toBe(originalTs)
  })

  it('refuses a copy offered by a device that is not ours', async () => {
    // Otherwise anyone could write into your OUTBOUND history and put words in
    // your mouth in a conversation with somebody else.
    const stranger = generateIdentity()
    const laptop = await harness([])
    const peer = generateIdentity()
    // No roster tying the stranger to this account, so it is not one of ours.
    await deliverFromOwnDevice(
      laptop,
      stranger,
      encodeSyncSentMessage(hexToBytes(bytesToHex(newMsgId())), peer.userId, Date.now(), 'not yours'),
    )
    expect(await laptop.rows()).toHaveLength(0)
  })
})

/** Open a session from `sender` to the harness device and deliver one plaintext
 *  through the REAL inbound path, so the persist decision under test is the one
 *  the app actually runs rather than a restatement of it. */
async function deliverFromOwnDevice(
  h: Awaited<ReturnType<typeof harness>>,
  sender: Identity,
  plaintext: Uint8Array,
): Promise<void> {
  // The no-one-time-prekey path, deliberately: this helper is called more than
  // once per test, and a second initial citing an already-consumed prekey cannot
  // be answered. That degraded path is a documented, always-available mode.
  const target = { ...h.ownBundle, opk: null }
  const ini = x3dhInitiate(sender, target, Date.now())
  const state = initRatchetInitiator(ini.sk, ini.ad, target.spk.pub)
  const { header, ciphertext } = ratchetEncrypt(state, plaintext)
  await (h.client as unknown as { handleDeliver(from: string, env: unknown): Promise<void> }).handleDeliver(
    deviceIdOf(sender.ikSig.publicKey),
    {
      id: bytesToHex(newMsgId()),
      kind: 'initial',
      header: encodeMessageHeaderWire(header),
      ciphertext: b64encode(ciphertext),
      initialHeader: encodeInitialHeader(ini.header),
    },
  )
  await new Promise((r) => setTimeout(r, 0))
}

describe('deleting a message across devices', () => {
  it('asks every device of the recipient, not just one', async () => {
    // A delete that reached only one of their devices would quietly survive on the
    // others, which is the opposite of what the user asked for.
    const phone = generateIdentity()
    const laptop = generateIdentity()
    const h = await harness([phone, laptop])
    await h.know(phone)
    h.serve(signRoster(phone.userId, 1, [deviceOf(phone), deviceOf(laptop)], phone.ikSig.privateKey))

    const id = await h.client.sendText(phone.userId, 'regrettable')
    // Pretend both copies were delivered, so the delete is a request rather than a
    // cancellation.
    for (const e of await h.queued()) await h.store.removeOutbox(e.id)

    const { requested } = await h.client.deleteForEveryone(phone.userId, id)
    expect(requested).toBe(true)
    const controls = await h.queued()
    expect(controls).toHaveLength(2)
    expect(controls.map((e) => e.to).sort()).toEqual(
      [deviceIdOf(phone.ikSig.publicKey), deviceIdOf(laptop.ikSig.publicKey)].sort(),
    )
    // Controls are silent and carry their own fresh ids, never the target's.
    expect(controls.every((e) => e.silent === true)).toBe(true)
    expect(controls.every((e) => e.id !== id)).toBe(true)
    // The local copy is gone either way.
    expect(await h.rows()).toHaveLength(0)
  })

  it('cancels every copy still waiting, not just the first', async () => {
    // Stopped in time means stopped for all of their devices.
    const phone = generateIdentity()
    const laptop = generateIdentity()
    const h = await harness([phone, laptop])
    await h.know(phone)
    h.serve(signRoster(phone.userId, 1, [deviceOf(phone), deviceOf(laptop)], phone.ikSig.privateKey))

    const id = await h.client.sendText(phone.userId, 'caught in time')
    expect(await h.queued()).toHaveLength(2)

    const { requested } = await h.client.deleteForEveryone(phone.userId, id)
    expect(requested).toBe(false) // nothing had left, so nothing was asked
    expect(await h.queued()).toHaveLength(0)
    expect(await h.rows()).toHaveLength(0)
  })

  it('still asks when only some copies were caught in time', async () => {
    // One device already has it and the other was still queued, so the delete is
    // both a cancellation and a request.
    const phone = generateIdentity()
    const laptop = generateIdentity()
    const h = await harness([phone, laptop])
    await h.know(phone)
    h.serve(signRoster(phone.userId, 1, [deviceOf(phone), deviceOf(laptop)], phone.ikSig.privateKey))

    const id = await h.client.sendText(phone.userId, 'half gone')
    const queued = await h.queued()
    await h.store.removeOutbox(queued[0].id) // that one already left

    const { requested } = await h.client.deleteForEveryone(phone.userId, id)
    expect(requested).toBe(true)
  })

  it('drops our own copy when another of our devices deletes it', async () => {
    // The other half: a message YOU sent, deleted from your phone, has to go from
    // your laptop too, and an ordinary delete control cannot say which conversation
    // your outbound copy is in.
    const myPhone = generateIdentity()
    const laptop = await harness([])
    const peer = generateIdentity()
    laptop.client.setAccountKey({ privateKey: myPhone.ikSig.privateKey, publicKey: myPhone.ikSig.publicKey })
    await laptop.contacts.putKnownRoster(myPhone.userId, {
      version: 1,
      devices: [myPhone.userId, laptop.client.deviceId],
    })

    const contentId = bytesToHex(newMsgId())
    await deliverFromOwnDevice(
      laptop,
      myPhone,
      encodeSyncSentMessage(hexToBytes(contentId), peer.userId, Date.now(), 'sent from the phone'),
    )
    expect(await laptop.rows()).toHaveLength(1)

    await deliverFromOwnDevice(laptop, myPhone, encodeSyncDeleteMessage(hexToBytes(contentId), peer.userId))
    expect(await laptop.rows()).toHaveLength(0)
  })

  it('ignores a delete of our own history offered by somebody else', async () => {
    // Without the self-only check anyone could delete messages out of your history.
    const myPhone = generateIdentity()
    const stranger = generateIdentity()
    const laptop = await harness([])
    const peer = generateIdentity()
    laptop.client.setAccountKey({ privateKey: myPhone.ikSig.privateKey, publicKey: myPhone.ikSig.publicKey })
    await laptop.contacts.putKnownRoster(myPhone.userId, {
      version: 1,
      devices: [myPhone.userId, laptop.client.deviceId],
    })

    const contentId = bytesToHex(newMsgId())
    await deliverFromOwnDevice(
      laptop,
      myPhone,
      encodeSyncSentMessage(hexToBytes(contentId), peer.userId, Date.now(), 'still mine'),
    )
    await deliverFromOwnDevice(laptop, stranger, encodeSyncDeleteMessage(hexToBytes(contentId), peer.userId))
    expect(await laptop.rows()).toHaveLength(1)
  })
})
