// The forwarding fallback, and what a delivery report means once one message is
// several envelopes (Sesame B2).
//
// Fanning out only works when the SENDER knows about device lists. Every contact
// running an older build addresses one device and always will, and that window is
// measured in months. So the device that did receive a message passes a copy to
// its own siblings, and the way it knows to is the absence of a promise: a text
// whose fanned-out bit is clear is one nobody claims to have delivered anywhere
// else.
//
// Every assertion about what was passed on is made by DECRYPTING what the client
// actually queued, from the sibling's side, rather than by trusting the outbox
// row: the whole point of these records is what is inside them.

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
import { MemorySessionStore, type OutboxEntry } from '../storage/sessionStore'
import { ContactStore } from '../trust/contactStore'
import { NightjarClient } from './client'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import {
  type DecodedMessage,
  decodeMessage,
  encodeDeleteMessage,
  encodeSyncRecvDeleteMessage,
  encodeSyncRecvMessage,
  encodeTextMessage,
  newMsgId,
} from '../crypto/message'
import { type RatchetState, initRatchetInitiator, initRatchetResponder, ratchetDecrypt, ratchetEncrypt } from '../crypto/ratchet'
import { x3dhInitiate, x3dhRespond } from '../crypto/x3dh'
import {
  type WireEnvelope,
  b64encode,
  decodeEnvelope,
  encodeInitialHeader,
  encodeMessageHeaderWire,
} from '../wire/codec'

const stubKdf = (s: Uint8Array, salt: Uint8Array) => hash256(new Uint8Array([...s, ...salt]))

/** One identity's published bundle AND the private halves behind it, so a test
 *  can both be addressed and actually read what it was sent. */
function kitFor(id: Identity) {
  const own = buildOwnBundle(id, Date.now(), { spkId: 1, opkStartId: 1, opkCount: 3 })
  const bundle: FetchedBundle = {
    version: OWN_BUNDLE_VERSION,
    ikSigPub: own.ikSigPub,
    ikDhPub: own.ikDhPub,
    idkbindSig: own.idkbindSig,
    spk: own.spk,
    opk: own.opks[0],
  }
  return { own, bundle, spkPubById: new Map([[own.spk.id, own.spk.pub]]) }
}

type Kit = ReturnType<typeof kitFor>

function deviceOf(id: Identity): RosterDevice {
  return { deviceId: deviceIdOf(id.ikSig.publicKey), dkSigPub: id.ikSig.publicKey, addedAt: Date.now() }
}

/** Let the fire-and-forget work inside handleDeliver actually run. It chains
 *  several awaits (resolve the device list, open a session, commit), so one
 *  microtask drain is not enough. */
async function settle(): Promise<void> {
  for (let i = 0; i < 8; i++) await new Promise((r) => setTimeout(r, 0))
}

/** Like the fan-out harness, but rosters are served PER ACCOUNT: these tests need
 *  this device's own account to have a device list while the contact sending to it
 *  deliberately has none, which is the whole situation under test. */
async function harness(peers: Identity[]) {
  const identity = generateIdentity()
  const keys = new MemoryKeyStore()
  const lock = new InMemoryLock()
  const store = new MemorySessionStore()
  const prekeys = new PrekeyStore(keys, lock)
  const mine = buildOwnBundle(identity, Date.now(), { spkId: 1, opkStartId: 1, opkCount: 6 })
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
  const inbound: Array<{ from: string; id: string; text: string; ts: number }> = []
  const deleted: Array<{ from: string; id: string }> = []
  const client = new NightjarClient(
    identity,
    store,
    prekeys,
    contacts,
    lock,
    {
      onMessage: (from, m) => inbound.push({ from, id: m.id, text: m.text, ts: m.ts }),
      onDelete: (from, id) => deleted.push({ from, id }),
    },
    history,
  )
  const kits = new Map<string, Kit>()
  const add = (id: Identity) => {
    const k = kitFor(id)
    kits.set(deviceIdOf(id.ikSig.publicKey), k)
    return k
  }
  for (const p of peers) add(p)
  const rosters = new Map<string, ReturnType<typeof signRoster>>()
  ;(client as unknown as { directory: unknown }).directory = {
    fetchBundle: async (target: string) => ({ bundle: kits.get(target)?.bundle ?? null }),
    fetchRosterWithRotation: async (accountId: string) => ({ roster: rosters.get(accountId) ?? null, rotation: null }),
    deliveredCheck: async () => [],
  }
  return {
    client,
    store,
    history,
    contacts,
    identity,
    inbound,
    deleted,
    ownBundle,
    add,
    kit: (id: Identity) => kits.get(deviceIdOf(id.ikSig.publicKey)),
    serve: (r: ReturnType<typeof signRoster>) => rosters.set(r.accountId, r),
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

type Harness = Awaited<ReturnType<typeof harness>>

/** Make this device a LINKED device of `accountHolder`'s account: it holds the
 *  account key, and the account's published list names both of them. */
async function linkInto(h: Harness, accountHolder: Identity): Promise<void> {
  h.client.setAccountKey({ privateKey: accountHolder.ikSig.privateKey, publicKey: accountHolder.ikSig.publicKey })
  h.add(accountHolder)
  h.serve(
    signRoster(
      accountHolder.userId,
      1,
      [
        deviceOf(accountHolder),
        { deviceId: h.client.deviceId, dkSigPub: h.identity.ikSig.publicKey, addedAt: Date.now() },
      ],
      accountHolder.ikSig.privateKey,
    ),
  )
}

/** Deliver one plaintext to the harness device through the REAL inbound path, so
 *  what is under test is the code the app runs rather than a restatement of it. */
async function deliverFrom(h: Harness, sender: Identity, plaintext: Uint8Array): Promise<void> {
  // The no-one-time-prekey path deliberately: a second initial citing an
  // already-consumed prekey cannot be answered, and these tests deliver twice.
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
  await settle()
}

/** Reads what the client queued to one of our own other devices, from that
 *  device's side, keeping its ratchet across calls so a second control on the
 *  same session opens too. */
function siblingReader(sibling: Identity, kit: Kit) {
  let state: RatchetState | null = null
  return (entry: OutboxEntry): DecodedMessage => {
    const env = decodeEnvelope(entry.env as WireEnvelope)
    if (env.kind === 'initial') {
      const ih = env.initialHeader
      if (!ih) throw new Error('initial envelope without its header')
      const resp = x3dhRespond(
        sibling,
        ih,
        { spkPrivById: kit.own.spkPrivById, opkPrivById: kit.own.opkPrivById },
        Date.now(),
      )
      const spkPriv = kit.own.spkPrivById.get(ih.spkId)
      const spkPub = kit.spkPubById.get(ih.spkId)
      if (!spkPriv || !spkPub) throw new Error('unknown signed prekey id')
      const opened = ratchetDecrypt(
        initRatchetResponder(resp.sk, resp.ad, { privateKey: spkPriv, publicKey: spkPub }),
        env.header,
        env.ciphertext,
        Date.now(),
      )
      state = opened.state
      return decodeMessage(opened.plaintext)
    }
    if (!state) throw new Error('a normal envelope arrived with no session')
    const opened = ratchetDecrypt(state, env.header, env.ciphertext, Date.now())
    state = opened.state
    return decodeMessage(opened.plaintext)
  }
}

/** The queued controls addressed to one of our own other devices. */
async function toSibling(h: Harness, sibling: Identity): Promise<OutboxEntry[]> {
  const device = deviceIdOf(sibling.ikSig.publicKey)
  return (await h.queued()).filter((e) => e.to === device)
}

describe('passing on a message the sender addressed to one device only', () => {
  it('forwards it to this account other devices, carrying its id and arrival time', async () => {
    // The case that makes multi-device usable at all: a contact on a build that
    // has never heard of device lists sends one envelope, and the device that got
    // it is the only thing standing between the laptop and an empty conversation.
    const phone = generateIdentity()
    const alice = generateIdentity()
    const h = await harness([alice])
    await linkInto(h, phone)
    await h.know(alice)

    const contentId = bytesToHex(newMsgId())
    const before = Date.now()
    await deliverFrom(h, alice, encodeTextMessage(hexToBytes(contentId), 'sent the old way', false, false))

    expect(h.inbound).toHaveLength(1)
    expect(h.inbound[0]).toMatchObject({ from: alice.userId, id: contentId, text: 'sent the old way' })

    const out = await toSibling(h, phone)
    expect(out).toHaveLength(1)
    expect(out[0].silent).toBe(true) // nothing about a forward notifies anybody
    const kit = h.kit(phone)
    if (!kit) throw new Error('no kit for the sibling')
    const rec = siblingReader(phone, kit)(out[0])
    expect(rec.kind).toBe('syncRecv')
    if (rec.kind !== 'syncRecv') throw new Error('unreachable')
    // The ORIGINAL content id, so a later delete reaches it on both devices...
    expect(bytesToHex(rec.id)).toBe(contentId)
    // ...filed under the person who actually sent it, not the device relaying it...
    expect(rec.accountId).toBe(alice.userId)
    expect(rec.body).toBe('sent the old way')
    // ...and stamped when it arrived, not when the sibling next wakes up.
    expect(rec.ts).toBeGreaterThanOrEqual(before)
  })

  it('does not forward one the sender says it already fanned out', async () => {
    // A sender that addressed every device has already done this job, and a copy
    // per sibling per message would double the traffic for nothing.
    const phone = generateIdentity()
    const alice = generateIdentity()
    const h = await harness([alice])
    await linkInto(h, phone)
    await h.know(alice)

    await deliverFrom(h, alice, encodeTextMessage(newMsgId(), 'sent the new way', false, true))
    expect(h.inbound).toHaveLength(1)
    expect(await toSibling(h, phone)).toHaveLength(0)
  })

  it('never forwards a session-only message', async () => {
    // Session-only is the one kind deliberately written down nowhere (8.7), and a
    // forward sits in the outbox until it is delivered, which is a durable record
    // of exactly the thing that promised not to leave one.
    const phone = generateIdentity()
    const alice = generateIdentity()
    const h = await harness([alice])
    await linkInto(h, phone)
    await h.know(alice)

    await deliverFrom(h, alice, encodeTextMessage(newMsgId(), 'say nothing', true, false))
    expect(h.inbound).toHaveLength(1)
    expect(await toSibling(h, phone)).toHaveLength(0)
  })

  it('forwards nothing on an account that has only this device', async () => {
    // True for everyone who has not linked one, which is the invisibility property
    // the whole of Sesame is built to keep.
    const alice = generateIdentity()
    const h = await harness([alice])
    await h.know(alice)

    await deliverFrom(h, alice, encodeTextMessage(newMsgId(), 'just me', false, false))
    expect(h.inbound).toHaveLength(1)
    expect(await h.queued()).toHaveLength(0)
  })
})

describe('a send says whether it addressed every device', () => {
  it('marks a fanned-out message, and leaves a single-device one unmarked', async () => {
    // The two halves of the same claim, asserted on the wire the recipient reads:
    // saying "fanned" when it was not would strand the copy that was missed.
    const alicePhone = generateIdentity()
    const aliceLaptop = generateIdentity()
    const bob = generateIdentity()
    const h = await harness([alicePhone, aliceLaptop, bob])
    await h.know(alicePhone)
    await h.know(bob)
    h.serve(signRoster(alicePhone.userId, 1, [deviceOf(alicePhone), deviceOf(aliceLaptop)], alicePhone.ikSig.privateKey))

    await h.client.sendText(alicePhone.userId, 'to a person with two devices')
    const toLaptop = await toSibling(h, aliceLaptop)
    expect(toLaptop).toHaveLength(1)
    const laptopKit = h.kit(aliceLaptop)
    if (!laptopKit) throw new Error('no kit')
    const fanned = siblingReader(aliceLaptop, laptopKit)(toLaptop[0])
    expect(fanned.kind === 'text' && fanned.fanned).toBe(true)

    // Bob has published no device list, so nothing was fanned anywhere and his
    // device must not be told otherwise.
    await h.client.sendText(bob.userId, 'to a person with one')
    const toBob = await toSibling(h, bob)
    expect(toBob).toHaveLength(1)
    const bobKit = h.kit(bob)
    if (!bobKit) throw new Error('no kit')
    const plain = siblingReader(bob, bobKit)(toBob[0])
    expect(plain.kind === 'text' && plain.fanned).toBe(false)
  })
})

describe('receiving a message another of our devices passed on', () => {
  it('files it as an inbound message from the right person, at the right time', async () => {
    const phone = generateIdentity()
    const alice = generateIdentity()
    const h = await harness([])
    await linkInto(h, phone)

    const contentId = bytesToHex(newMsgId())
    const originalTs = Date.now() - 90_000
    await deliverFrom(h, phone, encodeSyncRecvMessage(hexToBytes(contentId), alice.userId, originalTs, 'via the phone'))

    const rows = await h.rows()
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({ id: contentId, peerId: alice.userId, dir: 'in', text: 'via the phone' })
    expect(rows[0].ts).toBe(originalTs)
    expect(h.inbound[0]).toMatchObject({ from: alice.userId, id: contentId, ts: originalTs })
  })

  it('refuses one offered by a device that is not ours', async () => {
    // Without this check anyone could write an INBOUND message attributed to a
    // third party, which is putting words in a contact's mouth.
    const phone = generateIdentity()
    const stranger = generateIdentity()
    const alice = generateIdentity()
    const h = await harness([])
    await linkInto(h, phone)

    await deliverFrom(h, stranger, encodeSyncRecvMessage(newMsgId(), alice.userId, Date.now(), 'alice never said this'))
    expect(await h.rows()).toHaveLength(0)
  })

  it('does not forward it again', async () => {
    // Only the device that received the original passes it on, so copies cannot
    // circulate between siblings.
    const phone = generateIdentity()
    const alice = generateIdentity()
    const h = await harness([])
    await linkInto(h, phone)

    await deliverFrom(h, phone, encodeSyncRecvMessage(newMsgId(), alice.userId, Date.now(), 'already passed on'))
    expect(await toSibling(h, phone)).toHaveLength(0)
  })
})

describe('passing on a delete', () => {
  it('forwards an inbound delete-for-everyone to our own devices', async () => {
    const phone = generateIdentity()
    const alice = generateIdentity()
    const h = await harness([alice])
    await linkInto(h, phone)
    await h.know(alice)
    const kit = h.kit(phone)
    if (!kit) throw new Error('no kit')
    const read = siblingReader(phone, kit)

    const contentId = bytesToHex(newMsgId())
    await deliverFrom(h, alice, encodeTextMessage(hexToBytes(contentId), 'regrettable', false, false))
    const first = await toSibling(h, phone)
    expect(first).toHaveLength(1)
    read(first[0]) // establishes the session, exactly as the sibling would
    for (const e of first) await h.store.removeOutbox(e.id) // that forward has left

    await deliverFrom(h, alice, encodeDeleteMessage(hexToBytes(contentId)))
    const second = await toSibling(h, phone)
    expect(second).toHaveLength(1)
    const rec = read(second[0])
    expect(rec.kind).toBe('syncRecvDelete')
    if (rec.kind !== 'syncRecvDelete') throw new Error('unreachable')
    expect(bytesToHex(rec.id)).toBe(contentId)
    expect(rec.accountId).toBe(alice.userId)
  })

  it('drops the received copy when another of our devices forwards a delete', async () => {
    const phone = generateIdentity()
    const alice = generateIdentity()
    const h = await harness([])
    await linkInto(h, phone)

    const contentId = bytesToHex(newMsgId())
    await deliverFrom(h, phone, encodeSyncRecvMessage(hexToBytes(contentId), alice.userId, Date.now(), 'goes away'))
    expect(await h.rows()).toHaveLength(1)

    await deliverFrom(h, phone, encodeSyncRecvDeleteMessage(hexToBytes(contentId), alice.userId))
    expect(await h.rows()).toHaveLength(0)
    expect(h.deleted.at(-1)).toMatchObject({ from: alice.userId, id: contentId })
  })

  it('ignores a forwarded delete offered by somebody else', async () => {
    const phone = generateIdentity()
    const stranger = generateIdentity()
    const alice = generateIdentity()
    const h = await harness([])
    await linkInto(h, phone)

    const contentId = bytesToHex(newMsgId())
    await deliverFrom(h, phone, encodeSyncRecvMessage(hexToBytes(contentId), alice.userId, Date.now(), 'stays'))
    await deliverFrom(h, stranger, encodeSyncRecvDeleteMessage(hexToBytes(contentId), alice.userId))
    expect(await h.rows()).toHaveLength(1)
  })
})

describe('what a delivery report means once one message is several envelopes', () => {
  it('marks the one saved message when any copy is picked up', async () => {
    // The relay speaks in transport ids and the user sees messages; without the
    // back-reference the indicator would simply stop working for anyone whose
    // contact has linked a device.
    const alicePhone = generateIdentity()
    const aliceLaptop = generateIdentity()
    const h = await harness([alicePhone, aliceLaptop])
    await h.know(alicePhone)
    h.serve(signRoster(alicePhone.userId, 1, [deviceOf(alicePhone), deviceOf(aliceLaptop)], alicePhone.ikSig.privateKey))

    const id = await h.client.sendText(alicePhone.userId, 'to both')
    const out = await h.queued()
    expect(out).toHaveLength(2)
    // The copy to their LAPTOP, whose transport id is nothing like the message id.
    const laptopCopy = out.find((e) => e.to === deviceIdOf(aliceLaptop.ikSig.publicKey))
    if (!laptopCopy) throw new Error('no copy to the laptop')
    expect(laptopCopy.id).not.toBe(id)

    await (h.client as unknown as { markDeliveredEnvelope(f: string, i: string): Promise<void> }).markDeliveredEnvelope(
      laptopCopy.to,
      laptopCopy.id,
    )
    const rows = await h.rows()
    expect(rows).toHaveLength(1)
    expect(rows[0].status).toBe('delivered')
  })

  it('does not treat one of OUR OWN devices getting a copy as delivery', async () => {
    // A copy reaching our own laptop says nothing about whether the person it was
    // written for has it, so it must never move the indicator.
    const myPhone = generateIdentity()
    const alice = generateIdentity()
    const h = await harness([alice])
    await linkInto(h, myPhone)
    await h.know(alice)

    const id = await h.client.sendText(alice.userId, 'a message')
    await settle()
    const selfCopy = (await toSibling(h, myPhone))[0]
    if (!selfCopy) throw new Error('no copy to our own other device')

    await (h.client as unknown as { markDeliveredEnvelope(f: string, i: string): Promise<void> }).markDeliveredEnvelope(
      selfCopy.to,
      selfCopy.id,
    )
    const row = (await h.rows()).find((m) => m.id === id)
    expect(row?.status).toBeUndefined()
  })
})
