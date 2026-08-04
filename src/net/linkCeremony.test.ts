// The link ceremony end to end (Sesame B1), two real clients with the relay
// hand-cranked between them.
//
// The security of linking rests on one thing: the secret in the QR travelled
// screen to camera, so the relay never saw it. These tests are about what that
// buys, and about what happens when the relay tries to spend it anyway.

import { describe, expect, it } from 'vitest'
import { LINK_SECRET_BYTES } from '../crypto/constants'
import { type Identity, accountIdOf, deviceIdOf, generateIdentity } from '../crypto/identity'
import { hash256, randomBytes } from '../crypto/primitives'
import { type LinkPayload, sealLink } from '../crypto/link'
import { AppLockStore } from '../storage/appLockStore'
import { HistoryStore } from '../storage/historyStore'
import { InMemoryLock } from '../storage/lock'
import { MemoryKeyStore } from '../storage/keystore'
import { PrekeyStore } from '../storage/prekeyStore'
import { MemorySessionStore } from '../storage/sessionStore'
import { ContactStore } from '../trust/contactStore'
import { newLinkCode, parseLinkCode } from '../trust/linkCode'
import { type DeviceRoster } from '../crypto/roster'
import { type WireDeviceRoster, b64encode, decodeDeviceRoster } from '../wire/codec'
import { openLink } from '../crypto/link'
import { NightjarClient } from './client'

const stubKdf = (s: Uint8Array, salt: Uint8Array) => hash256(new Uint8Array([...s, ...salt]))

interface Internals {
  handleLinkChunk(chunk: string): void
}

async function device(identity: Identity = generateIdentity()) {
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
  /** Chunks this device put on the wire, in order. */
  const sent: Array<{ to: string; chunk: string }> = []
  ;(client as unknown as { transport: unknown }).transport = {
    request: async (_id: string, msg: { to: string; chunk: string }) => {
      sent.push({ to: msg.to, chunk: msg.chunk })
      return { t: 'sent' }
    },
  }
  // A Directory that only remembers the last roster published, which is all the
  // device-list tests need and keeps the monotonicity check honest.
  let roster: DeviceRoster | null = null
  ;(client as unknown as { directory: unknown }).directory = {
    fetchRoster: async () => roster,
    fetchRosterWithRotation: async () => ({ roster, rotation: null }),
    publishRoster: async (wire: WireDeviceRoster) => {
      const next = decodeDeviceRoster(wire)
      roster = next
      return next.version
    },
  }
  return { identity, client, contacts, sent, security, published: () => roster }
}

async function knownContact(store: ContactStore) {
  const peer = generateIdentity()
  await store.recordFirstContact(peer.userId, peer.ikSig.publicKey, Date.now())
  return peer
}

describe('the link ceremony', () => {
  it('carries the account key and the contacts to the new device', async () => {
    const existing = await device()
    const fresh = await device()
    const friend = await knownContact(existing.contacts)
    await existing.contacts.setAlias(friend.userId, 'best friend')

    // The new device shows a code. The secret in it never goes near the relay.
    const { code } = newLinkCode(fresh.identity.ikSig.publicKey)
    const scanned = parseLinkCode(code)
    expect(scanned.deviceId).toBe(deviceIdOf(fresh.identity.ikSig.publicKey))

    // The new device starts listening under its own secret.
    let received: LinkPayload | null = null
    fresh.client.awaitLinkPayload(scanned.secret, (p) => {
      received = p
    })

    // The existing device sends. Both halves of the ceremony run over the wire.
    const { chunks } = await existing.client.sendLinkPayload(scanned.deviceId, scanned.secret)
    expect(chunks).toBe(1)
    expect(existing.sent[0].to).toBe(scanned.deviceId)
    for (const s of existing.sent) (fresh.client as unknown as Internals).handleLinkChunk(s.chunk)

    expect(received).not.toBeNull()
    const payload = received as unknown as LinkPayload
    expect(payload.accountId).toBe(accountIdOf(existing.identity.ikSig.publicKey))
    expect(payload.accountKeyPriv).toEqual(existing.identity.ikSig.privateKey)
    expect(payload.contacts.map((c) => c.peerId)).toEqual([friend.userId])
    expect(payload.aliases[friend.userId]).toBe('best friend')
  })

  it('sends no trust, so a linked device verifies for itself', async () => {
    // The difference from a move file, and Dan's call: a move REPLACES a device so
    // verifications travel; a link ADDS one, so it earns its own.
    const existing = await device()
    const fresh = await device()
    const friend = await knownContact(existing.contacts)
    await existing.contacts.markVerified(friend.userId, Date.now())
    expect((await existing.contacts.get(friend.userId))!.trust).toBe('verified')

    const scanned = parseLinkCode(newLinkCode(fresh.identity.ikSig.publicKey).code)
    let received: LinkPayload | null = null
    fresh.client.awaitLinkPayload(scanned.secret, (p) => {
      received = p
    })
    await existing.client.sendLinkPayload(scanned.deviceId, scanned.secret)
    for (const s of existing.sent) (fresh.client as unknown as Internals).handleLinkChunk(s.chunk)

    const payload = received as unknown as LinkPayload
    expect(payload.contacts).toEqual([{ peerId: friend.userId, ikSig: b64encode(friend.ikSig.publicKey) }])
    expect(JSON.stringify(payload)).not.toContain('verified')
  })

  it('ignores a transfer sealed under a secret this device never issued', async () => {
    // The relay knows the new device's id (it routes to it) but not the secret,
    // so this is the shape of a relay trying to inject an account of its choosing.
    const fresh = await device()
    const attacker = await device()
    const scanned = parseLinkCode(newLinkCode(fresh.identity.ikSig.publicKey).code)
    let received: LinkPayload | null = null
    fresh.client.awaitLinkPayload(scanned.secret, (p) => {
      received = p
    })

    const wrong = randomBytes(LINK_SECRET_BYTES)
    await attacker.client.sendLinkPayload(scanned.deviceId, wrong)
    for (const s of attacker.sent) (fresh.client as unknown as Internals).handleLinkChunk(s.chunk)

    expect(received).toBeNull()
    expect(fresh.security.join(' ')).toMatch(/could not open with its own linking code/)
  })

  it('ignores chunks entirely when this device is not being linked', async () => {
    const fresh = await device()
    const attacker = await device()
    const chunks = sealLink(
      {
        accountId: accountIdOf(attacker.identity.ikSig.publicKey),
        accountKeyPriv: attacker.identity.ikSig.privateKey,
        contacts: [],
        aliases: {},
        createdAt: Date.now(),
      },
      randomBytes(LINK_SECRET_BYTES),
    )
    // No awaitLinkPayload: nothing is listening, so nothing is buffered.
    for (const c of chunks) (fresh.client as unknown as Internals).handleLinkChunk(b64encode(c))
    expect(fresh.security).toEqual([])
  })

  it('reassembles a transfer that needed several chunks, in any order', async () => {
    const existing = await device()
    const fresh = await device()
    for (let i = 0; i < 400; i++) await knownContact(existing.contacts)

    const scanned = parseLinkCode(newLinkCode(fresh.identity.ikSig.publicKey).code)
    let received: LinkPayload | null = null
    fresh.client.awaitLinkPayload(scanned.secret, (p) => {
      received = p
    })
    const { chunks } = await existing.client.sendLinkPayload(scanned.deviceId, scanned.secret)
    expect(chunks).toBeGreaterThan(1)

    // Delivered backwards, and one repeated, as a relay is free to do.
    const wire = [...existing.sent].reverse()
    for (const s of [...wire, wire[0]]) (fresh.client as unknown as Internals).handleLinkChunk(s.chunk)
    expect(received).not.toBeNull()
    expect((received as unknown as LinkPayload).contacts).toHaveLength(400)
  })

  it('does not fire until the transfer is complete', async () => {
    const existing = await device()
    const fresh = await device()
    for (let i = 0; i < 400; i++) await knownContact(existing.contacts)
    const scanned = parseLinkCode(newLinkCode(fresh.identity.ikSig.publicKey).code)
    let received: LinkPayload | null = null
    fresh.client.awaitLinkPayload(scanned.secret, (p) => {
      received = p
    })
    await existing.client.sendLinkPayload(scanned.deviceId, scanned.secret)

    // Everything but the last chunk: a partial account is never handed over.
    for (const s of existing.sent.slice(0, -1)) (fresh.client as unknown as Internals).handleLinkChunk(s.chunk)
    expect(received).toBeNull()
    expect(fresh.security).toEqual([])
  })

  it('makes the linked device act as the account, not as a device of one', async () => {
    // The point of the whole ceremony. Before it, a fresh device is its own
    // account; after it, it signs and resolves as the account it joined, while
    // keeping its own device identity for the relay and for its sessions.
    const existing = await device()
    const fresh = await device()
    const accountId = accountIdOf(existing.identity.ikSig.publicKey)
    expect(fresh.client.account.accountId).not.toBe(accountId)

    const scanned = parseLinkCode(newLinkCode(fresh.identity.ikSig.publicKey).code)
    let received: LinkPayload | null = null
    fresh.client.awaitLinkPayload(scanned.secret, (p) => {
      received = p
    })
    await existing.client.sendLinkPayload(scanned.deviceId, scanned.secret)
    for (const s of existing.sent) (fresh.client as unknown as Internals).handleLinkChunk(s.chunk)

    const payload = received as unknown as LinkPayload
    fresh.client.setAccountKey({
      privateKey: payload.accountKeyPriv,
      publicKey: existing.identity.ikSig.publicKey,
    })

    expect(fresh.client.account.accountId).toBe(accountId)
    // ...and its DEVICE id is still its own, which is what the relay
    // authenticates and what its ratchet sessions run between.
    expect(fresh.client.deviceId).toBe(deviceIdOf(fresh.identity.ikSig.publicKey))
    expect(fresh.client.deviceId).not.toBe(accountId)
  })

  it('stops listening once a link completes, so a second transfer is ignored', async () => {
    const existing = await device()
    const fresh = await device()
    const scanned = parseLinkCode(newLinkCode(fresh.identity.ikSig.publicKey).code)
    let count = 0
    fresh.client.awaitLinkPayload(scanned.secret, () => {
      count++
    })
    await existing.client.sendLinkPayload(scanned.deviceId, scanned.secret)
    for (const s of existing.sent) (fresh.client as unknown as Internals).handleLinkChunk(s.chunk)
    expect(count).toBe(1)

    // A replay of the same chunks, which the relay is free to attempt.
    for (const s of existing.sent) (fresh.client as unknown as Internals).handleLinkChunk(s.chunk)
    expect(count).toBe(1)
  })
})

describe('a device that already has an account of its own', () => {
  it('refuses to join another, rather than merging two accounts into one store', async () => {
    // Linking deliberately KEEPS what a device holds (it adds a device, it does
    // not replace one), so joining from a device that was already somebody would
    // leave one store holding two accounts: the old account's saved messages and
    // live sessions filed under the new account's identity, with the old contact
    // list replaced out from under them. Refused at the protocol layer, so it does
    // not depend on the UI never offering it.
    const fresh = await device()
    const account = await device()
    // Registered, exactly as the relay would report after this device joined or
    // was invited on its own.
    ;(fresh.client as unknown as { authed: unknown }).authed = { registered: true, opkCount: 10 }
    expect(fresh.client.isRegistered).toBe(true)

    await expect(fresh.client.registerAsDevice(account.client.account.accountId)).rejects.toThrow(
      /already has an account of its own/,
    )
  })

  it('still lets a device that has never registered join', async () => {
    // The guard must not be a blanket refusal: this is the whole normal path.
    const fresh = await device()
    const account = await device()
    expect(fresh.client.isRegistered).toBe(false)
    // Fails later, at the directory call this harness does not stub, which is
    // past the guard and is the point being asserted.
    await expect(fresh.client.registerAsDevice(account.client.account.accountId)).rejects.not.toThrow(
      /already has an account of its own/,
    )
  })
})

describe('handing the transfer over a screen instead of the relay', () => {
  it('seals it as ONE unit, and nothing goes near the wire', async () => {
    // The preferred path. The chunking the relay path does is a property of the
    // relay (its envelopes are capped), so a transfer that goes screen to camera
    // is one sealed piece and needs no second format to put back together.
    const existing = await device()
    const fresh = await device()
    const friend = await knownContact(existing.contacts)
    await existing.contacts.setAlias(friend.userId, 'best friend')

    const scanned = parseLinkCode(newLinkCode(fresh.identity.ikSig.publicKey).code)
    const blob = await existing.client.sealLinkForOptical(scanned.secret)

    // Nothing was handed to the transport at all: that is the whole point.
    expect(existing.sent).toHaveLength(0)

    const payload = openLink([blob], scanned.secret)
    expect(payload.accountId).toBe(accountIdOf(existing.identity.ikSig.publicKey))
    expect(payload.accountKeyPriv).toEqual(existing.identity.ikSig.privateKey)
    expect(payload.contacts.map((c) => c.peerId)).toEqual([friend.userId])
    expect(payload.aliases[friend.userId]).toBe('best friend')
    // Trust is absent here exactly as it is on the relay path: a linked device
    // verifies for itself however the transfer reached it.
    expect(Object.keys(payload)).not.toContain('trust')
  })

  it('refuses to open under any secret but the one on the screen', async () => {
    const existing = await device()
    const fresh = await device()
    const scanned = parseLinkCode(newLinkCode(fresh.identity.ikSig.publicKey).code)
    const blob = await existing.client.sealLinkForOptical(scanned.secret)
    expect(() => openLink([blob], randomBytes(LINK_SECRET_BYTES))).toThrow()
  })

  it('carries the same payload whichever way it travelled', async () => {
    // The two transports must be interchangeable, or a device linked optically
    // would differ from one linked over the relay in some way nobody tested.
    const existing = await device()
    const fresh = await device()
    await knownContact(existing.contacts)
    const scanned = parseLinkCode(newLinkCode(fresh.identity.ikSig.publicKey).code)

    const optical = openLink([await existing.client.sealLinkForOptical(scanned.secret)], scanned.secret)
    await existing.client.sendLinkPayload(scanned.deviceId, scanned.secret)
    let viaRelay: LinkPayload | null = null
    fresh.client.awaitLinkPayload(scanned.secret, (p) => {
      viaRelay = p
    })
    for (const s of existing.sent) (fresh.client as unknown as Internals).handleLinkChunk(s.chunk)
    const relayed = viaRelay as unknown as LinkPayload

    expect(relayed.accountId).toBe(optical.accountId)
    expect(relayed.accountKeyPriv).toEqual(optical.accountKeyPriv)
    expect(relayed.contacts).toEqual(optical.contacts)
    expect(relayed.aliases).toEqual(optical.aliases)
  })
})

describe('the device list this account publishes', () => {
  it('starts as this device alone, and gains the one that was linked', async () => {
    const existing = await device()
    const fresh = await device()

    // Before anything is published, an account IS one device: its own.
    const before = await existing.client.listDevices()
    expect(before).toEqual([
      { deviceId: existing.client.deviceId, addedAt: 0, isThisDevice: true, isFirstDevice: true },
    ])

    const scanned = parseLinkCode(newLinkCode(fresh.identity.ikSig.publicKey).code)
    await existing.client.authorizeDevice(scanned.deviceId, scanned.dkSigPub)

    const after = await existing.client.listDevices()
    expect(after.map((d) => d.deviceId)).toEqual([existing.client.deviceId, scanned.deviceId])
    expect(after.find((d) => d.isThisDevice)?.deviceId).toBe(existing.client.deviceId)
    // Exactly one row is the first device, and it is the one whose id is the
    // account id. A linked device reads the same list and needs this to know
    // which row it must not offer to remove.
    expect(after.filter((d) => d.isFirstDevice).map((d) => d.deviceId)).toEqual([existing.client.account.accountId])
  })

  it('removing one publishes a NEWER list without it', async () => {
    // Monotonic on purpose: the server refusing to go backwards can be undone by
    // whoever owns the server, but a contact's own high-water mark cannot.
    const existing = await device()
    const fresh = await device()
    const scanned = parseLinkCode(newLinkCode(fresh.identity.ikSig.publicKey).code)
    const v1 = await existing.client.authorizeDevice(scanned.deviceId, scanned.dkSigPub)

    const v2 = await existing.client.removeDevice(scanned.deviceId)
    expect(v2).toBeGreaterThan(v1)
    expect((await existing.client.listDevices()).map((d) => d.deviceId)).toEqual([existing.client.deviceId])
  })

  it('refuses to remove the first device, whose key IS the account key', async () => {
    // Its device id is the account id, so removing it would be an account taking
    // itself off its own list. Retiring it is a move, or an account-key rotation.
    const existing = await device()
    const fresh = await device()
    const scanned = parseLinkCode(newLinkCode(fresh.identity.ikSig.publicKey).code)
    await existing.client.authorizeDevice(scanned.deviceId, scanned.dkSigPub)

    await expect(existing.client.removeDevice(existing.client.account.accountId)).rejects.toThrow(/first device/)
  })

  it('refuses to remove a device that is not on the list', async () => {
    const existing = await device()
    const fresh = await device()
    const other = await device()
    const scanned = parseLinkCode(newLinkCode(fresh.identity.ikSig.publicKey).code)
    await existing.client.authorizeDevice(scanned.deviceId, scanned.dkSigPub)

    await expect(existing.client.removeDevice(other.client.deviceId)).rejects.toThrow(/not on this account/)
  })
})
