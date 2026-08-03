// The device hello (Sesame B2): attributing a sending DEVICE to a person.
//
// Conversations are filed by account and sessions run between devices, so a
// receiver has to bridge the two. It cannot do it alone: its cache maps account
// to devices, and a message from an unfamiliar device gives it nothing to look
// the account up by. So the sender says which account it belongs to, and the
// whole question is what happens when that claim is a lie.

import { describe, expect, it } from 'vitest'
import { decodeMessage, encodeHelloMessage, newMsgId } from '../crypto/message'
import { type Identity, accountIdOf, deviceIdOf, generateIdentity } from '../crypto/identity'
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
  let served: ReturnType<typeof signRoster> | null = null
  ;(client as unknown as { directory: unknown }).directory = { fetchRoster: async () => served }
  return {
    client,
    contacts,
    security,
    serve: (r: ReturnType<typeof signRoster> | null) => {
      served = r
    },
    know: async (peer: Identity) => {
      await contacts.recordFirstContact(peer.userId, peer.ikSig.publicKey, Date.now())
    },
  }
}

describe('the hello record', () => {
  it('round-trips an account id', () => {
    const account = generateIdentity()
    const d = decodeMessage(encodeHelloMessage(newMsgId(), account.userId))
    expect(d.kind).toBe('hello')
    if (d.kind !== 'hello') return
    expect(d.accountId).toBe(account.userId)
  })

  it('refuses anything that is not a full-width id, on both sides', () => {
    expect(() => encodeHelloMessage(newMsgId(), 'too-short')).toThrow(/full-width/)
    // ...and a hand-built record carrying rubbish is malformed rather than trusted.
    const good = encodeHelloMessage(newMsgId(), generateIdentity().userId)
    const tampered = new Uint8Array(good)
    tampered[tampered.length - 1] = 0x21 // '!' is not in the base32 alphabet
    expect(decodeMessage(tampered).kind).toBe('malformed')
    expect(decodeMessage(good.slice(0, good.length - 1)).kind).toBe('malformed')
  })

  it('reads as nothing at all on a build that predates it', () => {
    // Forward compatibility is what lets a linked device talk to a contact who
    // has not updated: they see an unknown kind and ignore it, which leaves them
    // reading the sender as an account of one, exactly as before.
    const older = new Uint8Array([...encodeHelloMessage(newMsgId(), generateIdentity().userId).slice(0, 5), 0x7f])
    expect(decodeMessage(older).kind).toBe('malformed')
  })
})

describe('attributing a device to an account', () => {
  it('reads an unknown device as an account of one, with no network at all', async () => {
    // The case that covers every user today: a first device's account key IS its
    // device key, so the two ids are the same string.
    const h = await harness()
    const peer = generateIdentity()
    expect(await h.client.accountForDevice(peer.userId)).toBe(peer.userId)
  })

  it('attributes a linked device once its account has listed it', async () => {
    const h = await harness()
    const peer = generateIdentity()
    const laptop = generateIdentity()
    await h.know(peer)
    h.serve(signRoster(peer.userId, 1, [deviceOf(peer), deviceOf(laptop)], peer.ikSig.privateKey))

    const laptopId = deviceIdOf(laptop.ikSig.publicKey)
    // Before the hello there is nothing to go on, so it reads as its own account.
    expect(await h.client.accountForDevice(laptopId)).toBe(laptopId)

    await (h.client as unknown as Internals).handleHello(laptopId, peer.userId)
    expect(await h.client.accountForDevice(laptopId)).toBe(peer.userId)
    expect(h.security).toEqual([])
  })

  it('refuses a device claiming an account that has not listed it, and says so', async () => {
    // The attack: a stranger asserting they are one of your contact's devices, to
    // have their messages filed inside that conversation.
    const h = await harness()
    const peer = generateIdentity()
    const stranger = generateIdentity()
    await h.know(peer)
    // The account's real roster does NOT include the stranger.
    h.serve(signRoster(peer.userId, 1, [deviceOf(peer)], peer.ikSig.privateKey))

    const strangerId = deviceIdOf(stranger.ikSig.publicKey)
    await (h.client as unknown as Internals).handleHello(strangerId, peer.userId)

    expect(await h.client.accountForDevice(strangerId)).toBe(strangerId)
    expect(h.security.join(' ')).toMatch(/has not listed it/)
  })

  it('refuses a claim about an account it holds no key for', async () => {
    // With no contact record there is no key to verify a roster under, so the
    // claim cannot be checked and is therefore not acted on.
    const h = await harness()
    const stranger = generateIdentity()
    const laptop = generateIdentity()
    h.serve(signRoster(stranger.userId, 1, [deviceOf(stranger), deviceOf(laptop)], stranger.ikSig.privateKey))

    const laptopId = deviceIdOf(laptop.ikSig.publicKey)
    await (h.client as unknown as Internals).handleHello(laptopId, stranger.userId)
    expect(await h.client.accountForDevice(laptopId)).toBe(laptopId)
  })

  it('does nothing for a device announcing an account that is already its own id', async () => {
    // A first device has no reason to send one, but if it does it is a statement
    // that is true by construction and costs nothing to accept.
    const h = await harness()
    const peer = generateIdentity()
    await (h.client as unknown as Internals).handleHello(peer.userId, peer.userId)
    expect(h.security).toEqual([])
    expect(await h.client.accountForDevice(peer.userId)).toBe(peer.userId)
  })

  it('keeps attributing after a roster moves forward', async () => {
    const h = await harness()
    const peer = generateIdentity()
    const laptop = generateIdentity()
    const tablet = generateIdentity()
    await h.know(peer)
    h.serve(signRoster(peer.userId, 1, [deviceOf(peer), deviceOf(laptop)], peer.ikSig.privateKey))
    await (h.client as unknown as Internals).handleHello(deviceIdOf(laptop.ikSig.publicKey), peer.userId)

    h.serve(signRoster(peer.userId, 2, [deviceOf(peer), deviceOf(laptop), deviceOf(tablet)], peer.ikSig.privateKey))
    await (h.client as unknown as Internals).handleHello(deviceIdOf(tablet.ikSig.publicKey), peer.userId)

    expect(await h.client.accountForDevice(deviceIdOf(laptop.ikSig.publicKey))).toBe(peer.userId)
    expect(await h.client.accountForDevice(deviceIdOf(tablet.ikSig.publicKey))).toBe(peer.userId)
    expect(accountIdOf(peer.ikSig.publicKey)).toBe(peer.userId)
  })
})
