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
