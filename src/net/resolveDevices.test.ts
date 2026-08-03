// Resolving where an account's devices are (Sesame B0, client side).
//
// The relay serves the roster, and the relay is not trusted, so every case here
// is about what happens when the answer is wrong: signed by the wrong key, stale,
// absent, or unreachable. The rule throughout is that a bad answer never widens
// the set of devices a message goes to, and never makes the app unable to send.

import { describe, expect, it } from 'vitest'
import { type Identity, accountIdOf, deviceIdOf, generateIdentity } from '../crypto/identity'
import { hash256 } from '../crypto/primitives'
import { type DeviceRoster, type RosterDevice, signRoster } from '../crypto/roster'
import { AppLockStore } from '../storage/appLockStore'
import { HistoryStore } from '../storage/historyStore'
import { InMemoryLock } from '../storage/lock'
import { MemoryKeyStore } from '../storage/keystore'
import { PrekeyStore } from '../storage/prekeyStore'
import { MemorySessionStore } from '../storage/sessionStore'
import { ContactStore } from '../trust/contactStore'
import { NightjarClient } from './client'

const stubKdf = (s: Uint8Array, salt: Uint8Array) => hash256(new Uint8Array([...s, ...salt]))

function deviceOf(id: Identity, addedAt = Date.now()): RosterDevice {
  return { deviceId: deviceIdOf(id.ikSig.publicKey), dkSigPub: id.ikSig.publicKey, addedAt }
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
  const security: string[] = []
  const changes: Array<{ accountId: string; added: string[]; removed: string[] }> = []
  const client = new NightjarClient(
    identity,
    store,
    prekeys,
    contacts,
    lock,
    {
      onMessage: () => {},
      onSecurity: (d) => security.push(d),
      onDevicesChanged: (accountId, change) => changes.push({ accountId, ...change }),
    },
    new HistoryStore(appLock),
  )
  /** What the relay will answer with, including the option of failing. */
  let served: DeviceRoster | null | Error = null
  ;(client as unknown as { directory: unknown }).directory = {
    fetchRoster: async () => {
      if (served instanceof Error) throw served
      return served
    },
  }
  const serve = (r: DeviceRoster | null | Error) => {
    served = r
  }
  const know = async (peer: Identity) => {
    await contacts.recordFirstContact(accountIdOf(peer.ikSig.publicKey), peer.ikSig.publicKey, Date.now())
  }
  return { identity, client, contacts, serve, security, changes, know }
}

describe('resolveDevices', () => {
  it('treats an account with no roster as the single device it is', async () => {
    // This is every account today, and every account that never links a second
    // device. It is what keeps multi-device invisible to people who do not use it.
    const h = await harness()
    const peer = generateIdentity()
    await h.know(peer)
    h.serve(null)
    expect(await h.client.resolveDevices(peer.userId)).toEqual([peer.userId])
  })

  it('returns the devices a valid roster claims, and remembers them', async () => {
    const h = await harness()
    const peer = generateIdentity()
    const laptop = generateIdentity()
    await h.know(peer)
    const devices = [deviceOf(peer), deviceOf(laptop)]
    h.serve(signRoster(peer.userId, 1, devices, peer.ikSig.privateKey))

    expect(await h.client.resolveDevices(peer.userId)).toEqual(devices.map((d) => d.deviceId))
    expect(await h.contacts.getKnownRoster(peer.userId)).toEqual({
      version: 1,
      devices: devices.map((d) => d.deviceId),
    })
    // A first sighting is not a change: there is nothing it differs from.
    expect(h.changes).toEqual([])
  })

  it('refuses a roster signed by anyone but the account, and says so', async () => {
    const h = await harness()
    const peer = generateIdentity()
    const impostor = generateIdentity()
    await h.know(peer)
    h.serve(signRoster(peer.userId, 1, [deviceOf(peer), deviceOf(impostor)], impostor.ikSig.privateKey))

    // Not widened to the impostor's device: still just the account itself.
    expect(await h.client.resolveDevices(peer.userId)).toEqual([peer.userId])
    expect(h.security.join(' ')).toMatch(/did not verify as theirs/)
    expect(await h.contacts.getKnownRoster(peer.userId)).toBeNull()
  })

  it('refuses an older roster than one already accepted, which is the rollback', async () => {
    // The Directory refusing to go backwards keeps an honest server honest. This
    // is the check that survives an operator who owns the Directory.
    const h = await harness()
    const peer = generateIdentity()
    const laptop = generateIdentity()
    await h.know(peer)
    const v2 = signRoster(peer.userId, 2, [deviceOf(peer), deviceOf(laptop)], peer.ikSig.privateKey)
    h.serve(v2)
    await h.client.resolveDevices(peer.userId)

    // Now the operator serves the older one, which is a perfectly valid signature
    // over stale facts. Only memory can catch this.
    h.serve(signRoster(peer.userId, 1, [deviceOf(peer)], peer.ikSig.privateKey))
    expect(await h.client.resolveDevices(peer.userId)).toEqual([
      deviceIdOf(peer.ikSig.publicKey),
      deviceIdOf(laptop.ikSig.publicKey),
    ])
    expect(h.security.join(' ')).toMatch(/out-of-date device list/)
    expect((await h.contacts.getKnownRoster(peer.userId))!.version).toBe(2)
  })

  it('refuses a replayed roster at the version already held', async () => {
    const h = await harness()
    const peer = generateIdentity()
    await h.know(peer)
    const v1 = signRoster(peer.userId, 1, [deviceOf(peer)], peer.ikSig.privateKey)
    h.serve(v1)
    await h.client.resolveDevices(peer.userId)

    // A DIFFERENT roster at the same version must not displace the stored one.
    const other = generateIdentity()
    h.serve(signRoster(peer.userId, 1, [deviceOf(peer), deviceOf(other)], peer.ikSig.privateKey))
    expect(await h.client.resolveDevices(peer.userId)).toEqual([deviceIdOf(peer.ikSig.publicKey)])
    expect(h.changes).toEqual([])
  })

  it('reports a device appearing, which is the event that matters', async () => {
    const h = await harness()
    const peer = generateIdentity()
    const laptop = generateIdentity()
    await h.know(peer)
    h.serve(signRoster(peer.userId, 1, [deviceOf(peer)], peer.ikSig.privateKey))
    await h.client.resolveDevices(peer.userId)

    h.serve(signRoster(peer.userId, 2, [deviceOf(peer), deviceOf(laptop)], peer.ikSig.privateKey))
    await h.client.resolveDevices(peer.userId)

    expect(h.changes).toEqual([
      { accountId: peer.userId, added: [deviceIdOf(laptop.ikSig.publicKey)], removed: [] },
    ])
  })

  it('keeps the devices it knows when the relay is unreachable', async () => {
    const h = await harness()
    const peer = generateIdentity()
    const laptop = generateIdentity()
    await h.know(peer)
    h.serve(signRoster(peer.userId, 1, [deviceOf(peer), deviceOf(laptop)], peer.ikSig.privateKey))
    const devices = await h.client.resolveDevices(peer.userId)

    h.serve(new Error('offline'))
    expect(await h.client.resolveDevices(peer.userId)).toEqual(devices)
    // And an account being dropped from the Directory does not erase what we know.
    h.serve(null)
    expect(await h.client.resolveDevices(peer.userId)).toEqual(devices)
  })

  it('will not verify a roster for someone it holds no key for', async () => {
    // With no contact record there is nothing to check a signature against, so the
    // account is addressed as the one device its id names. Refusing to guess.
    const h = await harness()
    const stranger = generateIdentity()
    const other = generateIdentity()
    h.serve(signRoster(stranger.userId, 1, [deviceOf(stranger), deviceOf(other)], stranger.ikSig.privateKey))
    expect(await h.client.resolveDevices(stranger.userId)).toEqual([stranger.userId])
  })

  it('resolves this account itself under its own account key', async () => {
    // Self-resolution has no contact record to read, and it is what the sender's
    // own devices will be looked up with.
    const h = await harness()
    const laptop = generateIdentity()
    const me = h.client.account
    const devices = [deviceOf(h.identity), deviceOf(laptop)]
    h.serve(signRoster(me.accountId, 1, devices, me.accountKey.privateKey))
    expect(await h.client.resolveDevices(me.accountId)).toEqual(devices.map((d) => d.deviceId))
  })
})

describe('authorizing a device', () => {
  it('refuses a code whose id does not match the key inside it', async () => {
    // The scan is the whole security of linking: a device id IS the hash of its
    // key, so this check means a tampered code cannot add a device the account
    // did not mean to add, and the relay never gets a say in who joins.
    const h = await harness()
    const laptop = generateIdentity()
    const attacker = generateIdentity()
    await expect(
      h.client.authorizeDevice(deviceIdOf(laptop.ikSig.publicKey), attacker.ikSig.publicKey),
    ).rejects.toThrow(/does not match the key/)
  })

  it('adds to what is already published rather than replacing it', async () => {
    // Linking a third device from the second must not silently drop the first.
    const h = await harness()
    const phone = h.identity
    const laptop = generateIdentity()
    const tablet = generateIdentity()
    const me = h.client.account
    const published: number[] = []
    h.serve(signRoster(me.accountId, 4, [deviceOf(phone), deviceOf(laptop)], me.accountKey.privateKey))
    ;(h.client as unknown as { directory: { publishRoster(r: unknown): Promise<number> } }).directory.publishRoster =
      async (r) => {
        const roster = r as { version: number; devices: Array<{ deviceId: string }> }
        published.push(roster.version)
        expect(roster.devices.map((d) => d.deviceId)).toEqual([
          deviceIdOf(phone.ikSig.publicKey),
          deviceIdOf(laptop.ikSig.publicKey),
          deviceIdOf(tablet.ikSig.publicKey),
        ])
        return roster.version
      }

    const version = await h.client.authorizeDevice(deviceIdOf(tablet.ikSig.publicKey), tablet.ikSig.publicKey)
    // Version moves forward from what was published, never restarts.
    expect(version).toBe(5)
    expect(published).toEqual([5])
  })
})

describe('the account and device split', () => {
  it('leaves a single-device account exactly where it already was', async () => {
    // The migration property the whole design is built around: an existing user's
    // account id, device id and user id are ONE id, so nothing moves. Their inbox,
    // their published prekeys, their sessions and above all their safety numbers
    // are untouched, and nobody has to verify anybody again.
    const h = await harness()
    expect(h.client.account.accountId).toBe(h.identity.userId)
    expect(h.client.deviceId).toBe(h.identity.userId)
    expect(h.client.account.accountKey.publicKey).toEqual(h.identity.ikSig.publicKey)
  })
})
