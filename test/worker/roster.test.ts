// Device rosters in the Directory (Sesame B0b), against the real Durable Object.
//
// The roster is how a sender learns where an account's devices are, so the
// Directory's job is narrow and worth pinning: store what an account signed,
// serve it to anyone, refuse everything else. It cannot author a roster, because
// it holds no account key, and these tests are what say so out loud.

import { env } from 'cloudflare:test'
import { describe, expect, it } from 'vitest'
import { type Identity, accountIdOf, deviceIdOf, generateIdentity } from '../../src/crypto/identity'
import { OWN_BUNDLE_VERSION, buildOwnBundle } from '../../src/crypto/prekeys'
import { type RosterDevice, signRoster } from '../../src/crypto/roster'
import { encodeDeviceRoster, encodePublishedBundle, type WireDeviceRoster } from '../../src/wire/codec'
import { DirectoryError, callDO, directoryStub } from '../../worker/shared'

const dir = () => directoryStub(env)

async function registeredAccount(): Promise<Identity> {
  const id = generateIdentity()
  const { code } = await callDO<{ code: string }>(dir(), '/mintInvite', { inviter: '@admin', now: Date.now() })
  const own = buildOwnBundle(id, Date.now(), { spkId: 1, opkStartId: 1, opkCount: 3 })
  await callDO(dir(), '/register', {
    userId: id.userId,
    inviteCode: code,
    bundle: encodePublishedBundle({
      version: OWN_BUNDLE_VERSION,
      ikSigPub: own.ikSigPub,
      ikDhPub: own.ikDhPub,
      idkbindSig: own.idkbindSig,
      spk: own.spk,
      opks: own.opks,
    }),
    now: Date.now(),
  })
  return id
}

function deviceOf(id: Identity, addedAt = Date.now()): RosterDevice {
  return { deviceId: deviceIdOf(id.ikSig.publicKey), dkSigPub: id.ikSig.publicKey, addedAt }
}

async function publish(roster: WireDeviceRoster): Promise<{ version: number }> {
  return callDO<{ version: number }>(dir(), '/publishRoster', { roster })
}

async function fetchRoster(accountId: string): Promise<WireDeviceRoster | null> {
  const r = await callDO<{ roster: WireDeviceRoster | null }>(dir(), '/fetchRoster', { accountId })
  return r.roster
}

describe('device rosters (Sesame)', () => {
  it('an account with no roster reads as null, not as an error', async () => {
    // Every account is in this state until it links a second device. The caller
    // treats null as "one device, at the account id", which is what makes the
    // whole feature invisible to accounts that never link anything.
    const account = await registeredAccount()
    expect(await fetchRoster(account.userId)).toBeNull()
  })

  it('stores what the account signed and serves it back unchanged', async () => {
    const account = await registeredAccount()
    const laptop = generateIdentity()
    const devices = [deviceOf(account), deviceOf(laptop)]
    const signed = signRoster(accountIdOf(account.ikSig.publicKey), 1, devices, account.ikSig.privateKey)

    expect(await publish(encodeDeviceRoster(signed))).toEqual({ version: 1 })
    const served = await fetchRoster(account.userId)
    expect(served).toEqual(encodeDeviceRoster(signed))
    expect(served!.devices.map((d) => d.deviceId).sort()).toEqual(devices.map((d) => d.deviceId).sort())
  })

  it('refuses a roster signed by anyone but the account', async () => {
    // The Directory verifies against the identity key registered under the account
    // id, so it cannot be talked into publishing a device list for someone else.
    const account = await registeredAccount()
    const impostor = generateIdentity()
    const forged = signRoster(account.userId, 1, [deviceOf(account)], impostor.ikSig.privateKey)
    await expect(publish(encodeDeviceRoster(forged))).rejects.toThrow(DirectoryError)
    expect(await fetchRoster(account.userId)).toBeNull()
  })

  it('refuses a roster naming a device whose key it does not carry', async () => {
    const account = await registeredAccount()
    const attacker = generateIdentity()
    // The id of a device the account owns, beside a key the attacker owns.
    const swapped: RosterDevice = {
      deviceId: deviceIdOf(account.ikSig.publicKey),
      dkSigPub: attacker.ikSig.publicKey,
      addedAt: Date.now(),
    }
    const roster = signRoster(account.userId, 1, [swapped], account.ikSig.privateKey)
    await expect(publish(encodeDeviceRoster(roster))).rejects.toThrow(DirectoryError)
  })

  it('refuses an unregistered account, so the table cannot be filled by strangers', async () => {
    const stranger = generateIdentity()
    const roster = signRoster(stranger.userId, 1, [deviceOf(stranger)], stranger.ikSig.privateKey)
    await expect(publish(encodeDeviceRoster(roster))).rejects.toThrow(/no such account/)
  })

  it('refuses an empty roster, which would make the account unreachable', async () => {
    const account = await registeredAccount()
    const empty = signRoster(account.userId, 1, [], account.ikSig.privateKey)
    await expect(publish(encodeDeviceRoster(empty))).rejects.toThrow(DirectoryError)
  })

  it('only moves forward: a replayed or equal version is refused', async () => {
    const account = await registeredAccount()
    const v1 = signRoster(account.userId, 1, [deviceOf(account)], account.ikSig.privateKey)
    const v2 = signRoster(account.userId, 2, [deviceOf(account), deviceOf(generateIdentity())], account.ikSig.privateKey)
    await publish(encodeDeviceRoster(v1))
    await publish(encodeDeviceRoster(v2))

    // Replaying the older one is how an operator would hide a device that was
    // added, or restore one that was removed. Refused here as a liveness measure;
    // the binding defence is the client's own high-water mark.
    await expect(publish(encodeDeviceRoster(v1))).rejects.toThrow(/does not follow/)
    // And a DIFFERENT roster at the same version cannot displace the stored one.
    const v2b = signRoster(account.userId, 2, [deviceOf(account)], account.ikSig.privateKey)
    await expect(publish(encodeDeviceRoster(v2b))).rejects.toThrow(/does not follow/)

    expect((await fetchRoster(account.userId))!.version).toBe(2)
    expect((await fetchRoster(account.userId))!.devices).toHaveLength(2)
  })

  it('accepts a publish from a device that is not the account itself', async () => {
    // Authorization is the signature, never the caller: a linked device
    // authenticates as ITSELF, so requiring caller == account would leave every
    // device but the first unable to update the roster.
    const account = await registeredAccount()
    const laptop = generateIdentity()
    const roster = signRoster(account.userId, 1, [deviceOf(account), deviceOf(laptop)], account.ikSig.privateKey)
    // Published here with no caller identity of any kind attached.
    expect(await publish(encodeDeviceRoster(roster))).toEqual({ version: 1 })
  })

  it('lets a listed device register with no invite, and refuses an unlisted one', async () => {
    // A new device is not a new user, so it must not cost an invite. What replaces
    // the invite is the roster, which only the account key can produce.
    const account = await registeredAccount()
    const laptop = generateIdentity()
    const laptopId = deviceIdOf(laptop.ikSig.publicKey)
    const own = buildOwnBundle(laptop, Date.now(), { spkId: 1, opkStartId: 1, opkCount: 4 })
    const bundle = encodePublishedBundle({
      version: OWN_BUNDLE_VERSION,
      ikSigPub: own.ikSigPub,
      ikDhPub: own.ikDhPub,
      idkbindSig: own.idkbindSig,
      spk: own.spk,
      opks: own.opks,
    })

    // Before the account lists it, there is nothing authorizing it.
    await expect(
      callDO(dir(), '/registerDevice', { deviceId: laptopId, accountId: account.userId, bundle, now: Date.now() }),
    ).rejects.toThrow(/has not listed/)

    await publish(
      encodeDeviceRoster(
        signRoster(account.userId, 1, [deviceOf(account), deviceOf(laptop)], account.ikSig.privateKey),
      ),
    )
    const r = await callDO<{ opkCount: number }>(dir(), '/registerDevice', {
      deviceId: laptopId,
      accountId: account.userId,
      bundle,
      now: Date.now(),
    })
    expect(r.opkCount).toBe(4)
    // And it is now reachable like any other registered id.
    const fetched = await callDO<{ bundle: unknown }>(dir(), '/fetchBundle', {
      fetcher: account.userId,
      target: laptopId,
      now: Date.now(),
    })
    expect(fetched.bundle).not.toBeNull()
  })

  it('will not let a device register under a key that is not its id', async () => {
    // The roster makes device ids public, so registration still has to prove
    // possession of the device's private half rather than just naming the id.
    const account = await registeredAccount()
    const laptop = generateIdentity()
    const attacker = generateIdentity()
    await publish(
      encodeDeviceRoster(
        signRoster(account.userId, 1, [deviceOf(account), deviceOf(laptop)], account.ikSig.privateKey),
      ),
    )
    const own = buildOwnBundle(attacker, Date.now(), { spkId: 1, opkStartId: 1, opkCount: 2 })
    const bundle = encodePublishedBundle({
      version: OWN_BUNDLE_VERSION,
      ikSigPub: own.ikSigPub,
      ikDhPub: own.ikDhPub,
      idkbindSig: own.idkbindSig,
      spk: own.spk,
      opks: own.opks,
    })
    await expect(
      callDO(dir(), '/registerDevice', {
        deviceId: deviceIdOf(laptop.ikSig.publicKey), // a listed device...
        accountId: account.userId,
        bundle, // ...but the attacker's key
        now: Date.now(),
      }),
    ).rejects.toThrow(/does not match/)
  })

  it('retires the prekeys of a device the account stops listing', async () => {
    // The only part of removal a server can enforce: no NEW sessions to it.
    // Existing ones keep working, and this is not revocation.
    const account = await registeredAccount()
    const laptop = generateIdentity()
    const laptopId = deviceIdOf(laptop.ikSig.publicKey)
    await publish(
      encodeDeviceRoster(
        signRoster(account.userId, 1, [deviceOf(account), deviceOf(laptop)], account.ikSig.privateKey),
      ),
    )
    const own = buildOwnBundle(laptop, Date.now(), { spkId: 1, opkStartId: 1, opkCount: 2 })
    await callDO(dir(), '/registerDevice', {
      deviceId: laptopId,
      accountId: account.userId,
      bundle: encodePublishedBundle({
        version: OWN_BUNDLE_VERSION,
        ikSigPub: own.ikSigPub,
        ikDhPub: own.ikDhPub,
        idkbindSig: own.idkbindSig,
        spk: own.spk,
        opks: own.opks,
      }),
      now: Date.now(),
    })
    expect(
      (await callDO<{ bundle: unknown }>(dir(), '/fetchBundle', { fetcher: account.userId, target: laptopId, now: Date.now() }))
        .bundle,
    ).not.toBeNull()

    // The account drops it.
    await publish(encodeDeviceRoster(signRoster(account.userId, 2, [deviceOf(account)], account.ikSig.privateKey)))
    expect(
      (await callDO<{ bundle: unknown }>(dir(), '/fetchBundle', { fetcher: account.userId, target: laptopId, now: Date.now() }))
        .bundle,
    ).toBeNull()
  })

  it('never retires the account device itself, whatever a roster says', async () => {
    // Its row holds the key every future roster is verified against, so dropping
    // it would leave the account unable to change its device list ever again.
    const account = await registeredAccount()
    const laptop = generateIdentity()
    await publish(
      encodeDeviceRoster(
        signRoster(account.userId, 1, [deviceOf(account), deviceOf(laptop)], account.ikSig.privateKey),
      ),
    )
    // A roster that omits the account's own device.
    await publish(encodeDeviceRoster(signRoster(account.userId, 2, [deviceOf(laptop)], account.ikSig.privateKey)))
    expect(
      (
        await callDO<{ bundle: unknown }>(dir(), '/fetchBundle', {
          fetcher: laptop.userId,
          target: account.userId,
          now: Date.now(),
        })
      ).bundle,
    ).not.toBeNull()
    // And the account can still publish, which is what would otherwise be lost.
    await publish(encodeDeviceRoster(signRoster(account.userId, 3, [deviceOf(account)], account.ikSig.privateKey)))
  })

  it('refuses a structurally malformed roster before verifying anything', async () => {
    const account = await registeredAccount()
    const good = encodeDeviceRoster(signRoster(account.userId, 1, [deviceOf(account)], account.ikSig.privateKey))
    const bad: unknown[] = [
      { ...good, devices: 'not an array' },
      { ...good, accountId: 'too-short' },
      { ...good, sig: 'not-base64!!' },
      { ...good, devices: [{ ...good.devices[0], dkSigPub: '' }] },
      { ...good, devices: [{ ...good.devices[0], deviceId: 'nope' }] },
    ]
    for (const roster of bad) {
      await expect(callDO(dir(), '/publishRoster', { roster })).rejects.toThrow()
    }
  })
})
