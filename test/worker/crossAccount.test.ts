// What one account can do to ANOTHER through the Directory.
//
// Every other worker suite is single-account by construction: one account, its
// own devices, its own roster. That shape cannot express the defects this file
// exists for, which is why they survived a full multi-device review and were
// found only by an adversarial pass that asked "what can Mallory do to Bob".
//
// Two rules are pinned here, and both rest on the same fact: a device id is the
// hash of a PUBLIC key, and every key in this Directory is public, so naming a
// device proves nothing whatsoever about owning it.
//
//   1. Listing somebody else's device in your own roster must not let you delete
//      their published prekeys. It used to: two frames, repeatable, against
//      anybody, leaving them unable to accept a new conversation until they next
//      connected.
//   2. A device is not an account. Adding a device costs no invite, deliberately,
//      so if a device's row counted as a registered member then one invited
//      account could mint unlimited identities, each able to mint invites of its
//      own. That is the invite gate, which is the spine of the whole anti-abuse
//      story, unbolted from the inside.

import { env } from 'cloudflare:test'
import { describe, expect, it } from 'vitest'
import { type Identity, accountIdOf, deviceIdOf, generateIdentity } from '../../src/crypto/identity'
import { OWN_BUNDLE_VERSION, buildOwnBundle } from '../../src/crypto/prekeys'
import { type RosterDevice, signRoster } from '../../src/crypto/roster'
import { signRotation } from '../../src/crypto/rotation'
import {
  type WireDeviceRoster,
  encodeDeviceRoster,
  encodePublishedBundle,
  encodeRotationStatement,
} from '../../src/wire/codec'
import { DirectoryError, callDO, directoryStub } from '../../worker/shared'

const dir = () => directoryStub(env)

function bundleOf(id: Identity, opkCount = 3) {
  const own = buildOwnBundle(id, Date.now(), { spkId: 1, opkStartId: 1, opkCount })
  return encodePublishedBundle({
    version: OWN_BUNDLE_VERSION,
    ikSigPub: own.ikSigPub,
    ikDhPub: own.ikDhPub,
    idkbindSig: own.idkbindSig,
    spk: own.spk,
    opks: own.opks,
  })
}

async function registeredAccount(): Promise<Identity> {
  const id = generateIdentity()
  const { code } = await callDO<{ code: string }>(dir(), '/mintInvite', { inviter: '@admin', now: Date.now() })
  await callDO(dir(), '/register', { userId: id.userId, inviteCode: code, bundle: bundleOf(id), now: Date.now() })
  return id
}

function deviceOf(id: Identity, addedAt = Date.now()): RosterDevice {
  return { deviceId: deviceIdOf(id.ikSig.publicKey), dkSigPub: id.ikSig.publicKey, addedAt }
}

async function publishRoster(roster: WireDeviceRoster): Promise<{ version: number }> {
  return callDO<{ version: number }>(dir(), '/publishRoster', { roster })
}

async function reachable(target: string, fetcher: string): Promise<boolean> {
  const r = await callDO<{ bundle: unknown }>(dir(), '/fetchBundle', { fetcher, target, now: Date.now() })
  return r.bundle !== null
}

/** Add `device` to `account`, the way the real linking flow does: the account
 *  publishes a roster listing it, then the device registers itself. */
async function link(account: Identity, device: Identity, version: number): Promise<void> {
  await publishRoster(
    encodeDeviceRoster(signRoster(account.userId, version, [deviceOf(account), deviceOf(device)], account.ikSig.privateKey)),
  )
  await callDO(dir(), '/registerDevice', {
    deviceId: deviceIdOf(device.ikSig.publicKey),
    accountId: account.userId,
    bundle: bundleOf(device, 2),
    now: Date.now(),
  })
}

describe('what one account can do to another', () => {
  it('cannot delete a stranger’s prekeys by listing then dropping their device', async () => {
    // The attack: Mallory reads the victim's public key (it is public), lists
    // their device in HER OWN validly signed roster, then publishes a roster
    // without it. The drop used to fire on any id that left the list.
    const mallory = await registeredAccount()
    const victim = await registeredAccount()
    const bystander = await registeredAccount()
    expect(await reachable(victim.userId, bystander.userId)).toBe(true)

    const victimAsHerDevice: RosterDevice = {
      deviceId: victim.userId, // their id IS the hash of their public key
      dkSigPub: victim.ikSig.publicKey,
      addedAt: Date.now(),
    }
    // Both publishes are accepted: the roster is validly signed by Mallory, and
    // refusing it would need the Directory to know whose device that is. What is
    // refused is the DELETION, which is the part that reaches somebody else.
    await publishRoster(
      encodeDeviceRoster(signRoster(mallory.userId, 1, [deviceOf(mallory), victimAsHerDevice], mallory.ikSig.privateKey)),
    )
    await publishRoster(encodeDeviceRoster(signRoster(mallory.userId, 2, [deviceOf(mallory)], mallory.ikSig.privateKey)))

    expect(await reachable(victim.userId, bystander.userId)).toBe(true)
  })

  it('still retires a device of its OWN, which is what removal means', async () => {
    // The other half: the rule must not be so cautious that removal stops
    // working. This account watched its own device register here.
    const account = await registeredAccount()
    const laptop = generateIdentity()
    const laptopId = deviceIdOf(laptop.ikSig.publicKey)
    await link(account, laptop, 1)
    expect(await reachable(laptopId, account.userId)).toBe(true)

    await publishRoster(encodeDeviceRoster(signRoster(account.userId, 2, [deviceOf(account)], account.ikSig.privateKey)))
    expect(await reachable(laptopId, account.userId)).toBe(false)
  })

  it('lets a rotated account retire the first device it rotated away from', async () => {
    // The case with no claim record at all: a first device's row is written by
    // /register, so the successor's authority over it comes from the recorded
    // rotation rather than from having watched it register.
    const account = await registeredAccount()
    const laptop = generateIdentity()
    await link(account, laptop, 1)
    const next = generateIdentity()
    const newId = accountIdOf(next.ikSig.publicKey)
    await callDO(dir(), '/publishRotation', {
      statement: encodeRotationStatement(
        signRotation(account.userId, account.ikSig.privateKey, next.ikSig, Date.now()),
      ),
    })
    await publishRoster(
      encodeDeviceRoster(signRoster(newId, 1, [deviceOf(account), deviceOf(laptop)], next.ikSig.privateKey)),
    )
    expect(await reachable(account.userId, laptop.userId)).toBe(true)

    // Drop the device that used to hold the account key.
    await publishRoster(encodeDeviceRoster(signRoster(newId, 2, [deviceOf(laptop)], next.ikSig.privateKey)))
    expect(await reachable(account.userId, laptop.userId)).toBe(false)
  })

  it('heals a device that was added before the record existed', async () => {
    // The migration case, and the reason a claim can be re-asserted at all.
    // Devices linked before this record existed have no row, and nothing else
    // would ever give them one: registration happens once, and the prekeys a
    // device republishes afterwards say nothing about whose it is. Without the
    // heal, taking such a device off the list would silently stop retiring its
    // keys, which is a REGRESSION against the previous behavior rather than a
    // new caution.
    const account = await registeredAccount()
    const laptop = generateIdentity()
    const laptopId = deviceIdOf(laptop.ikSig.publicKey)
    await link(account, laptop, 1)
    // Wipe the record to stand in for a device linked by an older build.
    await callDO(dir(), '/claimDevice', { deviceId: laptopId, accountId: account.userId, now: Date.now() })

    // Re-asserted on connect: the id is the server-verified one, and the account
    // must already list it.
    expect(await callDO<{ claimed: boolean }>(dir(), '/claimDevice', {
      deviceId: laptopId,
      accountId: account.userId,
      now: Date.now(),
    })).toEqual({ claimed: true })

    // And a device the account does NOT list cannot claim its way in.
    const stranger = generateIdentity()
    await expect(
      callDO(dir(), '/claimDevice', {
        deviceId: deviceIdOf(stranger.ikSig.publicKey),
        accountId: account.userId,
        now: Date.now(),
      }),
    ).rejects.toThrow(/has not listed/)

    // Removal retires its prekeys again, which is the behavior being restored.
    await publishRoster(encodeDeviceRoster(signRoster(account.userId, 2, [deviceOf(account)], account.ikSig.privateKey)))
    expect(await reachable(laptopId, account.userId)).toBe(false)
  })

  it('does not let a device mint invites, so one invite cannot become many', async () => {
    // Adding a device costs no invite by design. If a device's row also counted
    // as a registered member, one invited account could add devices for keypairs
    // it generated on the spot and hand each one a fresh invite budget.
    const account = await registeredAccount()
    const laptop = generateIdentity()
    await link(account, laptop, 1)

    await expect(
      callDO(dir(), '/mintInvite', { inviter: deviceIdOf(laptop.ikSig.publicKey), now: Date.now() }),
    ).rejects.toThrow(DirectoryError)
    // The account it belongs to still can.
    await callDO(dir(), '/mintInvite', { inviter: account.userId, now: Date.now() })
  })

  it('does not let a device become an account root of its own', async () => {
    // The same hole from the other direction: if a device row were an account,
    // it could publish its own device list and rotate, minting account ids
    // without limit and each of those able to do it again.
    const account = await registeredAccount()
    const laptop = generateIdentity()
    const laptopId = deviceIdOf(laptop.ikSig.publicKey)
    await link(account, laptop, 1)

    const phantom = generateIdentity()
    await expect(
      publishRoster(
        encodeDeviceRoster(signRoster(laptopId, 1, [deviceOf(laptop), deviceOf(phantom)], laptop.ikSig.privateKey)),
      ),
    ).rejects.toThrow(/no such account/)
    await expect(
      callDO(dir(), '/publishRotation', {
        statement: encodeRotationStatement(signRotation(laptopId, laptop.ikSig.privateKey, phantom.ikSig, Date.now())),
      }),
    ).rejects.toThrow(/no such account/)
  })
})
