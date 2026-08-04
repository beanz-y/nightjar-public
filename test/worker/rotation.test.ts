// Account-key rotation in the Directory (Sesame), against the real Durable
// Object.
//
// Rotation is the only thing that can move an account to a new key without
// making its owner a stranger to everybody, and the Directory's part in it is
// narrow: record which key replaces which, so a rotated account can publish a
// device list at all, and serve that record to anyone who asks so a contact who
// was offline can catch up. It authors nothing and it verifies everything
// against a key it already holds.
//
// The property these tests exist to protect, beyond the mechanics, is the one an
// earlier design nearly gave away: the account namespace stays invite-gated. A
// rotation can only start from an account this Directory already knows, so
// nobody can mint account ids out of fresh keypairs and fill the one shared
// Directory with device lists for people who do not exist.

import { env } from 'cloudflare:test'
import { describe, expect, it } from 'vitest'
import { MAX_ROTATION_CHAIN } from '../../src/crypto/constants'
import { type Identity, accountIdOf, deviceIdOf, generateIdentity } from '../../src/crypto/identity'
import { OWN_BUNDLE_VERSION, buildOwnBundle } from '../../src/crypto/prekeys'
import { type RosterDevice, signRoster } from '../../src/crypto/roster'
import { rotationSigningBytes, signRotation } from '../../src/crypto/rotation'
import { ed25519Sign } from '../../src/crypto/primitives'
import {
  type WireDeviceRoster,
  type WireRotationStatement,
  encodeDeviceRoster,
  encodePublishedBundle,
  encodeRotationStatement,
} from '../../src/wire/codec'
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

function rotate(from: Identity, to: Identity, at = Date.now()): WireRotationStatement {
  return encodeRotationStatement(signRotation(accountIdOf(from.ikSig.publicKey), from.ikSig.privateKey, to.ikSig, at))
}

async function publishRotation(statement: WireRotationStatement): Promise<{ newAccountId: string; chainLen: number }> {
  return callDO<{ newAccountId: string; chainLen: number }>(dir(), '/publishRotation', { statement })
}

async function fetchRotation(accountId: string): Promise<WireRotationStatement | null> {
  const r = await callDO<{ statement: WireRotationStatement | null }>(dir(), '/fetchRotation', { accountId })
  return r.statement
}

async function publishRoster(roster: WireDeviceRoster): Promise<{ version: number }> {
  return callDO<{ version: number }>(dir(), '/publishRoster', { roster })
}

async function bundleOf(target: string, fetcher: string): Promise<unknown> {
  const r = await callDO<{ bundle: unknown }>(dir(), '/fetchBundle', { fetcher, target, now: Date.now() })
  return r.bundle
}

describe('account-key rotation (Sesame)', () => {
  it('an account that never rotated reads as null, not as an error', async () => {
    const account = await registeredAccount()
    expect(await fetchRotation(account.userId)).toBeNull()
  })

  it('records a rotation and serves the statement back unchanged', async () => {
    const account = await registeredAccount()
    const next = generateIdentity()
    const statement = rotate(account, next)

    const published = await publishRotation(statement)
    expect(published.newAccountId).toBe(accountIdOf(next.ikSig.publicKey))
    expect(published.chainLen).toBe(1)
    // Served verbatim: a contact verifies it themselves, under the key they
    // already hold, so nothing here is trusted to have interpreted it.
    expect(await fetchRotation(account.userId)).toEqual(statement)
    // And the pointer runs one way only. The successor is not itself rotated.
    expect(await fetchRotation(accountIdOf(next.ikSig.publicKey))).toBeNull()
  })

  it('lets the rotated account publish a device list, which is the whole blocker', async () => {
    // Before this existed, a roster was verified against the identity key
    // registered under the account id. A rotated account id belongs to no device,
    // so there was no row, so it could never publish a roster: an account that
    // rotated would have had no way to say where its devices are.
    const account = await registeredAccount()
    const laptop = generateIdentity()
    const next = generateIdentity()
    const newId = accountIdOf(next.ikSig.publicKey)

    // Until the rotation is recorded there is nothing to verify a roster against.
    const early = signRoster(newId, 1, [deviceOf(account)], next.ikSig.privateKey)
    await expect(publishRoster(encodeDeviceRoster(early))).rejects.toThrow(/no such account/)

    await publishRotation(rotate(account, next))
    const roster = signRoster(newId, 1, [deviceOf(account), deviceOf(laptop)], next.ikSig.privateKey)
    expect(await publishRoster(encodeDeviceRoster(roster))).toEqual({ version: 1 })

    const served = await callDO<{ roster: WireDeviceRoster | null }>(dir(), '/fetchRoster', { accountId: newId })
    expect(served.roster).toEqual(encodeDeviceRoster(roster))
    // Signed by the NEW key only. The old one is finished.
    const stale = signRoster(newId, 2, [deviceOf(account)], account.ikSig.privateKey)
    await expect(publishRoster(encodeDeviceRoster(stale))).rejects.toThrow(DirectoryError)
  })

  it('keeps serving the old account, so contacts who have not heard are not cut off', async () => {
    // A rotation does not retire anything. Contacts still on the old id keep
    // reaching the same devices until they learn about it and follow.
    const account = await registeredAccount()
    const laptop = generateIdentity()
    await publishRoster(
      encodeDeviceRoster(signRoster(account.userId, 1, [deviceOf(account), deviceOf(laptop)], account.ikSig.privateKey)),
    )
    await publishRotation(rotate(account, generateIdentity()))

    const served = await callDO<{ roster: WireDeviceRoster | null }>(dir(), '/fetchRoster', {
      accountId: account.userId,
    })
    expect(served.roster!.devices).toHaveLength(2)
    expect(await bundleOf(account.userId, laptop.userId)).not.toBeNull()

    // What stops is CHANGING it. A rotated account has moved on, so adding a
    // device to the retired one is refused even though its key still signs.
    const later = signRoster(
      account.userId,
      2,
      [deviceOf(account), deviceOf(laptop), deviceOf(generateIdentity())],
      account.ikSig.privateKey,
    )
    await expect(publishRoster(encodeDeviceRoster(later))).rejects.toThrow(/has rotated/)

    // And the same at the other door: a device still listed on that frozen list
    // cannot go on registering itself under the retired account, which would be
    // a right the freeze was meant to end.
    const own = buildOwnBundle(laptop, Date.now(), { spkId: 1, opkStartId: 1, opkCount: 2 })
    await expect(
      callDO(dir(), '/registerDevice', {
        deviceId: deviceIdOf(laptop.ikSig.publicKey),
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
      }),
    ).rejects.toThrow(/has rotated/)
  })

  it('refuses a rotation from an account it does not know', async () => {
    // The invite gate, carried through rotation: without this, anyone could mint
    // account ids from fresh keypairs and fill the one shared Directory.
    const stranger = generateIdentity()
    await expect(publishRotation(rotate(stranger, generateIdentity()))).rejects.toThrow(/no such account/)
  })

  it('refuses a statement the old key did not sign', async () => {
    const account = await registeredAccount()
    const next = generateIdentity()
    const impostor = generateIdentity()
    const genuine = signRotation(account.userId, account.ikSig.privateKey, next.ikSig, Date.now())
    const bytes = rotationSigningBytes(genuine.oldAccountId, genuine.newAccountId, genuine.newAccountKey, genuine.rotatedAt)
    const forged = encodeRotationStatement({ ...genuine, oldSig: ed25519Sign(bytes, impostor.ikSig.privateKey) })

    await expect(publishRotation(forged)).rejects.toThrow(DirectoryError)
    expect(await fetchRotation(account.userId)).toBeNull()
  })

  it('refuses a rotation to a key its author does not hold', async () => {
    // The counter-signature, checked server-side as well as on every client:
    // otherwise an account could rotate "to" a contact's published account key
    // and drag its whole contact list onto somebody else's identity.
    const account = await registeredAccount()
    const victim = generateIdentity()
    const bytes = rotationSigningBytes(
      account.userId,
      accountIdOf(victim.ikSig.publicKey),
      victim.ikSig.publicKey,
      Date.now(),
    )
    const transplant = encodeRotationStatement({
      oldAccountId: account.userId,
      newAccountId: accountIdOf(victim.ikSig.publicKey),
      newAccountKey: victim.ikSig.publicKey,
      rotatedAt: Date.now(),
      oldSig: ed25519Sign(bytes, account.ikSig.privateKey),
      newSig: ed25519Sign(bytes, account.ikSig.privateKey),
    })
    await expect(publishRotation(transplant)).rejects.toThrow(DirectoryError)
  })

  it('refuses a rotation onto a key nobody can hold', async () => {
    // A small-order key verifies an all-zero signature, so the counter-signature
    // proves nothing and the successor account would be world-writable: every
    // roster published for it would verify under zeros as well, letting anyone
    // redirect the contacts that followed. The Directory refuses it too, so a
    // client that never learned this cannot be talked into following one.
    const account = await registeredAccount()
    const zeroKey = new Uint8Array(32)
    const zeroId = accountIdOf(zeroKey)
    const bytes = rotationSigningBytes(account.userId, zeroId, zeroKey, Date.now())
    const degenerate = encodeRotationStatement({
      oldAccountId: account.userId,
      newAccountId: zeroId,
      newAccountKey: zeroKey,
      rotatedAt: Date.now(),
      oldSig: ed25519Sign(bytes, account.ikSig.privateKey),
      newSig: new Uint8Array(64),
    })
    await expect(publishRotation(degenerate)).rejects.toThrow(/not a key anybody can hold/)
    expect(await fetchRotation(account.userId)).toBeNull()
  })

  it('records the first rotation only, and repeating it is safe', async () => {
    const account = await registeredAccount()
    const next = generateIdentity()
    const statement = rotate(account, next)
    const first = await publishRotation(statement)

    // Retrying an interrupted rotation answers rather than failing.
    expect(await publishRotation(statement)).toEqual(first)

    // A second successor is refused. Whoever holds the old key could otherwise
    // flip a contact list back and forth between two of them.
    await expect(publishRotation(rotate(account, generateIdentity()))).rejects.toThrow(/already rotated/)
    expect((await fetchRotation(account.userId))!.newAccountId).toBe(first.newAccountId)
  })

  it('refuses rotating into an account that has itself rotated away', async () => {
    // That would close the chain into a cycle, and a client following it would
    // never arrive anywhere.
    const first = await registeredAccount()
    const second = await registeredAccount()
    await publishRotation(rotate(first, generateIdentity()))
    await expect(publishRotation(rotate(second, first))).rejects.toThrow(/itself rotated away/)
  })

  it('follows a chain, and stops it growing without end', async () => {
    // Each rotation mints an account id out of nothing but a keypair, so the
    // chain is what bounds how much one invited account can make the Directory
    // hold, and how far a client will ever have to walk.
    let current = await registeredAccount()
    for (let hop = 1; hop <= MAX_ROTATION_CHAIN; hop++) {
      const next = generateIdentity()
      expect((await publishRotation(rotate(current, next))).chainLen).toBe(hop)
      current = next
    }
    await expect(publishRotation(rotate(current, generateIdentity()))).rejects.toThrow(/at most/)
  })

  it('makes the first device removable, which nothing else could do', async () => {
    // A first device's key IS the account key, so before rotation the Directory
    // refuses to retire it: dropping its row would leave the account unable to
    // change its own device list ever again. After rotation the account key lives
    // in the rotation record instead, and that device is an ordinary one.
    const account = await registeredAccount()
    const laptop = generateIdentity()
    const laptopId = deviceIdOf(laptop.ikSig.publicKey)
    const own = buildOwnBundle(laptop, Date.now(), { spkId: 1, opkStartId: 1, opkCount: 2 })
    const bundle = encodePublishedBundle({
      version: OWN_BUNDLE_VERSION,
      ikSigPub: own.ikSigPub,
      ikDhPub: own.ikDhPub,
      idkbindSig: own.idkbindSig,
      spk: own.spk,
      opks: own.opks,
    })
    await publishRoster(
      encodeDeviceRoster(signRoster(account.userId, 1, [deviceOf(account), deviceOf(laptop)], account.ikSig.privateKey)),
    )
    await callDO(dir(), '/registerDevice', {
      deviceId: laptopId,
      accountId: account.userId,
      bundle,
      now: Date.now(),
    })

    const next = generateIdentity()
    const newId = accountIdOf(next.ikSig.publicKey)
    await publishRotation(rotate(account, next))
    await publishRoster(
      encodeDeviceRoster(signRoster(newId, 1, [deviceOf(account), deviceOf(laptop)], next.ikSig.privateKey)),
    )
    expect(await bundleOf(account.userId, laptopId)).not.toBeNull()

    // The rotated account drops the device that used to hold its key.
    await publishRoster(encodeDeviceRoster(signRoster(newId, 2, [deviceOf(laptop)], next.ikSig.privateKey)))
    expect(await bundleOf(account.userId, laptopId)).toBeNull()
    // The laptop is untouched, and the account can still publish.
    expect(await bundleOf(laptopId, account.userId)).not.toBeNull()
    await publishRoster(encodeDeviceRoster(signRoster(newId, 3, [deviceOf(laptop)], next.ikSig.privateKey)))
  })

  it('refuses a structurally malformed statement before verifying anything', async () => {
    const account = await registeredAccount()
    const good = rotate(account, generateIdentity())
    const bad: unknown[] = [
      { ...good, oldAccountId: 'too-short' },
      { ...good, newAccountId: 'nope' },
      { ...good, newAccountKey: 'not-base64!!' },
      { ...good, newAccountKey: '' },
      { ...good, oldSig: 'AAAA' },
      { ...good, rotatedAt: -1 },
    ]
    for (const statement of bad) {
      await expect(callDO(dir(), '/publishRotation', { statement })).rejects.toThrow()
    }
    expect(await fetchRotation(account.userId)).toBeNull()
  })
})
