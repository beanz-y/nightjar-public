// Device roster (Sesame). The roster is what tells a sender where an account's
// devices are, so every check here is one that stops somebody being handed the
// wrong set: a roster signed by the wrong key, one naming a device whose key it
// does not carry, one lifted from another account, or an old one served again to
// hide a device that was removed.

import { describe, expect, it } from 'vitest'
import { CLOCK_SKEW_MS, MAX_DEVICES_PER_ACCOUNT, TAG_ROSTER, TAG_SPK } from './constants'
import { accountIdOf, deviceIdOf } from './identity'
import {
  type DeviceRoster,
  type RosterDevice,
  RosterError,
  isRosterNewer,
  rosterDiff,
  rosterSigningBytes,
  signRoster,
  verifyRoster,
} from './roster'
import { concatBytes, domainSeparate, ed25519Public, ed25519Sign, u32be, u64be, utf8 } from './primitives'

const NOW = 1_700_000_000_000

/** Deterministic keys, so the layout test below pins actual bytes. */
function keyPair(fill: number) {
  const privateKey = new Uint8Array(32).fill(fill)
  return { privateKey, publicKey: ed25519Public(privateKey) }
}

function deviceFor(fill: number, addedAt = NOW): RosterDevice {
  const k = keyPair(fill)
  return { deviceId: deviceIdOf(k.publicKey), dkSigPub: k.publicKey, addedAt }
}

const account = keyPair(1)
const accountId = accountIdOf(account.publicKey)

function rosterOf(devices: RosterDevice[], version = 1, priv = account.privateKey): DeviceRoster {
  return signRoster(accountId, version, devices, priv)
}

describe('roster signing bytes', () => {
  it('are length-framed field by field, in a pinned order', () => {
    // Built here WITHOUT domainSeparate, so this fails if either the framing or
    // the field order changes. Both are wire-format changes: every existing
    // signature stops verifying.
    const d = deviceFor(2)
    const tag = utf8(TAG_ROSTER)
    const frame = (b: Uint8Array) => concatBytes(u32be(b.length), b)
    const expected = concatBytes(
      frame(tag),
      frame(utf8(accountId)),
      frame(u32be(7)), // version
      frame(u32be(1)), // device count
      frame(utf8(d.deviceId)),
      frame(d.dkSigPub),
      frame(u64be(d.addedAt)),
    )
    expect(rosterSigningBytes(accountId, 7, [d])).toEqual(expected)
  })

  it('cannot be confused by regrouping the devices', () => {
    // The count is signed and every field is length-framed, so two devices can
    // never be read as one device with a longer id, or as three.
    const a = deviceFor(2)
    const b = deviceFor(3)
    expect(rosterSigningBytes(accountId, 1, [a, b])).not.toEqual(rosterSigningBytes(accountId, 1, [b, a]))
    expect(rosterSigningBytes(accountId, 1, [a])).not.toEqual(rosterSigningBytes(accountId, 1, [a, b]))
  })

  it('are domain-separated from the other things the account key signs', () => {
    // On a first device the account key ALSO signs auth challenges and signed
    // prekeys. A signature over the same fields under another tag must not verify
    // here, or one use is an oracle for another (the v0.1 signing-oracle bug).
    const d = deviceFor(2)
    const parts = [utf8(accountId), u32be(1), u32be(1), utf8(d.deviceId), d.dkSigPub, u64be(d.addedAt)]
    const underSpkTag = ed25519Sign(domainSeparate(TAG_SPK, ...parts), account.privateKey)
    const forged: DeviceRoster = { accountId, version: 1, devices: [d], sig: underSpkTag }
    expect(() => verifyRoster(forged, account.publicKey, NOW)).toThrow(RosterError)
  })
})

describe('verifyRoster', () => {
  it('accepts a well-formed roster', () => {
    expect(() => verifyRoster(rosterOf([deviceFor(2), deviceFor(3)]), account.publicKey, NOW)).not.toThrow()
  })

  it('refuses one signed by a different key, even if everything else matches', () => {
    const impostor = keyPair(9)
    const r = signRoster(accountId, 1, [deviceFor(2)], impostor.privateKey)
    expect(() => verifyRoster(r, account.publicKey, NOW)).toThrow(/signature does not verify/)
  })

  it('refuses a key that is not this account', () => {
    const other = keyPair(9)
    expect(() => verifyRoster(rosterOf([deviceFor(2)]), other.publicKey, NOW)).toThrow(/does not match the account id/)
  })

  it('refuses a roster lifted onto another account', () => {
    // The account id is inside the signature, so a valid roster cannot be replayed
    // under someone else's id even by an operator holding both.
    const victim = keyPair(9)
    const stolen: DeviceRoster = { ...rosterOf([deviceFor(2)]), accountId: accountIdOf(victim.publicKey) }
    expect(() => verifyRoster(stolen, victim.publicKey, NOW)).toThrow(RosterError)
  })

  it('refuses a device id that does not match the key beside it', () => {
    // The attack this stops: a roster that names a device the account controls
    // while carrying a key the attacker controls, so mail routes to the id but
    // the session runs to their key.
    const real = deviceFor(2)
    const attacker = keyPair(9)
    const swapped: RosterDevice = { deviceId: real.deviceId, dkSigPub: attacker.publicKey, addedAt: NOW }
    const r = rosterOf([swapped])
    expect(() => verifyRoster(r, account.publicKey, NOW)).toThrow(/device id does not match the key/)
  })

  it('refuses an empty roster, which would make the account unreachable', () => {
    expect(() => verifyRoster(rosterOf([]), account.publicKey, NOW)).toThrow(/no devices/)
  })

  it('refuses duplicates and over-long lists', () => {
    const d = deviceFor(2)
    expect(() => verifyRoster(rosterOf([d, { ...d }]), account.publicKey, NOW)).toThrow(/listed twice/)
    const many = Array.from({ length: MAX_DEVICES_PER_ACCOUNT + 1 }, (_, i) => deviceFor(i + 10))
    expect(() => verifyRoster(rosterOf(many), account.publicKey, NOW)).toThrow(/more than/)
  })

  it('refuses an implausible added-at time, but tolerates clock skew', () => {
    expect(() => verifyRoster(rosterOf([deviceFor(2, -1)]), account.publicKey, NOW)).toThrow(/implausible/)
    expect(() => verifyRoster(rosterOf([deviceFor(2, NOW + CLOCK_SKEW_MS + 1)]), account.publicKey, NOW)).toThrow(
      /implausible/,
    )
    expect(() =>
      verifyRoster(rosterOf([deviceFor(2, NOW + CLOCK_SKEW_MS - 1)]), account.publicKey, NOW),
    ).not.toThrow()
  })

  it('refuses a version that is not a positive integer', () => {
    for (const version of [0, -1, 1.5, Number.NaN]) {
      expect(() => verifyRoster(rosterOf([deviceFor(2)], version), account.publicKey, NOW)).toThrow(RosterError)
    }
  })

  it('notices every field being tampered with after signing', () => {
    const d = deviceFor(2)
    const good = rosterOf([d], 4)
    const tampered: DeviceRoster[] = [
      { ...good, version: 5 },
      { ...good, devices: [...good.devices, deviceFor(3)] },
      { ...good, devices: [{ ...d, addedAt: d.addedAt + 1 }] },
      { ...good, sig: concatBytes(good.sig.slice(0, 63), Uint8Array.from([good.sig[63] ^ 1])) },
    ]
    for (const r of tampered) expect(() => verifyRoster(r, account.publicKey, NOW)).toThrow(RosterError)
  })
})

describe('rollback and change detection', () => {
  it('only accepts a strictly newer version, and refuses an equal one', () => {
    // Equal is refused rather than treated as a no-op: two different rosters at one
    // version means something is wrong, and taking the second would let an operator
    // choose which one a given contact sees.
    expect(isRosterNewer(rosterOf([deviceFor(2)], 3), null)).toBe(true)
    expect(isRosterNewer(rosterOf([deviceFor(2)], 4), 3)).toBe(true)
    expect(isRosterNewer(rosterOf([deviceFor(2)], 3), 3)).toBe(false)
    expect(isRosterNewer(rosterOf([deviceFor(2)], 2), 3)).toBe(false)
  })

  it('reports what changed, which is what the contact has to be told', () => {
    const phone = deviceFor(2)
    const laptop = deviceFor(3)
    const before = rosterOf([phone], 1)
    expect(rosterDiff(before, rosterOf([phone, laptop], 2))).toEqual({ added: [laptop.deviceId], removed: [] })
    expect(rosterDiff(before, rosterOf([laptop], 2))).toEqual({ added: [laptop.deviceId], removed: [phone.deviceId] })
    expect(rosterDiff(null, before)).toEqual({ added: [phone.deviceId], removed: [] })
  })
})
