// The device roster (Sesame, multi-device).
//
// An account is a person; a device is one of the things they read Nightjar on.
// The roster is the account's statement of which devices are its own: a list,
// signed by the ACCOUNT key, that the Directory stores and serves to anyone who
// asks. A sender reads it to know every device to fan a message out to.
//
// What makes it trustworthy is what the account key already means. A contact
// verified the account key out of band (the safety number, DESIGN 6.2), so a
// roster that verifies under that key is the account itself saying "these devices
// are mine". The operator holds the roster but cannot author one: it has no
// account key, and the signature is checked against a key the contact already
// confirmed in person.
//
// Two properties this module is responsible for, both load-bearing:
//
//   1. The signed bytes are CANONICAL. They are built by `domainSeparate`, which
//      length-frames the tag and every field, so two different rosters cannot
//      produce the same bytes and no field can absorb its neighbour. This is why
//      the roster is never signed as JSON: two encoders that order or space keys
//      differently would disagree about what was signed.
//
//   2. Every id in it is checked against the key beside it. A device id IS
//      base32(SHA-256(its key)), and the account id IS base32(SHA-256(the account
//      key)), so `verifyRoster` recomputes both rather than believing either. A
//      roster cannot name a device whose key it does not carry, and cannot be
//      transplanted to another account, because the account id is inside the
//      signature.
//
// Rollback is NOT solved here. `version` is monotonic, but an operator serving an
// older, perfectly valid roster to hide a device that was removed is a legitimate
// signature over stale facts. The defence is the caller's: keep a high-water mark
// per contact and refuse anything below it (see `isRosterNewer`). Server-side
// monotonicity is liveness, not security.
//
// A hash chain over previous versions was considered and deliberately left out:
// it would let a client that already holds version N confirm N+1 descends from it,
// but anyone able to sign a fork holds the account key and can sign a consistent
// chain just as easily, so it buys nothing against the attacker who matters.
//
// The roster carries NO device names. It is served in the clear to anyone who asks
// for the account, and "Dan's work laptop" is not something to hand out. Names are
// local, like chat nicknames (DESIGN 8.9).

import { CLOCK_SKEW_MS, MAX_DEVICES_PER_ACCOUNT, TAG_ROSTER } from './constants'
import { accountIdOf, deviceIdOf } from './identity'
import { domainSeparate, ed25519Sign, ed25519Verify, u32be, u64be, utf8 } from './primitives'

/** One device an account claims. */
export interface RosterDevice {
  /** base32(SHA-256(dkSigPub)); recomputed on verify, never trusted as given. */
  readonly deviceId: string
  /** That device's own Ed25519 signing key (32 bytes). */
  readonly dkSigPub: Uint8Array
  /** When the account added it, in ms. Shown to the user; never a security input. */
  readonly addedAt: number
}

/** An account's signed device list. */
export interface DeviceRoster {
  readonly accountId: string
  /** Monotonic, starts at 1. Only ever compared, never used as a timestamp. */
  readonly version: number
  readonly devices: readonly RosterDevice[]
  /** Ed25519 signature by the ACCOUNT key over `rosterSigningBytes`. */
  readonly sig: Uint8Array
}

/** Thrown by `verifyRoster`. Distinct so callers can tell a bad roster from a
 *  network or storage failure, and surface it as the security event it is. */
export class RosterError extends Error {
  constructor(message: string) {
    super(`roster: ${message}`)
    this.name = 'RosterError'
  }
}

/**
 * The exact bytes an account key signs. Canonical and injective by construction:
 * `domainSeparate` length-frames the tag and every part, and the device count is
 * signed, so no regrouping of the device fields yields the same bytes.
 *
 * Field order is pinned by a known-answer test. Changing anything here changes
 * every signature, so it is a wire-format change.
 */
export function rosterSigningBytes(
  accountId: string,
  version: number,
  devices: readonly RosterDevice[],
): Uint8Array {
  const parts: Uint8Array[] = [utf8(accountId), u32be(version), u32be(devices.length)]
  for (const d of devices) {
    parts.push(utf8(d.deviceId), d.dkSigPub, u64be(d.addedAt))
  }
  return domainSeparate(TAG_ROSTER, ...parts)
}

/** Sign a roster with the account key. The caller is responsible for `version`
 *  being one higher than whatever it is replacing. */
export function signRoster(
  accountId: string,
  version: number,
  devices: readonly RosterDevice[],
  accountPriv: Uint8Array,
): DeviceRoster {
  return {
    accountId,
    version,
    devices: devices.map((d) => ({ ...d })),
    sig: ed25519Sign(rosterSigningBytes(accountId, version, devices), accountPriv),
  }
}

/**
 * Check a roster, fail-closed. Throws `RosterError` on anything wrong; returns
 * nothing on success, so there is no truthy value to misuse.
 *
 * `accountKeyPub` is the key the caller already holds for this account: a contact
 * record for someone else's account, or this device's own account key. It is NOT
 * taken from the roster, because a roster that carried its own key would only
 * prove it was signed by whoever wrote it.
 *
 * The `now` bound on `addedAt` exists because a wild timestamp would sort a device
 * to the top or bottom of a list the user reads when deciding whether a device is
 * theirs. It is presentation integrity, not a security control, which is why
 * clock skew is tolerated rather than rejected.
 */
export function verifyRoster(roster: DeviceRoster, accountKeyPub: Uint8Array, now: number): void {
  if (accountIdOf(accountKeyPub) !== roster.accountId) {
    throw new RosterError('the account key does not match the account id it claims')
  }
  if (!Number.isSafeInteger(roster.version) || roster.version < 1) {
    throw new RosterError('version must be a positive integer')
  }
  if (roster.devices.length === 0) {
    throw new RosterError('an account with no devices is unreachable; refusing')
  }
  if (roster.devices.length > MAX_DEVICES_PER_ACCOUNT) {
    throw new RosterError(`more than ${MAX_DEVICES_PER_ACCOUNT} devices`)
  }
  const seen = new Set<string>()
  for (const d of roster.devices) {
    if (d.dkSigPub.length !== 32) throw new RosterError('device key is not 32 bytes')
    // The binding that makes a device id mean anything: the id IS the hash of the
    // key beside it, so the roster cannot name a device it does not carry a key for.
    if (deviceIdOf(d.dkSigPub) !== d.deviceId) {
      throw new RosterError('a device id does not match the key listed with it')
    }
    if (seen.has(d.deviceId)) throw new RosterError('the same device is listed twice')
    seen.add(d.deviceId)
    if (!Number.isSafeInteger(d.addedAt) || d.addedAt < 0 || d.addedAt > now + CLOCK_SKEW_MS) {
      throw new RosterError('a device has an implausible added-at time')
    }
  }
  if (roster.sig.length !== 64) throw new RosterError('signature is not 64 bytes')
  if (!ed25519Verify(roster.sig, rosterSigningBytes(roster.accountId, roster.version, roster.devices), accountKeyPub)) {
    throw new RosterError('signature does not verify under the account key')
  }
}

/**
 * Whether `candidate` may replace `known`, which is the ONLY rollback defence
 * that actually binds (see the module header). Equal versions are refused rather
 * than accepted as a no-op: two different rosters at one version means something
 * is wrong, and quietly taking the second would let an operator pick which one a
 * given contact sees.
 */
export function isRosterNewer(candidate: DeviceRoster, knownVersion: number | null): boolean {
  return knownVersion === null || candidate.version > knownVersion
}

/** What changed between the devices last known for an account and the devices it
 *  now claims, for the alert a contact must see. A device APPEARING is the event
 *  that matters: an operator cannot cause it, because a roster is signed by the
 *  account key, so it is either a link that account really made or something that
 *  already holds their account key, and only the person can tell which.
 *
 *  Takes id lists rather than rosters because ids are what a client keeps: a
 *  device id is the hash of its key, and the bundle fetch that reaches a device
 *  already refuses a key that does not hash to the id asked for. */
export function rosterDiff(
  before: readonly string[] | null,
  after: readonly string[],
): { added: string[]; removed: string[] } {
  const had = new Set(before ?? [])
  const has = new Set(after)
  return {
    added: [...has].filter((id) => !had.has(id)),
    removed: [...had].filter((id) => !has.has(id)),
  }
}

/** The device ids a verified roster claims, in the order it lists them. */
export function rosterDeviceIds(roster: DeviceRoster): string[] {
  return roster.devices.map((d) => d.deviceId)
}
