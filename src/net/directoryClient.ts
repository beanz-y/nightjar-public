// Typed client wrappers over the directory operations that ride the transport
// (P4). Each is a reqId-correlated request/response; the transport rejects the
// promise if the server returns an { t:'error' } with the same reqId.

import type { FetchedBundle } from '../crypto/prekeys'
import type { DeviceRoster } from '../crypto/roster'
import type { RotationStatement } from '../crypto/rotation'

import {
  type WireDeviceRoster,
  type WirePublishedBundle,
  type WireRotationStatement,
  type WireSignedPrekey,
  type WireOneTimePrekey,
  decodeDeviceRoster,
  decodeFetchedBundle,
  decodeRotationStatement,
} from '../wire/codec'
import type { Transport } from './transport'

function reqId(): string {
  return crypto.randomUUID()
}

export class DirectoryClient {
  constructor(private readonly transport: Transport) {}

  async register(inviteCode: string, bundle: WirePublishedBundle): Promise<number> {
    const id = reqId()
    const r = await this.transport.request(id, { t: 'register', reqId: id, inviteCode, bundle })
    if (r.t !== 'registered') throw new Error(`register: unexpected ${r.t}`)
    return r.opkCount
  }

  async publishBundle(spk: WireSignedPrekey, opks: WireOneTimePrekey[]): Promise<number> {
    const id = reqId()
    const r = await this.transport.request(id, { t: 'publishBundle', reqId: id, spk, opks })
    if (r.t !== 'published') throw new Error(`publishBundle: unexpected ${r.t}`)
    return r.opkCount
  }

  async fetchBundle(target: string): Promise<{ bundle: FetchedBundle | null; degraded: boolean }> {
    const id = reqId()
    const r = await this.transport.request(id, { t: 'fetchBundle', reqId: id, target })
    if (r.t !== 'bundle') throw new Error(`fetchBundle: unexpected ${r.t}`)
    return { bundle: r.bundle ? decodeFetchedBundle(r.bundle) : null, degraded: r.degraded }
  }

  async mintInvite(): Promise<{ code: string; inviterFingerprint: string }> {
    const id = reqId()
    const r = await this.transport.request(id, { t: 'mintInvite', reqId: id })
    if (r.t !== 'invite') throw new Error(`mintInvite: unexpected ${r.t}`)
    return { code: r.code, inviterFingerprint: r.inviterFingerprint }
  }

  /** The server-verified user ids that redeemed our invites (mutual invite, 6.3).
   *  The relay is untrusted, so the array shape is defended here: a missing/garbage
   *  `joiners` degrades to an empty list instead of throwing at the caller. */
  async inviteRedemptions(): Promise<string[]> {
    const id = reqId()
    const r = await this.transport.request(id, { t: 'inviteRedemptions', reqId: id })
    if (r.t !== 'redemptions') throw new Error(`inviteRedemptions: unexpected ${r.t}`)
    return Array.isArray(r.joiners) ? r.joiners : []
  }

  /** Register this device's bundle as a device of `accountId` (Sesame). Consumes
   *  no invite; the account's signed roster listing this device is what authorizes
   *  it, so this fails until the linking device has published that roster. */
  async registerDevice(accountId: string, bundle: WirePublishedBundle): Promise<number> {
    const id = reqId()
    const r = await this.transport.request(id, { t: 'registerDevice', reqId: id, accountId, bundle })
    if (r.t !== 'registered') throw new Error(`registerDevice: unexpected ${r.t}`)
    return r.opkCount
  }

  /** Publish this account's signed device roster (Sesame). The signature is the
   *  authorization, so this works from any of the account's devices. */
  async publishRoster(roster: WireDeviceRoster): Promise<number> {
    const id = reqId()
    const r = await this.transport.request(id, { t: 'publishRoster', reqId: id, roster })
    if (r.t !== 'rosterPublished') throw new Error(`publishRoster: unexpected ${r.t}`)
    return r.version
  }

  /** Where an account's devices are, or null if it has never published a roster
   *  (every account today). Decoding is STRUCTURAL only: the relay is untrusted,
   *  so a roster is not to be believed until `verifyRoster` has checked it under
   *  an account key the caller already holds. A structurally broken answer
   *  degrades to null, which the caller reads as "one device", rather than
   *  throwing at a call site that only wanted an address. */
  async fetchRoster(accountId: string): Promise<DeviceRoster | null> {
    return (await this.fetchRosterWithRotation(accountId)).roster
  }

  /** The device list AND, if that account rotated its key away, the statement
   *  naming its successor. One round trip, because the caller asking where to
   *  send is exactly who needs to know they moved. Both halves are structural
   *  decodes only: a rotation is worth nothing until `verifyRotation` has checked
   *  it under a key the caller already holds. */
  async fetchRosterWithRotation(
    accountId: string,
  ): Promise<{ roster: DeviceRoster | null; rotation: RotationStatement | null }> {
    const id = reqId()
    const r = await this.transport.request(id, { t: 'fetchRoster', reqId: id, accountId })
    if (r.t !== 'roster') throw new Error(`fetchRoster: unexpected ${r.t}`)
    let roster: DeviceRoster | null = null
    if (r.roster) {
      try {
        roster = decodeDeviceRoster(r.roster)
      } catch {
        roster = null
      }
    }
    let rotation: RotationStatement | null = null
    if (r.rotation) {
      try {
        rotation = decodeRotationStatement(r.rotation)
      } catch {
        rotation = null
      }
    }
    return { roster, rotation }
  }

  /** Re-assert that this device belongs to `accountId` (Sesame). Idempotent, and
   *  best-effort by contract: the caller sends it on connect and ignores failure,
   *  because a device that cannot say so is exactly as reachable as before. */
  async claimDevice(accountId: string): Promise<boolean> {
    const id = reqId()
    const r = await this.transport.request(id, { t: 'claimDevice', reqId: id, accountId })
    if (r.t !== 'deviceClaimed') throw new Error(`claimDevice: unexpected ${r.t}`)
    return r.claimed
  }

  /** Record which key replaces this account's (Sesame, account-key rotation).
   *  The statement is its own authorization, so like a roster this works from any
   *  device of the account. Returns the successor the Directory has on record,
   *  which is what makes a retried rotation safe: republishing the same one
   *  answers with the same id rather than failing. */
  async publishRotation(statement: WireRotationStatement): Promise<string> {
    const id = reqId()
    const r = await this.transport.request(id, { t: 'publishRotation', reqId: id, statement })
    if (r.t !== 'rotationPublished') throw new Error(`publishRotation: unexpected ${r.t}`)
    return r.newAccountId
  }

  /** Whether an account rotated, and to what. ONE hop: a chain is followed by
   *  asking again, because each hop must be verified under the key the previous
   *  one introduced.
   *
   *  Same untrusted-relay discipline as `fetchRoster`. Decoding is STRUCTURAL
   *  only, and a structurally broken answer degrades to null, which the caller
   *  reads as "they did not rotate". Believing it needs `verifyRotation` under a
   *  key the caller already holds. */
  async fetchRotation(accountId: string): Promise<RotationStatement | null> {
    const id = reqId()
    const r = await this.transport.request(id, { t: 'fetchRotation', reqId: id, accountId })
    if (r.t !== 'rotation') throw new Error(`fetchRotation: unexpected ${r.t}`)
    if (!r.statement) return null
    try {
      return decodeRotationStatement(r.statement)
    } catch {
      return null
    }
  }

  /** Which of `ids` the recipient's inbox has recorded as picked up (delivery
   *  indicator catch-up). Same untrusted-relay discipline as above: a garbage
   *  response degrades to "none confirmed", never to a false positive, and the
   *  caller filters to ids it actually asked about. */
  async deliveredCheck(to: string, ids: string[]): Promise<string[]> {
    const id = reqId()
    const r = await this.transport.request(id, { t: 'deliveredCheck', reqId: id, to, ids })
    if (r.t !== 'deliveredList') throw new Error(`deliveredCheck: unexpected ${r.t}`)
    if (!Array.isArray(r.ids)) return []
    const asked = new Set(ids)
    return r.ids.filter((x): x is string => typeof x === 'string' && asked.has(x))
  }
}
