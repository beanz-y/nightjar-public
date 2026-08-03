// Typed client wrappers over the directory operations that ride the transport
// (P4). Each is a reqId-correlated request/response; the transport rejects the
// promise if the server returns an { t:'error' } with the same reqId.

import type { FetchedBundle } from '../crypto/prekeys'
import type { DeviceRoster } from '../crypto/roster'
import {
  type WireDeviceRoster,
  type WirePublishedBundle,
  type WireSignedPrekey,
  type WireOneTimePrekey,
  decodeDeviceRoster,
  decodeFetchedBundle,
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
    const id = reqId()
    const r = await this.transport.request(id, { t: 'fetchRoster', reqId: id, accountId })
    if (r.t !== 'roster') throw new Error(`fetchRoster: unexpected ${r.t}`)
    if (!r.roster) return null
    try {
      return decodeDeviceRoster(r.roster)
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
