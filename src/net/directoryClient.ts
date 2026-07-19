// Typed client wrappers over the directory operations that ride the transport
// (P4). Each is a reqId-correlated request/response; the transport rejects the
// promise if the server returns an { t:'error' } with the same reqId.

import type { FetchedBundle } from '../crypto/prekeys'
import { type WirePublishedBundle, type WireSignedPrekey, type WireOneTimePrekey, decodeFetchedBundle } from '../wire/codec'
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
}
