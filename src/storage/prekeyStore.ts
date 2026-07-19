// Durable storage of the user's OWN prekey private keys (P4). To respond to an
// X3DH initial message (DESIGN 4.2), the responder needs the private halves of
// the signed prekey and the one-time prekey the initiator referenced by id. Those
// are generated at registration (buildOwnBundle) and must survive a reload, so
// they live here rather than only in memory.
//
// One-time prekeys are single-use: consumeOpk deletes the private half so it can
// never seed two sessions. Mutations run under a lock to serialise concurrent
// consumes (two different peers' initials arriving at once).

import type { KeyPair } from '../crypto/primitives'
import { type WireSignedPrekey, b64decode, b64encode } from '../wire/codec'
import type { KeyStore } from './keystore'
import type { Lock } from './lock'

const PREKEYS_KEY = 'prekeys.v1'
const PREKEYS_LOCK = 'nightjar-prekeys'
const encoder = new TextEncoder()
const decoder = new TextDecoder()

interface StoredSpk {
  id: number
  priv: string
  pub: string
  /** The IK_sig signature over the SPK, kept so it can be re-published verbatim
   *  during OPK replenishment (the directory re-verifies it). */
  sig?: string
  createdAt: number
  expiry: number
}
interface StoredPrekeys {
  spks: StoredSpk[]
  opks: Array<{ id: number; priv: string }>
}

/** What the inbound X3DH responder path looks up, by id. */
export interface ResponderPrekeys {
  spkPrivById: Map<number, Uint8Array>
  spkPubById: Map<number, Uint8Array>
  opkPrivById: Map<number, Uint8Array>
}

/** The shape buildOwnBundle returns, plus the SPK metadata we persist. */
export interface OwnPrekeyMaterial {
  spk: { id: number; createdAt: number; expiry: number; pub: Uint8Array; sig: Uint8Array }
  spkPrivById: ReadonlyMap<number, Uint8Array>
  opks: Array<{ id: number; pub: Uint8Array }>
  opkPrivById: ReadonlyMap<number, Uint8Array>
}

export class PrekeyStore {
  constructor(
    private readonly store: KeyStore,
    private readonly lock: Lock,
  ) {}

  private async read(): Promise<StoredPrekeys> {
    const bytes = await this.store.get(PREKEYS_KEY)
    if (!bytes) return { spks: [], opks: [] }
    return JSON.parse(decoder.decode(bytes)) as StoredPrekeys
  }

  private async write(data: StoredPrekeys): Promise<void> {
    await this.store.put(PREKEYS_KEY, encoder.encode(JSON.stringify(data)))
  }

  /** Persist the freshly generated prekey material (from registration). Replaces
   *  any prior set: a fresh registration invalidates old prekeys (DESIGN 8.3). */
  async setFromRegistration(material: OwnPrekeyMaterial): Promise<void> {
    await this.lock.withLock(PREKEYS_LOCK, async () => {
      const spkPriv = material.spkPrivById.get(material.spk.id)
      if (!spkPriv) throw new Error('prekeyStore: missing SPK private for its id')
      const data: StoredPrekeys = {
        spks: [
          {
            id: material.spk.id,
            priv: b64encode(spkPriv),
            pub: b64encode(material.spk.pub),
            sig: b64encode(material.spk.sig),
            createdAt: material.spk.createdAt,
            expiry: material.spk.expiry,
          },
        ],
        opks: material.opks.map((o) => {
          const priv = material.opkPrivById.get(o.id)
          if (!priv) throw new Error(`prekeyStore: missing OPK private for id ${o.id}`)
          return { id: o.id, priv: b64encode(priv) }
        }),
      }
      await this.write(data)
    })
  }

  /** Add newly generated one-time prekeys (replenishment). */
  async addOpks(opks: Array<{ id: number; priv: Uint8Array }>): Promise<void> {
    await this.lock.withLock(PREKEYS_LOCK, async () => {
      const data = await this.read()
      const known = new Set(data.opks.map((o) => o.id))
      for (const o of opks) if (!known.has(o.id)) data.opks.push({ id: o.id, priv: b64encode(o.priv) })
      await this.write(data)
    })
  }

  /** Look up the responder material by id (read-only, no lock needed). */
  async responderKeys(): Promise<ResponderPrekeys> {
    const data = await this.read()
    return {
      spkPrivById: new Map(data.spks.map((s) => [s.id, b64decode(s.priv, 32)])),
      spkPubById: new Map(data.spks.map((s) => [s.id, b64decode(s.pub, 32)])),
      opkPrivById: new Map(data.opks.map((o) => [o.id, b64decode(o.priv, 32)])),
    }
  }

  /** The stored signed prekey in wire form (id/createdAt/expiry/pub/sig), for
   *  re-publishing during OPK replenishment. Null if none is stored, or the
   *  stored SPK predates the signature being persisted (pre-P5). */
  async signedPrekeyWire(): Promise<WireSignedPrekey | null> {
    const data = await this.read()
    const s = data.spks[0]
    if (!s || !s.sig) return null
    return { id: s.id, createdAt: s.createdAt, expiry: s.expiry, pub: s.pub, sig: s.sig }
  }

  /** The signed-prekey keypair for an id, if held (for initRatchetResponder). */
  async spkKeyPair(id: number): Promise<KeyPair | null> {
    const data = await this.read()
    const s = data.spks.find((x) => x.id === id)
    return s ? { privateKey: b64decode(s.priv, 32), publicKey: b64decode(s.pub, 32) } : null
  }

  /** Consume (permanently delete) a one-time prekey's private key. Single-use. */
  async consumeOpk(id: number): Promise<void> {
    await this.lock.withLock(PREKEYS_LOCK, async () => {
      const data = await this.read()
      const next = data.opks.filter((o) => o.id !== id)
      if (next.length !== data.opks.length) {
        data.opks = next
        await this.write(data)
      }
    })
  }

  async availableOpkCount(): Promise<number> {
    return (await this.read()).opks.length
  }

  /** Highest OPK id in use, for generating a non-colliding replenishment batch. */
  async maxOpkId(): Promise<number> {
    const data = await this.read()
    return data.opks.reduce((m, o) => Math.max(m, o.id), 0)
  }
}
