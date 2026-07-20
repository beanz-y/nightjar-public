// Durable storage of the user's OWN prekey private keys (P4). To respond to an
// X3DH initial message (DESIGN 4.2), the responder needs the private halves of
// the signed prekey and the one-time prekey the initiator referenced by id. Those
// are generated at registration (buildOwnBundle) and must survive a reload, so
// they live here rather than only in memory.
//
// One-time prekeys are single-use: consumeOpk deletes the private half so it can
// never seed two sessions. Mutations run under a lock to serialise concurrent
// consumes (two different peers' initials arriving at once).

import { SPK_RETIRE_GRACE_MS } from '../crypto/constants'
import type { KeyPair } from '../crypto/primitives'
import { type WireSignedPrekey, b64decode, b64encode } from '../wire/codec'
import type { KeyStore } from './keystore'
import type { Lock } from './lock'

export const PREKEYS_KEY = 'prekeys.v1'
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
  /** The SPK id the Directory last ACKNOWLEDGED holding (set only after a
   *  successful register/publish). When this trails the newest stored SPK, a
   *  publish failed mid-rotation and is retried on the next connect (P8). */
  publishedSpkId?: number
  /** True between writing a FULL fresh prekey set locally (setFromRegistration)
   *  and the Directory acknowledging that registration. If a full registration
   *  is interrupted here, recovery must be a purging full re-register (which
   *  hard-invalidates the OPKs the owner no longer holds the privates for), NOT
   *  a plain publishBundle (which would leave those stale OPKs served). See the
   *  P9 stale-OPK finding. */
  regUnconfirmed?: boolean
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
   *  any prior set: a fresh registration invalidates old prekeys (DESIGN 8.3).
   *  Marks the registration UNCONFIRMED until confirmRegistration lands, so an
   *  interrupted full registration recovers via a purging re-register. */
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
        regUnconfirmed: true,
      }
      await this.write(data)
    })
  }

  /** The Directory acknowledged a FULL registration of this SPK id: it now
   *  serves this exact prekey set, so the set is confirmed and published. */
  async confirmRegistration(spkId: number): Promise<void> {
    await this.lock.withLock(PREKEYS_LOCK, async () => {
      const data = await this.read()
      data.regUnconfirmed = false
      data.publishedSpkId = spkId
      await this.write(data)
    })
  }

  /** True while a full registration's local prekeys exist but the Directory has
   *  not acknowledged them (recovery must be a purging re-register, not a
   *  publishBundle). Falsy for a healthy set and for a pre-P8 stored set. */
  async isRegistrationUnconfirmed(): Promise<boolean> {
    return (await this.read()).regUnconfirmed === true
  }

  /** Append a freshly rotated signed prekey (P8). Prior SPKs are KEPT: an
   *  in-flight initial message may cite an old SPK id for as long as the
   *  envelope TTL allows, so their private halves stay until pruneRetiredSpks
   *  ages them out. Commit is local-FIRST: an SPK public key must never reach
   *  the Directory before its private half is durable here. */
  async addSpk(spk: {
    id: number
    createdAt: number
    expiry: number
    priv: Uint8Array
    pub: Uint8Array
    sig: Uint8Array
  }): Promise<void> {
    await this.lock.withLock(PREKEYS_LOCK, async () => {
      const data = await this.read()
      if (data.spks.some((s) => s.id === spk.id)) throw new Error(`prekeyStore: SPK id ${spk.id} already stored`)
      data.spks.push({
        id: spk.id,
        priv: b64encode(spk.priv),
        pub: b64encode(spk.pub),
        sig: b64encode(spk.sig),
        createdAt: spk.createdAt,
        expiry: spk.expiry,
      })
      await this.write(data)
    })
  }

  /** The newest stored SPK's metadata (rotation decision input), or null. */
  async newestSpk(): Promise<{ id: number; createdAt: number; expiry: number } | null> {
    const s = this.newestOf(await this.read())
    return s ? { id: s.id, createdAt: s.createdAt, expiry: s.expiry } : null
  }

  /** Highest SPK id in use, for generating the next rotation id. */
  async maxSpkId(): Promise<number> {
    const data = await this.read()
    return data.spks.reduce((m, s) => Math.max(m, s.id), 0)
  }

  async publishedSpkId(): Promise<number | null> {
    return (await this.read()).publishedSpkId ?? null
  }

  /** Record that the Directory acknowledged holding this SPK id. */
  async markSpkPublished(id: number): Promise<void> {
    await this.lock.withLock(PREKEYS_LOCK, async () => {
      const data = await this.read()
      data.publishedSpkId = id
      await this.write(data)
    })
  }

  /** Drop retired SPK private keys once nothing can legitimately cite them: an
   *  initial can be BUILT until the SPK's expiry (+ skew) and then sit queued
   *  for the envelope TTL, so retention runs to expiry + SPK_RETIRE_GRACE_MS.
   *  The newest SPK is never dropped. Returns how many were pruned. */
  async pruneRetiredSpks(now: number): Promise<number> {
    return this.lock.withLock(PREKEYS_LOCK, async () => {
      const data = await this.read()
      const newest = this.newestOf(data)
      const keep = data.spks.filter((s) => s === newest || now <= s.expiry + SPK_RETIRE_GRACE_MS)
      const pruned = data.spks.length - keep.length
      if (pruned > 0) {
        data.spks = keep
        await this.write(data)
      }
      return pruned
    })
  }

  private newestOf(data: StoredPrekeys): StoredSpk | null {
    return data.spks.reduce<StoredSpk | null>((m, s) => (!m || s.createdAt > m.createdAt ? s : m), null)
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

  /** The NEWEST stored signed prekey in wire form (id/createdAt/expiry/pub/sig),
   *  for re-publishing during OPK replenishment and rotation retry. Null if none
   *  is stored, or it predates the signature being persisted (pre-P5). */
  async signedPrekeyWire(): Promise<WireSignedPrekey | null> {
    const s = this.newestOf(await this.read())
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
