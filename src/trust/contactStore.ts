// Contact trust (DESIGN 6, the highest-value control in the system).
//
// A subtlety specific to Nightjar shapes this module: a userId IS
// SHA-256(IK_sig) (section 3). So a userId's identity key is fixed by the id
// itself. There is no "key change" for a given userId the way Signal has one
// (where a phone number's key can rotate): a different IK_sig is a different
// userId, i.e. a different contact. DESIGN 6.4's key-change policy therefore
// collapses into two LIVE controls, both realised here plus at the call sites:
//
//   1. Key <-> userId binding. A fetched or received IK_sig MUST hash to the
//      userId we expected, or the directory served a substituted key (the cheap
//      key-swap attack of 6.1). The client (send) and inbound (receive) enforce
//      deriveUserId(key) == peerId BEFORE any DH; this module re-checks it when
//      recording a contact. A stored key that ever disagreed with a presented one
//      hashing to the SAME userId would be a hash collision or local corruption,
//      and we fail closed on it (`conflict`).
//   2. userId <-> person binding. Does this userId belong to the real person?
//      Only the out-of-band safety-number check answers that (6.2). It is the
//      TRUST LEVEL tracked here: 'unverified' (trust on first use), 'invite'
//      (arrived through a trusted invite, 6.3, one-directional authentication),
//      or 'verified' (safety numbers compared in person).
//
// The safety-number rendering and the verify/invite UI are the React layer (still
// to come); this module is the durable trust STATE and the binding checks.

import { deriveUserId } from '../crypto/identity'
import { b64encode } from '../wire/codec'
import type { KeyStore } from '../storage/keystore'
import type { Lock } from '../storage/lock'

export type TrustLevel = 'unverified' | 'invite' | 'verified'

export interface Contact {
  peerId: string
  /** The IK_sig public key bound to this userId (base64url). */
  ikSig: string
  trust: TrustLevel
  firstSeen: number
  verifiedAt: number | null
}

/** Comparing a presented IK_sig against what we already hold for a peer. */
export type Assessment =
  | { outcome: 'first-contact' }
  | { outcome: 'match' }
  | { outcome: 'conflict' } // stored key disagrees (collision/corruption): fail closed

/** Thrown when a presented key conflicts with a stored one for the same userId
 *  (a fail-safe: given userId == hash(IK_sig) this should be unreachable). */
export class KeyConflictError extends Error {
  constructor(readonly peerId: string) {
    super(`contact key conflict for ${peerId}`)
    this.name = 'KeyConflictError'
  }
}

const CONTACTS_KEY = 'contacts.v1'
const CONTACTS_LOCK = 'nightjar-contacts'
const encoder = new TextEncoder()
const decoder = new TextDecoder()

export class ContactStore {
  constructor(
    private readonly store: KeyStore,
    private readonly lock: Lock,
  ) {}

  private async read(): Promise<Record<string, Contact>> {
    const bytes = await this.store.get(CONTACTS_KEY)
    if (!bytes) return {}
    return JSON.parse(decoder.decode(bytes)) as Record<string, Contact>
  }

  private async write(map: Record<string, Contact>): Promise<void> {
    await this.store.put(CONTACTS_KEY, encoder.encode(JSON.stringify(map)))
  }

  private async mutate<T>(fn: (map: Record<string, Contact>) => T): Promise<T> {
    return this.lock.withLock(CONTACTS_LOCK, async () => {
      const map = await this.read()
      const result = fn(map)
      await this.write(map)
      return result
    })
  }

  async get(peerId: string): Promise<Contact | null> {
    return (await this.read())[peerId] ?? null
  }

  async list(): Promise<Contact[]> {
    return Object.values(await this.read())
  }

  async trustLevel(peerId: string): Promise<TrustLevel | null> {
    return (await this.get(peerId))?.trust ?? null
  }

  /** Compare a presented key for a peer against what we hold (read-only). The
   *  caller is expected to have already checked deriveUserId(presented)==peerId. */
  async assess(peerId: string, presentedIkSig: Uint8Array): Promise<Assessment> {
    const c = await this.get(peerId)
    if (!c) return { outcome: 'first-contact' }
    return c.ikSig === b64encode(presentedIkSig) ? { outcome: 'match' } : { outcome: 'conflict' }
  }

  /** Record a peer's key on first contact. `trust` is 'invite' when the key came
   *  through an out-of-band invite (6.3), else 'unverified' (TOFU). Idempotent
   *  for the same key; upgrades TOFU->invite; a conflicting key fails closed. */
  async recordFirstContact(
    peerId: string,
    ikSig: Uint8Array,
    now: number,
    trust: 'unverified' | 'invite' = 'unverified',
  ): Promise<void> {
    if (deriveUserId(ikSig) !== peerId) throw new Error('contacts: IK_sig does not match peer id')
    const encoded = b64encode(ikSig)
    await this.mutate((map) => {
      const existing = map[peerId]
      if (existing) {
        if (existing.ikSig !== encoded) throw new KeyConflictError(peerId)
        if (trust === 'invite' && existing.trust === 'unverified') existing.trust = 'invite'
        return
      }
      map[peerId] = { peerId, ikSig: encoded, trust, firstSeen: now, verifiedAt: null }
    })
  }

  /** The user completed the out-of-band safety-number check (6.2): this userId is
   *  confirmed to belong to the real person. */
  async markVerified(peerId: string, now: number): Promise<void> {
    await this.mutate((map) => {
      const c = map[peerId]
      if (!c) throw new Error('contacts: verify an unknown peer')
      c.trust = 'verified'
      c.verifiedAt = now
    })
  }
}
