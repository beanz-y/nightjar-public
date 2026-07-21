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
import { openBlob, sealBlob } from '../crypto/appLock'
import { b64decode, b64encode } from '../wire/codec'
import type { AppLockStore } from '../storage/appLockStore'
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
const PENDING_KEY = 'contacts.pending.v1'
const ALIASES_KEY = 'aliases.v1'
const MAX_PENDING_RECORDS = 100
const MAX_ALIAS_LENGTH = 60
const encoder = new TextEncoder()
const decoder = new TextDecoder()

/** True if `raw` is a pre-P10c PLAINTEXT blob (our JSON object), as opposed to a
 *  sealed blob (salt||ciphertext, effectively random and never valid JSON). Used
 *  to migrate a device that predates the app-lock. */
function isLegacyPlaintextJson(raw: Uint8Array): boolean {
  try {
    const v = JSON.parse(decoder.decode(raw)) as unknown
    return typeof v === 'object' && v !== null
  } catch {
    return false
  }
}

/** Trust work that failed transiently and must not be lost (P8): an inviter pin
 *  whose bundle fetch failed after registration consumed the invite, and inbound
 *  first-contact records whose write failed after the session committed. Both
 *  are retried on every connect until they land. */
export interface PendingTrust {
  inviterPin?: string
  records: Array<{ peerId: string; ikSig: string }>
}

export class ContactStore {
  constructor(
    private readonly store: KeyStore,
    private readonly lock: Lock,
    /** When present, every contact/pending/alias blob is encrypted at rest under
     *  the app-lock's contacts sub-key (P10c). Omitted in tests (plaintext) and
     *  before a lock exists; the real app always supplies an UNLOCKED one, since
     *  contacts are only ever touched behind the unlock screen. */
    private readonly appLock?: AppLockStore,
  ) {}

  // Read a keystore blob, decrypting under the contacts sub-key when the app-lock
  // is wired. `label` (the slot name) is bound in the AEAD so blobs can't be swapped.
  //
  // Upgrade path (P10c): a device that predates the app-lock stored these blobs as
  // PLAINTEXT JSON. When the lock is first enrolled, the old blob cannot be opened
  // (it is not a sealed blob). We detect that a decrypt failure is actually legacy
  // plaintext (it still parses as our JSON), adopt it, and re-seal it now so it is
  // encrypted at rest going forward. A genuinely corrupt or wrong-key sealed blob is
  // not valid JSON, so it re-throws (never silently treated as data).
  private async getSealed(key: string, label: string): Promise<Uint8Array | null> {
    const raw = await this.store.get(key)
    if (raw == null) return null
    if (!this.appLock) return raw
    const ck = this.appLock.contactsKey() // throws AppLockedError when locked (propagates)
    try {
      return openBlob(ck, label, raw)
    } catch (e) {
      if (isLegacyPlaintextJson(raw)) {
        await this.putSealed(key, label, raw).catch(() => {}) // one-time migration to sealed
        return raw
      }
      throw e
    }
  }

  private async putSealed(key: string, label: string, bytes: Uint8Array): Promise<void> {
    await this.store.put(key, this.appLock ? sealBlob(this.appLock.contactsKey(), label, bytes) : bytes)
  }

  private async read(): Promise<Record<string, Contact>> {
    const bytes = await this.getSealed(CONTACTS_KEY, CONTACTS_KEY)
    if (!bytes) return {}
    return JSON.parse(decoder.decode(bytes)) as Record<string, Contact>
  }

  private async write(map: Record<string, Contact>): Promise<void> {
    await this.putSealed(CONTACTS_KEY, CONTACTS_KEY, encoder.encode(JSON.stringify(map)))
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

  // --- chat aliases (local, cosmetic) -------------------------------------
  //
  // A per-device nickname for a peer, so a chat is identifiable by name instead
  // of a 52-char device id. Aliases are LOCAL and cosmetic only: they never touch
  // the wire, the crypto, or the trust level, and the real userId + trust badge
  // stay visible so verification is always by identity, not by a label anyone
  // could set. Keyed by peerId so a chat can be named before it is a full contact.

  async getAliases(): Promise<Record<string, string>> {
    const bytes = await this.getSealed(ALIASES_KEY, ALIASES_KEY)
    if (!bytes) return {}
    try {
      const m = JSON.parse(decoder.decode(bytes)) as Record<string, string>
      return m && typeof m === 'object' ? m : {}
    } catch {
      return {}
    }
  }

  /** Set (or clear, with an empty name) a peer's local nickname. */
  async setAlias(peerId: string, name: string): Promise<void> {
    const trimmed = name.trim().slice(0, MAX_ALIAS_LENGTH)
    await this.lock.withLock(CONTACTS_LOCK, async () => {
      const map = await this.getAliases()
      if (trimmed) map[peerId] = trimmed
      else delete map[peerId]
      if (Object.keys(map).length === 0) await this.store.delete(ALIASES_KEY)
      else await this.putSealed(ALIASES_KEY, ALIASES_KEY, encoder.encode(JSON.stringify(map)))
    })
  }

  // --- pending trust work (P8 durability) ---------------------------------

  async getPendingTrust(): Promise<PendingTrust> {
    const bytes = await this.getSealed(PENDING_KEY, PENDING_KEY)
    if (!bytes) return { records: [] }
    try {
      const p = JSON.parse(decoder.decode(bytes)) as PendingTrust
      return {
        ...(typeof p.inviterPin === 'string' ? { inviterPin: p.inviterPin } : {}),
        records: Array.isArray(p.records) ? p.records : [],
      }
    } catch {
      return { records: [] }
    }
  }

  async mutatePendingTrust(fn: (p: PendingTrust) => void): Promise<void> {
    await this.lock.withLock(CONTACTS_LOCK, async () => {
      const p = await this.getPendingTrust()
      fn(p)
      p.records = p.records.slice(-MAX_PENDING_RECORDS)
      if (!p.inviterPin && p.records.length === 0) {
        await this.store.delete(PENDING_KEY)
      } else {
        await this.putSealed(PENDING_KEY, PENDING_KEY, encoder.encode(JSON.stringify(p)))
      }
    })
  }

  /** Erase all local contact/pending/alias blobs. Used by the forgot-secret
   *  app-lock reset (P10c): these blobs are sealed under the Local Data Key, so
   *  once the LDK is discarded they are unrecoverable ciphertext and MUST be
   *  cleared, or a re-enrolled lock (a new LDK) cannot open them and the app fails
   *  to start. The contact list can be recovered from a backup afterwards. */
  async wipeLocalData(): Promise<void> {
    await this.lock.withLock(CONTACTS_LOCK, async () => {
      await this.store.delete(CONTACTS_KEY)
      await this.store.delete(PENDING_KEY)
      await this.store.delete(ALIASES_KEY)
    })
  }

  /** Replace the whole contact map from a restored backup (P8, DESIGN 8.3).
   *  Restore-only: it runs against a freshly wiped device, so replacing (not
   *  merging) is the correct semantics. Every row is re-checked against the
   *  key<->userId binding here as well, independent of the backup decoder. */
  async replaceAllFromBackup(contacts: Contact[]): Promise<void> {
    const map: Record<string, Contact> = {}
    for (const c of contacts) {
      if (deriveUserId(b64decode(c.ikSig, 32)) !== c.peerId) continue
      map[c.peerId] = { ...c }
    }
    await this.lock.withLock(CONTACTS_LOCK, async () => {
      await this.write(map)
      // Clear any pending-trust work parked by the PRIOR identity on this device
      // so a restored identity starts from a clean ledger (fresh-device premise).
      await this.store.delete(PENDING_KEY)
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
