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

import { ENVELOPE_TTL_MS, INVITE_TTL_MS, MAX_RETRY_LEDGER } from '../crypto/constants'
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
/** Peers deleted on this device (see ContactStore.remove). Sealed like the others. */
const DISMISSED_KEY = 'contacts.dismissed.v1'
/** Per-peer retry-receipt throttling (8.10). Sealed like the others. */
const RETRY_KEY = 'contacts.retry.v1'
/** A dismissal expires with the relay-side invite record that motivates it, so the
 *  list cannot become a permanent record of everyone you ever deleted. */
const DISMISSAL_TTL_MS = INVITE_TTL_MS
/** Bound, newest kept: this list is convenience, never a security control.
 *  Exported: the move-package importer must cap at the SAME bound, or the next
 *  contact write here would silently trim what the import claimed to keep. */
export const MAX_DISMISSALS = 200
const MAX_PENDING_RECORDS = 100
/** Exported for the same lockstep reason as MAX_DISMISSALS. */
export const MAX_ALIAS_LENGTH = 60
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

/** A peer the user deleted here. `auto` false means they have since been recorded
 *  again deliberately, so only the timestamp still matters (the send path uses it
 *  to avoid a one-time prekey the peer already consumed). `hadSession` records
 *  whether a ratchet session existed at deletion time, which is what makes that
 *  prekey judgement correct: a peer deleted before any session existed consumed
 *  nothing, so their next handshake must NOT be pushed onto the degraded path. */
interface Dismissal {
  at: number
  auto: boolean
  hadSession: boolean
}

/** Per-peer throttling state for the retry-receipt (DESIGN 8.10). Both directions
 *  share one record because they describe one conversation, and because the cap
 *  below then bounds the whole feature rather than each half of it.
 *   - `askedAt`/`attempts` bound what this device sends THEM: how recently we
 *     asked them to resend, and how many asks have gone unanswered. Cleared as
 *     soon as anything from them decrypts, which is the only honest evidence that
 *     the conversation recovered.
 *   - `honoredAt` bounds what this device does FOR them: when we last acted on a
 *     request of theirs. This is the half that has to be durable, because it is
 *     the only bound a hostile requester cannot simply choose to ignore. */
interface RetryState {
  askedAt?: number
  attempts?: number
  honoredAt?: number
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

  /** Peers deleted on this device, so the relay-driven paths do not add them back.
   *  PROPAGATES a read failure: callers that only consult the list can fall back to
   *  "no dismissals", but a caller that is about to REWRITE or DELETE the blob must
   *  be able to tell "genuinely empty" from "could not read it", or a single failed
   *  open silently destroys every deletion marker on the device. */
  private async loadDismissals(): Promise<Record<string, Dismissal>> {
    const bytes = await this.getSealed(DISMISSED_KEY, DISMISSED_KEY)
    if (!bytes) return {}
    const m = JSON.parse(decoder.decode(bytes)) as Record<string, Dismissal>
    if (!m || typeof m !== 'object') return {}
    // Age out, so this never becomes a permanent shadow list of people you once
    // deleted. The reason it exists (the relay's invite record) expires too.
    const cutoff = Date.now() - DISMISSAL_TTL_MS
    const out: Record<string, Dismissal> = {}
    for (const [peer, d] of Object.entries(m)) {
      if (d && typeof d.at === 'number' && d.at > cutoff) {
        out[peer] = { at: d.at, auto: d.auto !== false, hadSession: d.hadSession === true }
      }
    }
    return out
  }

  /** The consulting read: fail-OPEN, because a corrupt or wrong-key blob must never
   *  be able to break contact recording for the whole app. Never use this to decide
   *  what to write back; see `loadDismissals`. */
  private async readDismissals(): Promise<Record<string, Dismissal>> {
    try {
      return await this.loadDismissals()
    } catch {
      return {}
    }
  }

  /** Read-modify-write of the contact map AND the dismissal list under ONE hold of
   *  the contacts lock, so a delete and a concurrent record cannot interleave and
   *  disagree about whether this peer exists. */
  private async mutateWithDismissals<T>(
    fn: (map: Record<string, Contact>, dismissals: Record<string, Dismissal>) => T,
  ): Promise<T> {
    return this.lock.withLock(CONTACTS_LOCK, async () => {
      const map = await this.read()
      // Fail-open for the GATE decision (an unreadable list must not stop contacts
      // being recorded), but remember that it failed, so the write-back below can
      // never mistake "unreadable" for "empty" and delete the whole blob.
      let readOk = true
      let dismissals: Record<string, Dismissal> = {}
      try {
        dismissals = await this.loadDismissals()
      } catch {
        readOk = false
      }
      const before = JSON.stringify(dismissals)
      const result = fn(map, dismissals)
      await this.write(map)
      if (JSON.stringify(dismissals) !== before) {
        const trimmed = Object.entries(dismissals)
          .sort((a, b) => b[1].at - a[1].at)
          .slice(0, MAX_DISMISSALS)
        // Writing new markers over an unreadable blob loses nothing (it was already
        // unusable), but DELETING on the strength of a failed read would throw away
        // markers we simply could not see.
        if (trimmed.length === 0) {
          if (readOk) await this.store.delete(DISMISSED_KEY)
        } else {
          await this.putSealed(DISMISSED_KEY, DISMISSED_KEY, encoder.encode(JSON.stringify(Object.fromEntries(trimmed))))
        }
      }
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
    /** Set by paths the USER did not ask for: the mutual-invite redemption sync and
     *  the pending-trust retry, both driven by what the relay reports. Those are
     *  refused for a peer the user deleted; everything else (an actual message from
     *  them, or the user adding them back) records normally and clears the block.
     *  See `remove` for why the check has to be in here and not at the call site. */
    relayDriven = false,
    /** Refuse if the peer was deleted AFTER this moment. Used by the inbound
     *  recovery path, whose bundle fetch takes long enough for a user to press
     *  delete part-way through: without it, a message that arrived just before the
     *  delete would re-create the contact just after it. Checked here, under the
     *  same lock as the write, for the same reason `relayDriven` is. */
    refuseIfDismissedAfter?: number,
  ): Promise<boolean> {
    if (deriveUserId(ikSig) !== peerId) throw new Error('contacts: IK_sig does not match peer id')
    const encoded = b64encode(ikSig)
    return this.mutateWithDismissals((map, dismissals) => {
      if (relayDriven && dismissals[peerId]?.auto) return false // deleted here; do not resurrect
      const d0 = dismissals[peerId]
      if (refuseIfDismissedAfter !== undefined && d0 && d0.at > refuseIfDismissedAfter) return false
      const existing = map[peerId]
      if (existing) {
        if (existing.ikSig !== encoded) throw new KeyConflictError(peerId)
        if (trust === 'invite' && existing.trust === 'unverified') existing.trust = 'invite'
        return true
      }
      // Recording again on purpose (they messaged, or the user re-added them) lifts
      // the auto-block, but keeps the deletion TIMESTAMP: the send path needs it to
      // avoid re-using a one-time prekey the peer already consumed (see client.ts).
      const d = dismissals[peerId]
      if (d) d.auto = false
      map[peerId] = { peerId, ikSig: encoded, trust, firstSeen: now, verifiedAt: null }
      return true
    })
  }

  /**
   * Forget a peer: their contact record, their nickname, and any parked pending
   * trust, plus a marker that stops the RELAY-driven paths re-adding them.
   *
   * The marker is what makes a delete stick. Without it, the mutual invite
   * (DESIGN 6.3) re-learns anyone who redeemed one of your invites on the very
   * next connect, for as long as the relay retains the invite record, so the
   * deleted contact would silently return within about a minute.
   *
   * It is enforced inside `recordFirstContact`, which is the single choke point
   * every path funnels through, rather than at the call sites. A call-site check
   * would be a time-of-check gap: `addContact` performs a NETWORK bundle fetch
   * between reading the contact list and writing the record, so a delete landing
   * during that fetch would be overwritten by a decision made before it happened.
   *
   * This is NOT a block. Nightjar has none: the relay accepts a message for any
   * registered user, and a message that actually arrives from this peer records
   * them again as a new, unverified contact. The marker only stops the app adding
   * them back on its own initiative.
   */
  async remove(peerId: string, now: number): Promise<void> {
    // Three separate blobs, so three separate holds of the contacts lock rather
    // than one nested hold (the lock is a plain mutex, not re-entrant). The caller
    // holds the per-peer session lock across the whole delete, which is what makes
    // the sequence atomic against sending and receiving.
    await this.mutateWithDismissals((map, dismissals) => {
      delete map[peerId]
      // `markDismissed` normally ran first and already recorded whether a session
      // existed; preserve that rather than flattening it to a conservative false.
      dismissals[peerId] = { at: now, auto: true, hadSession: dismissals[peerId]?.hadSession === true }
    })
    await this.setAlias(peerId, '')
    await this.mutatePendingTrust((p) => {
      if (p.inviterPin === peerId) delete p.inviterPin
      p.records = p.records.filter((r) => r.peerId !== peerId)
    })
    // The recovery ledger names them too, and 8.9 promises a delete leaves no row
    // that does. Dropping `honoredAt` hands them at most one more honored request,
    // which can only resend history this delete has already swept away.
    await this.mutateRetryState(peerId, (r) => {
      delete r.askedAt
      delete r.honoredAt
      delete r.attempts
    })
  }

  /** Record the deletion marker without touching the contact map, so an interruption
   *  part-way through a delete still leaves the marker behind. `hadSession` says
   *  whether a ratchet session existed at this moment, which is the only honest
   *  basis for the send path's stale-prekey judgement (see `getDismissal`). */
  async markDismissed(peerId: string, now: number, hadSession = false): Promise<void> {
    await this.mutateWithDismissals((_map, dismissals) => {
      dismissals[peerId] = { at: now, auto: true, hadSession }
    })
  }

  /** When this peer was deleted here, or null. */
  async dismissedAt(peerId: string): Promise<number | null> {
    return (await this.readDismissals())[peerId]?.at ?? null
  }

  /** The deletion record, or null. The send path uses it to decide whether a
   *  re-established session must skip the directory's one-time prekey: that is only
   *  true when a session existed when they were deleted, because only then did the
   *  peer already consume the prekey the directory would serve again. */
  async getDismissal(peerId: string): Promise<{ at: number; hadSession: boolean } | null> {
    const d = (await this.readDismissals())[peerId]
    return d ? { at: d.at, hadSession: d.hadSession } : null
  }

  /** Rewrite the dismissal blob without its expired entries. Filtering happens on
   *  every read, so this changes no behaviour; it is what makes the 30-day bound
   *  true ON DISK rather than only in memory, which is what DESIGN 8.9 claims.
   *  Called on connect alongside the other retention sweeps.
   *
   *  Uses the PROPAGATING read on purpose. This method deletes the blob when nothing
   *  is left, so running it on a fail-open empty result would turn any single failed
   *  open (a lock engaging mid-sweep, say) into the permanent loss of every deletion
   *  marker, and the mutual invite would then re-learn every deleted contact. */
  async pruneDismissals(): Promise<void> {
    await this.lock.withLock(CONTACTS_LOCK, async () => {
      const raw = await this.store.get(DISMISSED_KEY)
      if (raw == null) return
      let kept: Record<string, Dismissal>
      try {
        kept = await this.loadDismissals() // already TTL-filtered
      } catch {
        return // could not read it: leave it exactly as it is
      }
      if (Object.keys(kept).length === 0) await this.store.delete(DISMISSED_KEY)
      else await this.putSealed(DISMISSED_KEY, DISMISSED_KEY, encoder.encode(JSON.stringify(kept)))
    })
  }

  // --- retry-receipt throttling (8.10) ------------------------------------
  //
  // Sealed like every other blob here, because it is a per-peer list: read in
  // cleartext it would say who this device recently could not hear from, and
  // whose recovery it answered.

  /** TTL-filtered read of the whole ledger. Entries older than the envelope TTL
   *  are dropped on sight: past it the relay no longer holds the undelivered
   *  messages that caused the entry, so it can throttle nothing that still exists.
   *  PROPAGATES failures, for the same reason `loadDismissals` does. */
  private async loadRetry(now: number): Promise<Record<string, RetryState>> {
    const bytes = await this.getSealed(RETRY_KEY, RETRY_KEY)
    if (!bytes) return {}
    const m = JSON.parse(decoder.decode(bytes)) as Record<string, RetryState>
    if (!m || typeof m !== 'object') return {}
    const cutoff = now - ENVELOPE_TTL_MS
    const out: Record<string, RetryState> = {}
    for (const [peer, r] of Object.entries(m)) {
      if (!r || typeof r !== 'object') continue
      const askedAt = typeof r.askedAt === 'number' ? r.askedAt : undefined
      const honoredAt = typeof r.honoredAt === 'number' ? r.honoredAt : undefined
      if (Math.max(askedAt ?? 0, honoredAt ?? 0) <= cutoff) continue
      out[peer] = {
        ...(askedAt !== undefined ? { askedAt } : {}),
        ...(honoredAt !== undefined ? { honoredAt } : {}),
        ...(typeof r.attempts === 'number' ? { attempts: r.attempts } : {}),
      }
    }
    return out
  }

  /** One peer's throttling state. Fail-OPEN: an unreadable ledger must not be able
   *  to stop recovery, and the worst it can cost is one extra round trip that the
   *  ANSWERING side bounds anyway. */
  async getRetryState(peerId: string, now = Date.now()): Promise<RetryState> {
    try {
      return (await this.loadRetry(now))[peerId] ?? {}
    } catch {
      return {}
    }
  }

  /** Read-modify-write one peer's throttling state under the contacts lock, so two
   *  inbound envelopes racing each other cannot both decide they are the first ask. */
  async mutateRetryState(peerId: string, fn: (r: RetryState) => void, now = Date.now()): Promise<void> {
    await this.lock.withLock(CONTACTS_LOCK, async () => {
      let readOk = true
      let map: Record<string, RetryState> = {}
      try {
        map = await this.loadRetry(now)
      } catch {
        readOk = false
      }
      const r: RetryState = { ...(map[peerId] ?? {}) }
      fn(r)
      if (r.askedAt === undefined && r.honoredAt === undefined) delete map[peerId]
      else map[peerId] = r
      const rows = Object.entries(map)
        .sort((a, b) => Math.max(b[1].askedAt ?? 0, b[1].honoredAt ?? 0) - Math.max(a[1].askedAt ?? 0, a[1].honoredAt ?? 0))
        .slice(0, MAX_RETRY_LEDGER)
      // Same asymmetry as the dismissal blob: writing over an unreadable ledger
      // loses nothing, but deleting it on the strength of a failed read would throw
      // away throttling state that is simply unreadable right now.
      if (rows.length === 0) {
        if (readOk) await this.store.delete(RETRY_KEY)
      } else {
        await this.putSealed(RETRY_KEY, RETRY_KEY, encoder.encode(JSON.stringify(Object.fromEntries(rows))))
      }
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
      await this.store.delete(DISMISSED_KEY)
      await this.store.delete(RETRY_KEY)
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
      // Likewise the deleted-peer list: it belongs to the identity that made it,
      // and inheriting it would silently gate contacts for a different identity.
      await this.store.delete(DISMISSED_KEY)
      // And the recovery ledger (8.10), which is about sessions this device no
      // longer has: inheriting it would make the restored device believe it had
      // already asked contacts to resend, in the exact situation that needs asking.
      await this.store.delete(RETRY_KEY)
    })
  }

  /** Export-side alias read (Phase D move). PROPAGATES failures where getAliases
   *  fails open: an exporter that read {} from a broken blob would seal a file
   *  asserting "no nicknames" inside an honest-looking success report. */
  async exportAliases(): Promise<Record<string, string>> {
    const bytes = await this.getSealed(ALIASES_KEY, ALIASES_KEY)
    if (!bytes) return {}
    const m = JSON.parse(decoder.decode(bytes)) as Record<string, string>
    return m && typeof m === 'object' ? m : {}
  }

  /** Export-side deletion-marker read (Phase D move). Propagating, TTL-filtered,
   *  and WITHOUT hadSession: that field answers "did THIS device's published
   *  prekeys get consumed", and the importing device's re-registration (fresh
   *  prekeys, fetcher vends cleared server-side) falsifies it by construction. */
  async exportDismissals(): Promise<Record<string, { at: number; auto: boolean }>> {
    const m = await this.loadDismissals()
    const out: Record<string, { at: number; auto: boolean }> = {}
    for (const [peer, d] of Object.entries(m)) out[peer] = { at: d.at, auto: d.auto }
    return out
  }

  /** Replace contacts + nicknames + deletion markers from a move file (Phase D).
   *  ONE method on purpose: replaceAllFromBackup deletes the dismissal blob as
   *  part of its own contract, so separate replace calls would be one call-site
   *  transposition away from silently destroying the markers the move exists to
   *  carry. Every write is a BLIND whole-blob overwrite, never read-modify-write:
   *  a crashed earlier import attempt may have left blobs behind, and a re-run
   *  must converge without being able to read them. */
  async replaceAllForMove(
    contacts: Contact[],
    aliases: Record<string, string>,
    dismissals: Record<string, { at: number; auto: boolean }>,
  ): Promise<void> {
    const map: Record<string, Contact> = {}
    for (const c of contacts) {
      if (deriveUserId(b64decode(c.ikSig, 32)) !== c.peerId) continue
      map[c.peerId] = { ...c }
    }
    await this.lock.withLock(CONTACTS_LOCK, async () => {
      await this.write(map)
      // The prior identity's parked trust work never carries (fresh-device premise).
      await this.store.delete(PENDING_KEY)
      // Nor its recovery ledger: a move is the single most likely reason the new
      // device will need to ask everyone to resend (8.10), so it must start clean.
      await this.store.delete(RETRY_KEY)
      if (Object.keys(aliases).length === 0) {
        await this.store.delete(ALIASES_KEY)
      } else {
        await this.putSealed(ALIASES_KEY, ALIASES_KEY, encoder.encode(JSON.stringify(aliases)))
      }
      const rows = Object.entries(dismissals)
        .map(([peer, d]) => [peer, { at: d.at, auto: d.auto, hadSession: false }] as const)
        .sort((a, b) => b[1].at - a[1].at)
        .slice(0, MAX_DISMISSALS)
      if (rows.length === 0) {
        await this.store.delete(DISMISSED_KEY)
      } else {
        await this.putSealed(DISMISSED_KEY, DISMISSED_KEY, encoder.encode(JSON.stringify(Object.fromEntries(rows))))
      }
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

  /**
   * Withdraw a verification the user no longer stands behind (they verified the
   * wrong person, or a later comparison did not match).
   *
   * Deliberately MANUAL only. Nothing automatic, and in particular nothing driven
   * by a scan, may reach this: the scanned input is attacker-chosen, so an
   * automatic downgrade would hand anyone who can show a camera a QR code a
   * durable way to strip a real verification.
   *
   * Drops to 'unverified' rather than restoring whatever the contact was before.
   * 'invite' asserts that an invite authenticated this direction (6.3), which is a
   * first-contact fact, and re-asserting it here would re-state an authentication
   * the user has just disputed.
   */
  async unverify(peerId: string): Promise<void> {
    await this.mutate((map) => {
      const c = map[peerId]
      if (!c) throw new Error('contacts: unverify an unknown peer')
      c.trust = 'unverified'
      // null, not undefined: the field is `number | null`, and the backup encoder
      // validates it as such (backup.ts), so an undefined would make this contact
      // silently fail validation and be DROPPED on restore.
      c.verifiedAt = null
    })
  }
}
