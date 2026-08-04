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
//      that binding BEFORE any DH, at the DEVICE level, since that is what a
//      session runs between (Sesame); this module re-checks the ACCOUNT one when
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
import { accountIdOf } from '../crypto/identity'
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
/** Known device rosters, per account (Sesame). Sealed like the others: it is a
 *  list of which contacts have how many devices. */
const ROSTERS_KEY = 'contacts.rosters.v1'
/** Account renames (rotation) that are in progress. Sealed with the rest: it is a
 *  list of who this device talks to, in two forms. */
const RENAME_KEY = 'contacts.renames.v1'
/** What each DEVICE said its own account is, recorded only after that claim was
 *  checked against the account's signed device list. Sealed with the rest: it is a
 *  map of who this device talks to and how many machines they read on. */
const DEVICE_CLAIMS_KEY = 'contacts.deviceclaims.v1'
/** Peers owed a session-refresh ping after a move (Phase D, 8.3), drained by the
 *  client once the post-move re-registration succeeds. Durable so a crash between
 *  the move and the first connect cannot lose the list.
 *
 *  It lives HERE, sealed, rather than beside the identity in the raw key store,
 *  because it is a list of contacts: written in the clear it was a plaintext
 *  roster of everyone the new device had just imported, sitting on disk exactly
 *  when a freshly-moved device is most likely to be lost or examined, and lasting
 *  until the drain finished. That contradicted 8.5's promise that nothing stored
 *  names a peer. The key name is unchanged, so `getSealed` adopts and re-seals a
 *  plaintext list left by an older build on its first read. */
const MOVE_REFRESH_KEY = 'move.refresh.v1'
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

/** The last device roster this device accepted for an account (Sesame). */
export interface KnownRoster {
  /** The highest version ever accepted. Never decreases; that is the point. */
  version: number
  /** Device ids only. See the note where these are read for why no keys. */
  devices: string[]
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
    // An ACCOUNT binding (Sesame): a contact record is about a person, so the key
    // it stores is their account key, which is also the key their safety number
    // covers. Devices are bound separately, where a session is opened.
    if (accountIdOf(ikSig) !== peerId) throw new Error('contacts: IK_sig does not match peer id')
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

  // --- known device rosters (Sesame) --------------------------------------
  //
  // What this device has been told about an account's devices, and the highest
  // roster version it has ever accepted for them. The version is the part that
  // matters: the Directory refusing to go backwards only keeps an honest server
  // honest, so the binding rollback defence is that a client never accepts a
  // roster below the highest it has already seen (src/crypto/roster.ts).
  //
  // Only ids are kept, never keys. A device id IS the hash of its key, and the
  // bundle fetch that reaches a device already refuses a key that does not hash
  // to the id asked for, so caching keys here would add a second copy of
  // something already bound and a second thing to keep in step.

  private async loadRosters(): Promise<Record<string, KnownRoster>> {
    const bytes = await this.getSealed(ROSTERS_KEY, ROSTERS_KEY)
    if (!bytes) return {}
    const m = JSON.parse(decoder.decode(bytes)) as Record<string, KnownRoster>
    if (!m || typeof m !== 'object') return {}
    const out: Record<string, KnownRoster> = {}
    for (const [account, r] of Object.entries(m)) {
      if (!r || typeof r.version !== 'number' || !Array.isArray(r.devices)) continue
      if (r.devices.some((d) => typeof d !== 'string')) continue
      out[account] = { version: r.version, devices: [...r.devices] }
    }
    return out
  }

  /** What this device last accepted for `accountId`, or null if it has never seen
   *  a roster for them. Fail-OPEN, like the other consulting reads: an unreadable
   *  blob must not break addressing. The cost is that a rollback could go
   *  unnoticed while the blob is unreadable, which is strictly better than the app
   *  being unable to send at all, and the roster still has to verify. */
  async getKnownRoster(accountId: string): Promise<KnownRoster | null> {
    try {
      return (await this.loadRosters())[accountId] ?? null
    } catch {
      return null
    }
  }

  /** Every roster this device has accepted, for the device-to-account lookup a
   *  receiver needs (Sesame). Fail-OPEN like the single-account read above. */
  async listKnownRosters(): Promise<Record<string, KnownRoster>> {
    try {
      return await this.loadRosters()
    } catch {
      return {}
    }
  }

  /** Record an accepted roster. The caller has already verified the signature and
   *  checked the version against `getKnownRoster`.
   *
   *  The stored version is CLAMPED to the highest ever seen, which is what makes
   *  the field the monotonic mark its type says it is rather than a promise the
   *  callers have to keep. Two ways it was not: the caller's check-then-write
   *  straddles a network round trip, so two overlapping resolves can land out of
   *  order; and the self-account writers store a version the RELAY reported back
   *  from a publish. Neither can now lower the mark. A LOWER version arriving
   *  with a different device list is refused wholesale rather than half-applied,
   *  since a rolled-back list is exactly what the mark exists to catch. */
  async putKnownRoster(accountId: string, roster: KnownRoster): Promise<void> {
    await this.lock.withLock(CONTACTS_LOCK, async () => {
      let readOk = true
      let map: Record<string, KnownRoster> = {}
      try {
        map = await this.loadRosters()
      } catch {
        readOk = false
      }
      const known = map[accountId]
      if (known && roster.version < known.version) return
      map[accountId] = { version: roster.version, devices: [...roster.devices] }
      if (Object.keys(map).length === 0) {
        if (readOk) await this.store.delete(ROSTERS_KEY)
      } else {
        await this.putSealed(ROSTERS_KEY, ROSTERS_KEY, encoder.encode(JSON.stringify(map)))
      }
    })
  }

  // --- post-move refresh list (Phase D, 8.3) ------------------------------

  /** Peers still owed a post-move session-refresh ping, oldest first. Fail-OPEN:
   *  an unreadable list must not wedge the drain, and the cost of losing it is a
   *  refresh ping that the user's own first message would send anyway. */
  async getMoveRefresh(): Promise<string[]> {
    try {
      const bytes = await this.getSealed(MOVE_REFRESH_KEY, MOVE_REFRESH_KEY)
      if (!bytes) return []
      const list = JSON.parse(decoder.decode(bytes)) as unknown
      if (!Array.isArray(list) || list.some((p) => typeof p !== 'string')) return []
      return list as string[]
    } catch {
      return []
    }
  }

  /** Replace the list (a blind overwrite, like the other move-staged blobs), or
   *  delete it when empty. */
  async setMoveRefresh(peerIds: string[]): Promise<void> {
    await this.lock.withLock(CONTACTS_LOCK, async () => {
      if (peerIds.length === 0) await this.store.delete(MOVE_REFRESH_KEY)
      else await this.putSealed(MOVE_REFRESH_KEY, MOVE_REFRESH_KEY, encoder.encode(JSON.stringify(peerIds)))
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
      await this.store.delete(MOVE_REFRESH_KEY)
      await this.store.delete(ROSTERS_KEY)
    })
  }

  /** Replace the whole contact map from a restored backup (P8, DESIGN 8.3).
   *  Restore-only: it runs against a freshly wiped device, so replacing (not
   *  merging) is the correct semantics. Every row is re-checked against the
   *  key<->userId binding here as well, independent of the backup decoder. */
  async replaceAllFromBackup(contacts: Contact[]): Promise<void> {
    const map: Record<string, Contact> = {}
    for (const c of contacts) {
      if (accountIdOf(b64decode(c.ikSig, 32)) !== c.peerId) continue
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
      // An identity backup carries no refresh list; a stale one belongs to whoever
      // was on this device before.
      await this.store.delete(MOVE_REFRESH_KEY)
      // Known device rosters go too, and with them the highest version this device
      // had accepted for each contact. That is an honest cost of restoring rather
      // than an oversight: a device with no memory has nothing to refuse a rollback
      // against, and will accept whatever roster it is served first, exactly as it
      // accepts a contact's key on first contact. It rebuilds as contacts are
      // re-fetched.
      await this.store.delete(ROSTERS_KEY)
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
      if (accountIdOf(b64decode(c.ikSig, 32)) !== c.peerId) continue
      map[c.peerId] = { ...c }
    }
    await this.lock.withLock(CONTACTS_LOCK, async () => {
      await this.write(map)
      // The prior identity's parked trust work never carries (fresh-device premise).
      await this.store.delete(PENDING_KEY)
      // Nor its recovery ledger: a move is the single most likely reason the new
      // device will need to ask everyone to resend (8.10), so it must start clean.
      await this.store.delete(RETRY_KEY)
      // Nor a refresh list from a crashed earlier import; the caller writes the
      // real one immediately after this returns.
      await this.store.delete(MOVE_REFRESH_KEY)
      // Known rosters do not ride a move either. The move file's format is fixed
      // and does not carry them, so a moved device starts with no roster memory and
      // therefore no rollback history, the same as a restored one.
      await this.store.delete(ROSTERS_KEY)
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

  /**
   * Adopt the contacts a link transfer carried (Sesame B1).
   *
   * Every one is recorded as UNVERIFIED, whatever the sending device thought.
   * That is the deliberate difference from `replaceAllForMove`, which keeps
   * verification because a move replaces a device; a link adds one, and a device
   * earns its own verification by a human comparing safety numbers on it. Nothing
   * remote can mark a contact verified here, not even another of your own devices.
   *
   * Blind overwrites, like the move variant, so re-running an interrupted link
   * converges without having to read what a previous attempt left behind.
   */
  async replaceAllForLink(
    contacts: Array<{ peerId: string; ikSig: string }>,
    aliases: Record<string, string>,
  ): Promise<void> {
    const now = Date.now()
    const map: Record<string, Contact> = {}
    for (const c of contacts) {
      try {
        if (accountIdOf(b64decode(c.ikSig, 32)) !== c.peerId) continue
      } catch {
        continue
      }
      map[c.peerId] = { peerId: c.peerId, ikSig: c.ikSig, trust: 'unverified', firstSeen: now, verifiedAt: null }
    }
    await this.lock.withLock(CONTACTS_LOCK, async () => {
      await this.write(map)
      // A freshly linked device has no history of its own for any of these.
      await this.store.delete(PENDING_KEY)
      await this.store.delete(RETRY_KEY)
      await this.store.delete(MOVE_REFRESH_KEY)
      await this.store.delete(DISMISSED_KEY)
      await this.store.delete(ROSTERS_KEY)
      const kept = Object.entries(aliases).filter(([peer]) => map[peer] !== undefined)
      if (kept.length === 0) await this.store.delete(ALIASES_KEY)
      else await this.putSealed(ALIASES_KEY, ALIASES_KEY, encoder.encode(JSON.stringify(Object.fromEntries(kept))))
    })
  }

  /**
   * Move everything filed under one account id to another (account-key rotation).
   *
   * A rotated contact is the SAME PERSON with a new account id, and this is what
   * makes that true of the stored state rather than merely of the protocol: the
   * contact record, the name you gave them, a dismissal, the retry throttle and
   * the device list all move across together. Sessions deliberately do NOT: they
   * are keyed by DEVICE, and a rotation changes the account key, not the devices,
   * so the ratchets keep running untouched. Saved messages are handled separately
   * (they are sealed under per-row keys, so moving them is a batched re-seal).
   *
   * TRUST IS NOT CARRIED. The new binding lands as 'unverified' no matter what
   * the old one was, and the caller must say so out loud. Rotation preserves the
   * relationship; it never preserves the verification, because an attacker
   * holding the old key can sign a rotation exactly as validly as the owner can.
   * Carrying a verified badge across would hand that attacker the badge.
   *
   * Refuses to overwrite: if `newId` is already a contact, this does nothing and
   * returns false, because merging two conversations is a decision for the user
   * rather than something to do silently underneath them.
   */
  async renameAccount(oldId: string, newId: string, newIkSig: string): Promise<boolean> {
    if (oldId === newId) return false
    // The binding, checked here as well as by the caller's signature check: an id
    // IS the hash of its key, so a rename that does not satisfy it is nonsense.
    try {
      if (accountIdOf(b64decode(newIkSig, 32)) !== newId) return false
    } catch {
      return false
    }
    return this.lock.withLock(CONTACTS_LOCK, async () => {
      const map = await this.read()
      const old = map[oldId]
      if (!old || map[newId]) return false
      map[newId] = { peerId: newId, ikSig: newIkSig, trust: 'unverified', firstSeen: old.firstSeen, verifiedAt: null }
      delete map[oldId]
      await this.write(map)

      // The small per-account maps. Each is read, re-keyed and written back only
      // if it actually held something for the old id, so a rotation never
      // rewrites blobs it has no business touching.
      await this.moveKeyed(ALIASES_KEY, oldId, newId)
      await this.moveKeyed(DISMISSED_KEY, oldId, newId)
      await this.moveKeyed(RETRY_KEY, oldId, newId)
      // The device list does NOT move: it belongs to the old account key, which
      // signed it, and the new account has to publish its own. Dropping it also
      // resets the rollback high-water mark, which is correct: the new account's
      // versions start again at 1 and are not comparable with the old ones.
      await this.dropKeyed(ROSTERS_KEY, oldId)
      // A pending post-move refresh still owes this person a ping; it is a list
      // of ids, not a map, so it is rewritten in place.
      await this.renameInList(MOVE_REFRESH_KEY, oldId, newId)
      return true
    })
  }

  /**
   * Renames that have started but not finished, so one that is interrupted can be
   * picked up again rather than leaving a person split across two ids forever.
   *
   * Written BEFORE any row moves and cleared only after the last one, which makes
   * an interruption recoverable in the one direction that matters: a resume can
   * always finish, and re-running a finished step is a no-op because a row that
   * already moved is no longer at the old key.
   */
  async setPendingRename(oldId: string, to: { newId: string; ikSig: string }): Promise<void> {
    await this.lock.withLock(CONTACTS_LOCK, async () => {
      const map = await this.loadPendingRenames()
      map[oldId] = to
      await this.putSealed(RENAME_KEY, RENAME_KEY, encoder.encode(JSON.stringify(map)))
    })
  }

  async clearPendingRename(oldId: string): Promise<void> {
    await this.lock.withLock(CONTACTS_LOCK, async () => {
      const map = await this.loadPendingRenames()
      if (!(oldId in map)) return
      delete map[oldId]
      if (Object.keys(map).length === 0) await this.store.delete(RENAME_KEY)
      else await this.putSealed(RENAME_KEY, RENAME_KEY, encoder.encode(JSON.stringify(map)))
    })
  }

  /** Fail-CLOSED to "none pending": an unreadable blob must not make a caller
   *  believe a rename is outstanding and re-run it against unknown ids. */
  async pendingRenames(): Promise<Record<string, { newId: string; ikSig: string }>> {
    try {
      return await this.loadPendingRenames()
    } catch {
      return {}
    }
  }

  private async loadPendingRenames(): Promise<Record<string, { newId: string; ikSig: string }>> {
    const bytes = await this.getSealed(RENAME_KEY, RENAME_KEY)
    if (!bytes) return {}
    const m = JSON.parse(decoder.decode(bytes)) as Record<string, { newId: string; ikSig: string }>
    const out: Record<string, { newId: string; ikSig: string }> = {}
    for (const [k, v] of Object.entries(m)) {
      if (typeof v?.newId === 'string' && typeof v?.ikSig === 'string') out[k] = { newId: v.newId, ikSig: v.ikSig }
    }
    return out
  }

  // --- what each device says it belongs to (Sesame, corroboration) ---------
  //
  // A device list says "these devices are mine". It is signed, but signing it
  // proves only that the account SAID it: a device id is the hash of a public
  // key, and every key here is public, so any account can name any device. That
  // one-sidedness is what let a hostile contact capture a third party's messages
  // into their own conversation, and worse, silently switch off the victim's own
  // cross-device sync by making their devices resolve to somebody else.
  //
  // So attribution needs BOTH halves: the account claims the device, and the
  // device claims the account. This is the second half. It is recorded only after
  // a device said so over a session that runs on ITS OWN device key, and only
  // after the named account's signed list was checked to contain it, so neither
  // side alone can produce an entry here.

  /** What this device recorded `deviceId` as claiming, or null. */
  async deviceClaim(deviceId: string): Promise<string | null> {
    try {
      const map = await this.loadDeviceClaims()
      return map[deviceId] ?? null
    } catch {
      return null // an unreadable map means no corroboration, never a free pass
    }
  }

  /** Record a device's own statement of which account it belongs to. */
  async recordDeviceClaim(deviceId: string, accountId: string): Promise<void> {
    await this.lock.withLock(CONTACTS_LOCK, async () => {
      const map = await this.loadDeviceClaims().catch(() => ({}) as Record<string, string>)
      if (map[deviceId] === accountId) return
      map[deviceId] = accountId
      await this.putSealed(DEVICE_CLAIMS_KEY, DEVICE_CLAIMS_KEY, encoder.encode(JSON.stringify(map)))
    })
  }

  /** Move every claim that points at `oldId` to `newId` (an account-key rotation).
   *  Without this a rotated contact's devices keep corroborating an id that no
   *  longer exists, so nothing they send is attributable to them again. */
  async repointDeviceClaims(oldId: string, newId: string): Promise<void> {
    await this.lock.withLock(CONTACTS_LOCK, async () => {
      const map = await this.loadDeviceClaims().catch(() => ({}) as Record<string, string>)
      let changed = false
      for (const [deviceId, accountId] of Object.entries(map)) {
        if (accountId !== oldId) continue
        map[deviceId] = newId
        changed = true
      }
      if (changed) await this.putSealed(DEVICE_CLAIMS_KEY, DEVICE_CLAIMS_KEY, encoder.encode(JSON.stringify(map)))
    })
  }

  private async loadDeviceClaims(): Promise<Record<string, string>> {
    const bytes = await this.getSealed(DEVICE_CLAIMS_KEY, DEVICE_CLAIMS_KEY)
    if (!bytes) return {}
    const m = JSON.parse(decoder.decode(bytes)) as Record<string, string>
    const out: Record<string, string> = {}
    for (const [k, v] of Object.entries(m)) if (typeof v === 'string') out[k] = v
    return out
  }

  /** Forget the device list held for one account. Used when that id is retired
   *  (an account-key rotation): a stale self entry would keep answering
   *  "which account does this device belong to" with an id that no longer exists. */
  async forgetKnownRoster(accountId: string): Promise<void> {
    await this.lock.withLock(CONTACTS_LOCK, async () => {
      await this.dropKeyed(ROSTERS_KEY, accountId)
    })
  }

  /** Move one entry of a sealed `Record<string, unknown>` blob to a new key. */
  private async moveKeyed(blobKey: string, oldId: string, newId: string): Promise<void> {
    try {
      const bytes = await this.getSealed(blobKey, blobKey)
      if (!bytes) return
      const map = JSON.parse(decoder.decode(bytes)) as Record<string, unknown>
      if (!(oldId in map)) return
      if (!(newId in map)) map[newId] = map[oldId]
      delete map[oldId]
      await this.putSealed(blobKey, blobKey, encoder.encode(JSON.stringify(map)))
    } catch {
      /* an unreadable side blob must not stop the rename that matters */
    }
  }

  private async dropKeyed(blobKey: string, oldId: string): Promise<void> {
    try {
      const bytes = await this.getSealed(blobKey, blobKey)
      if (!bytes) return
      const map = JSON.parse(decoder.decode(bytes)) as Record<string, unknown>
      if (!(oldId in map)) return
      delete map[oldId]
      if (Object.keys(map).length === 0) await this.store.delete(blobKey)
      else await this.putSealed(blobKey, blobKey, encoder.encode(JSON.stringify(map)))
    } catch {
      /* as above */
    }
  }

  private async renameInList(blobKey: string, oldId: string, newId: string): Promise<void> {
    try {
      const bytes = await this.getSealed(blobKey, blobKey)
      if (!bytes) return
      const list = JSON.parse(decoder.decode(bytes)) as string[]
      if (!Array.isArray(list) || !list.includes(oldId)) return
      const next = [...new Set(list.map((p) => (p === oldId ? newId : p)))]
      await this.putSealed(blobKey, blobKey, encoder.encode(JSON.stringify(next)))
    } catch {
      /* as above */
    }
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
