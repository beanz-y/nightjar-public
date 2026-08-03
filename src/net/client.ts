// Client orchestrator (P4 + P5). Ties the transport, the durable session store,
// the prekey store, the contact/trust store, and the single-writer lock into the
// surface the UI uses: connect, register, mint/redeem an invite, send text, and a
// callback for received text. It realises the send discipline (encrypt once,
// persist the ratchet advance AND the outbox entry atomically, THEN release to
// the socket; ack the relay only after the plaintext is durably consumed).
//
// P5 additions:
//   - Sessions are a per-peer BOOK (docs/SESSION-GLARE.md): a send uses the
//     current session; a first send with no session opens a new initiator session
//     and makes it current.
//   - Inbound results include `dropped` (a permanently-undecryptable envelope the
//     relay should stop redelivering): it is acked like a duplicate.
//   - One-time prekeys auto-replenish when the local stock runs low.

import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { type Identity, deriveUserId } from '../crypto/identity'
import type { PushSubscriptionInfo } from '../platform'
import { decodeMessage, encodeDeleteMessage, encodeRefreshMessage, encodeTextMessage, newMsgId } from '../crypto/message'
import type { HistoryUnitMessage } from '../crypto/historyUnit'
import {
  MAX_DELIVERED_CHECK_IDS,
  MOVE_MAX_MESSAGES,
  OPK_BATCH,
  OPK_REPLENISH_THRESHOLD,
  OPK_VEND_TTL_MS,
  OUTBOX_RETRY_HORIZON_MS,
  SEEN_ID_TTL_MS,
  SPK_ROTATION_MS,
} from '../crypto/constants'
import { OWN_BUNDLE_VERSION, buildOwnBundle, generateOneTimePrekeys, generateSignedPrekey } from '../crypto/prekeys'
import { deserializeRatchet, initRatchetInitiator, ratchetEncrypt, serializeRatchet } from '../crypto/ratchet'
import { x3dhInitiate } from '../crypto/x3dh'
import { type Contact, type ContactStore, type TrustLevel, KeyConflictError } from '../trust/contactStore'
import type { InviteArtifact } from '../trust/inviteArtifact'
import { currentSession, promoteSession, updateSession } from '../session/sessionBook'
import type { DeliveryStatus, HistoryStore } from '../storage/historyStore'
import type { Lock } from '../storage/lock'
import type { PrekeyStore } from '../storage/prekeyStore'
import type { HistoryRecord, OutboxEntry, SessionBook, SessionStore } from '../storage/sessionStore'
import {
  type Envelope,
  type WireEnvelope,
  b64decode,
  b64encode,
  decodeEnvelope,
  encodeInitialHeader,
  encodeMessageHeaderWire,
  encodeOneTimePrekey,
  encodePublishedBundle,
} from '../wire/codec'
import { processInbound } from './inbound'
import { DirectoryClient } from './directoryClient'
import { type AuthedInfo, Transport } from './transport'

const sessionLock = (peerId: string) => `nightjar-session:${peerId}`
const REPLENISH_LOCK = 'nightjar-opk-replenish'

/** An export refusal the UI words for the user (Phase D). The move must not
 *  proceed while sends are queued (they would cross as rows neither device will
 *  ever transmit) or past the message cap (a truncated file is worse than none). */
export class MoveBlockedError extends Error {
  constructor(
    readonly reason: 'outbox' | 'too-large',
    readonly count: number,
  ) {
    super(
      reason === 'outbox'
        ? `move blocked: ${count} message(s) still queued to send`
        : `move blocked: ${count} saved messages exceed the move-file cap`,
    )
    this.name = 'MoveBlockedError'
  }
}

// Reconnect backoff (P8): exponential with jitter, capped. A dropped socket
// self-heals; the UI additionally kicks reconnectNow() on visibility/online.
const RECONNECT_MIN_MS = 1000
const RECONNECT_MAX_MS = 60 * 1000

/** userId = 52-char lowercase base32 (SHA-256(IK_sig)). Used to reject a malformed
 *  joiner id from an untrusted relay before wasting a bundle fetch on it. */
const USER_ID_RE = /^[a-z2-7]{52}$/
/** Throttle the on-reconnect redemption backstop so a flapping socket cannot hammer
 *  the shared Directory (the InvitePanel's active poll calls syncInviteContacts()
 *  directly for immediate freshness while a user watches someone join). */
const REDEMPTION_SYNC_MIN_INTERVAL_MS = 60 * 1000
/** Throttle for the delivery catch-up. It is a whole-history scan, and missing one
 *  round costs nothing: the live report covers everything that happens while
 *  connected, and the next connect picks up the rest. */
const DELIVERED_CHECK_MIN_INTERVAL_MS = 60 * 1000

/** A message as the UI/history layer sees it: keyed by the content msgId (P10b)
 *  for a structured message, or the transport envelope id for a legacy one. The
 *  same id is used for the optimistic bubble, the history row, and (P10d) a
 *  delete target, so a live bubble and its later-hydrated copy share one id. */
export interface ClientMessage {
  id: string
  text: string
  ts: number
  /** Session-only (P10e): shown live but never persisted. */
  ephemeral?: boolean
}

/** A message loaded back from persistent history (P10b): carries its direction
 *  since history holds both sent and received messages. */
export interface StoredMessage {
  id: string
  dir: 'in' | 'out'
  text: string
  ts: number
  /** An outbound message whose delivery permanently failed/timed out; kept so the
   *  reloaded bubble still reads as "not sent", never as delivered. */
  failed?: boolean
  /** How far an outbound message got. Absent means unknown (still queued, or a
   *  marker that never landed), which the UI renders as nothing rather than as an
   *  affirmative claim. */
  status?: DeliveryStatus
}

export interface ClientCallbacks {
  /** A decrypted message arrived from `from`. */
  onMessage: (from: string, msg: ClientMessage) => void
  /** Optional (P10d): `from` deleted-for-everyone the message with content id
   *  `id`. The local history row was already removed atomically; the UI should
   *  drop that bubble. Idempotent (a redelivered delete repeats harmlessly). */
  onDelete?: (from: string, id: string) => void
  /** Optional: an inbound envelope failed to process or was dropped (transient
   *  operational noise; the UI may show it as an overwritable notice). */
  onError?: (detail: string) => void
  /** Optional: a SECURITY event (a key conflict for a known userId, i.e. a
   *  would-be substitution or local corruption). The UI must show these
   *  stickily, never silently overwrite them. */
  onSecurity?: (detail: string) => void
  /** Optional: a queued message (by envelope id) was PERMANENTLY rejected by the
   *  relay and dropped from the outbox. The UI marks that exact message failed so
   *  it never reads as delivered (the envelope id equals the UI message id). */
  onSendFailed?: (envId: string, reason: string) => void
  /** Optional (Phase D): a message from this LIVE contact was permanently
   *  undecryptable and dropped, typically because it was encrypted for a session
   *  that did not ride a move; the honest UI move is "ask them to resend". Only
   *  ever fired for a current, non-deleted contact: a deleted peer's dropped
   *  backlog stays anonymous on purpose (naming them would undo the delete). */
  onUnreadableFrom?: (peerId: string) => void
  /** Optional: how far one of OUR sent messages got, by content id. Only ever
   *  moves forward (sent -> delivered), and both states are the relay's word, not
   *  a signed statement by the peer. A UI hint, never a security property. */
  onDelivery?: (peer: string, id: string, status: DeliveryStatus) => void
  /** Optional: the authenticated connection came up (true) or dropped (false).
   *  Fires on every transition, including automatic reconnects. */
  onConnection?: (connected: boolean) => void
  /** Optional: the contact set changed OUTSIDE a user action (a mutual-invite joiner
   *  was auto-learned, or deferred trust work landed) after the UI's own connect-time
   *  refresh already ran. The UI re-reads listContacts() so the new contact appears
   *  without waiting for the next reconnect. */
  onContactsChanged?: () => void
}

export class NightjarClient {
  readonly transport: Transport
  readonly directory: DirectoryClient
  private authed: AuthedInfo | null = null
  private closed = false
  private connecting = false
  private reconnectAttempt = 0
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  /** Transient send-error codes already surfaced, so a retry loop reports a stuck
   *  queue once rather than on every flush. Cleared when a send gets through. */
  private readonly warnedSendCodes = new Set<string>()
  /** When the mutual-invite redemption sync last ran (throttles the reconnect backstop). */
  private lastRedemptionSyncAt = 0
  /** When the delivery catch-up last ran. It scans and decrypts every stored
   *  message, which is O(all history) on the main thread, and afterConnect runs on
   *  every reconnect (a waking phone re-enters it on visibility and network
   *  events). Throttled for the same reason the redemption sync is. */
  private lastDeliveredCheckAt = 0
  /** Peers whose contact record is being re-fetched right now (see recoverContact),
   *  so a burst of messages from a peer we hold no record for causes ONE directory
   *  fetch rather than one per message. */
  private readonly recoveringContacts = new Set<string>()
  /** Queued-send ids already reported as unreadable, so a stuck row is surfaced once
   *  rather than on every reconnect (mirrors `warnedSendCodes`). */
  private readonly warnedUnreadableOutbox = new Set<string>()
  /** Live contacts already named in an unreadable-message notice this connect
   *  (Phase D), so a redelivering backlog names each sender once, not per drop. */
  private readonly notedUnreadableFrom = new Set<string>()

  constructor(
    private readonly identity: Identity,
    private readonly store: SessionStore,
    private readonly prekeys: PrekeyStore,
    private readonly contacts: ContactStore,
    private readonly lock: Lock,
    private readonly cb: ClientCallbacks,
    /** Persistent history (P10b). When omitted, messages are delivered but not
     *  persisted (tests, self-tests). The real app always supplies one. */
    private readonly history?: HistoryStore,
  ) {
    this.transport = new Transport(identity)
    this.directory = new DirectoryClient(this.transport)
  }

  get userId(): string {
    return this.identity.userId
  }

  get isRegistered(): boolean {
    return this.authed?.registered ?? false
  }

  get opkCount(): number {
    return this.authed?.opkCount ?? 0
  }

  /** The relay's VAPID key for Web Push, or null when push is not configured. */
  get pushKey(): string | null {
    return this.authed?.pushKey ?? null
  }

  /** Re-affirm (or clear) foreground state, so the relay only pushes a nudge when
   *  no device is watching (P6). Best-effort: a dropped presence just means the
   *  next envelope may push; it never affects message delivery. */
  sendPresence(watching: boolean): void {
    try {
      this.transport.raw({ t: 'presence', watching })
    } catch {
      /* not connected; presence is re-sent on reconnect + heartbeat */
    }
  }

  /** Register this device's push subscription with the relay (over the authed
   *  socket, so it is filed against the verified userId). */
  subscribePush(sub: PushSubscriptionInfo): void {
    try {
      this.transport.raw({ t: 'pushSubscribe', endpoint: sub.endpoint, p256dh: sub.p256dh, auth: sub.auth })
    } catch {
      /* not connected; the UI re-subscribes on the next connect */
    }
  }

  /** Drop this device's push subscription from the relay. */
  unsubscribePush(endpoint: string): void {
    try {
      this.transport.raw({ t: 'pushUnsubscribe', endpoint })
    } catch {
      /* not connected; the relay ages the row out via its TTL */
    }
  }

  async connect(): Promise<AuthedInfo> {
    this.transport.onDeliver((from, envJson) => void this.handleDeliver(from, envJson))
    this.transport.onDelivered((id, from) => void this.markDelivery(from, id, 'delivered'))
    this.transport.onSendError((ref, code, msg) => this.handleSendError(ref, code, msg))
    this.transport.onClose(() => {
      this.cb.onConnection?.(false)
      this.scheduleReconnect()
    })
    this.authed = await this.transport.connect()
    await this.afterConnect()
    return this.authed
  }

  /** Post-auth housekeeping, shared by first connect and every reconnect. */
  private async afterConnect(): Promise<void> {
    this.reconnectAttempt = 0
    this.notedUnreadableFrom.clear()
    this.cb.onConnection?.(true)
    await this.flushOutbox()
    // If we came back with a low server-side OPK stock (a run of inbound sessions
    // depleted it while we were away), top it back up.
    if (this.authed?.registered && this.authed.opkCount < OPK_REPLENISH_THRESHOLD) {
      void this.maybeReplenishOpks().catch(() => {})
    }
    // Rotate the signed prekey on cadence (P8): without this, the registration
    // SPK ages past SPK_MAX_AGE_MS and every NEW inbound session fails at the
    // initiator's bundle check. Best-effort; retried on every connect.
    if (this.authed?.registered) {
      void this.maybeRotateSpk().catch(() => {})
    }
    // Age out expired deleted-peer markers on disk, not just on read (8.9).
    void this.contacts.pruneDismissals().catch(() => {})
    // Age out client-side dedup/failure rows (P8). Best-effort maintenance;
    // the replay guard is intentionally never pruned (DESIGN 4.3).
    void this.store.pruneExpired(Date.now()).catch(() => {})
    // Retry trust work that failed transiently on an earlier connect (P8).
    void this.flushPendingTrust().catch(() => {})
    // Learn anyone who redeemed our invites while we were away (mutual invite,
    // DESIGN 6.3), so they can be verified without waiting for a first message.
    // Throttled; best-effort.
    void this.flushInviteRedemptions().catch(() => {})
    // Catch up on messages the peer picked up while we were offline: the live
    // delivery report has no one to reach then, and nothing is queued for it.
    void this.flushDeliveredChecks().catch(() => {})
  }

  /** Land pending trust work: the inviter pin (DESIGN 6.3) and inbound
   *  first-contact records whose original writes failed after their sessions
   *  had already committed. Each item is removed only once it lands (or is
   *  proven conflicting, which is surfaced as a security event). */
  private async flushPendingTrust(): Promise<void> {
    const pending = await this.contacts.getPendingTrust()
    let changed = false
    for (const r of pending.records) {
      try {
        // A refusal here means the user deleted this peer, so dropping the parked
        // record is the intended outcome, not a lost write: if they ever get a
        // message through again, the inbound path records them fresh (an `initial`
        // via handleInitial, a `normal` on a kept session via recoverContact).
        await this.contacts.recordFirstContact(r.peerId, b64decode(r.ikSig, 32), Date.now(), 'unverified', true)
        changed = true
        await this.contacts.mutatePendingTrust((p) => {
          p.records = p.records.filter((x) => x.peerId !== r.peerId)
        })
      } catch (e) {
        if (e instanceof KeyConflictError) {
          this.cb.onSecurity?.(`stored key for ${r.peerId.slice(0, 12)}… conflicts with the one presented earlier; verify safety numbers`)
          await this.contacts.mutatePendingTrust((p) => {
            p.records = p.records.filter((x) => x.peerId !== r.peerId)
          })
        }
        // Other failures: keep the record; retried next connect.
      }
    }
    if (pending.inviterPin) {
      try {
        // The RETRY of a parked pin is relay-driven, unlike the join that parked it:
        // without this it would re-add a deleted inviter at 'invite' trust and clear
        // the marker, which is the exact resurrection the choke point exists to stop.
        await this.addInviteContact(pending.inviterPin, true)
        changed = true
        await this.contacts.mutatePendingTrust((p) => {
          delete p.inviterPin
        })
      } catch {
        // Keep it; retried next connect.
      }
    }
    // Surface any landed record/pin now: flushPendingTrust runs AFTER onConnection
    // already triggered the UI's connect-time contact refresh, so without this the
    // pinned inviter / recovered contact would not appear until the next reconnect.
    if (changed) this.cb.onContactsChanged?.()
  }

  /** On-reconnect backstop for the mutual-invite sync, throttled so a flapping
   *  socket cannot repeatedly poll the shared Directory. The InvitePanel calls
   *  syncInviteContacts() directly (unthrottled) while a user actively watches a
   *  join, so responsiveness there does not depend on this interval. */
  private async flushInviteRedemptions(): Promise<void> {
    if (!this.authed?.registered) return
    if (Date.now() - this.lastRedemptionSyncAt < REDEMPTION_SYNC_MIN_INTERVAL_MS) return
    await this.syncInviteContacts()
  }

  /** Learn everyone who redeemed our invites and record each unknown joiner as a
   *  TOFU ('unverified') contact (mutual invite, DESIGN 6.3), so the inviter can
   *  verify them WITHOUT waiting for a first message. Returns the count of newly
   *  recorded contacts (the InvitePanel uses it to confirm a join landed).
   *
   *  The joiner id comes from the relay's redemption report (`used_by`), a relay
   *  ASSERTION with no cryptographic binding to the intended invitee: a lying or
   *  compelled relay could name an attacker-controlled id (or the real bearer of a
   *  passed-on code), caught only by the out-of-band safety number. So these land at
   *  'unverified' exactly like any TOFU contact (addContact's default), never at
   *  'invite'. Idempotent, never rejects; a conflicting key surfaces via onSecurity
   *  like every other trust path, everything else is retried on the next connect. */
  async syncInviteContacts(): Promise<number> {
    if (!this.authed?.registered) return 0
    this.lastRedemptionSyncAt = Date.now()
    let added = 0
    try {
      const joiners = await this.directory.inviteRedemptions()
      const known = new Set((await this.contacts.list()).map((c) => c.peerId))
      for (const joiner of new Set(joiners)) {
        if (joiner === this.userId || known.has(joiner) || !USER_ID_RE.test(joiner)) continue
        // Cheap pre-check purely to avoid work: the authoritative refusal is inside
        // recordFirstContact (a check here alone would be a TOCTOU across the fetch
        // below). Without it we would fetch a deleted peer's bundle on every connect
        // for 30 days, vending and wasting one of THEIR one-time prekeys each time.
        if ((await this.contacts.dismissedAt(joiner)) !== null) continue
        try {
          const recorded = await this.addContact(joiner, true) // refused for a deleted peer
          known.add(joiner)
          if (recorded) added++
        } catch (e) {
          if (e instanceof KeyConflictError) {
            this.cb.onSecurity?.(
              `stored key for ${joiner.slice(0, 12)}… conflicts with the one presented earlier; verify safety numbers`,
            )
          }
          // else transient (relay unreachable, bundle not yet propagated): retried next connect.
        }
      }
    } catch {
      // Directory unreachable or contacts unavailable: best-effort, retried next connect.
    }
    if (added > 0) this.cb.onContactsChanged?.()
    return added
  }

  private scheduleReconnect(): void {
    if (this.closed || this.reconnectTimer) return
    const backoff = Math.min(RECONNECT_MAX_MS, RECONNECT_MIN_MS * 2 ** this.reconnectAttempt)
    const delay = backoff * (0.5 + Math.random() * 0.5) // jitter: [0.5x, 1x]
    this.reconnectAttempt += 1
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null
      void this.tryReconnect()
    }, delay)
  }

  private async tryReconnect(): Promise<void> {
    if (this.closed || this.transport.isOpen || this.connecting) return
    this.connecting = true
    try {
      this.authed = await this.transport.connect()
      await this.afterConnect()
    } catch {
      this.scheduleReconnect()
    } finally {
      this.connecting = false
    }
  }

  /** Kick an immediate reconnect attempt (page became visible, network came
   *  back). No-op while closed or already connected. */
  reconnectNow(): void {
    if (this.closed || this.transport.isOpen) return
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    this.reconnectAttempt = 0
    void this.tryReconnect()
  }

  close(): void {
    this.closed = true
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    this.transport.close()
  }

  // A send error naming a specific envelope (ref). Permanent rejections drop
  // the outbox entry (it would fail identically on every future flush) and are
  // surfaced; transient ones (queue_full, a not-registered race) stay queued.
  private handleSendError(ref: string, code: string, msg: string): void {
    const permanent = code === 'bad_to' || code === 'bad_envelope' || code === 'too_large'
    if (!permanent) {
      // A transient rejection keeps the entry queued and retries, which is right,
      // but retrying in total silence is the worst failure mode in the system: a
      // full recipient inbox (queue_full, which is shared across ALL senders) can
      // swallow every message to that peer for the whole 7-day retry horizon while
      // the sender sees nothing wrong. Say so once per code, without touching the
      // outbox: the message really is still pending, so it must not read as failed.
      if (!this.warnedSendCodes.has(code)) {
        this.warnedSendCodes.add(code)
        if (code === 'queue_full') {
          this.cb.onError?.(
            "their inbox is full, so messages are not getting through right now. Yours are still queued and will retry, but they may not arrive until their device catches up.",
          )
        } else {
          this.cb.onError?.(`the relay is refusing messages for now (${code}): still queued, will retry`)
        }
      }
      return
    }
    this.warnedSendCodes.delete(code)
    // Flag the persisted outbound row failed BEFORE dropping the outbox entry, so
    // a reload re-renders it as "not sent" rather than as delivered. The row is
    // keyed by (peer, out, contentId); the peer comes from the outbox entry (both
    // keyed by ref == contentId). Best-effort: the live onSendFailed already flags
    // the in-RAM bubble regardless.
    void (async () => {
      try {
        if (this.history) {
          const entry = (await this.store.pendingOutbox()).entries.find((e) => e.id === ref)
          if (entry) await this.store.historyMarkFailed(this.history.storageKey(entry.to, 'out', ref))
        }
      } catch {
        /* best-effort */
      }
      await this.store.removeOutbox(ref).catch(() => {})
    })()
    // Mark the exact message failed (envelope id == UI message id) so it never
    // reads as delivered; onError is only a fallback if the UI does not correlate.
    this.cb.onSendFailed?.(ref, `${code}: ${msg}`)
    this.cb.onError?.(`a message could not be delivered (${code}): ${msg}`)
  }

  /** Register this identity behind a single-use invite, publishing a fresh
   *  prekey bundle and persisting the private prekeys for later responding.
   *  Serialized on the replenish lock so a registration can never interleave
   *  its prekey writes/publish with rotation or OPK replenishment. */
  async register(inviteCode: string): Promise<number> {
    return this.lock.withLock(REPLENISH_LOCK, () => this.registerUnderLock(inviteCode))
  }

  private async registerUnderLock(inviteCode: string): Promise<number> {
    const now = Date.now()
    const own = buildOwnBundle(this.identity, now, { spkId: 1, opkStartId: 1, opkCount: OPK_BATCH })
    await this.prekeys.setFromRegistration({
      spk: { id: own.spk.id, createdAt: own.spk.createdAt, expiry: own.spk.expiry, pub: own.spk.pub, sig: own.spk.sig },
      spkPrivById: own.spkPrivById,
      opks: own.opks,
      opkPrivById: own.opkPrivById,
    })
    const bundle = encodePublishedBundle({
      version: OWN_BUNDLE_VERSION,
      ikSigPub: own.ikSigPub,
      ikDhPub: own.ikDhPub,
      idkbindSig: own.idkbindSig,
      spk: own.spk,
      opks: own.opks,
    })
    const opkCount = await this.directory.register(inviteCode, bundle)
    // Only after the Directory acknowledged: the full set is now served, so the
    // registration is confirmed (and this SPK id marked published).
    await this.prekeys.confirmRegistration(own.spk.id).catch(() => {})
    if (this.authed) this.authed = { ...this.authed, registered: true, opkCount }
    return opkCount
  }

  /** Re-publish everything from scratch for an ALREADY-REGISTERED identity (a
   *  restore, or a self-heal when local prekeys are missing): a fresh SPK + OPK
   *  batch, with the Directory's re-registration branch hard-invalidating every
   *  previously published prekey and outstanding vend (DESIGN 8.3). Consumes no
   *  invite: the server ignores the code for a known identity. */
  async reregister(): Promise<number> {
    return this.register('')
  }

  /** Onboarding (DESIGN 6.3): register behind the invite code, then pin the
   *  inviter from the shared artifact (if it carried one). Registration
   *  consumed the single-use invite, so a transient pin failure must not lose
   *  the inviter identity: it is persisted and retried on every connect. */
  async joinWithInvite(artifact: InviteArtifact): Promise<void> {
    await this.register(artifact.code)
    if (artifact.inviter && artifact.inviter !== this.userId) {
      try {
        await this.addInviteContact(artifact.inviter)
      } catch {
        const inviter = artifact.inviter
        await this.contacts.mutatePendingTrust((p) => {
          p.inviterPin = inviter
        }).catch(() => {})
      }
    }
  }

  async mintInvite(): Promise<{ code: string; inviterFingerprint: string }> {
    return this.directory.mintInvite()
  }

  /** Pin the inviter as an invite-trusted contact (DESIGN 6.3). Fetches the
   *  inviter's bundle, checks the key<->userId binding, and records them at
   *  'invite' trust (inviter -> joiner authentication). */
  async addInviteContact(inviterUserId: string, relayDriven = false): Promise<void> {
    const { bundle } = await this.directory.fetchBundle(inviterUserId)
    if (!bundle) throw new Error(`inviter ${inviterUserId} is not registered`)
    if (deriveUserId(bundle.ikSigPub) !== inviterUserId) throw new Error('inviter key does not match its id')
    await this.contacts.recordFirstContact(inviterUserId, bundle.ikSigPub, Date.now(), 'invite', relayDriven)
  }

  /** Add a contact by userId (TOFU): fetch their bundle, enforce the key<->userId
   *  binding, and record them at 'unverified' so a safety number can be shown and
   *  verified immediately - WITHOUT having to exchange a message first (the fix for
   *  "verify does nothing after I add someone by their code/QR"). Idempotent and
   *  never downgrades an existing invite/verified contact (recordFirstContact only
   *  upgrades trust). Throws if the peer is not registered. */
  async addContact(peerId: string, relayDriven = false): Promise<boolean> {
    const { bundle } = await this.directory.fetchBundle(peerId)
    if (!bundle) throw new Error(`${peerId} is not registered`)
    if (deriveUserId(bundle.ikSigPub) !== peerId) throw new Error(`directory served a key that does not match ${peerId}`)
    // `relayDriven` marks the mutual-invite sync, which the contact store refuses
    // for a peer the user deleted. A user-initiated add lifts that block instead.
    // Returns whether a record now exists, so the caller does not report adding
    // someone it was refused.
    return this.contacts.recordFirstContact(peerId, bundle.ikSigPub, Date.now(), 'unverified', relayDriven)
  }

  /** The trust level held for a peer (DESIGN 6), or null if unknown. */
  async trustOf(peerId: string): Promise<TrustLevel | null> {
    return this.contacts.trustLevel(peerId)
  }

  /** All known contacts, for the contact list + trust badges. */
  async listContacts(): Promise<Contact[]> {
    return this.contacts.list()
  }

  /** Local per-device chat nicknames (cosmetic; see ContactStore). */
  async listAliases(): Promise<Record<string, string>> {
    return this.contacts.getAliases()
  }

  /** Set or clear a peer's local nickname. */
  async setAlias(peerId: string, name: string): Promise<void> {
    return this.contacts.setAlias(peerId, name)
  }

  /** Record that the out-of-band safety-number check passed for a peer (6.2). */
  async markVerified(peerId: string): Promise<void> {
    return this.contacts.markVerified(peerId, Date.now())
  }

  /** Withdraw a verification (user-initiated only, never automatic; see
   *  ContactStore.unverify). The contact and its key are kept. */
  async unverify(peerId: string): Promise<void> {
    return this.contacts.unverify(peerId)
  }

  /**
   * Send text to a peer. Uses the current session, or opens a new one (X3DH) if
   * none exists. Runs under the per-peer lock. Returns the CONTENT msgId (hex),
   * which the caller uses as its UI message id.
   *
   * Two ids (P10b, DESIGN two-id rule): a 16-byte CONTENT msgId lives inside the
   * ratchet plaintext (the NJM1 record) and is the history key + future delete
   * target; the TRANSPORT envelope id is what the relay dedups/acks/outboxes on.
   * For a first-send TEXT message the content id is brand-new, so it is SAFE to
   * use it as the transport id too (no existing envelope to clobber, no delete
   * reusing an existing id) - and doing so keeps one stable id across the
   * optimistic bubble, the outbox, the history row, and a later send-failure
   * `ref`, which survives a reload (a fresh-UUID transport id would not map back
   * to the hydrated content-keyed bubble). A DELETE control (P10d) will instead
   * get its OWN fresh transport id, since it targets an EXISTING content id.
   *
   * `msgId`, if given, is that content id (the UI pre-generated it for the
   * optimistic bubble); otherwise a fresh one is minted. `uiTs`, if given, is the
   * timestamp the optimistic bubble was stamped with, so the persisted history row
   * carries the SAME ts and a reload cannot reorder this message relative to an
   * interleaved inbound one (whose live and stored ts already match).
   */
  async sendText(to: string, text: string, msgId?: string, uiTs?: number, ephemeral = false): Promise<string> {
    const contentIdHex = msgId ?? bytesToHex(newMsgId())
    // The ratchet plaintext is the structured NJM1 record (not raw utf8): it carries
    // the content id + kind + the ephemeral flag both sides need. A session-only
    // (ephemeral, P10e) message is authenticated with flags bit0 set and is NEVER
    // sealed into history on either device. It is otherwise delivered EXACTLY like a
    // normal message (same outbox + ack + retransmit): the only difference is the
    // skipped history seal. That is deliberate - a session-ESTABLISHING initial must
    // be delivered reliably, or a single lost frame would orphan the session and
    // break ALL future traffic (including non-ephemeral) to this peer.
    const plaintext = encodeTextMessage(hexToBytes(contentIdHex), text, ephemeral)
    const entry = await this.lock.withLock(sessionLock(to), async () => {
      const now = Date.now()
      const ts = uiTs ?? now
      const book = await this.store.loadBook(to)
      const current = currentSession(book)
      // Seal the sent message for history - UNLESS it is ephemeral (never persisted,
      // send OR receive) or history is not wired. Done inside the lock, before the
      // commit, so a seal failure aborts the send with nothing queued; the row rides
      // the same tx as the ratchet advance + outbox (commit before release), stamped
      // with the UI ts so live and hydrated ordering agree.
      const historyRow =
        !ephemeral && this.history ? this.history.seal({ id: contentIdHex, peerId: to, dir: 'out', ts, text }) : undefined

      if (current) {
        // Established (or pending) session: a normal ratchet message. `now` as
        // legacyTs stamps any pre-P8 skipped entries so the re-serialized
        // snapshot below cannot mark them instantly expired.
        const { state, header, ciphertext } = ratchetEncrypt(deserializeRatchet(current.snapshot, now), plaintext)
        const env: WireEnvelope = {
          id: contentIdHex,
          kind: 'normal',
          header: encodeMessageHeaderWire(header),
          ciphertext: b64encode(ciphertext),
        }
        const advanced = updateSession(book!, current.id, serializeRatchet(state), now)
        const e: OutboxEntry = { id: contentIdHex, to, env, createdAt: now }
        await this.store.saveBookWithOutbox(to, advanced, e, historyRow) // commit before release
        return e
      }

      // No session: open a fresh initiator session carrying this text (shared
      // helper; the transport id equals the content id for a first-send text,
      // per the two-id rule's one safe case).
      return this.openInitiatorEntry(to, plaintext, contentIdHex, {
        book,
        now,
        ...(historyRow ? { historyRow } : {}),
      })
    })
    this.fire(entry)
    return entry.id
  }

  /** Open a fresh initiator session to `to` and commit `plaintext` as its first
   *  message: bundle fetch, key<->userId binding check, trust assessment and
   *  first-contact recording, the deleted-peer prekey strip, X3DH, and the atomic
   *  session+outbox(+history) commit. Shared by a first-contact text, the
   *  post-move session-refresh ping, and a delete control sent where no session
   *  survives (Phase D). The CALLER holds the per-peer session lock. */
  private async openInitiatorEntry(
    to: string,
    plaintext: Uint8Array,
    transportId: string,
    opts: { book: SessionBook | null; now: number; historyRow?: HistoryRecord; silent?: boolean },
  ): Promise<OutboxEntry> {
    const { book, now } = opts
    const { bundle } = await this.directory.fetchBundle(to)
    if (!bundle) throw new Error(`peer ${to} is not registered`)
    // The fetched IK_sig MUST hash to the userId we asked for. Because a userId
    // IS SHA-256(IK_sig) (DESIGN 3), this catches a directory that served a
    // substituted key for this contact (the cheap key-swap of 6.1) before any
    // DH, without needing the out-of-band check. The safety number still covers
    // the complementary case (a wrong userId handed to us at all).
    if (deriveUserId(bundle.ikSigPub) !== to) {
      throw new Error(`directory served a key that does not match ${to}`)
    }
    // Fail closed if we already hold a DIFFERENT key for this userId (collision
    // or local corruption); else record on first contact below.
    const a = await this.contacts.assess(to, bundle.ikSigPub)
    if (a.outcome === 'conflict') throw new KeyConflictError(to)

    // Record the contact BEFORE committing the session. A later send to an
    // established peer takes the current-session branch and never touches
    // the contact store, so if this record were only best-effort AFTER the commit,
    // a single contacts-store hiccup would leave a durable session with no contact
    // record: the peer would be unverifiable forever (no stored IK_sig -> no safety
    // number, the priority-1 control). Recording first means a failure aborts this
    // first-contact send with nothing queued to lose. (Contact/trust is not message
    // content, so it is recorded even for an ephemeral first message.)
    if (a.outcome === 'first-contact') {
      await this.contacts.recordFirstContact(to, bundle.ikSigPub, now)
    }

    // Re-establishing with someone whose session we USED to hold, and deleted
    // recently, must NOT use the directory's one-time prekey. The vend is
    // idempotent per (fetcher, target) for OPK_VEND_TTL_MS, so a re-fetch inside
    // that window hands back the SAME OPK, whose private half the peer consumed
    // when the first session was set up. They would fail to respond, our initial
    // would be poison-dropped after its retries, and the conversation would be
    // silently dead while our own UI showed it delivered. The no-OPK path is the
    // documented degraded mode (DESIGN 4.3) and always opens, because the peer
    // keeps its signed-prekey private half through the retire grace period.
    //
    // `hadSession` is load-bearing, not belt-and-braces. Deleting a conversation
    // KEEPS the session (8.9), so reaching this branch at all means the session
    // was lost some other way. A peer deleted before any session existed consumed
    // NOTHING, and stripping their prekey would downgrade a perfectly healthy
    // handshake to the degraded path for no reason. (After a MOVE, re-registration
    // also cleared this user's fetcher-side vends at the Directory, so a re-fetch
    // there vends fresh; imported markers carry hadSession=false for the same
    // reason and never reach this strip.)
    let usable = bundle
    try {
      const dismissal = await this.contacts.getDismissal(to)
      if (dismissal?.hadSession && now - dismissal.at < OPK_VEND_TTL_MS && bundle.opk) {
        usable = { ...bundle, opk: null }
      }
    } catch {
      /* best-effort: on doubt, use the bundle as served */
    }
    const ini = x3dhInitiate(this.identity, usable, now)
    const state0 = initRatchetInitiator(ini.sk, ini.ad, usable.spk.pub)
    const { state, header, ciphertext } = ratchetEncrypt(state0, plaintext)
    const env: WireEnvelope = {
      id: transportId,
      kind: 'initial',
      header: encodeMessageHeaderWire(header),
      ciphertext: b64encode(ciphertext),
      initialHeader: encodeInitialHeader(ini.header),
    }
    const promoted = promoteSession(book, serializeRatchet(state), now)
    const e: OutboxEntry = { id: transportId, to, env, createdAt: now, ...(opts.silent ? { silent: true } : {}) }
    await this.store.saveBookWithOutbox(to, promoted, e, opts.historyRow)
    return e
  }

  /** Send the post-move session-refresh ping to `peer` (Phase D, DESIGN 8.3): a
   *  fresh X3DH initial carrying a record every receiver, old build or new,
   *  renders and persists as NOTHING (an unknown NJM1 kind). Its entire value is
   *  that receiving it promotes a live session, so the peer's NEXT send stops
   *  riding the dead pre-move session this device could never decrypt (which
   *  would be poison-dropped while the relay told them "delivered"). Silent: no
   *  push nudge, nothing user-visible arrives. A peer with a live session is
   *  skipped (the user's own first message already refreshed it). Throws on
   *  failure; the drain loop classifies permanent vs retryable. */
  async sendSessionRefresh(peer: string): Promise<void> {
    const entry = await this.lock.withLock(sessionLock(peer), async () => {
      const now = Date.now()
      const book = await this.store.loadBook(peer)
      if (currentSession(book)) return null
      const transportId = bytesToHex(newMsgId())
      return this.openInitiatorEntry(peer, encodeRefreshMessage(newMsgId()), transportId, { book, now, silent: true })
    })
    if (entry) this.fire(entry)
  }

  /**
   * Record how far one of our outbound messages got, and tell the UI.
   *
   * Monotonic: 'sent' never overwrites 'delivered', so an out-of-order report (a
   * reconnect catch-up racing a live report, or a retransmit re-resolving
   * waitSent) cannot walk a message backwards.
   *
   * The status is sealed INSIDE the row rather than kept beside it, so a device
   * image learns nothing about which rows are outbound or how many reached the
   * peer (DESIGN 8.5). That costs a re-seal, which runs under the per-peer lock so
   * a row keeps exactly one writer, and draws a fresh salt so there is no
   * keystream reuse. Best-effort throughout: a delivery indicator must never
   * affect message handling.
   */
  private async markDelivery(peer: string, id: string, status: DeliveryStatus): Promise<void> {
    if (!this.history) return
    try {
      const changed = await this.lock.withLock(sessionLock(peer), async () => {
        const key = this.history!.storageKey(peer, 'out', id)
        const row = await this.store.historyGet(key)
        if (!row) return false // ephemeral, deleted, or a control envelope
        const msg = this.history!.open(row)
        if (msg.status === status || msg.status === 'delivered') return false
        const resealed = this.history!.seal({ ...msg, status }, row.failed)
        await this.store.historyUpdate(resealed)
        return true
      })
      if (changed) this.cb.onDelivery?.(peer, id, status)
    } catch {
      /* best-effort: never let a status update disturb messaging */
    }
  }

  /**
   * Catch up on deliveries that happened while this device was offline.
   *
   * The live report (`delivered`) is fire-and-forget, so it reaches nobody when
   * the sender is away, which for a phone is the common case. Rather than have the
   * relay keep a delivery log for us (DESIGN 7.5 says it keeps none), we ask, on
   * reconnect, which of our own recent unconfirmed envelope ids the peer's inbox
   * has recorded as consumed. Bounded, and only ever about ids we generated.
   *
   * Never downgrades: an id the relay does not report stays 'sent', because the
   * relay's seen-id set has its own retention and absence is not evidence.
   */
  private async flushDeliveredChecks(): Promise<void> {
    if (!this.history) return
    const now = Date.now()
    if (now - this.lastDeliveredCheckAt < DELIVERED_CHECK_MIN_INTERVAL_MS) return
    this.lastDeliveredCheckAt = now
    const rows = await this.store.historyLoadAll()
    const cutoff = now - SEEN_ID_TTL_MS
    // Collect candidates with their timestamps FIRST, then take the newest per
    // peer. Truncating during the scan would keep whichever ids happened to come
    // first out of `getAll()`, and the history key is an opaque HMAC, so that order
    // is uncorrelated with time: past the cap, a fixed arbitrary subset would be
    // asked about on every single connect and the rest could never be confirmed.
    // This is the same trap the outbox flush had, so it gets the same answer.
    const byPeer = new Map<string, Array<{ id: string; ts: number }>>()
    for (const row of rows) {
      if (row.failed) continue
      let msg
      try {
        msg = this.history.open(row)
      } catch {
        continue
      }
      if (msg.dir !== 'out' || msg.status !== 'sent') continue
      // The relay's seen-id set is pruned on its own TTL, so an older message
      // would answer "not delivered" forever. Do not ask about those at all.
      if (msg.ts < cutoff) continue
      const list = byPeer.get(msg.peerId) ?? []
      list.push({ id: msg.id, ts: msg.ts })
      byPeer.set(msg.peerId, list)
    }
    for (const [peer, candidates] of byPeer) {
      if (candidates.length === 0) continue
      const ids = candidates
        .sort((a, b) => b.ts - a.ts) // newest first
        .slice(0, MAX_DELIVERED_CHECK_IDS)
        .map((c) => c.id)
      try {
        const delivered = await this.directory.deliveredCheck(peer, ids)
        for (const id of delivered) await this.markDelivery(peer, id, 'delivered')
      } catch {
        /* best-effort */
      }
    }
  }

  /**
   * Remove the saved messages for one peer, keeping the contact, its verification
   * and the live session. "Clear this chat", not "delete this person".
   *
   * Returns how many rows could not be opened (and so could not be identified or
   * removed). Reported rather than swallowed: an unopenable row is one the caller
   * must not claim to have deleted.
   */
  async clearMessages(peer: string): Promise<{ removed: number; unreadable: number }> {
    return this.lock.withLock(sessionLock(peer), () => this.sweepHistory(peer))
  }

  /**
   * Delete what this device holds for one peer: saved messages, the contact record
   * and its verification, the nickname, and any queued sends.
   *
   * It deliberately KEEPS the ratchet session, so the peer can still reach you.
   * Destroying it black-holes them: their app keeps sending on the session it still
   * holds, those messages arrive on a device with no session, fail to decrypt, and
   * are acked-and-dropped, which the relay reports back to them as DELIVERED. Both
   * sides are then lied to. Someone who deleted a chat to tidy up silently stops
   * receiving that person for good, with nothing on screen to say so, while the
   * sender watches every message turn to a delivered tick. A delete is a filing
   * decision, and it must not quietly become a one-way mute nobody can see.
   *
   * It is not a substitute for blocking either, and must never read as one: this
   * removes what is YOURS and leaves the channel they can reach you on. Nightjar
   * has no block yet, and that is the honest gap, not something a delete can fake.
   *
   * The at-rest cost is small and is disclosed rather than hidden: the session names
   * this peer on the device. That store already names EVERY contact in cleartext, so
   * removing one row moved nothing from unreadable to readable. Keying it opaquely
   * (as history already is) is the real fix and is its own piece of work.
   *
   * Ordering is chosen for crash recoverability, since inbound cannot interleave
   * anyway (the whole thing runs under the per-peer lock that processInbound and
   * sendText also take). Messages go FIRST and the contact goes LAST, so a failure
   * part-way leaves the conversation still visible and the operation repeatable,
   * rather than an orphaned thread the UI can no longer offer to delete.
   *
   * What this cannot do, and what the UI must therefore not claim: it does not
   * block them (Nightjar has no block, and their next message reopens the chat as a
   * fresh unverified contact), it does not touch their copy, and it cannot recall
   * anything already handed to the relay.
   */
  async deleteConversation(peer: string): Promise<{ removed: number; unreadable: number; cancelled: number }> {
    return this.lock.withLock(sessionLock(peer), async () => {
      // 1. Saved messages. The only enumerator is a full scan plus a decrypt per
      //    row, because history keys are opaque by design.
      const swept = await this.sweepHistory(peer)
      // 2. Queued sends to this peer, so nothing further goes out to them. An
      //    envelope already handed to the socket is gone; we cannot recall it, and
      //    the caller's wording must not pretend otherwise. Counted because
      //    "what was still queued is gone" is something to be told, not inferred.
      let cancelled = 0
      // Only rows that OPEN can be attributed to this peer. An unreadable one names
      // nobody, so it is neither cancelled nor counted here, exactly as an
      // unopenable history row is not counted as deleted.
      for (const e of (await this.store.pendingOutbox()).entries) {
        if (e.to === peer) {
          await this.store.removeOutbox(e.id).catch(() => {})
          cancelled++
        }
      }
      // 3. Mark the peer deleted BEFORE the contact write, so an interruption still
      //    leaves the marker that keeps the relay-driven paths from re-adding them.
      //    Idempotent, and `remove` below preserves what this records.
      //
      //    `hadSession` is captured HERE, while the book is still readable, because
      //    it is the only honest basis for the stale-prekey judgement on a later
      //    re-establishment: a peer deleted before any session existed never
      //    consumed a one-time prekey (see the send path).
      const hadSession = ((await this.store.loadBook(peer))?.sessions.length ?? 0) > 0
      await this.contacts.markDismissed(peer, Date.now(), hadSession)
      // 4. The ratchet session book is INTENTIONALLY LEFT ALONE (see the doc above):
      //    it is what lets this peer keep reaching you, and its removal is what would
      //    silently destroy their messages while telling them they had arrived.
      // 5. Contact, nickname, parked trust work.
      await this.contacts.remove(peer, Date.now())
      return { ...swept, cancelled }
    })
  }

  /** Remove every history row belonging to `peer`. Caller holds the per-peer lock,
   *  which is what makes the scan's snapshot authoritative: without it, a message
   *  committing mid-scan would survive and re-hydrate the "deleted" conversation. */
  private async sweepHistory(peer: string): Promise<{ removed: number; unreadable: number }> {
    if (!this.history) return { removed: 0, unreadable: 0 }
    const rows = await this.store.historyLoadAll()
    let removed = 0
    let unreadable = 0
    for (const row of rows) {
      let msg
      try {
        msg = this.history.open(row)
      } catch (e) {
        // A row that cannot be opened is normally corruption, and is counted so the
        // caller never claims to have deleted it. But the SAME throw happens when
        // the idle app-lock fires mid-sweep and discards the key: every remaining
        // row would then "fail to open", the sweep would report a tidy count, and
        // the caller would go on to destroy the session and the outbox having
        // deleted almost nothing. Fail the whole operation instead, so the user is
        // told and can retry with the conversation still intact.
        if (!this.history.isUnlocked) {
          throw new Error('the app locked while deleting; nothing further was removed, try again')
        }
        unreadable++
        continue
      }
      if (msg.peerId !== peer) continue
      await this.store.historyRemove(row.key)
      removed++
    }
    return { removed, unreadable }
  }

  /** All persisted conversations, decrypted and grouped by peer, each sorted
   *  oldest-first (P10b boot hydration). Rows that do not authenticate under the
   *  current key are skipped rather than throwing, so one corrupt row cannot block
   *  loading the rest. */
  async loadAllHistory(): Promise<Record<string, StoredMessage[]>> {
    if (!this.history) return {}
    const rows = await this.store.historyLoadAll()
    // Defence-in-depth (P10d): the atomic delete commit removes a row and writes
    // its tombstone together, so a row and a tombstone for it should never coexist;
    // if a crash ever left one behind, drop it here rather than resurrect a deleted
    // message on reload.
    const tombstoned = new Set(await this.store.tombstoneKeys())
    const out: Record<string, StoredMessage[]> = {}
    for (const row of rows) {
      if (tombstoned.has(row.key)) continue
      try {
        const m = this.history.open(row)
        const msg: StoredMessage = { id: m.id, dir: m.dir, text: m.text, ts: m.ts }
        if (row.failed) msg.failed = true
        if (m.status) msg.status = m.status
        ;(out[m.peerId] ??= []).push(msg)
      } catch {
        /* unreadable record (corruption / wrong key): skip it */
      }
    }
    for (const peer of Object.keys(out)) out[peer].sort((a, b) => a.ts - b.ts)
    return out
  }

  /** Remove one persisted message (P10d delete / P10e ephemeral cleanup). */
  async removeHistory(peerId: string, dir: 'in' | 'out', id: string): Promise<void> {
    if (this.history) await this.store.historyRemove(this.history.storageKey(peerId, dir, id))
  }

  /** Gather everything a move file carries (Phase D, DESIGN 8.3); the caller
   *  seals. Refuses rather than truncates (MoveBlockedError) while sends are
   *  still queued or past the message cap, and ABORTS if the app locks mid-scan:
   *  every remaining row would read "unreadable" and the export would complete
   *  as a silently partial file claiming success, the exact failure
   *  sweepHistory's guard exists to prevent. loadAllHistory is deliberately NOT
   *  used here: its per-row catch skips unreadable rows without counting them.
   *
   *  Torn-snapshot discipline: history is scanned FIRST, the contact-side blobs
   *  are read LAST (propagating reads, never the fail-open consultors), and any
   *  peer whose deletion marker postdates the scan start is stripped (contact,
   *  nickname, rows) with the marker KEPT, so a deleteConversation landing
   *  mid-gather cannot resurrect on the new device. */
  async exportMoveData(): Promise<{
    contacts: Contact[]
    aliases: Record<string, string>
    dismissals: Record<string, { at: number; auto: boolean }>
    messages: HistoryUnitMessage[]
    /** Rows that would not open while the app stayed unlocked (corruption):
     *  not in the file, and the panel says so. */
    unreadable: number
    /** Readable rows whose peer has no contact row (nothing the importer could
     *  bind them to): not in the file, and the panel says so. */
    orphaned: number
  }> {
    const history = this.history
    if (!history) throw new Error('history is not available on this client')
    const start = Date.now()
    const pending = await this.store.pendingOutbox()
    const queued = pending.entries.length + pending.unreadable.length
    if (queued > 0) throw new MoveBlockedError('outbox', queued)
    const tombstoned = new Set(await this.store.tombstoneKeys())
    const rows = await this.store.historyLoadAll()
    const all: HistoryUnitMessage[] = []
    let unreadable = 0
    for (const row of rows) {
      if (tombstoned.has(row.key)) continue
      let msg
      try {
        msg = history.open(row)
      } catch {
        if (!history.isUnlocked) {
          throw new Error('the app locked while exporting; unlock and try again (nothing was written)')
        }
        unreadable++
        continue
      }
      const m: HistoryUnitMessage = { id: msg.id, peer: msg.peerId, dir: msg.dir, ts: msg.ts, text: msg.text }
      if (msg.status) m.status = msg.status
      if (row.failed && msg.dir === 'out') m.failed = true
      all.push(m)
    }
    if (all.length > MOVE_MAX_MESSAGES) throw new MoveBlockedError('too-large', all.length)
    // Contact-side blobs LAST; propagating reads only, then the torn-snapshot filter.
    const contacts = await this.contacts.list()
    const aliases = await this.contacts.exportAliases()
    const dismissals = await this.contacts.exportDismissals()
    const midGather = new Set(
      Object.entries(dismissals)
        .filter(([, d]) => d.at >= start)
        .map(([p]) => p),
    )
    const keptContacts = contacts.filter((c) => !midGather.has(c.peerId))
    const ids = new Set(keptContacts.map((c) => c.peerId))
    const keptAliases: Record<string, string> = {}
    for (const [k, v] of Object.entries(aliases)) if (!midGather.has(k)) keptAliases[k] = v
    let orphaned = 0
    const messages = all.filter((m) => {
      if (midGather.has(m.peer)) return false // deleted mid-gather: the marker rides, rows do not
      if (!ids.has(m.peer)) {
        orphaned++
        return false
      }
      return true
    })
    return { contacts: keptContacts, aliases: keptAliases, dismissals, messages, unreadable, orphaned }
  }

  /**
   * Delete-for-everyone a message YOU sent (P10d, DESIGN 8.6). Always removes the
   * local copy; whether the peer is asked to remove it too depends on delivery
   * state:
   *   - still queued in your OWN outbox (not yet delivered): CANCEL the send
   *     (drop the outbox entry) rather than transmit it and then chase it with a
   *     delete. Nothing was delivered, so there is nothing to recall.
   *   - already delivered (not in the outbox): send a `delete{contentId}` control
   *     with its OWN fresh transport id (the two-id rule) on the current session,
   *     or on a FRESH initiator session when none survives (moved history, Phase D).
   *
   * `id` is the content msgId (hex) the bubble/history is keyed by. Returns whether
   * a delete request was actually sent to the peer. Best-effort and honest-client-
   * dependent: a delivered delete only asks; it is never a guarantee (see 8.6), so
   * the UI says "delete sent", never "deleted for everyone".
   */
  async deleteForEveryone(peer: string, id: string): Promise<{ requested: boolean }> {
    // A text's outbox entry is keyed by its content id (the two-id rule makes them
    // equal for a first-send text), so a still-queued target is found by that id.
    // Matched on the outbox row's PLAINTEXT id, and on that alone: an id is 16
    // random bytes, so it cannot collide across peers, and matching this way means a
    // queued target can still be cancelled on a device where the row will not open.
    const pending = await this.store.pendingOutbox()
    const stillQueued =
      pending.entries.some((e) => e.id === id && e.to === peer) || pending.unreadable.includes(id)
    // Remove the local sent copy regardless (dir='out').
    if (this.history) await this.store.historyRemove(this.history.storageKey(peer, 'out', id)).catch(() => {})
    if (stillQueued) {
      await this.store.removeOutbox(id).catch(() => {})
      return { requested: false }
    }
    const sent = await this.sendDeleteControl(peer, id)
    return { requested: sent }
  }

  // Encrypt + queue a delete control targeting content id `targetId`, with its OWN
  // fresh transport id (never the target's id: reusing it would make the relay
  // treat the delete as a duplicate of the original and drop it, and would clobber
  // a still-queued original in the outbox). The control is not itself persisted to
  // history. With no live session it opens a FRESH initiator session (Phase D):
  // "no session means the target was never delivered" stopped being true the day
  // moved history could arrive without its sessions, and a delete is a valid first
  // message (the receiver's compound-key check scopes what it can remove).
  private async sendDeleteControl(peer: string, targetId: string): Promise<boolean> {
    const plaintext = encodeDeleteMessage(hexToBytes(targetId))
    try {
      const entry = await this.lock.withLock(sessionLock(peer), async () => {
        const now = Date.now()
        const book = await this.store.loadBook(peer)
        const current = currentSession(book)
        const transportId = bytesToHex(newMsgId()) // fresh 16-byte id, distinct from targetId
        if (!current) {
          return this.openInitiatorEntry(peer, plaintext, transportId, { book, now, silent: true })
        }
        const { state, header, ciphertext } = ratchetEncrypt(deserializeRatchet(current.snapshot, now), plaintext)
        const env: WireEnvelope = {
          id: transportId,
          kind: 'normal',
          header: encodeMessageHeaderWire(header),
          ciphertext: b64encode(ciphertext),
        }
        const advanced = updateSession(book!, current.id, serializeRatchet(state), now)
        // silent: a delete control is delivered without a push nudge, so deleting a
        // message never notifies the recipient (it still applies in-band / on drain).
        const e: OutboxEntry = { id: transportId, to: peer, env, createdAt: now, silent: true }
        await this.store.saveBookWithOutbox(peer, advanced, e) // commit before release; no history row
        return e
      })
      this.fire(entry)
      return true
    } catch {
      // Unreachable peer (unregistered, key conflict, directory down): the local
      // copy is already removed; the ask could not be queued. Honest answer: false.
      return false
    }
  }

  // Fire a queued envelope at the socket and arrange for its outbox entry to be
  // dropped when the relay acks durable storage (`sent`). Retransmission on a
  // later flush re-sends the byte-identical stored envelope; the relay dedups.
  private fire(e: OutboxEntry): void {
    void this.transport.waitSent(e.id).then(() => {
      this.warnedSendCodes.clear() // something got through: a later stall warns again
      // Stamp a POSITIVE "it left this device" marker before dropping the outbox
      // entry. The status must never be inferred from the ABSENCE of a failure
      // marker: marking a row failed is best-effort and can be skipped or throw
      // while the outbox entry is dropped regardless, so "no marker" has to mean
      // unknown, not sent. A control envelope (a delete) has no history row, and
      // historyUpdate only touches rows that exist, so it is a no-op there.
      void this.markDelivery(e.to, e.id, 'sent')
      return this.store.removeOutbox(e.id)
    })
    try {
      this.transport.raw({ t: 'send', to: e.to, env: e.env as WireEnvelope, ...(e.silent ? { silent: true } : {}) })
    } catch {
      // Not connected; the entry stays queued and flushes on reconnect.
    }
  }

  private async flushOutbox(): Promise<void> {
    const now = Date.now()
    const pending = await this.store.pendingOutbox()
    // A queued row that will not open can never be re-encrypted (its ratchet advance
    // committed in the same transaction), so it cannot be sent and must not be
    // silently dropped either. Say so ONCE per id, leave the row in place, and let
    // the retry horizon below remove it like any other timed-out entry: `createdAt`
    // is deliberately in cleartext so that still works on a row nothing can read.
    for (const id of pending.unreadable) {
      if (this.warnedUnreadableOutbox.has(id)) continue
      this.warnedUnreadableOutbox.add(id)
      this.cb.onSendFailed?.(id, 'this queued message could not be read on this device and will not be sent')
    }
    for (const e of pending.entries) {
      if (now - e.createdAt > OUTBOX_RETRY_HORIZON_MS) {
        // Past the retry horizon: give up (DESIGN 7.2). Flag the persisted row
        // failed and notify, so this never-delivered message is not shown as
        // delivered after a reload (P10b), then drop the outbox entry.
        if (this.history) await this.store.historyMarkFailed(this.history.storageKey(e.to, 'out', e.id)).catch(() => {})
        await this.store.removeOutbox(e.id)
        this.cb.onSendFailed?.(e.id, 'delivery timed out (undelivered for too long)')
        continue
      }
      this.fire(e)
    }
  }

  // Name the sender of a permanently-dropped envelope ONLY when they are a live,
  // non-deleted contact (see the dropped branch below for why a deleted peer's
  // backlog stays anonymous). Once per peer per connect; best-effort throughout.
  private async noteUnreadableFrom(peer: string): Promise<void> {
    if (!this.cb.onUnreadableFrom || this.notedUnreadableFrom.has(peer)) return
    try {
      if ((await this.contacts.trustLevel(peer)) === null) return
      if ((await this.contacts.dismissedAt(peer)) !== null) return
      this.notedUnreadableFrom.add(peer)
      this.cb.onUnreadableFrom(peer)
    } catch {
      /* best-effort */
    }
  }

  private async handleDeliver(from: string, envJson: unknown): Promise<void> {
    let env: Envelope
    try {
      env = decodeEnvelope(envJson as WireEnvelope)
    } catch {
      this.cb.onError?.('dropped a malformed envelope')
      return
    }
    const now = Date.now()
    let res
    try {
      res = await processInbound(env, from, {
        me: this.identity,
        prekeys: this.prekeys,
        store: this.store,
        contacts: this.contacts,
        lock: this.lock,
        now,
        // Only include the key when set: exactOptionalPropertyTypes forbids an
        // explicit `undefined` for the optional `history` dep.
        ...(this.history ? { history: this.history } : {}),
      })
    } catch (e) {
      // Transient (retry on redelivery) or a surfaced security event: do NOT ack.
      if (e instanceof KeyConflictError) {
        this.cb.onSecurity?.(
          `an incoming message presented a key that conflicts with the one stored for ${from.slice(0, 12)}…; the message was refused. Verify safety numbers with this contact.`,
        )
      } else {
        this.cb.onError?.(String(e instanceof Error ? e.message : e))
      }
      return
    }
    // processInbound persisted before returning, so a delivered plaintext is
    // durably consumed. Deliver to the UI FIRST, then ack best-effort: a lost ack
    // only causes an idempotent redelivery (hasSeen -> duplicate). `duplicate` and
    // `dropped` are just acked (the latter stops a poison redelivery).
    if (res.kind === 'delivered') {
      // Classify the plaintext for RENDERING (the persist decision already ran,
      // atomically, inside processInbound). decodeMessage is total; this runs
      // strictly after the commit, so a malformed/delete record only changes what
      // the UI shows, never protocol state. Route: text/legacy -> render; delete
      // (P10d) -> apply a removal; malformed -> render nothing (forward-compat).
      const decoded = decodeMessage(res.plaintext)
      if (decoded.kind === 'text') {
        // A text whose delete-for-everyone already arrived was suppressed by the
        // inbound processor (not persisted, tombstoned): do not render it.
        if (!res.suppressed) {
          this.cb.onMessage(from, { id: bytesToHex(decoded.id), text: decoded.body, ts: now, ephemeral: decoded.ephemeral })
        }
      } else if (decoded.kind === 'legacy') {
        this.cb.onMessage(from, { id: env.id, text: decoded.body, ts: now })
      } else if (decoded.kind === 'delete') {
        // Delete-for-everyone (P10d). The target row was removed + tombstoned
        // atomically inside processInbound; tell the UI to drop the bubble too.
        this.cb.onDelete?.(from, bytesToHex(decoded.id))
      }
      // decoded.kind 'malformed': clean-ignored (forward-compat).
      if (res.consumedOpk) {
        // Mirror the server-side vend so the tracked Directory count trends down
        // between connects and replenishment fires before the Directory depletes.
        if (this.authed) this.authed = { ...this.authed, opkCount: Math.max(0, this.authed.opkCount - 1) }
        void this.maybeReplenishOpks().catch(() => {})
      }
    } else if (res.kind === 'dropped') {
      // Anonymous by default: after a delete this fires on every reconnect for as
      // long as the relay holds the deleted peer's queued messages, and printing
      // the id would undo the very thing the delete promised (see the same
      // reasoning in inbound.ts). When the sender IS a live, non-deleted contact
      // (the post-move case: their device still sends on a session that did not
      // ride the move), the honest notice is the NAMED one, once per connect.
      void this.noteUnreadableFrom(from)
      this.cb.onError?.(`dropped a message that could not be read: ${res.reason}`)
    }
    try {
      this.transport.raw({ t: 'ack', id: env.id })
    } catch {
      // Socket gone; the relay redelivers and we re-ack on reconnect.
    }
    // After the ack, never before it: recovering a contact is a trust convenience
    // and must not sit between a decrypted message and its acknowledgement.
    if (res.kind === 'delivered') void this.recoverContact(from, now)
  }

  /**
   * A message arrived from someone we hold no contact record for. Re-record them.
   *
   * This is the other half of deleting a conversation (8.9). The delete keeps the
   * ratchet session on purpose, so the peer's app keeps sending `normal` messages,
   * and the normal-message path is the one inbound path that never reaches the
   * first-contact recording an `initial` gets. Without this the conversation comes
   * back with no stored IK_sig, and therefore no SAFETY NUMBER: the priority-1
   * control (DESIGN 6, 12), silently unavailable on a conversation the user is
   * actively having. It is also what makes 8.9's promise true, that a message from
   * a deleted peer records them again and lifts the deletion marker.
   *
   * Re-fetching the bundle is sound rather than a trust hole: a userId IS
   * SHA-256(IK_sig) (DESIGN 3), and the binding check below rejects anything else,
   * so a hostile or compelled directory cannot substitute a key for a known id.
   *
   * Deliberately NOT relay-driven. The trigger is a message that authenticated
   * under a ratchet session only this peer can hold, which is the same evidence
   * `handleInitial` records on, not something the relay can assert.
   */
  private async recoverContact(peer: string, seenAt: number): Promise<void> {
    if (this.recoveringContacts.has(peer)) return // a burst must cause one fetch, not one each
    try {
      if (await this.contacts.trustLevel(peer)) return // already known: nothing to do
    } catch {
      return // contacts unreadable (locked mid-teardown); the next message retries
    }
    this.recoveringContacts.add(peer)
    try {
      const { bundle } = await this.directory.fetchBundle(peer)
      if (!bundle) return // deregistered: retried whenever they next get through
      if (deriveUserId(bundle.ikSigPub) !== peer) {
        throw new Error(`directory served a key that does not match ${peer}`)
      }
      // A delete pressed WHILE that fetch was in flight has to win, or the recovery
      // would quietly undo it. Checked inside the contacts lock, next to the write.
      await this.contacts.recordFirstContact(peer, bundle.ikSigPub, Date.now(), 'unverified', false, seenAt)
      this.cb.onContactsChanged?.()
    } catch (e) {
      if (e instanceof KeyConflictError) {
        this.cb.onSecurity?.(
          `a message arrived from ${peer.slice(0, 12)}… whose key conflicts with the one stored for them. Verify safety numbers with this contact.`,
        )
      }
      // Anything else (offline, not registered) is retried on their next message.
    } finally {
      this.recoveringContacts.delete(peer)
    }
  }

  // Top up one-time prekeys when the DIRECTORY runs low, so an initiator can
  // always get an OPK (a depleted user degrades to the no-OPK path, DESIGN 4.3).
  // Serialized on its own lock so two tabs (or overlapping triggers) cannot
  // publish colliding id batches.
  private async maybeReplenishOpks(): Promise<void> {
    if (!this.isRegistered) return
    await this.lock.withLock(REPLENISH_LOCK, async () => {
      // Gate on the DIRECTORY's available-OPK count (what an initiator can actually
      // fetch), tracked in authed.opkCount and re-anchored on connect + after each
      // publish. The LOCAL private-key count is the wrong signal: the server vends
      // (decrements) on every bundle FETCH, while the local count drops only when
      // an initial actually ARRIVES, so the local count over-reports and would
      // suppress replenishment exactly when the Directory is depleted.
      if (this.opkCount >= OPK_REPLENISH_THRESHOLD) return
      const spk = await this.prekeys.signedPrekeyWire()
      if (!spk) return // pre-P5 stored SPK without a persisted signature; skip
      const startId = (await this.prekeys.maxOpkId()) + 1
      const pairs = generateOneTimePrekeys(startId, OPK_BATCH)
      await this.prekeys.addOpks(pairs.map((p) => ({ id: p.opk.id, priv: p.priv })))
      const opkCount = await this.directory.publishBundle(
        spk,
        pairs.map((p) => encodeOneTimePrekey(p.opk)),
      )
      await this.prekeys.markSpkPublished(spk.id).catch(() => {})
      if (this.authed) this.authed = { ...this.authed, opkCount }
    })
  }

  /**
   * Rotate the signed prekey on the SPK_ROTATION_MS cadence (P8, DESIGN 4.1).
   * Runs on every authenticated connect, under the same lock as OPK
   * replenishment so the two can never interleave publishes. Three cases:
   *   - no local SPK at all: a restored identity whose forced re-registration
   *     was interrupted -> redo the full re-registration (fresh SPK + OPKs,
   *     server hard-invalidates the old bundle it may still be serving);
   *   - newest SPK unpublished (a rotation crashed between local commit and the
   *     Directory ack) -> retry the publish;
   *   - newest SPK older than the cadence -> generate + publish the successor.
   * Old SPK private halves are kept for late in-flight initials and pruned on
   * the SPK_RETIRE_GRACE_MS horizon. Discipline: the new private half is
   * durable locally BEFORE its public half is offered to the Directory.
   */
  async maybeRotateSpk(now = Date.now()): Promise<void> {
    if (!this.isRegistered) return
    await this.lock.withLock(REPLENISH_LOCK, async () => {
      const newest = await this.prekeys.newestSpk()
      // No local SPK at all, OR a full registration that never got the Directory
      // ack: recover with a purging full re-register, NEVER a plain publishBundle.
      // publishBundle only rotates the SPK row and appends OPKs; it would leave
      // the Directory serving the prior batch of OPKs whose private halves this
      // device no longer holds, silently breaking every new inbound session that
      // fetches one (P9 stale-OPK finding). The full register path runs the
      // Directory's existing-user branch, which DELETEs the stale opks + vends.
      if (!newest || (await this.prekeys.isRegistrationUnconfirmed())) {
        // Already inside the replenish lock: use the under-lock body directly.
        await this.registerUnderLock('')
        return
      }
      const published = await this.prekeys.publishedSpkId()
      const needsRotate = now - newest.createdAt >= SPK_ROTATION_MS
      const needsPublish = published !== newest.id
      if (!needsRotate && !needsPublish) {
        await this.prekeys.pruneRetiredSpks(now)
        return
      }
      if (needsRotate) {
        const id = (await this.prekeys.maxSpkId()) + 1
        const { spk, priv } = generateSignedPrekey(this.identity, id, now)
        await this.prekeys.addSpk({ id, createdAt: spk.createdAt, expiry: spk.expiry, priv, pub: spk.pub, sig: spk.sig })
      }
      const wire = await this.prekeys.signedPrekeyWire()
      if (!wire) return // pre-P5 stored SPK without a persisted signature
      const opkCount = await this.directory.publishBundle(wire, [])
      await this.prekeys.markSpkPublished(wire.id)
      if (this.authed) this.authed = { ...this.authed, opkCount }
      await this.prekeys.pruneRetiredSpks(now)
    })
  }
}
