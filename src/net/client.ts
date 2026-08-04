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
import { type Identity, accountIdOf, deriveUserId, deviceIdOf } from '../crypto/identity'
import { type KeyPair, ed25519Generate } from '../crypto/primitives'
import { type RosterDevice, isRosterNewer, rosterDeviceIds, rosterDiff, signRoster, verifyRoster } from '../crypto/roster'
import { type RotationStatement, signRotation, verifyRotation } from '../crypto/rotation'
import { type AccountIdentity, accountIdentityOf } from '../trust/accountIdentity'
import { type LinkPayload, openLink, readLinkChunkHeader, sealLink } from '../crypto/link'
import type { PushSubscriptionInfo } from '../platform'
import {
  decodeMessage,
  encodeDeleteMessage,
  encodeHelloMessage,
  encodeRefreshMessage,
  encodeRetryRequest,
  encodeRotationMessage,
  encodeSyncDeleteMessage,
  encodeSyncRecvDeleteMessage,
  encodeSyncRecvMessage,
  encodeSyncSentMessage,
  encodeTextMessage,
  newMsgId,
} from '../crypto/message'
import type { HistoryUnitMessage } from '../crypto/historyUnit'
import { openHistoryTransfer, sealHistoryTransfer } from '../crypto/historyTransfer'
import {
  LINK_MAX_PAYLOAD_BYTES,
  LINK_SECRET_BYTES,
  MAX_DELIVERED_CHECK_IDS,
  MAX_DEVICES_PER_ACCOUNT,
  MOVE_MAX_MESSAGES,
  OPK_BATCH,
  OPK_REPLENISH_THRESHOLD,
  OPK_VEND_TTL_MS,
  OUTBOX_RETRY_HORIZON_MS,
  RETRY_HONOR_MIN_INTERVAL_MS,
  RETRY_REQUEST_AFTER_ATTEMPTS,
  RETRY_REQUEST_MAX_ATTEMPTS,
  RETRY_REQUEST_MIN_INTERVAL_MS,
  RETRY_RESEND_MAX_MESSAGES,
  RETRY_RESEND_WINDOW_MS,
  SEEN_ID_TTL_MS,
  SPK_ROTATION_MS,
} from '../crypto/constants'
import { OWN_BUNDLE_VERSION, buildOwnBundle, generateOneTimePrekeys, generateSignedPrekey } from '../crypto/prekeys'
import { deserializeRatchet, initRatchetInitiator, ratchetEncrypt, serializeRatchet } from '../crypto/ratchet'
import { x3dhInitiate } from '../crypto/x3dh'
import { type Contact, type ContactStore, type TrustLevel, KeyConflictError } from '../trust/contactStore'
import type { InviteArtifact } from '../trust/inviteArtifact'
import { currentSession, promoteSession, updateSession } from '../session/sessionBook'
import type { DeliveryStatus, HistoryMessage, HistoryStore } from '../storage/historyStore'
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
  encodeDeviceRoster,
  encodeRotationStatement,
  encodeMessageHeaderWire,
  encodeOneTimePrekey,
  encodePublishedBundle,
} from '../wire/codec'
import { UndecryptableError, processInbound } from './inbound'
import { DirectoryClient } from './directoryClient'
import { type AuthedInfo, Transport } from './transport'

const sessionLock = (peerId: string) => `nightjar-session:${peerId}`
const REPLENISH_LOCK = 'nightjar-opk-replenish'
/** Rows sealed per durable write when importing saved messages: large enough to
 *  amortize the commit, small enough that progress moves and memory stays flat.
 *  Matches the move importer's batch for the same reasons. */
const HISTORY_IMPORT_BATCH = 500

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
  /** Optional (8.10): this device asked `peerId`'s device to re-establish and send
   *  its recent messages again, because something they sent could not be read here. */
  onRetryRequested?: (peerId: string) => void
  /** Optional (8.10): the ask above has gone unanswered its full number of times.
   *  Nothing further will be sent automatically; the UI tells the user to ask. */
  onRetryExhausted?: (peerId: string) => void
  /** Optional (Sesame): another of THIS account's devices sent a message, and
   *  this is the copy so the conversation reads the same wherever you open it.
   *  `accountId` is who it was sent TO; the message is yours, not theirs. */
  onSyncedSent?: (accountId: string, msg: { id: string; text: string; ts: number }) => void
  /** Optional (Sesame): the set of devices an account claims has changed since
   *  this device last looked, measured against the single device we addressed them
   *  as before any list existed. An operator cannot cause this, so it is the signal
   *  that distinguishes a link the person really made from something that already
   *  holds their account key.
   *
   *  `first` marks the first list ever seen for that account, which is a real event
   *  (their first extra device) but reads differently for somebody just added, so
   *  the wording is the UI's to choose. It is NOT a reason to stay quiet: for your
   *  OWN account a first list you did not publish is what a stolen account key
   *  produces, and it used to be the one case that was silent. */
  onDevicesChanged?: (accountId: string, change: { added: string[]; removed: string[]; first: boolean }) => void
  /** Optional (8.10): this device honored a resend request from `peerId` and sent
   *  `count` of its own recent messages again. NEVER silent: it is the only signal
   *  the user gets that someone holding their contact's identity pulled recent
   *  messages, so the UI must show it every time (DESIGN 8.10, 1.3). */
  onRetryHonored?: (peerId: string, count: number) => void
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
  /** Peers this device has asked to resend during THIS run (8.10). Two jobs, both
   *  in RAM on purpose: it collapses a burst of undecryptable envelopes into one
   *  ask without touching the sealed ledger per message, and it is the cheap test
   *  for whether a newly decrypted message is worth clearing ask-state for. Losing
   *  it on restart costs nothing that matters: the durable ledger still throttles,
   *  and it ages out on its own. */
  private readonly askedRetryFrom = new Set<string>()
  /** Peers already told about this connect, once, that asking them has stopped
   *  (mirrors `notedUnreadableFrom`, kept separate so the two notices cannot
   *  suppress each other: they say different things and only one is actionable). */
  private readonly notedRetryExhausted = new Set<string>()
  /** Requesters whose resend is being assembled right now, so a redelivered
   *  request cannot start a second concurrent burst before the first one has
   *  written its throttle. */
  private readonly honoringRetry = new Set<string>()
  /** Set while this device is waiting to be linked (Sesame): the secret from the
   *  code it is showing, and the chunks received so far, grouped by transfer.
   *  RAM only, deliberately: the code is single-use and shown for the length of
   *  the ceremony, so a reload means showing a fresh one rather than leaving a
   *  key-bearing secret on disk. */
  private linkAwait: {
    secret: Uint8Array
    onPayload: (payload: LinkPayload) => void
    chunks: Map<string, Map<number, Uint8Array>>
  } | null = null

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
    /** The ACCOUNT key, on a device that was linked into an existing account
     *  (Sesame). Omitted on a first device, where the account key IS the device
     *  identity and is derived rather than stored. */
    private accountKeyPair?: KeyPair,
  ) {
    this.transport = new Transport(identity)
    this.directory = new DirectoryClient(this.transport)
  }

  /** Adopt an account key after linking, so the rest of this session signs and
   *  resolves as the account rather than as a device of one.
   *
   *  Passing null puts it back to being its own account, which is what a link
   *  that FAILED after the key was staged has to do: an adopted key is preferred
   *  over this device's own everywhere (see `account`), so a half-linked device
   *  that kept one would go on acting as an account it never joined. */
  setAccountKey(pair: KeyPair | null): void {
    this.accountKeyPair = pair ?? undefined
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
    this.transport.onDelivered((id, from) => void this.markDeliveredEnvelope(from, id))
    this.transport.onLinkChunk((chunk) => this.handleLinkChunk(chunk))
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
    this.notedRetryExhausted.clear()
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
    // A linked device introduces itself before its first message on a session, so
    // the receiver can file what follows under the right person rather than under
    // a device id it has never seen. A no-op on a first device, which is every
    // device until an account links a second one.
    await this.maybeSendHello(to).catch(() => {})

    // One message becomes one envelope per device the recipient reads on (Sesame).
    // For a recipient with no roster this is exactly [to], so everything below
    // collapses to precisely the single-envelope path it has always been, which is
    // the property that keeps this change safe for every existing conversation.
    const devices = await this.resolveDevices(to)
    const multi = devices.length > 1 || devices[0] !== to
    // The ratchet plaintext is the structured NJM1 record (not raw utf8): it carries
    // the content id + kind + the ephemeral flag both sides need. A session-only
    // (ephemeral, P10e) message is authenticated with flags bit0 set and is NEVER
    // sealed into history on either device. It is otherwise delivered EXACTLY like a
    // normal message (same outbox + ack + retransmit): the only difference is the
    // skipped history seal. That is deliberate - a session-ESTABLISHING initial must
    // be delivered reliably, or a single lost frame would orphan the session and
    // break ALL future traffic (including non-ephemeral) to this peer.
    //
    // `multi` doubles as the fanned-out flag, and the equivalence is exact: it is
    // true precisely when this send addressed a device list that was actually read,
    // so the recipient's device does not have to pass a copy to its siblings. When
    // the list could NOT be read (offline, a relay hiccup, a build with no idea
    // rosters exist) the flag stays clear and the recipient forwards, which is the
    // conservative direction: a duplicate copy upserts one row, a missing one is
    // gone.
    const plaintext = encodeTextMessage(hexToBytes(contentIdHex), text, ephemeral, multi)
    let first: OutboxEntry | null = null
    const queued: OutboxEntry[] = []
    let lastError: unknown = null

    for (const deviceId of devices) {
      try {
        // The history row rides the FIRST device's commit, so "a saved message
        // implies at least one envelope was durably queued" stays true. A later
        // device failing leaves a partially sent message, which is honest: some of
        // their devices have it. Failing before the first leaves nothing at all.
        const withHistory = first === null
        const entry = await this.sendOneCopy(deviceId, {
          plaintext,
          contentIdHex,
          account: to,
          text,
          uiTs,
          ephemeral,
          withHistory,
          multi,
          track: true,
        })
        if (first === null) first = entry
        queued.push(entry)
      } catch (e) {
        lastError = e
      }
    }
    if (first === null) throw lastError instanceof Error ? lastError : new Error(String(lastError))
    if (queued.length < devices.length) {
      this.cb.onError?.(
        `sent to ${queued.length} of ${devices.length} of their devices; the rest will not receive this message`,
      )
    }
    for (const e of queued) this.fire(e)
    // ...and a copy to this account's OWN other devices, so the conversation reads
    // the same wherever it is opened. Best-effort and deliberately after the real
    // send: a laptop not getting its copy is a cosmetic gap, and must never delay
    // or fail delivering the message to the person it was written for.
    if (!ephemeral) void this.syncToOwnDevices(to, contentIdHex, text, uiTs ?? Date.now())
    return contentIdHex
  }

  /**
   * Send this account's other devices a copy of something it just sent (Sesame).
   *
   * A no-op for every account that has not linked a second device: its own
   * resolved device list is just itself, so there is nobody to copy to and no
   * network call is made.
   *
   * Ephemeral messages are never copied. They are the one kind that is deliberately
   * not written down anywhere (8.7), and a device that was not in the room when one
   * was sent has no business being handed it later.
   */
  private async syncToOwnDevices(account: string, contentIdHex: string, text: string, ts: number): Promise<void> {
    try {
      const me = this.account
      const mine = (await this.resolveDevices(me.accountId)).filter((d) => d !== this.deviceId)
      if (mine.length === 0) return
      const plaintext = encodeSyncSentMessage(hexToBytes(contentIdHex), account, ts, text)
      for (const deviceId of mine) {
        try {
          const entry = await this.sendOneCopy(deviceId, {
            plaintext,
            contentIdHex,
            account,
            text,
            uiTs: ts,
            ephemeral: false,
            // The history row was already written by the send this is a copy OF.
            withHistory: false,
            multi: true,
          })
          this.fire(entry)
        } catch {
          /* one of my own devices missing a copy is not worth failing a send over */
        }
      }
    } catch {
      /* likewise */
    }
  }

  /**
   * Pass a message this device just received on to this account's other devices
   * (Sesame, the forwarding fallback).
   *
   * The self-sync above covers messages this account SENT. This covers the other
   * and much larger half: messages sent TO it by somebody whose app addressed one
   * device only. That is every contact still running a build that predates device
   * lists, and every contact whose app could not read the list at the moment they
   * pressed send. Without it, a second device would show a conversation that is
   * missing most of what the other person said, which is a worse failure than not
   * offering multi-device at all, because it looks like it is working.
   *
   * A no-op for an account with one device, so it costs nothing for anyone who
   * has not linked one. Best-effort and strictly after the ack: a message is
   * delivered to the person it was written for first, and everything else is
   * housekeeping.
   */
  private async forwardToOwnDevices(fromAccount: string, contentIdHex: string, text: string, ts: number): Promise<void> {
    try {
      const mine = (await this.resolveDevices(this.account.accountId)).filter((d) => d !== this.deviceId)
      if (mine.length === 0) return
      const plaintext = encodeSyncRecvMessage(hexToBytes(contentIdHex), fromAccount, ts, text)
      for (const deviceId of mine) await this.queueControl(deviceId, plaintext).catch(() => {})
    } catch {
      /* one of my own devices missing a copy is not worth disturbing anything over */
    }
  }

  /** Pass an inbound delete-for-everyone on to this account's other devices, so a
   *  message removed here is removed wherever the conversation is open.
   *
   *  Sent for EVERY inbound delete rather than only unfanned ones, because a
   *  delete control carries no room to say which it is (see the note on
   *  `encodeSyncRecvDeleteMessage`). Applying one twice removes nothing that is
   *  not already gone, so the duplicate is free. */
  private async forwardDeleteToOwnDevices(fromAccount: string, targetIdHex: string): Promise<void> {
    try {
      const mine = (await this.resolveDevices(this.account.accountId)).filter((d) => d !== this.deviceId)
      if (mine.length === 0) return
      const plaintext = encodeSyncRecvDeleteMessage(hexToBytes(targetIdHex), fromAccount)
      for (const deviceId of mine) await this.queueControl(deviceId, plaintext).catch(() => {})
    } catch {
      /* best-effort */
    }
  }

  /** Encrypt and durably queue ONE device's copy of a message. Split out of
   *  `sendText` so the fan-out loop has a single unit of work whose failure means
   *  exactly "this device did not get it", and so a control with no history row
   *  can reuse the same commit discipline. */
  private async sendOneCopy(
    deviceId: string,
    opts: {
      plaintext: Uint8Array
      contentIdHex: string
      account: string
      text: string
      uiTs: number | undefined
      ephemeral: boolean
      withHistory: boolean
      multi: boolean
      /** Whether this copy's delivery says anything about the message reaching
       *  the person it was written for. True for a copy to one of THEIR devices;
       *  false for a copy to one of our own, which arriving proves nothing about
       *  them and must never move the indicator. */
      track?: boolean
    },
  ): Promise<OutboxEntry> {
    const { plaintext, contentIdHex, account, ephemeral, multi } = opts
    return this.lock.withLock(sessionLock(deviceId), async () => {
      const now = Date.now()
      const ts = opts.uiTs ?? now
      const book = await this.store.loadBook(deviceId)
      const current = currentSession(book)
      // With several devices the entry id can no longer BE the content id (ids
      // must be unique within this outbox), so the two are carried separately and
      // the single-device case keeps its historical shape untouched.
      const transportId = multi ? bytesToHex(newMsgId()) : contentIdHex
      const extra = multi ? { contentId: contentIdHex, account } : {}
      // Seal the sent message for history - UNLESS it is ephemeral (never persisted,
      // send OR receive) or history is not wired. Done inside the lock, before the
      // commit, so a seal failure aborts the send with nothing queued; the row rides
      // the same tx as the ratchet advance + outbox (commit before release), stamped
      // with the UI ts so live and hydrated ordering agree.
      // Keyed by the ACCOUNT, never the device: a conversation is with a person,
      // and their devices are an implementation detail of reaching them.
      const historyRow =
        opts.withHistory && !ephemeral && this.history
          ? this.history.seal({ id: contentIdHex, peerId: account, dir: 'out', ts, text: opts.text })
          : undefined

      if (current) {
        // Established (or pending) session: a normal ratchet message. `now` as
        // legacyTs stamps any pre-P8 skipped entries so the re-serialized
        // snapshot below cannot mark them instantly expired.
        const { state, header, ciphertext } = ratchetEncrypt(deserializeRatchet(current.snapshot, now), plaintext)
        const env: WireEnvelope = {
          id: transportId,
          kind: 'normal',
          header: encodeMessageHeaderWire(header),
          ciphertext: b64encode(ciphertext),
        }
        const advanced = updateSession(book!, current.id, serializeRatchet(state), now)
        const e: OutboxEntry = { id: transportId, to: deviceId, env, createdAt: now, ...extra }
        await this.store.saveBookWithOutbox(deviceId, advanced, e, historyRow) // commit before release
        await this.noteSentRef(opts, transportId, contentIdHex, now)
        return e
      }

      // No session: open a fresh initiator session carrying this text (shared
      // helper; for a single-device recipient the transport id equals the content
      // id, per the two-id rule's one safe case).
      const entry = await this.openInitiatorEntry(deviceId, plaintext, transportId, {
        book,
        now,
        ...(historyRow ? { historyRow } : {}),
        ...extra,
      })
      await this.noteSentRef(opts, transportId, contentIdHex, now)
      return entry
    })
  }

  /** Remember what a fanned-out copy's transport id stands for, so a delivery
   *  report about it can be traced back to the one saved message it carries.
   *
   *  Written only in the multi-envelope case: with a single recipient device the
   *  transport id already IS the message id, so there is nothing to remember and
   *  that path stays exactly as it was. Best-effort, because everything it feeds
   *  is a display hint (DESIGN 8.8) and none of it may delay a send. */
  private async noteSentRef(
    opts: { multi: boolean; track?: boolean; account: string },
    transportId: string,
    contentIdHex: string,
    now: number,
  ): Promise<void> {
    if (!opts.multi || !opts.track || !this.history) return
    try {
      await this.store.putSentRef(transportId, this.history.storageKey(opts.account, 'out', contentIdHex), now)
    } catch {
      /* the indicator degrades to unknown, which is its honest default */
    }
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
    opts: {
      book: SessionBook | null
      now: number
      historyRow?: HistoryRecord
      silent?: boolean
      /** Set when one message is being fanned out to several devices (Sesame), so
       *  the entry records the logical message and the conversation separately
       *  from its own id and its device. */
      contentId?: string
      account?: string
    },
  ): Promise<OutboxEntry> {
    const { book, now } = opts
    const { bundle } = await this.directory.fetchBundle(to)
    if (!bundle) throw new Error(`peer ${to} is not registered`)
    // The fetched IK_sig MUST hash to the userId we asked for. Because a userId
    // IS SHA-256(IK_sig) (DESIGN 3), this catches a directory that served a
    // substituted key for this contact (the cheap key-swap of 6.1) before any
    // DH, without needing the out-of-band check. The safety number still covers
    // the complementary case (a wrong userId handed to us at all).
    // A DEVICE binding (Sesame): a prekey bundle belongs to a device, and this is
    // the session being opened to it. The account-level check is a different one,
    // made against the contact's account key just below.
    if (deviceIdOf(bundle.ikSigPub) !== to) {
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
    const e: OutboxEntry = {
      id: transportId,
      to,
      env,
      createdAt: now,
      ...(opts.silent ? { silent: true } : {}),
      ...(opts.contentId ? { contentId: opts.contentId } : {}),
      ...(opts.account ? { account: opts.account } : {}),
    }
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
   * A relay report that one of our ENVELOPES was picked up.
   *
   * The relay speaks in transport ids and knows nothing else; the user sees
   * messages. For a recipient reading on one device those are the same string and
   * this is a straight pass-through, which is every conversation that has not
   * grown a second device. For a fanned-out message it is not, so the back-
   * reference written at send time says which saved message this envelope was
   * carrying, and the mark lands on that.
   */
  private async markDeliveredEnvelope(from: string, transportId: string): Promise<void> {
    let ref: { key: string } | null = null
    try {
      ref = await this.store.getSentRef(transportId)
    } catch {
      /* fall through to the direct reading below */
    }
    if (!ref) return this.markDelivery(from, transportId, 'delivered')
    // `from` is deliberately not used here: it is the DEVICE that acked, and the
    // conversation this belongs to is whatever the message itself says it is.
    try {
      const row = await this.store.historyGet(ref.key)
      if (!row || !this.history) return
      const msg = this.history.open(row)
      await this.markDelivery(msg.peerId, msg.id, 'delivered')
      // One device acking is the whole claim (8.8), so the other copies of this
      // message have nothing left to tell us.
      await this.store.removeSentRef(transportId).catch(() => {})
    } catch {
      /* the row is gone (deleted), unreadable, or the app locked: nothing to mark */
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
    // What each saved message actually went out AS. One message is one envelope
    // for a recipient with one device (and the ids are the same string, so there
    // is no row here at all), or one envelope per device otherwise.
    const refsByKey = new Map<string, string[]>()
    for (const r of await this.store.listSentRefs().catch(() => [])) {
      const list = refsByKey.get(r.key) ?? []
      list.push(r.id)
      refsByKey.set(r.key, list)
    }
    // Collect candidates with their timestamps FIRST, then take the newest per
    // peer. Truncating during the scan would keep whichever ids happened to come
    // first out of `getAll()`, and the history key is an opaque HMAC, so that order
    // is uncorrelated with time: past the cap, a fixed arbitrary subset would be
    // asked about on every single connect and the rest could never be confirmed.
    // This is the same trap the outbox flush had, so it gets the same answer.
    const byPeer = new Map<string, { fanned: boolean; candidates: Array<{ ask: string; msgId: string; ts: number }> }>()
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
      const entry = byPeer.get(msg.peerId) ?? { fanned: false, candidates: [] }
      const transports = refsByKey.get(row.key)
      if (transports?.length) {
        entry.fanned = true
        for (const t of transports) entry.candidates.push({ ask: t, msgId: msg.id, ts: msg.ts })
      } else {
        entry.candidates.push({ ask: msg.id, msgId: msg.id, ts: msg.ts })
      }
      byPeer.set(msg.peerId, entry)
    }
    for (const [peer, { fanned, candidates }] of byPeer) {
      if (candidates.length === 0) continue
      const asked = candidates
        .sort((a, b) => b.ts - a.ts) // newest first
        .slice(0, MAX_DELIVERED_CHECK_IDS)
      const ids = asked.map((c) => c.ask)
      const msgOf = new Map(asked.map((c) => [c.ask, c.msgId]))
      // Which inboxes hold the answer. Each copy went to a different device, and
      // an inbox only knows about its own, so a fanned-out message means asking
      // each of them. Nobody who has not linked a device reaches this branch, so
      // the extra roster fetch is paid for only where it buys something.
      const inboxes = fanned ? await this.resolveDevices(peer).catch(() => [peer]) : [peer]
      for (const inbox of inboxes) {
        try {
          const delivered = await this.directory.deliveredCheck(inbox, ids)
          for (const id of delivered) {
            const msgId = msgOf.get(id)
            if (!msgId) continue // an id we did not ask about; ignore rather than trust
            await this.markDelivery(peer, msgId, 'delivered')
            if (msgId !== id) await this.store.removeSentRef(id).catch(() => {})
          }
        } catch {
          /* best-effort */
        }
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
        // Match the CONVERSATION, not the routing label. Once a message is fanned
        // out, each copy is addressed to one of the peer's devices, so `to` is a
        // device id and only `account` names the conversation. Matching on `to`
        // alone left every copy but the first queued, and the next flush sent
        // them to a conversation the user had just deleted. `account` is written
        // only in the multi-device case and always names the conversation, so
        // this cannot over-match; it is the same rule `deleteForEveryone` and
        // `fire` already use.
        if (e.to === peer || e.account === peer) {
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
    // Found by the LOGICAL message, not by the envelope: with several devices one
    // message is several entries, each with its own id. The entry id is still
    // checked because for a single-device recipient the two are the same.
    const queuedCopies = pending.entries.filter((e) => e.contentId === id || e.id === id)
    const stillQueued = queuedCopies.length > 0 || pending.unreadable.includes(id)
    // Remove the local sent copy regardless (dir='out'), and tell this account's
    // OTHER devices to drop theirs. That second part needs its own record: an
    // ordinary delete control asks a RECIPIENT to drop something they received, and
    // says nothing that would let your own laptop find the copy it sent.
    if (this.history) await this.store.historyRemove(this.history.storageKey(peer, 'out', id)).catch(() => {})
    void this.syncDeleteToOwnDevices(peer, id)

    if (stillQueued) {
      // Cancel EVERY copy still waiting, so a message stopped in time is stopped
      // for all of their devices and not only the one that happened to match.
      for (const e of queuedCopies) await this.store.removeOutbox(e.id).catch(() => {})
      await this.store.removeOutbox(id).catch(() => {})
      // Some of their devices can already have it while others were still queued,
      // so only report "nothing was sent" when every copy was caught in time.
      const devices = await this.resolveDevices(peer).catch(() => [peer])
      if (queuedCopies.length >= devices.length) return { requested: false }
    }
    const sent = await this.sendDeleteControl(peer, id)
    return { requested: sent }
  }

  /** Tell this account's other devices to drop their copy of a message it sent.
   *  A no-op for an account with one device, and best-effort: a laptop still
   *  showing a deleted message is a gap worth closing, never a reason to fail the
   *  delete the user actually asked for. */
  private async syncDeleteToOwnDevices(account: string, targetId: string): Promise<void> {
    try {
      const me = this.account
      const mine = (await this.resolveDevices(me.accountId)).filter((d) => d !== this.deviceId)
      if (mine.length === 0) return
      const plaintext = encodeSyncDeleteMessage(hexToBytes(targetId), account)
      for (const deviceId of mine) await this.queueControl(deviceId, plaintext).catch(() => {})
    } catch {
      /* best-effort */
    }
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
    // Every device they read on, or the delete quietly survives on the ones that
    // were missed. For a single-device recipient this resolves to [peer], which is
    // exactly the one-envelope behaviour this has always had.
    const devices = await this.resolveDevices(peer).catch(() => [peer])
    let any = false
    for (const deviceId of devices) {
      try {
        await this.queueControl(deviceId, plaintext)
        any = true
      } catch {
        // Unreachable device (unregistered, key conflict, directory down). The
        // local copy is already gone; this device simply was not asked.
      }
    }
    return any
  }

  /** Encrypt and durably queue one control envelope to a DEVICE: no history row, a
   *  fresh transport id, and silent, so nothing about it notifies anybody. */
  private async queueControl(deviceId: string, plaintext: Uint8Array): Promise<void> {
    const entry = await this.lock.withLock(sessionLock(deviceId), async () => {
      const now = Date.now()
      const book = await this.store.loadBook(deviceId)
      const current = currentSession(book)
      const transportId = bytesToHex(newMsgId()) // fresh, never the target's id
      if (!current) {
        return this.openInitiatorEntry(deviceId, plaintext, transportId, { book, now, silent: true })
      }
      const { state, header, ciphertext } = ratchetEncrypt(deserializeRatchet(current.snapshot, now), plaintext)
      const env: WireEnvelope = {
        id: transportId,
        kind: 'normal',
        header: encodeMessageHeaderWire(header),
        ciphertext: b64encode(ciphertext),
      }
      const advanced = updateSession(book!, current.id, serializeRatchet(state), now)
      // silent: a delete is delivered without a push nudge, so deleting a message
      // never notifies anyone (it still applies in-band and on drain).
      const e: OutboxEntry = { id: transportId, to: deviceId, env, createdAt: now, silent: true }
      await this.store.saveBookWithOutbox(deviceId, advanced, e) // commit before release
      return e
    })
    this.fire(entry)
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
      //
      // Marked against the CONVERSATION and the LOGICAL MESSAGE, which for a
      // recipient with several devices are not the entry's own `to` and `id`:
      // one message is one envelope per device, so N entries share one history
      // row. Marking is monotonic, so the first device to report wins and the
      // rest are no-ops, which is what makes "sent" mean "it left this device"
      // rather than "it left for all of them".
      void this.markDelivery(e.account ?? e.to, e.contentId ?? e.id, 'sent')
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
        // Against the conversation and the logical message, for the same reason
        // `fire` marks delivery that way: with several devices, N entries share
        // one history row and one bubble.
        const account = e.account ?? e.to
        const contentId = e.contentId ?? e.id
        if (this.history) {
          await this.store.historyMarkFailed(this.history.storageKey(account, 'out', contentId)).catch(() => {})
        }
        await this.store.removeOutbox(e.id)
        this.cb.onSendFailed?.(contentId, 'delivery timed out (undelivered for too long)')
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

  // --- device rosters (Sesame) ----------------------------------------------

  /** This device's account identity. Distinct from its device identity, though on
   *  an account's first device they are the same key (see accountIdentity.ts). */
  get account(): AccountIdentity {
    // A linked device holds the account key it was given; a first device IS its
    // account, so it derives one. Both answer the same question, which is why
    // every caller asks here instead of reaching for `identity.ikSig`.
    return this.accountKeyPair
      ? { accountId: accountIdOf(this.accountKeyPair.publicKey), accountKey: this.accountKeyPair }
      : accountIdentityOf(this.identity)
  }

  /** This device's own id: what the relay authenticates and what addresses this
   *  inbox. Equal to the account id until this account links a second device. */
  get deviceId(): string {
    return deviceIdOf(this.identity.ikSig.publicKey)
  }

  /**
   * Which account a sending device belongs to (Sesame).
   *
   * Three answers, in order, and the third is what makes this invisible to
   * everyone who never links a device:
   *
   *   1. a cached roster that lists it, which is the verified answer;
   *   2. nothing, if a device claimed an account that has not listed it;
   *   3. the device id ITSELF, otherwise.
   *
   * Three is right rather than a fallback: a first device's account key IS its
   * device key, so its device id and account id are the same string. Every
   * single-device peer, which today is all of them, resolves through it without a
   * roster, a hello, or a network round trip.
   */
  async accountForDevice(deviceId: string): Promise<string> {
    try {
      const known = await this.contacts.listKnownRosters()
      for (const [accountId, roster] of Object.entries(known)) {
        if (roster.devices.includes(deviceId)) return accountId
      }
    } catch {
      /* an unreadable cache must not stop a message being filed somewhere sane */
    }
    return deviceId
  }

  /**
   * A device said which account it belongs to. Check it, and remember it if true.
   *
   * The claim itself is worth nothing: anyone can put any id in a message. What
   * makes it mean something is that the named account has to have LISTED this
   * device in a roster signed by its account key, which the relay cannot forge
   * and cannot alter. `resolveDevices` does that check, including refusing a
   * roster older than one already seen.
   *
   * A device claiming an account that has not listed it is not attributed, and it
   * is worth telling the user about: an honest device has no reason to do it.
   */
  private async handleHello(fromDeviceId: string, accountId: string): Promise<void> {
    if (accountId === fromDeviceId) return // a first device announcing itself: already true
    try {
      const devices = await this.resolveDevices(accountId)
      if (devices.includes(fromDeviceId)) return // verified, and now cached
      this.cb.onSecurity?.(
        `a device claimed to belong to ${accountId.slice(0, 12)}…, but that account has not listed it. ` +
          `Its messages are not being filed under them.`,
      )
    } catch {
      /* best-effort: an unverifiable claim is simply not acted on */
    }
  }

  /** Announce this device to `peer` on a new session, if it is a device whose id
   *  is not already its account id. A first device never needs to: its two ids are
   *  the same, so a receiver reads it correctly with no help. */
  private async maybeSendHello(peer: string): Promise<void> {
    const me = this.account
    if (me.accountId === this.deviceId) return
    const plaintext = encodeHelloMessage(newMsgId(), me.accountId)
    const entry = await this.lock.withLock(sessionLock(peer), async () => {
      const now = Date.now()
      const book = await this.store.loadBook(peer)
      if (currentSession(book)) return null // already introduced on this session
      // Sent as the session-OPENING message, not as a follow-up, so it cannot
      // arrive after the first real message and leave it unattributable.
      return this.openInitiatorEntry(peer, plaintext, bytesToHex(newMsgId()), { book, now, silent: true })
    })
    if (entry) this.fire(entry)
  }

  /**
   * Send a device being linked everything it needs to join this account (Sesame).
   *
   * `secret` came out of the QR this device just scanned, so it never crossed the
   * network. That is what authenticates the transfer in BOTH directions at once:
   * only a device holding it can open the payload, and only a device that scanned
   * the code holds it, so the receiving device learns the sender was standing in
   * the room without any key agreement at all.
   *
   * Delivered live or not at all. The payload carries this account's private key,
   * and leaving that in a relay queue for the envelope TTL would be a far worse
   * exposure than asking both devices to be awake for a few seconds, which they
   * are, because one just photographed the other's screen.
   *
   * Trust is deliberately not sent. See the note in crypto/link.ts: a linked
   * device shows every contact as unverified until a human compares safety
   * numbers on THAT device.
   */
  async sendLinkPayload(deviceId: string, secret: Uint8Array): Promise<{ chunks: number }> {
    const chunks = sealLink(await this.buildLinkPayload(), secret)
    for (const chunk of chunks) {
      // Sequential on purpose: a failure part-way is reported as a failure, and
      // the user retries the whole ceremony rather than being left with a device
      // holding half an account.
      await this.transport.request(bytesToHex(newMsgId()), {
        t: 'sendLink',
        reqId: bytesToHex(newMsgId()),
        to: deviceId,
        chunk: b64encode(chunk),
      })
    }
    return { chunks: chunks.length }
  }

  /** Everything a device needs to join this account. Gathered in one place so the
   *  two transports below cannot drift apart in what they hand over. */
  private async buildLinkPayload(): Promise<LinkPayload> {
    const me = this.account
    const contacts = await this.contacts.list()
    const aliases = await this.contacts.getAliases().catch(() => ({}))
    return {
      accountId: me.accountId,
      accountKeyPriv: me.accountKey.privateKey,
      contacts: contacts.map((c) => ({ peerId: c.peerId, ikSig: c.ikSig })),
      aliases,
      createdAt: Date.now(),
    }
  }

  /**
   * The same transfer, sealed as ONE unit for a screen rather than for the relay
   * (Sesame). The preferred way to link: this never reaches the network at all, so
   * the account key is never handed to the relay in any form, not even sealed.
   *
   * What it does NOT hide is the event. Authorizing the new device publishes a
   * roster and the new device registers itself, both over the relay, so the
   * operator still learns that an account gained a device and when. Optical is
   * about the payload, and saying otherwise would be an over-claim.
   */
  async sealLinkForOptical(secret: Uint8Array): Promise<Uint8Array> {
    const [only] = sealLink(await this.buildLinkPayload(), secret, LINK_MAX_PAYLOAD_BYTES)
    return only
  }

  // --- moving saved messages between this account's devices (DESIGN 8.12) ----

  /**
   * What a history transfer would carry if it were sent now, WITHOUT sealing
   * anything: the counts and the sealed size, so the panel can show what each
   * span of time costs before anyone commits to holding two devices together.
   *
   * `since` bounds it by message time. Everything the export path already refuses
   * is refused here for the same reasons: a row whose delete arrived is not
   * resurrected, a row that will not open is counted rather than skipped
   * silently, and a row whose peer this device holds no contact for is left out,
   * because the receiving device would have nothing to bind it to.
   */
  async prepareHistoryTransfer(since = 0): Promise<{
    messages: HistoryUnitMessage[]
    /** Rows that would not open while unlocked (corruption). Not carried. */
    unreadable: number
    /** Readable rows whose peer has no contact record. Not carried. */
    orphaned: number
    /** Sealed size, which is what actually determines how long this takes. */
    bytes: number
    /** Whether that size is over what one transfer may carry. */
    tooLarge: boolean
  }> {
    const history = this.history
    if (!history) throw new Error('history is not available on this client')
    const tombstoned = new Set(await this.store.tombstoneKeys())
    const contacts = new Set((await this.contacts.list()).map((c) => c.peerId))
    const all: HistoryUnitMessage[] = []
    let unreadable = 0
    let orphaned = 0
    for (const row of await this.store.historyLoadAll()) {
      if (tombstoned.has(row.key)) continue
      let msg
      try {
        msg = history.open(row)
      } catch {
        // Same guard the move export uses: if the app locked mid-scan every
        // remaining row would "fail to open" and the transfer would complete as a
        // silently partial one claiming success.
        if (!history.isUnlocked) throw new Error('the app locked while gathering; unlock and try again')
        unreadable++
        continue
      }
      if (msg.ts < since) continue
      if (!contacts.has(msg.peerId)) {
        orphaned++
        continue
      }
      const m: HistoryUnitMessage = { id: msg.id, peer: msg.peerId, dir: msg.dir, ts: msg.ts, text: msg.text }
      if (msg.status) m.status = msg.status
      if (row.failed && msg.dir === 'out') m.failed = true
      all.push(m)
    }
    all.sort((a, b) => a.ts - b.ts)
    // Measure by sealing for real rather than estimating: the estimate is what
    // the user decides on, so it must be the same number the send path enforces.
    let bytes = 0
    let tooLarge = false
    try {
      bytes = sealHistoryTransfer(
        { accountId: this.account.accountId, messages: all, createdAt: Date.now() },
        new Uint8Array(LINK_SECRET_BYTES),
      ).length
    } catch {
      tooLarge = true
    }
    return { messages: all, unreadable, orphaned, bytes, tooLarge }
  }

  /**
   * Seal this account's saved messages for the device showing `secret`.
   *
   * `toDevice` is checked against this account's own published device list first.
   * The seal alone proves only that the sender photographed a screen; it says
   * nothing about whose screen. Without this check, holding a phone in front of
   * somebody could walk away with every message they have.
   */
  async sealHistoryFor(toDevice: string, secret: Uint8Array, since = 0): Promise<Uint8Array> {
    if (toDevice === this.deviceId) throw new Error('that is this device\'s own code')
    const me = this.account
    const devices = await this.resolveDevices(me.accountId)
    if (!devices.includes(toDevice)) {
      throw new Error('that device is not on your account, so it is not being sent anything')
    }
    const { messages } = await this.prepareHistoryTransfer(since)
    return sealHistoryTransfer({ accountId: me.accountId, messages, createdAt: Date.now() }, secret)
  }

  /**
   * Take a transfer caught by this device's camera and merge it into history.
   *
   * MERGE, never replace: this device may already hold messages, and the point is
   * to end up with both. Rows are keyed by (peer, direction, content id), so a
   * message already here is written over itself and a transfer run twice changes
   * nothing, which is what makes it safe to simply try again.
   *
   * Returns what was added and what was refused, because both are things the
   * person needs told rather than a bare "done".
   */
  async importHistoryTransfer(
    blob: Uint8Array,
    secret: Uint8Array,
    onProgress?: (done: number, total: number) => void,
  ): Promise<{ imported: number; skippedUnknownPeer: number; skippedDeleted: number }> {
    const history = this.history
    if (!history) throw new Error('history is not available on this client')
    const payload = openHistoryTransfer(blob, secret, Date.now())
    // Sealed under our own code proves the sender was in the room, not that they
    // are us. Writing somebody else's conversations in under their peer ids would
    // put words in contacts' mouths exactly as a forged forwarded copy would.
    if (payload.accountId !== this.account.accountId) {
      throw new Error('those saved messages belong to a different account, so nothing was imported')
    }
    const contacts = new Set((await this.contacts.list()).map((c) => c.peerId))
    const tombstoned = new Set(await this.store.tombstoneKeys())
    // What this device already holds, so an incoming row can ADD to a message
    // rather than overwrite it. Merge-not-replace holds per ROW below; without
    // this it did not hold per FIELD, and the sending device is often the LESS
    // informed one: it may have queued a copy this device has since seen
    // delivered, or never learned that a send failed here. Overwriting walked
    // the delivery status backwards and cleared a `failed` flag, which re-arms a
    // resend for a message the user was told never left.
    const prior = new Map((await this.store.historyLoadAll()).map((r) => [r.key, r]))
    let imported = 0
    let skippedUnknownPeer = 0
    let skippedDeleted = 0
    const total = payload.messages.length
    let batch: HistoryRecord[] = []
    const flush = async () => {
      if (batch.length === 0) return
      await this.store.historyPutMany(batch)
      imported += batch.length
      batch = []
      onProgress?.(imported, total)
      // Yield so a progress line can paint; sealing is otherwise solid CPU.
      await new Promise((r) => setTimeout(r, 0))
    }
    for (const m of payload.messages) {
      // A peer this device holds no contact for has nothing to bind the message
      // to: no key, so no safety number, and a conversation that cannot be
      // verified. The move import refuses these for the same reason.
      if (!contacts.has(m.peer)) {
        skippedUnknownPeer++
        continue
      }
      const key = history.storageKey(m.peer, m.dir, m.id)
      // A message this device was told to delete stays deleted. The sending
      // device may never have heard about that delete, and a transfer must not
      // become a way to undo one.
      if (tombstoned.has(key)) {
        skippedDeleted++
        continue
      }
      const msg: HistoryMessage = { id: m.id, peerId: m.peer, dir: m.dir, ts: m.ts, text: m.text }
      if (m.status) msg.status = m.status
      let failed = m.failed
      const had = prior.get(key)
      if (had) {
        // Keep whichever side knows more. `failed` is sticky because only this
        // device can know its own send failed, and the status follows the same
        // monotonic rule markDelivery uses: 'delivered' is never walked back, and
        // a row that reached a state here is not reset by a copy that predates it.
        if (had.failed) failed = true
        try {
          const local = history.open(had)
          if (local.status === 'delivered' || (local.status && !msg.status)) msg.status = local.status
        } catch {
          /* an unopenable local row tells us nothing; take the incoming one */
        }
      }
      batch.push(history.seal(msg, failed))
      if (batch.length >= HISTORY_IMPORT_BATCH) await flush()
    }
    await flush()
    return { imported, skippedUnknownPeer, skippedDeleted }
  }

  // --- following a contact's account-key rotation ---------------------------
  //
  // A rotation gives one person a new account id. Everything filed under the old
  // one has to move, or "rotation preserves the relationship" is a claim about
  // the protocol that the stored state does not honor: the conversation would
  // split into a dead half and a live half with nothing saying they are the same
  // person.
  //
  // What moves and what does not, and why:
  //   - saved messages move, which is the expensive part: their storage key is an
  //     HMAC over the peer id and their AAD binds that key, so every row is
  //     re-sealed rather than relabelled;
  //   - the contact record, the name you gave them, a dismissal and the retry
  //     throttle move (contactStore.renameAccount);
  //   - SESSIONS DO NOT MOVE, and that is the good news: they are keyed by DEVICE,
  //     and a rotation changes the account key, not the devices, so every running
  //     ratchet keeps working and nobody re-establishes anything;
  //   - TOMBSTONES CANNOT MOVE. They are opaque HMACs with no stored preimage, so
  //     there is nothing to recompute a new key from. The honest consequence is
  //     narrow and worth stating: a message you deleted BEFORE this contact
  //     rotated is no longer protected from being re-imported by a later history
  //     transfer from another of your devices.
  //
  // Interruption is survivable rather than prevented. A pending-rename marker is
  // written first and cleared last, so a resume finishes the job; re-running a
  // completed step is a no-op because a row that already moved is not at the old
  // key any more. While a rename is half done the person shows as two threads,
  // which the resume collapses.

  /**
   * Replace this account's key, keeping the relationships.
   *
   * What this is FOR: a key that is gone but not in use. A phone that was lost or
   * handed on, storage you no longer trust. Contacts keep the conversation, the
   * history and the name they gave you instead of meeting a stranger.
   *
   * What it does NOT do, and the UI must say so in these words: it does not beat
   * somebody who is ACTIVELY USING the old key. They hold it too, so they can
   * sign a competing rotation that is exactly as valid as this one, and nothing
   * in the bytes tells the two apart. Every contact lands on the new key as
   * UNVERIFIED and has to re-compare safety numbers in person. Rotation preserves
   * the relationship; it never preserves the trust.
   *
   * The order is the whole safety argument. The Directory records the successor
   * FIRST, because a rotated account cannot publish a device list until it does
   * (its id belongs to no device, so there is no key to verify a roster against),
   * and only then is the new list published. If anything after the first step
   * fails, the rotation is already durable and the caller can simply run this
   * again: publishRotation is idempotent for the same successor, and refuses a
   * DIFFERENT one, so a retry can never fork the account.
   */
  async rotateAccount(onProgress?: (step: string) => void): Promise<{ accountId: string }> {
    const me = this.account
    const next = ed25519Generate()
    const statement = signRotation(me.accountId, me.accountKey.privateKey, next, Date.now())

    onProgress?.('recording the change')
    await this.directory.publishRotation(encodeRotationStatement(statement))

    // The device list, republished under the new account id. Same devices: a
    // rotation changes who the account IS, not what it reads on, which is why
    // every running session survives it untouched.
    onProgress?.('republishing your devices')
    const current = await this.directory.fetchRoster(me.accountId).catch(() => null)
    const devices: RosterDevice[] = current
      ? current.devices.map((d) => ({ deviceId: d.deviceId, dkSigPub: d.dkSigPub, addedAt: d.addedAt }))
      : [{ deviceId: this.deviceId, dkSigPub: this.identity.ikSig.publicKey, addedAt: Date.now() }]
    const roster = signRoster(statement.newAccountId, 1, devices, next.privateKey)
    await this.directory.publishRoster(encodeDeviceRoster(roster))

    // Adopt it locally only after the relay has both halves, so a device that
    // fails part-way through is still the old account and retries cleanly.
    this.accountKeyPair = next
    await this.contacts
      .putKnownRoster(statement.newAccountId, { version: 1, devices: devices.map((d) => d.deviceId) })
      .catch(() => {})

    // Tell everyone. Contacts need it to keep talking to us; our OWN devices need
    // it because they hold the retired key and would otherwise go on signing and
    // announcing as an account that has moved.
    onProgress?.('telling your contacts')
    const plaintext = encodeRotationMessage(newMsgId(), statement)
    const peers = await this.contacts.list().catch(() => [])
    for (const c of peers) {
      await this.sendControlTo(c.peerId, plaintext).catch(() => {})
    }
    for (const deviceId of devices) {
      if (deviceId.deviceId === this.deviceId) continue
      await this.sendControlTo(deviceId.deviceId, plaintext).catch(() => {})
    }
    return { accountId: statement.newAccountId }
  }

  /** Queue one control message to every device of `peer`, on the current session.
   *  Best-effort per device: a rotation that reaches three of a contact's four
   *  devices is still worth sending, and the Directory pointer covers the rest. */
  private async sendControlTo(peer: string, plaintext: Uint8Array): Promise<void> {
    const devices = await this.resolveDevices(peer).catch(() => [peer])
    for (const deviceId of devices) {
      const entry = await this.queueControl(deviceId, plaintext).catch(() => null)
      if (entry) this.fire(entry)
    }
  }

  /**
   * The Directory says this account moved. Verify that under the key we hold and,
   * if it is theirs, follow it. Returns the new account id, or null.
   *
   * This is the same check `handleRotation` runs, deliberately: a pointer served
   * by the relay is worth exactly as much as one announced over a session, which
   * is nothing until it verifies under a key this device already holds. The relay
   * is the untrusted party in both cases, and the signature is what settles it.
   */
  private async followRotation(oldId: string, st: RotationStatement): Promise<string | null> {
    if (st.oldAccountId !== oldId) return null
    const contact = await this.contacts.get(oldId).catch(() => null)
    if (!contact) return null // nobody we hold a key for: nothing to verify against
    try {
      verifyRotation(st, b64decode(contact.ikSig, 32), Date.now())
    } catch {
      // A pointer that does not verify is the relay saying something false about
      // somebody, which is worth telling the user about rather than swallowing.
      this.cb.onSecurity?.(
        `the relay said ${oldId.slice(0, 12)}… changed their account key, but the statement did not verify as ` +
          `theirs. It was ignored.`,
      )
      return null
    }
    await this.applyRotation(st.oldAccountId, st.newAccountId, b64encode(st.newAccountKey))
    this.cb.onSecurity?.(
      `${st.oldAccountId.slice(0, 12)}… changed their account key and is now ${st.newAccountId.slice(0, 12)}…. ` +
        `Your conversation moved with them, but the new key is UNVERIFIED: compare safety numbers with them in ` +
        `person before sending anything sensitive. A stolen key can sign this too.`,
    )
    return st.newAccountId
  }

  /**
   * A contact says their account key changed. Check it, then follow it.
   *
   * Three things have to hold before anything moves, and each closes a different
   * way of being moved somewhere you did not agree to go:
   *
   *   1. the statement must be ABOUT the account this message came from, so a
   *      contact cannot announce a rotation on somebody else's behalf;
   *   2. it must verify under the account key THIS DEVICE ALREADY HOLDS for them,
   *      never one that arrived with the message, which is the same rule the
   *      Directory and the roster follow;
   *   3. the successor must not already be a contact, because merging two
   *      conversations is the user's decision (renameAccount refuses it).
   *
   * Then it is applied and the user is TOLD, every time, with the honest framing:
   * their new binding is unverified, and it has to be re-checked in person. An
   * attacker holding the old key can sign a rotation exactly as validly as the
   * owner, so this notice is not decoration, it is the whole defence.
   */
  private async handleRotation(fromAccount: string, st: RotationStatement): Promise<void> {
    try {
      if (st.oldAccountId !== fromAccount) {
        this.cb.onSecurity?.(
          `${fromAccount.slice(0, 12)}… sent a key change for a different account (${st.oldAccountId.slice(0, 12)}…). ` +
            `It was ignored.`,
        )
        return
      }
      const contact = await this.contacts.get(fromAccount)
      if (!contact) return // nobody we hold a key for: nothing to verify against
      try {
        verifyRotation(st, b64decode(contact.ikSig, 32), Date.now())
      } catch (e) {
        this.cb.onSecurity?.(
          `a key change claimed for ${fromAccount.slice(0, 12)}… did not verify as theirs (${
            e instanceof Error ? e.message : String(e)
          }). It was ignored, and messages keep going to the account you already had.`,
        )
        return
      }
      const applied = await this.applyRotation(st.oldAccountId, st.newAccountId, b64encode(st.newAccountKey))
      if (applied.moved >= 0) {
        this.cb.onSecurity?.(
          `${st.oldAccountId.slice(0, 12)}… changed their account key and is now ${st.newAccountId.slice(0, 12)}…. ` +
            `Your conversation moved with them, but the new key is UNVERIFIED: compare safety numbers with them in ` +
            `person before sending anything sensitive. A stolen key can sign this too.`,
        )
      }
    } catch {
      /* best-effort: a failure here leaves the conversation exactly where it was */
    }
  }

  /**
   * Re-file everything this device holds for `oldId` under `newId`.
   *
   * The CALLER is responsible for having verified the rotation statement under
   * the account key it already holds for `oldId`. This method does not verify
   * anything: it is the storage half, and it will happily move a conversation
   * anywhere it is told to, which is exactly why nothing may call it without a
   * checked signature behind it.
   */
  async applyRotation(oldId: string, newId: string, newIkSig: string, onProgress?: (done: number, total: number) => void): Promise<{ moved: number }> {
    await this.contacts.setPendingRename(oldId, { newId, ikSig: newIkSig })
    const moved = await this.renameHistory(oldId, newId, onProgress)
    await this.contacts.renameAccount(oldId, newId, newIkSig)
    // A message QUEUED across the rotation keeps the old conversation label. It
    // is deliberately left alone: the only writer for an outbox row is the
    // atomic save that commits a ratchet advance with it, and widening that API
    // to relabel a queue entry would put a second writer on the most
    // safety-critical write in the app. The row is still addressed to a DEVICE,
    // which a rotation does not change, so the message is delivered normally and
    // the row is removed on ack. What is left stale is the label a delivery
    // indicator uses, and it fails the way indicators already fail (silently, in
    // the direction of showing less).
    await this.contacts.clearPendingRename(oldId)
    return { moved }
  }

  /** Finish any rename that was interrupted. Called on connect, where a resumed
   *  device is already doing other catch-up work. */
  async resumePendingRenames(): Promise<void> {
    const pending = await this.contacts.pendingRenames()
    for (const [oldId, to] of Object.entries(pending)) {
      try {
        await this.applyRotation(oldId, to.newId, to.ikSig)
      } catch {
        /* left pending on purpose: the next connect tries again */
      }
    }
  }

  /** Re-seal every saved message for `oldId` under `newId`. Batched, and each row
   *  is written at its new key BEFORE the old one is removed, so an interruption
   *  can only duplicate a row (which the next load dedups by content id), never
   *  lose one. */
  private async renameHistory(oldId: string, newId: string, onProgress?: (done: number, total: number) => void): Promise<number> {
    const history = this.history
    if (!history) return 0
    return this.lock.withLock(sessionLock(oldId), async () => {
      const rows = await this.store.historyLoadAll()
      const mine: Array<{ rec: HistoryRecord; msg: HistoryMessage }> = []
      for (const rec of rows) {
        try {
          const msg = history.open(rec)
          if (msg.peerId === oldId) mine.push({ rec, msg })
        } catch {
          /* an unopenable row names nobody, so it belongs to no rename */
        }
      }
      let done = 0
      for (let i = 0; i < mine.length; i += HISTORY_IMPORT_BATCH) {
        const slice = mine.slice(i, i + HISTORY_IMPORT_BATCH)
        await this.store.historyPutMany(slice.map(({ rec, msg }) => history.seal({ ...msg, peerId: newId }, rec.failed)))
        for (const { rec } of slice) await this.store.historyRemove(rec.key).catch(() => {})
        done += slice.length
        onProgress?.(done, mine.length)
        await new Promise((r) => setTimeout(r, 0))
      }
      return mine.length
    })
  }

  /**
   * The devices this account currently claims, newest addition last, with this
   * device marked. Read from the published roster so it says what CONTACTS see,
   * which is the thing worth showing: a device that is on the list can be sent to.
   */
  async listDevices(): Promise<
    Array<{ deviceId: string; addedAt: number; isThisDevice: boolean; isFirstDevice: boolean }>
  > {
    const me = this.account
    const roster = await this.directory.fetchRoster(me.accountId).catch(() => null)
    if (!roster) {
      // No roster published means an account of exactly one device: this one, which
      // is therefore also the first.
      return [{ deviceId: this.deviceId, addedAt: 0, isThisDevice: true, isFirstDevice: true }]
    }
    verifyRoster(roster, me.accountKey.publicKey, Date.now())
    return roster.devices
      .map((d) => ({
        deviceId: d.deviceId,
        addedAt: d.addedAt,
        isThisDevice: d.deviceId === this.deviceId,
        // The account's first device, whose device key IS the account key, so its
        // id is the account id. It cannot be removed from its own account, and a
        // LINKED device has to be told which row that is: from over there it looks
        // like any other entry, and offering a remove button that always fails is
        // worse than not offering one.
        isFirstDevice: d.deviceId === me.accountId,
      }))
      .sort((a, b) => a.addedAt - b.addedAt)
  }

  /**
   * Take a device off this account's list and publish the result (Sesame).
   *
   * This is NOT revocation, and the UI must not call it that. A device that was
   * linked holds the account key, so it can sign a list of its own putting itself
   * back; what this does is tell everyone else to stop sending to it, and it keeps
   * whatever it already had. For a device that is lost rather than retired, the
   * honest answer is to rotate the account key, which every contact then has to
   * re-verify.
   *
   * The FIRST device cannot be removed: its device key IS the account key, so its
   * id is the account id, and an account cannot be taken off itself.
   */
  async removeDevice(deviceId: string): Promise<number> {
    const me = this.account
    if (deviceId === me.accountId) {
      throw new Error('this account cannot remove its first device: its key is the account key')
    }
    const current = await this.directory.fetchRoster(me.accountId)
    if (!current) throw new Error('this account has no device list to remove anything from')
    verifyRoster(current, me.accountKey.publicKey, Date.now())
    const devices: RosterDevice[] = current.devices
      .filter((d) => d.deviceId !== deviceId)
      .map((d) => ({ deviceId: d.deviceId, dkSigPub: d.dkSigPub, addedAt: d.addedAt }))
    if (devices.length === current.devices.length) throw new Error('that device is not on this account')
    const version = current.version + 1
    const roster = signRoster(me.accountId, version, devices, me.accountKey.privateKey)
    const published = await this.directory.publishRoster(encodeDeviceRoster(roster))
    // The version we SIGNED, not the one the relay echoed (see authorizeDevice).
    await this.contacts
      .putKnownRoster(me.accountId, { version, devices: devices.map((d) => d.deviceId) })
      .catch(() => {})
    return published
  }

  /** Start listening for a link transfer sealed under `secret` (Sesame). Called
   *  by the device BEING linked, which generated the secret, so nothing here
   *  trusts the relay about who is sending. Returns a stop function. */
  awaitLinkPayload(secret: Uint8Array, onPayload: (payload: LinkPayload) => void): () => void {
    this.linkAwait = { secret, onPayload, chunks: new Map() }
    return () => {
      this.linkAwait = null
    }
  }

  /** A link chunk arrived. Buffer it, and open the transfer once it is complete.
   *  Bounded on both axes: chunks are grouped by the transfer id inside their own
   *  authenticated header, and a transfer that never completes simply never
   *  fires. Nothing is persisted, so an abandoned link leaves nothing behind. */
  private handleLinkChunk(chunkB64: string): void {
    const pending = this.linkAwait
    if (!pending) return // not linking: a stray chunk is nothing to us
    let chunk: Uint8Array
    let header
    try {
      chunk = b64decode(chunkB64)
      header = readLinkChunkHeader(chunk)
    } catch {
      return // not one of ours, or malformed: ignore rather than surface noise
    }
    const forTransfer = pending.chunks.get(header.transferId) ?? new Map<number, Uint8Array>()
    forTransfer.set(header.index, chunk)
    pending.chunks.set(header.transferId, forTransfer)
    if (forTransfer.size !== header.count) return

    let payload: LinkPayload
    try {
      payload = openLink([...forTransfer.values()], pending.secret)
    } catch (e) {
      // A complete-looking transfer that will not open under our own secret is
      // worth saying out loud: it means something other than the device we showed
      // the code to is talking to us.
      this.cb.onSecurity?.(
        `a device transfer arrived that this device could not open with its own linking code (${
          e instanceof Error ? e.message : String(e)
        }). It was discarded.`,
      )
      pending.chunks.delete(header.transferId)
      return
    }
    this.linkAwait = null
    pending.onPayload(payload)
  }

  /**
   * Add a device to this account's roster and publish it (Sesame, the authorizing
   * half of linking). Run on an EXISTING device after it has scanned the new
   * device's code, which is where `deviceId` and `dkSigPub` come from.
   *
   * The scan is what makes this safe. A device id IS the hash of its key, so
   * checking the two against each other means a code that was tampered with in
   * transit cannot name a device the account does not mean to add, and the relay
   * never gets a say in who joins an account.
   *
   * Publishing this is what lets the new device register at all: it consumes no
   * invite, and the roster is what stands in for one.
   */
  async authorizeDevice(deviceId: string, dkSigPub: Uint8Array): Promise<number> {
    if (deviceIdOf(dkSigPub) !== deviceId) {
      throw new Error('that device code does not match the key inside it')
    }
    const me = this.account
    const current = await this.directory.fetchRoster(me.accountId).catch(() => null)
    // Start from what is published, so a device linked from another of this
    // account's devices is not silently dropped by this one.
    const devices: RosterDevice[] = current
      ? current.devices.map((d) => ({ deviceId: d.deviceId, dkSigPub: d.dkSigPub, addedAt: d.addedAt }))
      : [{ deviceId: me.accountId, dkSigPub: me.accountKey.publicKey, addedAt: Date.now() }]
    if (!devices.some((d) => d.deviceId === deviceId)) {
      devices.push({ deviceId, dkSigPub, addedAt: Date.now() })
    }
    if (devices.length > MAX_DEVICES_PER_ACCOUNT) {
      throw new Error(`an account can hold at most ${MAX_DEVICES_PER_ACCOUNT} devices; remove one first`)
    }
    const version = (current?.version ?? 0) + 1
    const roster = signRoster(me.accountId, version, devices, me.accountKey.privateKey)
    const published = await this.directory.publishRoster(encodeDeviceRoster(roster))
    // Our own view of our own devices, so a later resolve does not read as a
    // change. Recorded at the version we SIGNED, never the one the relay echoed
    // back: this value is our own rollback high-water mark, and taking the
    // relay's number would let it hand back a low one and defeat the mark with
    // no attack more sophisticated than answering.
    await this.contacts
      .putKnownRoster(me.accountId, { version, devices: devices.map((d) => d.deviceId) })
      .catch(() => {})
    return published
  }

  /** Register THIS device as a device of `accountId` (Sesame, the joining half of
   *  linking). Mirrors `register`, minus the invite: an account's roster already
   *  listing this device is what authorizes it. */
  async registerAsDevice(accountId: string): Promise<number> {
    // A device that already has an account of its own must not join another.
    // Linking deliberately does NOT wipe: it keeps this device's identity, its
    // saved messages, its ratchet sessions and its send queue, because a link
    // ADDS a device rather than replacing one. Run it on a device that was
    // already somebody, and the result is one store holding two accounts: the old
    // account's messages and live sessions filed under the new account's identity,
    // with the old contact list replaced out from under them. Refuse at the
    // protocol layer, not just by hiding the button.
    if (this.isRegistered) {
      throw new Error('this device already has an account of its own; erase it before joining another')
    }
    return this.lock.withLock(REPLENISH_LOCK, async () => {
      const now = Date.now()
      const own = buildOwnBundle(this.identity, now, { spkId: 1, opkStartId: 1, opkCount: OPK_BATCH })
      await this.prekeys.setFromRegistration({
        spk: { id: own.spk.id, createdAt: own.spk.createdAt, expiry: own.spk.expiry, pub: own.spk.pub, sig: own.spk.sig },
        spkPrivById: own.spkPrivById,
        opks: own.opks,
        opkPrivById: own.opkPrivById,
      })
      const opkCount = await this.directory.registerDevice(
        accountId,
        encodePublishedBundle({
          version: OWN_BUNDLE_VERSION,
          ikSigPub: own.ikSigPub,
          ikDhPub: own.ikDhPub,
          idkbindSig: own.idkbindSig,
          spk: own.spk,
          opks: own.opks,
        }),
      )
      await this.prekeys.confirmRegistration(own.spk.id).catch(() => {})
      if (this.authed) this.authed = { ...this.authed, registered: true, opkCount }
      return opkCount
    })
  }

  /**
   * Where to reach `accountId`: every device that account claims, or just the
   * account itself when it claims none.
   *
   * An account with no roster is not a failure and is not unusual, it is every
   * account that has never linked a second device. Such an account IS a single
   * device at its own id, which is what makes multi-device invisible to everyone
   * who never uses it.
   *
   * Nothing here trusts the relay. A roster is believed only if it verifies under
   * an account key this device already holds (the contact's recorded key, or our
   * own), and only if it is NEWER than the highest version already accepted for
   * that account. That second check is the one that binds: the Directory refusing
   * to go backwards can be undone by an operator who owns the Directory, but it
   * cannot make this device forget what it has already seen.
   *
   * On anything suspicious this returns the LAST GOOD answer rather than the new
   * one, because failing closed here would mean failing to deliver.
   */
  async resolveDevices(accountId: string): Promise<string[]> {
    const known = await this.contacts.getKnownRoster(accountId).catch(() => null)
    const fallback = known?.devices.length ? known.devices : [accountId]
    // The key to verify under: our own account key for ourselves, otherwise the
    // key already recorded for this contact. With no contact record there is
    // nothing to verify against, so the account is addressed as one device.
    let accountKeyPub: Uint8Array
    if (accountId === this.account.accountId) {
      accountKeyPub = this.account.accountKey.publicKey
    } else {
      const contact = await this.contacts.get(accountId).catch(() => null)
      if (!contact) return fallback
      accountKeyPub = b64decode(contact.ikSig, 32)
    }

    let roster
    let rotation
    try {
      const answer = await this.directory.fetchRosterWithRotation(accountId)
      roster = answer.roster
      rotation = answer.rotation
    } catch {
      return fallback // offline or relay trouble: keep using what we know
    }
    // They rotated their account key while we were not listening, and the
    // announcement never reached us (offline past the queue's TTL, or a session
    // that could not be read). Following it here is the repair, and it happens at
    // the one moment it matters: somebody is about to send them something.
    //
    // NOT followed for our OWN account. A rotation performed on another of this
    // account's devices leaves this one holding the retired PRIVATE key, and
    // adopting the new id without the key to sign for it would produce a device
    // that claims an account it cannot act for. That device has to be added
    // again, which is the honest cost recorded on the rotate screen.
    if (rotation && accountId !== this.account.accountId) {
      const followed = await this.followRotation(accountId, rotation).catch(() => null)
      if (followed) return this.resolveDevices(followed)
    }
    if (!roster) {
      // No roster published. Only meaningful if we had one before, which would
      // mean an account's devices vanished from the Directory; keep what we know.
      return fallback
    }

    try {
      verifyRoster(roster, accountKeyPub, Date.now())
    } catch (e) {
      this.cb.onSecurity?.(
        `the device list served for ${accountId.slice(0, 12)}… did not verify as theirs (${
          e instanceof Error ? e.message : String(e)
        }). Messages will keep going to the devices already known for them.`,
      )
      return fallback
    }
    if (!isRosterNewer(roster, known?.version ?? null)) {
      // A valid signature over stale facts. The signature cannot detect this, only
      // memory can, which is why the memory exists.
      if (roster.version < (known?.version ?? 0)) {
        this.cb.onSecurity?.(
          `an out-of-date device list was served for ${accountId.slice(0, 12)}… (version ${roster.version}, ` +
            `after ${known?.version}). It was refused. If they recently removed a device, ask them to check.`,
        )
      }
      return fallback
    }

    const devices = rosterDeviceIds(roster)
    // The baseline for a FIRST sighting is the one device we have been addressing
    // them as, not nothing. This is the whole alert, not a detail: an account
    // publishes no roster until it links a second device, and the publisher always
    // seeds the list with its own device, so an account's first roster is ALWAYS
    // version 1 with two devices. Diffing that against nothing and then suppressing
    // it (the old `known &&`) silenced the only shape this event ever has, for
    // contacts AND for your own account, where a first roster you did not publish
    // is precisely what a stolen account key produces.
    const { added, removed } = rosterDiff(known?.devices ?? [accountId], devices)
    await this.contacts.putKnownRoster(accountId, { version: roster.version, devices }).catch(() => {})
    if (added.length > 0 || removed.length > 0) {
      // The event a contact has to be told about. An operator cannot cause it: a
      // roster is signed by the account key. So it is either a device that account
      // really linked, or something already holding their account key, and only
      // the person can tell which.
      //
      // `first` says this is the first list we have ever seen for them, so the UI
      // can say "reads on N devices" rather than "added a device" for somebody we
      // only just met, without the security case losing its alert.
      this.cb.onDevicesChanged?.(accountId, { added, removed, first: !known })
    }
    return devices
  }

  // --- the retry-receipt (DESIGN 8.10) --------------------------------------
  //
  // When one side loses its half of a session (a move, a restore, an evicted
  // database), the other side keeps encrypting to a ratchet nobody can open. Those
  // messages are poison-dropped and ACKED, so the relay reports them delivered and
  // neither person learns anything is wrong (8.9). The device that cannot read them
  // asks the sender to re-establish and send its recent messages again.
  //
  // The two bounds sit on opposite sides deliberately. This half is the polite one
  // and protects nobody: a hostile requester runs whatever client it likes. The
  // bound that holds is `honorRetryRequest` below, enforced by the device whose
  // messages are at stake.

  /**
   * Ask `peer` to resend, if this device has not asked too recently or too often.
   * Best-effort throughout: recovery is a convenience and must never interfere
   * with handling the message that triggered it.
   *
   * `peer` is the ACCOUNT, which is what the throttle, the ledger and the contact
   * check are all keyed by, so a contact reading on three devices produces one ask
   * rather than three. `toDevice` is which of their devices to send it to, and
   * defaults to the account (their first device). They are separated because the
   * bound is about a person and the delivery is about a machine.
   */
  private async maybeRequestRetry(peer: string, toDevice = peer): Promise<void> {
    if (this.askedRetryFrom.has(peer)) return // one ask per run per peer; the ledger covers restarts
    try {
      // Same gate as the unreadable notice: only a contact we still hold, and not
      // one the user deleted. A deleted peer's backlog must stay anonymous AND must
      // not cause this device to reach out to them on its own initiative.
      if ((await this.contacts.trustLevel(peer)) === null) return
      if ((await this.contacts.dismissedAt(peer)) !== null) return

      const now = Date.now()
      let proceed = false
      let exhausted = false
      // Check and record in ONE hold of the contacts lock. Two undecryptable
      // envelopes arriving together would otherwise both read "not asked yet".
      // Recording BEFORE sending is deliberate: a burned attempt costs one delayed
      // recovery, while a send that fails after a successful check could be retried
      // by every redelivery in the queue.
      await this.contacts.mutateRetryState(
        peer,
        (r) => {
          const attempts = r.attempts ?? 0
          if (attempts >= RETRY_REQUEST_MAX_ATTEMPTS) {
            exhausted = true
            return
          }
          if (r.askedAt !== undefined && now - r.askedAt < RETRY_REQUEST_MIN_INTERVAL_MS) return
          r.askedAt = now
          r.attempts = attempts + 1
          proceed = true
        },
        now,
      )
      if (exhausted) {
        // Say so once per run, then stop: a third unanswered ask means something is
        // wrong that asking a fourth time will not fix.
        if (!this.notedRetryExhausted.has(peer)) {
          this.notedRetryExhausted.add(peer)
          this.cb.onRetryExhausted?.(peer)
        }
        return
      }
      if (!proceed) return
      this.askedRetryFrom.add(peer)
      try {
        await this.sendRetryRequest(toDevice)
      } catch (e) {
        // The ask never left this device (they are unregistered right now, or the
        // directory is unreachable). Give the attempt back, because the exhausted
        // notice tells the user we asked and got no answer, and saying that about
        // a request that was never sent would be a lie. `askedAt` deliberately
        // STAYS, so the next try still waits out the interval rather than
        // retrying on every redelivery in the queue.
        await this.contacts
          .mutateRetryState(peer, (r) => {
            r.attempts = Math.max(0, (r.attempts ?? 1) - 1)
          })
          .catch(() => {})
        throw e
      }
      this.cb.onRetryRequested?.(peer)
    } catch {
      /* best-effort: the next redelivery tries again once the throttle allows */
    }
  }

  /** Queue the request itself: a control carrying no target, on the current session
   *  if one exists and otherwise on a fresh initiator session (which is the usual
   *  case, since needing to ask generally means holding no session at all). Silent,
   *  like every other control: nothing user-visible arrives at the other end. */
  private async sendRetryRequest(peer: string): Promise<void> {
    const plaintext = encodeRetryRequest(newMsgId())
    const entry = await this.lock.withLock(sessionLock(peer), async () => {
      const now = Date.now()
      const book = await this.store.loadBook(peer)
      const current = currentSession(book)
      const transportId = bytesToHex(newMsgId())
      if (!current) return this.openInitiatorEntry(peer, plaintext, transportId, { book, now, silent: true })
      const { state, header, ciphertext } = ratchetEncrypt(deserializeRatchet(current.snapshot, now), plaintext)
      const env: WireEnvelope = {
        id: transportId,
        kind: 'normal',
        header: encodeMessageHeaderWire(header),
        ciphertext: b64encode(ciphertext),
      }
      const advanced = updateSession(book!, current.id, serializeRatchet(state), now)
      const e: OutboxEntry = { id: transportId, to: peer, env, createdAt: now, silent: true }
      await this.store.saveBookWithOutbox(peer, advanced, e) // commit before release; no history row
      return e
    })
    this.fire(entry)
  }

  /** Something from `peer` decrypted, so whatever this device was asking them to
   *  repair is repaired. Clears the ask-state so a future break can ask again.
   *  Gated on the in-RAM set so an ordinary inbound message costs no ledger write. */
  private async clearRetryAsk(peer: string): Promise<void> {
    if (!this.askedRetryFrom.delete(peer)) return
    this.notedRetryExhausted.delete(peer)
    await this.contacts
      .mutateRetryState(peer, (r) => {
        delete r.askedAt
        delete r.attempts
      })
      .catch(() => {})
  }

  /**
   * Act on a resend request from `peer`: send our own recent messages to them
   * again. This is the half that has to hold, because the requester chooses what
   * their client does and this device is the one whose messages are at stake.
   *
   * Three bounds, all enforced here:
   *   - one honored request per requester per RETRY_HONOR_MIN_INTERVAL_MS,
   *     recorded durably before anything is sent;
   *   - at most RETRY_RESEND_MAX_MESSAGES messages, from at most the last
   *     RETRY_RESEND_WINDOW_MS, whichever binds first;
   *   - nothing at all for a peer this device does not hold as a contact.
   *
   * A resend can only ever reach the identity that was already the recipient: it
   * goes to a userId that IS SHA-256(IK_sig), on a session authenticated to that
   * key. What it does change is what a STOLEN identity is worth, which is why the
   * window is short and why the user is always told this happened (8.10, 1.3).
   *
   * The bound is per ACCOUNT while the resend goes to the DEVICE that asked, and
   * both halves of that matter. Per account, because otherwise someone reading on
   * three devices could pull three times the cap by asking from each in turn, and
   * the cap is what limits a stolen identity. To the asking device, because it is
   * the one that could not read them: sending to the account would deliver to
   * their first device, which is the one that was probably fine.
   */
  private async honorRetryRequest(peer: string, toDevice = peer): Promise<void> {
    if (!this.history) return
    if (this.honoringRetry.has(peer)) return
    this.honoringRetry.add(peer)
    try {
      if ((await this.contacts.trustLevel(peer)) === null) return
      const now = Date.now()
      let proceed = false
      await this.contacts.mutateRetryState(
        peer,
        (r) => {
          if (r.honoredAt !== undefined && now - r.honoredAt < RETRY_HONOR_MIN_INTERVAL_MS) return
          r.honoredAt = now
          proceed = true
        },
        now,
      )
      if (!proceed) return

      const rows = await this.collectResendable(peer, now)
      // Send oldest first so they arrive in the order they were originally written.
      let sent = 0
      for (const row of rows) {
        try {
          await this.queueResend(toDevice, row.id, row.text)
          sent++
        } catch {
          break // the session or the store is unhappy; stop rather than thrash
        }
      }
      // Reported even when nothing matched, because "someone asked" is the fact the
      // user needs, and a silent no-op would hide exactly the case worth seeing.
      this.cb.onRetryHonored?.(peer, sent)
    } catch {
      /* best-effort */
    } finally {
      this.honoringRetry.delete(peer)
    }
  }

  /** The bounded set of our own recent messages to `peer`, oldest first. Ephemeral
   *  messages are structurally absent (never persisted), deleted ones were removed
   *  from history when they were deleted, and rows marked failed are skipped: the
   *  sender has been told those never left, so quietly delivering them now would
   *  make the two devices disagree about what was said. */
  private async collectResendable(peer: string, now: number): Promise<Array<{ id: string; text: string; ts: number }>> {
    const history = this.history
    if (!history) return []
    const cutoff = now - RETRY_RESEND_WINDOW_MS
    const tombstoned = new Set(await this.store.tombstoneKeys())
    const out: Array<{ id: string; text: string; ts: number }> = []
    for (const row of await this.store.historyLoadAll()) {
      if (row.failed || tombstoned.has(row.key)) continue
      let m
      try {
        m = history.open(row)
      } catch {
        continue // unreadable row: nothing to resend from it
      }
      if (m.peerId !== peer || m.dir !== 'out' || m.ts < cutoff) continue
      out.push({ id: m.id, text: m.text, ts: m.ts })
    }
    out.sort((a, b) => a.ts - b.ts)
    return out.slice(-RETRY_RESEND_MAX_MESSAGES) // newest N, still oldest-first
  }

  /** Queue one message for redelivery under its ORIGINAL content id but a FRESH
   *  transport id. The content id is what makes this idempotent: the receiver keys
   *  history by it, so a copy they already hold upserts the same row instead of
   *  appearing twice. The transport id must NOT be reused, or a receiver that did
   *  once see the original would ack-and-drop this as a relay duplicate, which is
   *  precisely the case worth repairing. No history row is written: this device
   *  already has one, and re-sealing it would rewrite its timestamp. */
  private async queueResend(peer: string, contentIdHex: string, text: string): Promise<void> {
    const plaintext = encodeTextMessage(hexToBytes(contentIdHex), text, false)
    const entry = await this.lock.withLock(sessionLock(peer), async () => {
      const now = Date.now()
      const book = await this.store.loadBook(peer)
      const current = currentSession(book)
      const transportId = bytesToHex(newMsgId())
      // Silent: the requesting device is by definition awake and just asked, so a
      // push per resent message would be a notification storm for no benefit.
      if (!current) return this.openInitiatorEntry(peer, plaintext, transportId, { book, now, silent: true })
      const { state, header, ciphertext } = ratchetEncrypt(deserializeRatchet(current.snapshot, now), plaintext)
      const env: WireEnvelope = {
        id: transportId,
        kind: 'normal',
        header: encodeMessageHeaderWire(header),
        ciphertext: b64encode(ciphertext),
      }
      const advanced = updateSession(book!, current.id, serializeRatchet(state), now)
      const e: OutboxEntry = { id: transportId, to: peer, env, createdAt: now, silent: true }
      await this.store.saveBookWithOutbox(peer, advanced, e)
      return e
    })
    this.fire(entry)
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
        // Cache-only, as that dep requires: this runs inside the per-peer lock.
        accountOf: (deviceId) => this.accountForDevice(deviceId),
        selfAccountId: this.account.accountId,
      })
    } catch (e) {
      // Transient (retry on redelivery) or a surfaced security event: do NOT ack.
      if (e instanceof KeyConflictError) {
        this.cb.onSecurity?.(
          `an incoming message presented a key that conflicts with the one stored for ${from.slice(0, 12)}…; the message was refused. Verify safety numbers with this contact.`,
        )
      } else {
        // A message that has now failed twice is not a reordering that will heal
        // itself: ask them to re-establish and send it again (8.10). Deliberately
        // far below the poison bound, because the relay redelivers only when a
        // socket connects, so waiting for the drop would mean ten app sessions.
        if (e instanceof UndecryptableError && e.attempts >= RETRY_REQUEST_AFTER_ATTEMPTS) {
          // Keyed by the person, addressed to the device whose messages will not
          // open. Resolving the account matters rather than being tidy: the gate
          // inside is "is this a contact I still hold", and a contact record is
          // filed under an account, so passing the raw device id would make every
          // ask from a contact's SECOND device silently do nothing.
          void this.accountForDevice(from).then((acct) => this.maybeRequestRetry(acct, from))
        }
        this.cb.onError?.(String(e instanceof Error ? e.message : e))
      }
      return
    }
    // processInbound persisted before returning, so a delivered plaintext is
    // durably consumed. Deliver to the UI FIRST, then ack best-effort: a lost ack
    // only causes an idempotent redelivery (hasSeen -> duplicate). `duplicate` and
    // `dropped` are just acked (the latter stops a poison redelivery).
    let retryRequested = false
    let helloFrom: string | null = null
    let rotation: RotationStatement | null = null
    /** Work for this account's OTHER devices, run strictly after the ack. */
    let forward: (() => void) | null = null
    // Who this is FROM, as a person. `from` is a routing label naming one of their
    // devices; everything the user sees, and everything the trust layer holds, is
    // keyed by the account. The two are the same string for every single-device
    // peer, which is what makes this invisible to conversations that have not
    // grown a second device.
    const account = await this.accountForDevice(from)
    if (res.kind === 'delivered') {
      // Classify the plaintext for RENDERING (the persist decision already ran,
      // atomically, inside processInbound). decodeMessage is total; this runs
      // strictly after the commit, so a malformed/delete record only changes what
      // the UI shows, never protocol state. Route: text/legacy -> render; delete
      // (P10d) -> apply a removal; retry (8.10) -> answer it after the ack;
      // malformed -> render nothing (forward-compat).
      const decoded = decodeMessage(res.plaintext)
      if (decoded.kind === 'text') {
        // A text whose delete-for-everyone already arrived was suppressed by the
        // inbound processor (not persisted, tombstoned): do not render it.
        if (!res.suppressed) {
          const contentId = bytesToHex(decoded.id)
          this.cb.onMessage(account, { id: contentId, text: decoded.body, ts: now, ephemeral: decoded.ephemeral })
          // The sender did not say it addressed this account's other devices, so
          // they have not seen this and never will unless it is passed on. An
          // ephemeral message is deliberately never passed on (8.7).
          if (!decoded.fanned && !decoded.ephemeral) {
            forward = () => void this.forwardToOwnDevices(account, contentId, decoded.body, now)
          }
        }
      } else if (decoded.kind === 'legacy') {
        this.cb.onMessage(account, { id: env.id, text: decoded.body, ts: now })
      } else if (decoded.kind === 'delete') {
        // Delete-for-everyone (P10d). The target row was removed + tombstoned
        // atomically inside processInbound; tell the UI to drop the bubble too.
        const targetId = bytesToHex(decoded.id)
        this.cb.onDelete?.(account, targetId)
        forward = () => void this.forwardDeleteToOwnDevices(account, targetId)
      } else if (decoded.kind === 'syncRecv') {
        // A message a contact sent, passed on by another of this account's devices
        // because the contact's app addressed that one only. Persistence already
        // decided (and refused, if the sender was not one of ours) inside
        // processInbound; this only mirrors it into the open UI. Deliberately NOT
        // forwarded again: only the device that received the original forwards, so
        // there is no path for copies to circulate between siblings.
        if (!res.suppressed && account === this.account.accountId) {
          this.cb.onMessage(decoded.accountId, { id: bytesToHex(decoded.id), text: decoded.body, ts: decoded.ts })
        }
      } else if (decoded.kind === 'syncDelete' || decoded.kind === 'syncRecvDelete') {
        // Another of this account's devices deleted a message: one it sent (0x07)
        // or one it received (0x09). The row is already gone, removed atomically
        // inside processInbound; this drops the bubble in an open window too,
        // which otherwise kept showing a message that no longer exists on disk
        // until the next reload.
        if (account === this.account.accountId) {
          this.cb.onDelete?.(decoded.accountId, bytesToHex(decoded.id))
        }
      } else if (decoded.kind === 'syncSent') {
        // Persistence already decided (and refused, if this was not one of our own
        // devices) inside processInbound; this only mirrors it into the open UI.
        if (!res.suppressed && account === this.account.accountId) {
          this.cb.onSyncedSent?.(decoded.accountId, {
            id: bytesToHex(decoded.id),
            text: decoded.body,
            ts: decoded.ts,
          })
        }
      } else if (decoded.kind === 'hello') {
        // A device saying which account it belongs to (Sesame). Verified after the
        // ack, like every other convenience: attribution must never sit between a
        // decrypted message and its acknowledgement.
        helloFrom = decoded.accountId
      } else if (decoded.kind === 'retry') {
        // A resend request (8.10). Nothing is rendered and nothing was persisted
        // (planHistory classifies it as nothing to store); it is answered below,
        // strictly after the ack.
        retryRequested = true
      } else if (decoded.kind === 'rotation') {
        // A contact saying their account key changed. Verified and applied after
        // the ack, like every other convenience here: re-filing a conversation
        // must never sit between a decrypted message and its acknowledgement.
        rotation = decoded.statement
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
      void this.noteUnreadableFrom(account)
      // Normally the ask already went out many redeliveries ago; this covers the
      // envelope that was already most of the way to the bound when this build
      // arrived, and costs nothing when it has (the throttle declines it).
      void this.maybeRequestRetry(account, from)
      this.cb.onError?.(`dropped a message that could not be read: ${res.reason}`)
    }
    try {
      this.transport.raw({ t: 'ack', id: env.id })
    } catch {
      // Socket gone; the relay redelivers and we re-ack on reconnect.
    }
    // After the ack, never before it: recovering a contact is a trust convenience
    // and must not sit between a decrypted message and its acknowledgement. The
    // same rule covers both halves of the retry-receipt, which are convenience too:
    // answering someone's request, and noting that our own conversation with them
    // is working again (anything from them decrypting is the evidence for that).
    if (res.kind === 'delivered') {
      // All keyed by the person: a contact record, a recovery ledger entry and a
      // resend are about somebody, not about one of their devices.
      void this.recoverContact(account, now)
      void this.clearRetryAsk(account)
      if (retryRequested) void this.honorRetryRequest(account, from)
      if (helloFrom) void this.handleHello(from, helloFrom)
      if (rotation) void this.handleRotation(account, rotation)
      // Passing a copy to this account's own other devices is housekeeping too,
      // and the most expensive of it (an encrypt and a commit per sibling), so it
      // waits behind the acknowledgement like everything else here.
      forward?.()
    }
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
