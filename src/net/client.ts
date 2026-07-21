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

import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { type Identity, deriveUserId } from '../crypto/identity'
import type { PushSubscriptionInfo } from '../platform'
import { decodeMessage, encodeDeleteMessage, encodeTextMessage, newMsgId } from '../crypto/message'
import { OPK_BATCH, OPK_REPLENISH_THRESHOLD, OUTBOX_RETRY_HORIZON_MS, SPK_ROTATION_MS } from '../crypto/constants'
import { OWN_BUNDLE_VERSION, buildOwnBundle, generateOneTimePrekeys, generateSignedPrekey } from '../crypto/prekeys'
import { deserializeRatchet, initRatchetInitiator, ratchetEncrypt, serializeRatchet } from '../crypto/ratchet'
import { x3dhInitiate } from '../crypto/x3dh'
import { type Contact, type ContactStore, type TrustLevel, KeyConflictError } from '../trust/contactStore'
import type { InviteArtifact } from '../trust/inviteArtifact'
import { currentSession, promoteSession, updateSession } from '../session/sessionBook'
import type { HistoryStore } from '../storage/historyStore'
import type { Lock } from '../storage/lock'
import type { PrekeyStore } from '../storage/prekeyStore'
import type { OutboxEntry, SessionStore } from '../storage/sessionStore'
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

// Reconnect backoff (P8): exponential with jitter, capped. A dropped socket
// self-heals; the UI additionally kicks reconnectNow() on visibility/online.
const RECONNECT_MIN_MS = 1000
const RECONNECT_MAX_MS = 60 * 1000

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
  /** Optional: the authenticated connection came up (true) or dropped (false).
   *  Fires on every transition, including automatic reconnects. */
  onConnection?: (connected: boolean) => void
}

export class NightjarClient {
  readonly transport: Transport
  readonly directory: DirectoryClient
  private authed: AuthedInfo | null = null
  private closed = false
  private connecting = false
  private reconnectAttempt = 0
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null

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
    // Age out client-side dedup/failure rows (P8). Best-effort maintenance;
    // the replay guard is intentionally never pruned (DESIGN 4.3).
    void this.store.pruneExpired(Date.now()).catch(() => {})
    // Retry trust work that failed transiently on an earlier connect (P8).
    void this.flushPendingTrust().catch(() => {})
  }

  /** Land pending trust work: the inviter pin (DESIGN 6.3) and inbound
   *  first-contact records whose original writes failed after their sessions
   *  had already committed. Each item is removed only once it lands (or is
   *  proven conflicting, which is surfaced as a security event). */
  private async flushPendingTrust(): Promise<void> {
    const pending = await this.contacts.getPendingTrust()
    for (const r of pending.records) {
      try {
        await this.contacts.recordFirstContact(r.peerId, b64decode(r.ikSig, 32), Date.now())
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
        await this.addInviteContact(pending.inviterPin)
        await this.contacts.mutatePendingTrust((p) => {
          delete p.inviterPin
        })
      } catch {
        // Keep it; retried next connect.
      }
    }
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
    if (!permanent) return
    // Flag the persisted outbound row failed BEFORE dropping the outbox entry, so
    // a reload re-renders it as "not sent" rather than as delivered. The row is
    // keyed by (peer, out, contentId); the peer comes from the outbox entry (both
    // keyed by ref == contentId). Best-effort: the live onSendFailed already flags
    // the in-RAM bubble regardless.
    void (async () => {
      try {
        if (this.history) {
          const entry = (await this.store.pendingOutbox()).find((e) => e.id === ref)
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
  async addInviteContact(inviterUserId: string): Promise<void> {
    const { bundle } = await this.directory.fetchBundle(inviterUserId)
    if (!bundle) throw new Error(`inviter ${inviterUserId} is not registered`)
    if (deriveUserId(bundle.ikSigPub) !== inviterUserId) throw new Error('inviter key does not match its id')
    await this.contacts.recordFirstContact(inviterUserId, bundle.ikSigPub, Date.now(), 'invite')
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
  async sendText(to: string, text: string, msgId?: string, uiTs?: number): Promise<string> {
    const contentIdHex = msgId ?? bytesToHex(newMsgId())
    // The ratchet plaintext is the structured NJM1 record (not raw utf8): it
    // carries the content id + kind + ephemeral flag both sides need. P10b always
    // sends non-ephemeral text; the ephemeral toggle is P10e.
    const plaintext = encodeTextMessage(hexToBytes(contentIdHex), text, false)
    const entry = await this.lock.withLock(sessionLock(to), async () => {
      const now = Date.now()
      const ts = uiTs ?? now
      const book = await this.store.loadBook(to)
      const current = currentSession(book)
      // Seal the sent message for history (skipped when history is not wired).
      // Done inside the lock, before the commit, so a seal failure aborts the send
      // with nothing queued; the history row rides the same tx as the ratchet
      // advance + outbox (commit before release). Stamped with the UI ts so live
      // and hydrated ordering agree.
      const historyRow = this.history
        ? this.history.seal({ id: contentIdHex, peerId: to, dir: 'out', ts, text })
        : undefined

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

      // No session: fetch the peer bundle, run the trust check against its IK_sig,
      // and open a new initiator session only if the key is trusted (DESIGN 6.4).
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
      // established peer takes the current-session branch (below) and never
      // touches the contact store, so if this record were only best-effort AFTER
      // the commit, a single contacts-store hiccup would leave a durable session
      // with no contact record: the peer would be unverifiable forever (no stored
      // IK_sig -> no safety number, the priority-1 control). Recording first means
      // a failure aborts this first-contact send with nothing queued to lose; the
      // retry re-fetches, re-assesses, and re-records cleanly.
      if (a.outcome === 'first-contact') {
        await this.contacts.recordFirstContact(to, bundle.ikSigPub, now)
      }

      const ini = x3dhInitiate(this.identity, bundle, now)
      const state0 = initRatchetInitiator(ini.sk, ini.ad, bundle.spk.pub)
      const { state, header, ciphertext } = ratchetEncrypt(state0, plaintext)
      const env: WireEnvelope = {
        id: contentIdHex,
        kind: 'initial',
        header: encodeMessageHeaderWire(header),
        ciphertext: b64encode(ciphertext),
        initialHeader: encodeInitialHeader(ini.header),
      }
      const promoted = promoteSession(book, serializeRatchet(state), now)
      const e: OutboxEntry = { id: contentIdHex, to, env, createdAt: now }
      await this.store.saveBookWithOutbox(to, promoted, e, historyRow)
      return e
    })
    this.fire(entry)
    return entry.id
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

  /**
   * Delete-for-everyone a message YOU sent (P10d, DESIGN 8.6). Always removes the
   * local copy; whether the peer is asked to remove it too depends on delivery
   * state:
   *   - still queued in your OWN outbox (not yet delivered): CANCEL the send
   *     (drop the outbox entry) rather than transmit it and then chase it with a
   *     delete. Nothing was delivered, so there is nothing to recall.
   *   - already delivered (not in the outbox): send a `delete{contentId}` control
   *     with its OWN fresh transport id (the two-id rule) on the current session.
   *
   * `id` is the content msgId (hex) the bubble/history is keyed by. Returns whether
   * a delete request was actually sent to the peer. Best-effort and honest-client-
   * dependent: a delivered delete only asks; it is never a guarantee (see 8.6), so
   * the UI says "delete sent", never "deleted for everyone".
   */
  async deleteForEveryone(peer: string, id: string): Promise<{ requested: boolean }> {
    // A text's outbox entry is keyed by its content id (the two-id rule makes them
    // equal for a first-send text), so a still-queued target is found by that id.
    const stillQueued = (await this.store.pendingOutbox()).some((e) => e.id === id && e.to === peer)
    // Remove the local sent copy regardless (dir='out').
    if (this.history) await this.store.historyRemove(this.history.storageKey(peer, 'out', id)).catch(() => {})
    if (stillQueued) {
      await this.store.removeOutbox(id).catch(() => {})
      return { requested: false }
    }
    const sent = await this.sendDeleteControl(peer, id)
    return { requested: sent }
  }

  // Encrypt + queue a delete control targeting content id `targetId` on the peer's
  // current session, with its OWN fresh transport id (never the target's id: reusing
  // it would make the relay treat the delete as a duplicate of the original and drop
  // it, and would clobber a still-queued original in the outbox). The control is not
  // itself persisted to history. If no session exists we never delivered the target,
  // so there is nothing to recall.
  private async sendDeleteControl(peer: string, targetId: string): Promise<boolean> {
    const plaintext = encodeDeleteMessage(hexToBytes(targetId))
    const entry = await this.lock.withLock(sessionLock(peer), async () => {
      const now = Date.now()
      const book = await this.store.loadBook(peer)
      const current = currentSession(book)
      if (!current) return null
      const { state, header, ciphertext } = ratchetEncrypt(deserializeRatchet(current.snapshot, now), plaintext)
      const transportId = bytesToHex(newMsgId()) // fresh 16-byte id, distinct from targetId
      const env: WireEnvelope = {
        id: transportId,
        kind: 'normal',
        header: encodeMessageHeaderWire(header),
        ciphertext: b64encode(ciphertext),
      }
      const advanced = updateSession(book!, current.id, serializeRatchet(state), now)
      const e: OutboxEntry = { id: transportId, to: peer, env, createdAt: now }
      await this.store.saveBookWithOutbox(peer, advanced, e) // commit before release; no history row
      return e
    })
    if (!entry) return false
    this.fire(entry)
    return true
  }

  // Fire a queued envelope at the socket and arrange for its outbox entry to be
  // dropped when the relay acks durable storage (`sent`). Retransmission on a
  // later flush re-sends the byte-identical stored envelope; the relay dedups.
  private fire(e: OutboxEntry): void {
    void this.transport.waitSent(e.id).then(() => this.store.removeOutbox(e.id))
    try {
      this.transport.raw({ t: 'send', to: e.to, env: e.env as WireEnvelope })
    } catch {
      // Not connected; the entry stays queued and flushes on reconnect.
    }
  }

  private async flushOutbox(): Promise<void> {
    const now = Date.now()
    for (const e of await this.store.pendingOutbox()) {
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
      this.cb.onError?.(`dropped an undecryptable message from ${from.slice(0, 8)}…: ${res.reason}`)
    }
    try {
      this.transport.raw({ t: 'ack', id: env.id })
    } catch {
      // Socket gone; the relay redelivers and we re-ack on reconnect.
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
