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

import { type Identity, deriveUserId } from '../crypto/identity'
import type { PushSubscriptionInfo } from '../platform'
import { utf8 } from '../crypto/primitives'
import { OPK_BATCH, OPK_REPLENISH_THRESHOLD, OUTBOX_RETRY_HORIZON_MS } from '../crypto/constants'
import { OWN_BUNDLE_VERSION, buildOwnBundle, generateOneTimePrekeys } from '../crypto/prekeys'
import { deserializeRatchet, initRatchetInitiator, ratchetEncrypt, serializeRatchet } from '../crypto/ratchet'
import { x3dhInitiate } from '../crypto/x3dh'
import { type Contact, type ContactStore, type TrustLevel, KeyConflictError } from '../trust/contactStore'
import type { InviteArtifact } from '../trust/inviteArtifact'
import { currentSession, promoteSession, updateSession } from '../session/sessionBook'
import type { Lock } from '../storage/lock'
import type { PrekeyStore } from '../storage/prekeyStore'
import type { OutboxEntry, SessionStore } from '../storage/sessionStore'
import {
  type Envelope,
  type WireEnvelope,
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

const decode = (b: Uint8Array) => new TextDecoder().decode(b)
const sessionLock = (peerId: string) => `nightjar-session:${peerId}`
const REPLENISH_LOCK = 'nightjar-opk-replenish'

export interface ClientCallbacks {
  /** A decrypted message arrived from `from`. */
  onMessage: (from: string, text: string) => void
  /** Optional: an inbound envelope failed to process, was dropped, or a security
   *  check failed (forged/replayed/unknown, a substituted directory key). */
  onError?: (detail: string) => void
}

export class NightjarClient {
  readonly transport: Transport
  readonly directory: DirectoryClient
  private authed: AuthedInfo | null = null

  constructor(
    private readonly identity: Identity,
    private readonly store: SessionStore,
    private readonly prekeys: PrekeyStore,
    private readonly contacts: ContactStore,
    private readonly lock: Lock,
    private readonly cb: ClientCallbacks,
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
    this.authed = await this.transport.connect()
    await this.flushOutbox()
    // If we came back with a low server-side OPK stock (a run of inbound sessions
    // depleted it while we were away), top it back up.
    if (this.authed.registered && this.authed.opkCount < OPK_REPLENISH_THRESHOLD) {
      void this.maybeReplenishOpks().catch(() => {})
    }
    return this.authed
  }

  close(): void {
    this.transport.close()
  }

  /** Register this identity behind a single-use invite, publishing a fresh
   *  prekey bundle and persisting the private prekeys for later responding. */
  async register(inviteCode: string): Promise<number> {
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
    if (this.authed) this.authed = { ...this.authed, registered: true, opkCount }
    return opkCount
  }

  /** Onboarding (DESIGN 6.3): register behind the invite code, then pin the
   *  inviter from the shared artifact (if it carried one). */
  async joinWithInvite(artifact: InviteArtifact): Promise<void> {
    await this.register(artifact.code)
    if (artifact.inviter && artifact.inviter !== this.userId) {
      await this.addInviteContact(artifact.inviter)
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

  /** Record that the out-of-band safety-number check passed for a peer (6.2). */
  async markVerified(peerId: string): Promise<void> {
    return this.contacts.markVerified(peerId, Date.now())
  }

  /** Send text to a peer. Uses the current session, or opens a new one (X3DH) if
   *  none exists. Runs under the per-peer lock. */
  async sendText(to: string, text: string): Promise<void> {
    const entry = await this.lock.withLock(sessionLock(to), async () => {
      const now = Date.now()
      const id = crypto.randomUUID()
      const book = await this.store.loadBook(to)
      const current = currentSession(book)

      if (current) {
        // Established (or pending) session: a normal ratchet message.
        const { state, header, ciphertext } = ratchetEncrypt(deserializeRatchet(current.snapshot), utf8(text))
        const env: WireEnvelope = {
          id,
          kind: 'normal',
          header: encodeMessageHeaderWire(header),
          ciphertext: b64encode(ciphertext),
        }
        const advanced = updateSession(book!, current.id, serializeRatchet(state), now)
        const e: OutboxEntry = { id, to, env, createdAt: now }
        await this.store.saveBookWithOutbox(to, advanced, e) // commit before release
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
      const { state, header, ciphertext } = ratchetEncrypt(state0, utf8(text))
      const env: WireEnvelope = {
        id,
        kind: 'initial',
        header: encodeMessageHeaderWire(header),
        ciphertext: b64encode(ciphertext),
        initialHeader: encodeInitialHeader(ini.header),
      }
      const promoted = promoteSession(book, serializeRatchet(state), now)
      const e: OutboxEntry = { id, to, env, createdAt: now }
      await this.store.saveBookWithOutbox(to, promoted, e)
      return e
    })
    this.fire(entry)
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
        await this.store.removeOutbox(e.id) // past the retry horizon: give up (DESIGN 7.2)
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
    let res
    try {
      res = await processInbound(env, from, {
        me: this.identity,
        prekeys: this.prekeys,
        store: this.store,
        contacts: this.contacts,
        lock: this.lock,
        now: Date.now(),
      })
    } catch (e) {
      // Transient (retry on redelivery) or a surfaced security event: do NOT ack.
      this.cb.onError?.(String(e instanceof Error ? e.message : e))
      return
    }
    // processInbound persisted before returning, so a delivered plaintext is
    // durably consumed. Deliver to the UI FIRST, then ack best-effort: a lost ack
    // only causes an idempotent redelivery (hasSeen -> duplicate). `duplicate` and
    // `dropped` are just acked (the latter stops a poison redelivery).
    if (res.kind === 'delivered') {
      this.cb.onMessage(from, decode(res.plaintext))
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
      if (this.authed) this.authed = { ...this.authed, opkCount }
    })
  }
}
