// Inbox Durable Object (DESIGN 7.1, 7.2). One per user (idFromName(userId)). It
// holds the user's authenticated WebSocket(s), authenticates the connection with
// a structured challenge (DESIGN 7.3), forwards directory operations to the
// single Directory DO using the SERVER-VERIFIED user id, relays outgoing
// messages to the recipient's Inbox, and is itself a store-and-delete queue for
// this user's incoming ciphertext: it keeps an envelope only until the recipient
// acks it, keeps a delivered id in a seen-set long enough to ack-and-drop a
// duplicate, and alarm-purges anything past its TTL. It never sees a plaintext.

import {
  ENVELOPE_TTL_MS,
  MAX_PUSH_ENDPOINT_LEN,
  MAX_PUSH_SUBS,
  MAX_QUEUED_BYTES,
  MAX_QUEUED_ENVELOPES,
  PRESENCE_FRESH_MS,
  PUSH_SUB_TTL_MS,
  PUSH_TTL_SEC,
  SEEN_ID_TTL_MS,
} from '../src/crypto/constants'
import { type AuthChallenge, verifyAuthResponse } from '../src/wire/auth'
import { type WireEnvelope, type WireFetchedBundle, b64decode, decodeEnvelope } from '../src/wire/codec'
import { buildChallenge } from '../src/wire/auth'
import type {
  AckMsg,
  ClientMessage,
  FetchBundleMsg,
  PresenceMsg,
  PublishBundleMsg,
  PushSubscribeMsg,
  PushUnsubscribeMsg,
  RegisterMsg,
  SendMsg,
  ServerMessage,
} from '../src/wire/messages'
import { type PushSub, isAllowedPushEndpoint, pushConfigured, sendNudge, vapidPublicKey } from './push'
import { type Env, DirectoryError, USER_ID_RE, callDO, directoryStub, httpOrigin, inboxStub, json } from './shared'

/** Reject a ciphertext larger than this (defensive; a text message is tiny). */
const MAX_CIPHERTEXT_BYTES = 64 * 1024
/** How often the purge alarm runs while the queue is non-empty. */
const CLEANUP_INTERVAL_MS = 24 * 60 * 60 * 1000

interface Attachment {
  claimedUserId: string
  authed: boolean
  userId?: string
  challenge?: AuthChallenge
  registered?: boolean
  /** Whether this socket's page is in the foreground (drives the push gate). */
  watching?: boolean
  /** When `watching` was last affirmed; a stale affirmation no longer counts as
   *  foreground, so a slept/zombie socket cannot suppress a push forever (H4). */
  watchingAt?: number
}

interface DeliverBody {
  from: string
  env: WireEnvelope
  now: number
  /** Suppress the content-free push nudge for this envelope (a delete-for-everyone
   *  control, P10d): still stored + delivered/drained, just never notified. */
  silent?: boolean
}

export class Inbox {
  private readonly sql: SqlStorage

  constructor(
    private readonly ctx: DurableObjectState,
    private readonly env: Env,
  ) {
    this.sql = ctx.storage.sql
    ctx.blockConcurrencyWhile(async () => this.migrate())
  }

  private migrate(): void {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS envelopes (
        id TEXT PRIMARY KEY,
        sender TEXT NOT NULL,
        body TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS seen (
        id TEXT PRIMARY KEY,
        seen_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS push_subs (
        endpoint TEXT PRIMARY KEY,
        p256dh TEXT NOT NULL,
        auth TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
    `)
  }

  async fetch(req: Request): Promise<Response> {
    const path = new URL(req.url).pathname
    if (path === '/connect') return this.handleConnect(req)
    if (path === '/deliver') return this.handleDeliver(req)
    return new Response('not found', { status: 404 })
  }

  // --- connection + auth handshake --------------------------------------

  private handleConnect(req: Request): Response {
    if ((req.headers.get('Upgrade') || '').toLowerCase() !== 'websocket') {
      return new Response('expected a websocket', { status: 426 })
    }
    // The routing key rides the subprotocol (kept out of the URL/logs); a legacy
    // ?u= query param is still honoured during rollout. Only a routing hint: the
    // challenge-response below proves identity and closes on a mismatch.
    const proto = (req.headers.get('Sec-WebSocket-Protocol') || '').split(',')[0].trim()
    const offered = USER_ID_RE.test(proto)
    const u = offered ? proto : (new URL(req.url).searchParams.get('u') ?? '')
    if (!USER_ID_RE.test(u)) return new Response('bad user id', { status: 400 })

    const pair = new WebSocketPair()
    const server = pair[1]
    this.ctx.acceptWebSocket(server)

    const challenge = buildChallenge(httpOrigin(req), crypto.randomUUID(), Date.now())
    const att: Attachment = { claimedUserId: u, authed: false, challenge }
    server.serializeAttachment(att)
    this.sendTo(server, { t: 'challenge', challenge })
    // RFC 6455: when the client offered a subprotocol, the 101 MUST echo exactly one
    // of the offered values or strict browsers abort the connection (close 1006).
    // Legacy ?u= clients offer none, so we echo nothing for them.
    return new Response(null, {
      status: 101,
      webSocket: pair[0],
      ...(offered ? { headers: { 'Sec-WebSocket-Protocol': proto } } : {}),
    })
  }

  async webSocketMessage(ws: WebSocket, raw: string | ArrayBuffer): Promise<void> {
    let msg: ClientMessage
    try {
      msg = JSON.parse(typeof raw === 'string' ? raw : new TextDecoder().decode(raw)) as ClientMessage
    } catch {
      this.sendTo(ws, { t: 'error', code: 'bad_json', msg: 'malformed message' })
      return
    }
    const att = ws.deserializeAttachment() as Attachment | null
    if (!att) {
      this.sendTo(ws, { t: 'error', code: 'no_state', msg: 'connection lost its state' })
      return
    }

    if (!att.authed) {
      await this.handleAuth(ws, att, msg)
      return
    }
    await this.handleAuthed(ws, att.userId as string, msg)
  }

  private async handleAuth(ws: WebSocket, att: Attachment, msg: ClientMessage): Promise<void> {
    if (msg.t !== 'auth') {
      this.sendTo(ws, { t: 'error', code: 'unauthenticated', msg: 'authenticate first' })
      return
    }
    if (!att.challenge) {
      this.sendTo(ws, { t: 'error', code: 'no_challenge', msg: 'no challenge on this connection' })
      return
    }
    let userId: string
    try {
      const ikSigPub = b64decode(msg.ikSigPub, 32)
      const sig = b64decode(msg.sig, 64)
      userId = verifyAuthResponse(att.challenge, ikSigPub, sig, Date.now()).userId
    } catch (e) {
      this.sendTo(ws, { t: 'error', code: 'auth_failed', msg: String(e instanceof Error ? e.message : e) })
      ws.close(1008, 'auth failed')
      return
    }
    if (userId !== att.claimedUserId) {
      // The proven identity is not the inbox this socket connected to.
      this.sendTo(ws, { t: 'error', code: 'identity_mismatch', msg: 'key does not match this inbox' })
      ws.close(1008, 'identity mismatch')
      return
    }
    // Mark authenticated BEFORE any await, so a message that follows immediately
    // is treated as authenticated. Carry the initial foreground state in the same
    // write so `watching` is set atomically as the socket enters the authed set
    // (no undefined-default window; red-team H7). Spread `att` so nothing is
    // silently dropped (red-team M1).
    ws.serializeAttachment({ ...att, authed: true, userId, watching: msg.watching === true, watchingAt: Date.now() })

    let registered = false
    let opkCount = 0
    try {
      const r = await callDO<{ registered: boolean; opkCount: number }>(directoryStub(this.env), '/isRegistered', {
        userId,
      })
      registered = r.registered
      opkCount = r.opkCount
    } catch {
      // Directory unreachable: report unregistered; the client can retry register.
    }
    // Record registration on the socket so doSend can gate relay on it. Re-read
    // and spread the CURRENT attachment: a presence message may have interleaved
    // during the isRegistered await, and we must not clobber its watching update
    // (red-team M1).
    const cur = (ws.deserializeAttachment() as Attachment | null) ?? { ...att, authed: true, userId }
    ws.serializeAttachment({ ...cur, registered })
    let pushKey: string | null = null
    try {
      pushKey = pushConfigured(this.env) ? vapidPublicKey(this.env) : null
    } catch {
      pushKey = null // a malformed VAPID_JWK must not break auth
    }
    this.sendTo(ws, { t: 'authed', userId, registered, opkCount, pushKey })
    this.drainQueue(ws)
  }

  // --- authenticated message dispatch -----------------------------------

  private async handleAuthed(ws: WebSocket, userId: string, msg: ClientMessage): Promise<void> {
    switch (msg.t) {
      case 'register':
        return this.doRegister(ws, userId, msg)
      case 'publishBundle':
        return this.doPublish(ws, userId, msg)
      case 'fetchBundle':
        return this.doFetch(ws, userId, msg)
      case 'mintInvite':
        return this.doMintInvite(ws, userId, msg.reqId)
      case 'inviteRedemptions':
        return this.doInviteRedemptions(ws, userId, msg.reqId)
      case 'send':
        return this.doSend(ws, userId, msg)
      case 'ack':
        return this.doAck(msg)
      case 'drain':
        this.drainQueue(ws)
        return
      // Web Push ops (P6). Reached ONLY here, after the auth gate, so the userId
      // is always the challenge-verified one (red-team H1). `presence` just
      // updates this socket's own foreground state.
      case 'pushSubscribe':
        return this.doPushSubscribe(ws, msg)
      case 'pushUnsubscribe':
        this.doPushUnsubscribe(msg)
        return
      case 'presence':
        this.setWatching(ws, msg)
        return
      case 'auth':
        this.sendTo(ws, { t: 'error', code: 'already_authed', msg: 'already authenticated' })
        return
      default:
        this.sendTo(ws, { t: 'error', code: 'bad_type', msg: 'unknown message type' })
    }
  }

  private async doRegister(ws: WebSocket, userId: string, msg: RegisterMsg): Promise<void> {
    try {
      const r = await callDO<{ opkCount: number }>(directoryStub(this.env), '/register', {
        userId,
        inviteCode: msg.inviteCode,
        bundle: msg.bundle,
        now: Date.now(),
      })
      const att = ws.deserializeAttachment() as Attachment | null
      if (att) ws.serializeAttachment({ ...att, registered: true })
      this.sendTo(ws, { t: 'registered', reqId: msg.reqId, opkCount: r.opkCount })
    } catch (e) {
      this.replyError(ws, e, msg.reqId)
    }
  }

  private async doPublish(ws: WebSocket, userId: string, msg: PublishBundleMsg): Promise<void> {
    try {
      const r = await callDO<{ opkCount: number }>(directoryStub(this.env), '/publishBundle', {
        userId,
        spk: msg.spk,
        opks: msg.opks,
        now: Date.now(),
      })
      this.sendTo(ws, { t: 'published', reqId: msg.reqId, opkCount: r.opkCount })
    } catch (e) {
      this.replyError(ws, e, msg.reqId)
    }
  }

  private async doFetch(ws: WebSocket, userId: string, msg: FetchBundleMsg): Promise<void> {
    if (!USER_ID_RE.test(msg.target)) {
      this.sendTo(ws, { t: 'error', code: 'bad_target', msg: 'bad target user id', reqId: msg.reqId })
      return
    }
    try {
      const r = await callDO<{ bundle: WireFetchedBundle | null; degraded: boolean }>(
        directoryStub(this.env),
        '/fetchBundle',
        { fetcher: userId, target: msg.target, now: Date.now() },
      )
      this.sendTo(ws, { t: 'bundle', reqId: msg.reqId, target: msg.target, bundle: r.bundle, degraded: r.degraded })
    } catch (e) {
      this.replyError(ws, e, msg.reqId)
    }
  }

  private async doMintInvite(ws: WebSocket, userId: string, reqId: string): Promise<void> {
    try {
      const r = await callDO<{ code: string }>(directoryStub(this.env), '/mintInvite', {
        inviter: userId,
        now: Date.now(),
      })
      this.sendTo(ws, { t: 'invite', reqId, code: r.code, inviterFingerprint: userId })
    } catch (e) {
      this.replyError(ws, e, reqId)
    }
  }

  // Report who redeemed this user's invites (mutual invite, DESIGN 6.3), so the
  // inviter auto-learns each joiner as a TOFU contact without waiting for a message.
  // The `inviter` forwarded to the Directory is the challenge-verified userId, NEVER
  // a client-supplied value, so a user can only ever list their own joiners. Gated on
  // `registered` for consistency with the rest of the authed Directory surface (an
  // unregistered id owns no invites, so this is defense-in-depth, not the sole guard).
  private async doInviteRedemptions(ws: WebSocket, userId: string, reqId: string): Promise<void> {
    const att = ws.deserializeAttachment() as Attachment | null
    if (!att?.registered) {
      this.sendTo(ws, { t: 'redemptions', reqId, joiners: [] })
      return
    }
    try {
      const r = await callDO<{ joiners: string[] }>(directoryStub(this.env), '/inviteRedemptions', { inviter: userId })
      this.sendTo(ws, { t: 'redemptions', reqId, joiners: r.joiners })
    } catch (e) {
      this.replyError(ws, e, reqId)
    }
  }

  private async doSend(ws: WebSocket, userId: string, msg: SendMsg): Promise<void> {
    // Send errors carry `ref` = the envelope id (when parseable) so the sender
    // can stop retrying a PERMANENTLY undeliverable outbox entry instead of
    // silently re-firing it on every reconnect (P8 review fix).
    const refPart = typeof msg.env?.id === 'string' ? { ref: msg.env.id } : {}
    // Gate the relay surface on the sender being registered (invite-gated), so an
    // unregistered key-holder cannot flood a victim's inbox (P4 review).
    const att = ws.deserializeAttachment() as Attachment | null
    if (!att?.registered) {
      this.sendTo(ws, { t: 'error', code: 'not_registered', msg: 'register before sending', ...refPart })
      return
    }
    if (!USER_ID_RE.test(msg.to)) {
      this.sendTo(ws, { t: 'error', code: 'bad_to', msg: 'bad recipient user id', ...refPart })
      return
    }
    try {
      const env = decodeEnvelope(msg.env) // structural validation
      if (env.ciphertext.length > MAX_CIPHERTEXT_BYTES) {
        this.sendTo(ws, { t: 'error', code: 'too_large', msg: 'ciphertext too large', ...refPart })
        return
      }
    } catch {
      this.sendTo(ws, { t: 'error', code: 'bad_envelope', msg: 'malformed envelope', ...refPart })
      return
    }
    try {
      await callDO<{ stored: boolean; duplicate: boolean }>(inboxStub(this.env, msg.to), '/deliver', {
        from: userId,
        env: msg.env,
        now: Date.now(),
        ...(msg.silent ? { silent: true } : {}),
      })
      // Sender-side durability ack: the recipient inbox has the bytes (or already
      // had them). The sender's outbox can now stop retrying this id.
      this.sendTo(ws, { t: 'sent', id: msg.env.id })
    } catch (e) {
      this.replyError(ws, e, undefined, 'ref' in refPart ? refPart.ref : undefined)
    }
  }

  // Recipient acked durable consumption: drop the queued envelope and remember
  // the id so a redelivery is ack-and-dropped, not reprocessed (DESIGN 5.3, 7.1).
  private async doAck(msg: AckMsg): Promise<void> {
    // Validate the id exactly as the deliver path does, so a spammed ack cannot
    // insert oversized/arbitrary rows into the seen table (P4 review).
    if (typeof msg.id !== 'string' || msg.id.length === 0 || msg.id.length > 128) return
    const now = Date.now()
    this.ctx.storage.transactionSync(() => {
      this.sql.exec('DELETE FROM envelopes WHERE id = ?', msg.id)
      this.sql.exec('INSERT OR IGNORE INTO seen (id, seen_at) VALUES (?, ?)', msg.id, now)
    })
    await this.ensureAlarm(now)
  }

  // --- Web Push subscriptions + presence (P6, DESIGN 7.4) ---------------

  // Store a device's push subscription against THIS authed inbox. Gated on the
  // socket being registered (matches doSend's trust boundary; red-team N3), and
  // the endpoint is accepted only if it is https on a known push service and
  // bounded in length (SSRF + storage guards; red-team M5/H2). Keys must be the
  // right size. INSERT OR REPLACE refreshes created_at so an active device stays
  // fresh; a genuinely new device past the per-user cap evicts the oldest (LRU).
  private async doPushSubscribe(ws: WebSocket, msg: PushSubscribeMsg): Promise<void> {
    const att = ws.deserializeAttachment() as Attachment | null
    if (!att?.registered) {
      this.sendTo(ws, { t: 'error', code: 'not_registered', msg: 'register before subscribing to push' })
      return
    }
    if (typeof msg.endpoint !== 'string' || msg.endpoint.length > MAX_PUSH_ENDPOINT_LEN || !isAllowedPushEndpoint(msg.endpoint)) {
      this.sendTo(ws, { t: 'error', code: 'bad_endpoint', msg: 'push endpoint not accepted' })
      return
    }
    try {
      b64decode(msg.p256dh, 65) // uncompressed P-256 point
      b64decode(msg.auth, 16) // auth secret
    } catch {
      this.sendTo(ws, { t: 'error', code: 'bad_pushkeys', msg: 'malformed push keys' })
      return
    }
    const now = Date.now()
    this.ctx.storage.transactionSync(() => {
      const exists = this.sql.exec('SELECT 1 FROM push_subs WHERE endpoint = ?', msg.endpoint).toArray()[0]
      if (!exists) {
        const cnt = (this.sql.exec('SELECT COUNT(*) AS c FROM push_subs').toArray()[0] as { c: number }).c
        if (cnt >= MAX_PUSH_SUBS) {
          this.sql.exec(
            'DELETE FROM push_subs WHERE endpoint IN (SELECT endpoint FROM push_subs ORDER BY created_at LIMIT ?)',
            cnt - MAX_PUSH_SUBS + 1,
          )
        }
      }
      this.sql.exec(
        'INSERT OR REPLACE INTO push_subs (endpoint, p256dh, auth, created_at) VALUES (?, ?, ?, ?)',
        msg.endpoint,
        msg.p256dh,
        msg.auth,
        now,
      )
    })
    // Drive the TTL clock, so an idle inbox that only ever received a subscribe
    // still ages the row out later (red-team H3).
    await this.ensureAlarm(now)
  }

  private doPushUnsubscribe(msg: PushUnsubscribeMsg): void {
    if (typeof msg.endpoint !== 'string' || msg.endpoint.length > MAX_PUSH_ENDPOINT_LEN) return
    this.sql.exec('DELETE FROM push_subs WHERE endpoint = ?', msg.endpoint)
  }

  // Update this socket's foreground state (read-modify-write, so `registered`
  // etc. are never clobbered; red-team M1).
  private setWatching(ws: WebSocket, msg: PresenceMsg): void {
    const att = ws.deserializeAttachment() as Attachment | null
    if (!att) return
    ws.serializeAttachment({ ...att, watching: msg.watching === true, watchingAt: Date.now() })
  }

  /** True if some authed socket affirmed foreground within the freshness window;
   *  such a user is looking at the app, so a push would be a redundant nudge. */
  private hasFreshWatcher(now: number): boolean {
    return this.authedSockets().some((ws) => {
      const att = ws.deserializeAttachment() as Attachment | null
      return !!att?.watching && typeof att.watchingAt === 'number' && now - att.watchingAt < PRESENCE_FRESH_MS
    })
  }

  // Fan a content-free nudge out to every stored subscription, pruning any the
  // browser has discarded (404/410). Runs in ctx.waitUntil() off the deliver
  // path, so relay latency is never coupled to push-service latency (red-team M5).
  private async pushNudge(): Promise<void> {
    const subs = this.sql.exec('SELECT endpoint, p256dh, auth FROM push_subs').toArray() as unknown as PushSub[]
    if (subs.length === 0) return
    const results = await Promise.all(subs.map((s) => sendNudge(this.env, s, { ttl: PUSH_TTL_SEC })))
    for (let i = 0; i < subs.length; i++) {
      if (results[i].gone) this.sql.exec('DELETE FROM push_subs WHERE endpoint = ?', subs[i].endpoint)
    }
  }

  // --- store-and-deliver (called by a peer inbox forwarding a message) ---

  private async handleDeliver(req: Request): Promise<Response> {
    const body = (await req.json()) as DeliverBody
    const now = body.now
    const id = body.env.id
    if (typeof id !== 'string' || id.length === 0 || id.length > 128) {
      return json({ code: 'bad_id', msg: 'bad envelope id' }, 400)
    }

    // 'seen'  -> already delivered and acked: ack-and-drop, no push.
    // 'queued'-> already in the queue (a retransmit): keep one copy, no re-push;
    //            it is already deliverable via drain-on-connect.
    // 'new'   -> a genuinely new envelope: store and push to any live device.
    // Existence is checked explicitly rather than via cursor.rowsWritten, which
    // reports 0 for INSERT OR IGNORE in workerd. The whole check-then-insert runs
    // in one synchronous transaction, so it cannot interleave.
    const serialized = JSON.stringify(body.env)
    const status = this.ctx.storage.transactionSync((): 'seen' | 'queued' | 'new' | 'full' => {
      if (this.sql.exec('SELECT id FROM seen WHERE id = ?', id).toArray()[0]) return 'seen'
      if (this.sql.exec('SELECT id FROM envelopes WHERE id = ?', id).toArray()[0]) return 'queued'
      // Bound the queue so one sender cannot exhaust a victim's Inbox storage
      // (P4 review). Counted only for a genuinely new envelope.
      const stats = this.sql
        .exec('SELECT COUNT(*) AS c, COALESCE(SUM(LENGTH(body)), 0) AS b FROM envelopes')
        .toArray()[0] as { c: number; b: number }
      if (stats.c >= MAX_QUEUED_ENVELOPES || stats.b + serialized.length > MAX_QUEUED_BYTES) return 'full'
      this.sql.exec(
        'INSERT INTO envelopes (id, sender, body, created_at) VALUES (?, ?, ?, ?)',
        id,
        body.from,
        serialized,
        now,
      )
      return 'new'
    })

    if (status === 'full') return json({ code: 'queue_full', msg: 'recipient inbox is full' }, 429)
    if (status === 'new') {
      for (const ws of this.authedSockets()) {
        this.sendTo(ws, { t: 'deliver', from: body.from, env: body.env })
      }
      await this.ensureAlarm(now)
      // Nudge a CLOSED / backgrounded device: only when no socket is currently
      // foreground (a foreground app renders the in-band deliver, so a push would
      // just double-notify) AND the sender did not mark the envelope silent (a
      // delete-for-everyone control must not notify, P10d). Content-free; fanned out
      // in the background so the sender's deliver round-trip is not coupled to
      // push-service latency (M5).
      if (pushConfigured(this.env) && !body.silent && !this.hasFreshWatcher(Date.now())) {
        this.ctx.waitUntil(this.pushNudge())
      }
    }
    return json({ stored: true, duplicate: status !== 'new' })
  }

  private drainQueue(ws: WebSocket): void {
    const rows = this.sql
      .exec('SELECT sender, body FROM envelopes ORDER BY created_at')
      .toArray() as Array<{ sender: string; body: string }>
    for (const row of rows) {
      this.sendTo(ws, { t: 'deliver', from: row.sender, env: JSON.parse(row.body) as WireEnvelope })
    }
  }

  // --- lifecycle --------------------------------------------------------

  webSocketClose(): void {
    // Nothing to persist: presence is just whether an authed socket exists, and
    // the queue survives independently. Push (P6) will act on close.
  }

  webSocketError(): void {
    // The close handler (such as it is) covers cleanup.
  }

  async alarm(): Promise<void> {
    const now = Date.now()
    this.sql.exec('DELETE FROM envelopes WHERE created_at < ?', now - ENVELOPE_TTL_MS)
    this.sql.exec('DELETE FROM seen WHERE seen_at < ?', now - SEEN_ID_TTL_MS)
    // A device that stopped connecting (never re-subscribed) ages out (H3).
    this.sql.exec('DELETE FROM push_subs WHERE created_at < ?', now - PUSH_SUB_TTL_MS)
    const remaining = this.sql.exec('SELECT COUNT(*) AS c FROM envelopes').toArray()[0] as { c: number }
    const seenRemaining = this.sql.exec('SELECT COUNT(*) AS c FROM seen').toArray()[0] as { c: number }
    const subsRemaining = this.sql.exec('SELECT COUNT(*) AS c FROM push_subs').toArray()[0] as { c: number }
    // Keep the purge alarm alive while ANY table still holds rows, so push_subs
    // are actually reached by the TTL sweep (red-team H3).
    if (remaining.c > 0 || seenRemaining.c > 0 || subsRemaining.c > 0) {
      await this.ctx.storage.setAlarm(now + CLEANUP_INTERVAL_MS)
    }
  }

  private async ensureAlarm(now: number): Promise<void> {
    // Schedule a purge alarm if none is pending. Awaited so the storage I/O
    // happens within the request (workerd forbids I/O after the response).
    if ((await this.ctx.storage.getAlarm()) === null) {
      await this.ctx.storage.setAlarm(now + CLEANUP_INTERVAL_MS)
    }
  }

  // --- helpers ----------------------------------------------------------

  private authedSockets(): WebSocket[] {
    return this.ctx.getWebSockets().filter((ws) => {
      const att = ws.deserializeAttachment() as Attachment | null
      return !!att?.authed
    })
  }

  private sendTo(ws: WebSocket, msg: ServerMessage): void {
    try {
      ws.send(JSON.stringify(msg))
    } catch {
      // Socket gone; nothing to do.
    }
  }

  private replyError(ws: WebSocket, e: unknown, reqId?: string, ref?: string): void {
    const code = e instanceof DirectoryError ? e.code : 'internal'
    const msg = e instanceof Error ? e.message : String(e)
    this.sendTo(ws, { t: 'error', code, msg, ...(reqId ? { reqId } : {}), ...(ref ? { ref } : {}) })
  }
}
