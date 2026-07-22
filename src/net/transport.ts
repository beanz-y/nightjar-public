// Client WebSocket transport (P4). One authenticated connection to the user's
// Inbox DO. On connect it completes the challenge-response (verifying the
// challenge origin BEFORE signing, DESIGN 7.3), then multiplexes:
//   - request/response operations correlated by reqId (register, fetchBundle, ...)
//   - sender durability acks correlated by message id ('sent')
//   - server-pushed inbound envelopes ('deliver')
//
// It is transport only: no crypto state, no persistence. The client orchestrator
// (client.ts) drives it.

import type { Identity } from '../crypto/identity'
import { getRelayOrigin } from '../platform'
import { verifyAndSignChallenge } from '../wire/auth'
import { b64encode } from '../wire/codec'
import type { ClientMessage, ErrorMsg, ServerMessage } from '../wire/messages'

/** A server message that carries a reqId (a response to a request). */
type ReqScoped = Extract<ServerMessage, { reqId: string }>

/** Abandon a connection attempt that has neither authed nor failed by now. */
export const CONNECT_TIMEOUT_MS = 15 * 1000
/** Reject a request whose response never arrives (lost frame, wedged DO). The
 *  operation surfaces as a retryable error instead of hanging the UI forever. */
export const REQUEST_TIMEOUT_MS = 20 * 1000

function wsOrigin(): string {
  return getRelayOrigin().replace(/^http/, 'ws')
}

/** Whether the page is in the foreground right now, for the initial presence bit
 *  carried in the auth frame (P6). Defaults to not-watching off-DOM (a headless
 *  client is not a foreground reader). */
function docVisible(): boolean {
  return typeof document !== 'undefined' && document.visibilityState === 'visible'
}

export interface AuthedInfo {
  userId: string
  registered: boolean
  opkCount: number
  /** VAPID application-server key for Web Push, or null when the relay has no
   *  push configured (off-until-secret; P6). */
  pushKey: string | null
}

export class Transport {
  private ws: WebSocket | null = null
  private readonly pending = new Map<
    string,
    { resolve: (m: ReqScoped) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }
  >()
  private readonly sentWaiters = new Map<string, () => void>()
  private deliverHandler: ((from: string, envJson: unknown) => void) | null = null
  private closeHandler: (() => void) | null = null
  private sendErrorHandler: ((ref: string, code: string, msg: string) => void) | null = null

  constructor(private readonly identity: Identity) {}

  /**
   * Open and authenticate a connection. Resolves once the server confirms auth;
   * REJECTS on a pre-auth close (the server closes with 1008 on a bad auth
   * without this being a JS 'error' event) and on a deadline, so a caller can
   * always retry instead of hanging. Reconnect policy lives in the client.
   * Listeners guard on `this.ws === ws` so a late event from a superseded
   * socket can never fail the pending state of its replacement.
   */
  connect(): Promise<AuthedInfo> {
    return new Promise<AuthedInfo>((resolve, reject) => {
      // The userId rides the WebSocket subprotocol, NOT the URL. A query param lands
      // in edge/request logs (identity + IP + geo + TLS fingerprint in one row), so
      // the id is kept out of the URL entirely. It is only a routing hint here; the
      // socket is still authenticated by the challenge-response below.
      const url = `${wsOrigin()}/connect`
      const ws = new WebSocket(url, [this.identity.userId])
      this.ws = ws
      let settled = false
      const timer = setTimeout(() => {
        if (!settled) {
          settled = true
          reject(new Error('connect timed out'))
          ws.close()
        }
      }, CONNECT_TIMEOUT_MS)
      const settle = (fn: () => void) => {
        settled = true
        clearTimeout(timer)
        fn()
      }

      ws.addEventListener('message', (ev) => {
        if (this.ws !== ws) return
        let msg: ServerMessage
        try {
          msg = JSON.parse(ev.data as string) as ServerMessage
        } catch {
          return
        }
        if (msg.t === 'challenge') {
          try {
            const sig = verifyAndSignChallenge(
              msg.challenge,
              getRelayOrigin(),
              this.identity.ikSig.privateKey,
              Date.now(),
            )
            this.raw({
              t: 'auth',
              ikSigPub: b64encode(this.identity.ikSig.publicKey),
              sig: b64encode(sig),
              watching: docVisible(),
            })
          } catch (e) {
            if (!settled) settle(() => reject(e instanceof Error ? e : new Error(String(e))))
            ws.close()
          }
          return
        }
        if (msg.t === 'authed' && !settled) {
          settle(() =>
            resolve({
              userId: msg.userId,
              registered: msg.registered,
              opkCount: msg.opkCount,
              pushKey: msg.pushKey ?? null,
            }),
          )
          return
        }
        if (msg.t === 'error' && !settled && !msg.reqId && !msg.ref) {
          // Pre-auth server rejection (auth_failed / identity_mismatch): surface
          // it as the connect failure rather than waiting for the close.
          settle(() => reject(new Error(`${msg.code}: ${msg.msg}`)))
          return
        }
        this.dispatch(msg)
      })

      ws.addEventListener('error', () => {
        if (this.ws !== ws) return
        if (!settled) settle(() => reject(new Error('websocket error before authentication')))
      })
      ws.addEventListener('close', () => {
        if (this.ws !== ws) return
        this.ws = null
        if (!settled) settle(() => reject(new Error('connection closed before authentication')))
        this.failAllPending(new Error('connection closed'))
        this.closeHandler?.()
      })
    })
  }

  /** Route a server message to whichever waiter/handler is interested. */
  private dispatch(msg: ServerMessage): void {
    if (msg.t === 'error') {
      if (msg.reqId) return this.rejectPending(msg)
      if (msg.ref) return this.sendErrorHandler?.(msg.ref, msg.code, msg.msg)
      return
    }
    if (msg.t === 'sent') {
      const w = this.sentWaiters.get(msg.id)
      if (w) {
        this.sentWaiters.delete(msg.id)
        w()
      }
      return
    }
    if (msg.t === 'deliver') {
      this.deliverHandler?.(msg.from, msg.env)
      return
    }
    if ('reqId' in msg) {
      const p = this.pending.get(msg.reqId)
      if (p) {
        this.pending.delete(msg.reqId)
        p.resolve(msg)
      }
    }
  }

  private rejectPending(err: ErrorMsg): void {
    if (err.reqId) {
      const p = this.pending.get(err.reqId)
      if (p) {
        this.pending.delete(err.reqId)
        clearTimeout(p.timer)
        p.reject(new Error(`${err.code}: ${err.msg}`))
      }
    }
  }

  /** Send a request that expects a reqId-scoped response, with a deadline. */
  request(reqId: string, msg: ClientMessage): Promise<ReqScoped> {
    return new Promise<ReqScoped>((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pending.delete(reqId)) reject(new Error('request timed out'))
      }, REQUEST_TIMEOUT_MS)
      this.pending.set(reqId, {
        resolve: (m) => {
          clearTimeout(timer)
          resolve(m)
        },
        reject: (e) => {
          clearTimeout(timer)
          reject(e)
        },
        timer,
      })
      try {
        this.raw(msg)
      } catch (e) {
        if (this.pending.delete(reqId)) {
          clearTimeout(timer)
          reject(e instanceof Error ? e : new Error(String(e)))
        }
      }
    })
  }

  /** Resolve when the server acks durable storage of a sent message id. */
  waitSent(id: string): Promise<void> {
    return new Promise<void>((resolve) => this.sentWaiters.set(id, resolve))
  }

  raw(msg: ClientMessage): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) throw new Error('transport: not connected')
    this.ws.send(JSON.stringify(msg))
  }

  onDeliver(handler: (from: string, envJson: unknown) => void): void {
    this.deliverHandler = handler
  }

  onClose(handler: () => void): void {
    this.closeHandler = handler
  }

  /** Register the send-failure handler ({t:'error', ref}: a permanent reject of
   *  a specific envelope id from doSend). */
  onSendError(handler: (ref: string, code: string, msg: string) => void): void {
    this.sendErrorHandler = handler
  }

  get isOpen(): boolean {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN
  }

  close(): void {
    const ws = this.ws
    this.ws = null // deliberate close: the stale-socket guard mutes its events
    ws?.close()
    this.failAllPending(new Error('connection closed'))
  }

  private failAllPending(err: Error): void {
    for (const p of this.pending.values()) {
      clearTimeout(p.timer)
      p.reject(err)
    }
    this.pending.clear()
    this.sentWaiters.clear()
  }
}
