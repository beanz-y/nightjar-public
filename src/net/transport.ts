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
  private readonly pending = new Map<string, { resolve: (m: ReqScoped) => void; reject: (e: Error) => void }>()
  private readonly sentWaiters = new Map<string, () => void>()
  private deliverHandler: ((from: string, envJson: unknown) => void) | null = null
  private closeHandler: (() => void) | null = null

  constructor(private readonly identity: Identity) {}

  /** Open and authenticate the connection. Resolves once the server confirms auth. */
  connect(): Promise<AuthedInfo> {
    return new Promise<AuthedInfo>((resolve, reject) => {
      const url = `${wsOrigin()}/connect?u=${this.identity.userId}`
      const ws = new WebSocket(url)
      this.ws = ws
      let settled = false

      ws.addEventListener('message', (ev) => {
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
            settled = true
            reject(e instanceof Error ? e : new Error(String(e)))
            ws.close()
          }
          return
        }
        if (msg.t === 'authed' && !settled) {
          settled = true
          resolve({
            userId: msg.userId,
            registered: msg.registered,
            opkCount: msg.opkCount,
            pushKey: msg.pushKey ?? null,
          })
          return
        }
        this.dispatch(msg)
      })

      ws.addEventListener('error', () => {
        if (!settled) {
          settled = true
          reject(new Error('websocket error before authentication'))
        }
      })
      ws.addEventListener('close', () => {
        this.failAllPending(new Error('connection closed'))
        this.closeHandler?.()
      })
    })
  }

  /** Route a server message to whichever waiter/handler is interested. */
  private dispatch(msg: ServerMessage): void {
    if (msg.t === 'error') return this.rejectPending(msg)
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
        p.reject(new Error(`${err.code}: ${err.msg}`))
      }
    }
  }

  /** Send a request that expects a reqId-scoped response. */
  request(reqId: string, msg: ClientMessage): Promise<ReqScoped> {
    return new Promise<ReqScoped>((resolve, reject) => {
      this.pending.set(reqId, { resolve, reject })
      this.raw(msg)
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

  close(): void {
    this.ws?.close()
  }

  private failAllPending(err: Error): void {
    for (const p of this.pending.values()) p.reject(err)
    this.pending.clear()
    this.sentWaiters.clear()
  }
}
