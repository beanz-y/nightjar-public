// The client <-> server message protocol (P4), carried as JSON over one
// authenticated WebSocket per user (DESIGN 7). Discriminated on `t`. Byte-valued
// fields are already base64url (see codec.ts wire structs). Shared by client and
// server so both compile against one definition.
//
// Flow: the socket connects to the user's Inbox DO, which immediately sends a
// `challenge`. The client replies `auth`; on success the server sends `authed`.
// All other messages are rejected until authenticated. Directory operations
// (register/publishBundle/fetchBundle/mintInvite) are forwarded by the Inbox to
// the single Directory DO using the SERVER-VERIFIED user id, never a client
// claim. `send` is relayed to the recipient's Inbox; `deliver` pushes an inbound
// envelope; `ack`/`sent` are the two delivery-acknowledgement layers (DESIGN 7.2).

import type {
  WireFetchedBundle,
  WireEnvelope,
  WireOneTimePrekey,
  WirePublishedBundle,
  WireSignedPrekey,
} from './codec'
import type { AuthChallenge } from './auth'

// --- client -> server ----------------------------------------------------

export interface AuthMsg {
  t: 'auth'
  ikSigPub: string
  sig: string
  /** Initial foreground state, so the server sets `watching` atomically as the
   *  socket becomes authed (no undefined-default window; P6). */
  watching?: boolean
}

export interface RegisterMsg {
  t: 'register'
  reqId: string
  inviteCode: string
  bundle: WirePublishedBundle
}

export interface PublishBundleMsg {
  t: 'publishBundle'
  reqId: string
  spk: WireSignedPrekey
  opks: WireOneTimePrekey[]
}

export interface FetchBundleMsg {
  t: 'fetchBundle'
  reqId: string
  target: string
}

export interface MintInviteMsg {
  t: 'mintInvite'
  reqId: string
}

export interface InviteRedemptionsMsg {
  t: 'inviteRedemptions'
  reqId: string
}

export interface SendMsg {
  t: 'send'
  to: string
  env: WireEnvelope
  /** Suppress the recipient's content-free push nudge for this envelope (P10d): a
   *  delete-for-everyone control should never notify. The envelope is still stored
   *  and delivered in-band to a live device, and drained on the next connect if the
   *  recipient is offline, so the delete still applies - just without a notification. */
  silent?: boolean
}

export interface AckMsg {
  t: 'ack'
  id: string
}

export interface DrainMsg {
  t: 'drain'
}

// --- Web Push (P6, DESIGN 7.4) -------------------------------------------
// All three ride the AUTHENTICATED socket and are handled ONLY post-auth, so the
// server always uses the challenge-verified userId, never a client claim
// The subscription fields are the browser's PushSubscription,
// base64url. `presence` re-affirms foreground state to gate content-free pushes.

export interface PushSubscribeMsg {
  t: 'pushSubscribe'
  endpoint: string
  p256dh: string
  auth: string
}

export interface PushUnsubscribeMsg {
  t: 'pushUnsubscribe'
  endpoint: string
}

export interface PresenceMsg {
  t: 'presence'
  watching: boolean
}

export type ClientMessage =
  | AuthMsg
  | RegisterMsg
  | PublishBundleMsg
  | FetchBundleMsg
  | MintInviteMsg
  | InviteRedemptionsMsg
  | SendMsg
  | AckMsg
  | DrainMsg
  | PushSubscribeMsg
  | PushUnsubscribeMsg
  | PresenceMsg

// --- server -> client ----------------------------------------------------

export interface ChallengeMsg {
  t: 'challenge'
  challenge: AuthChallenge
}

export interface AuthedMsg {
  t: 'authed'
  userId: string
  registered: boolean
  opkCount: number
  /** The VAPID application-server key the client subscribes with (P6), or null
   *  when push is not configured on this relay (off-until-secret). */
  pushKey?: string | null
}

export interface RegisteredMsg {
  t: 'registered'
  reqId: string
  opkCount: number
}

export interface PublishedMsg {
  t: 'published'
  reqId: string
  opkCount: number
}

export interface BundleMsg {
  t: 'bundle'
  reqId: string
  target: string
  bundle: WireFetchedBundle | null // null: target not registered
  degraded: boolean // true when no OPK was available (DESIGN 4.3)
}

export interface InviteMsg {
  t: 'invite'
  reqId: string
  code: string
  inviterFingerprint: string // base32 user id of the inviter (DESIGN 6.3)
}

export interface RedemptionsMsg {
  t: 'redemptions'
  reqId: string
  /** Server-verified user ids that redeemed the caller's invites (mutual invite,
   *  DESIGN 6.3). A relay assertion, TOFU: the inviter records each at 'unverified'. */
  joiners: string[]
}

export interface DeliverMsg {
  t: 'deliver'
  from: string
  env: WireEnvelope
}

export interface SentMsg {
  t: 'sent'
  id: string // sender-side durability ack: stored at the recipient inbox
}

export interface ErrorMsg {
  t: 'error'
  code: string
  msg: string
  reqId?: string
  /** For send failures: the envelope id the error refers to, so the sender can
   *  drop a permanently undeliverable outbox entry (P8). */
  ref?: string
}

export type ServerMessage =
  | ChallengeMsg
  | AuthedMsg
  | RegisteredMsg
  | PublishedMsg
  | BundleMsg
  | InviteMsg
  | RedemptionsMsg
  | DeliverMsg
  | SentMsg
  | ErrorMsg
