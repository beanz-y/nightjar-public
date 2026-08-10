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
  WireDeviceRoster,
  WireFetchedBundle,
  WireEnvelope,
  WireOneTimePrekey,
  WirePublishedBundle,
  WireRotationStatement,
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

/** Publish this account's signed device roster (Sesame). The roster carries its
 *  own authorization: it is signed by the account key, and the Directory verifies
 *  that signature against the identity key registered for the account it names.
 *  The CALLER is deliberately not the authorization, because a linked device
 *  authenticates as itself and must still be able to update its account's roster. */
export interface PublishRosterMsg {
  t: 'publishRoster'
  reqId: string
  roster: WireDeviceRoster
}

/** One chunk of a link transfer, sent to a device being linked (Sesame).
 *
 *  Deliberately NOT an envelope, and deliberately NOT stored. A link payload
 *  carries the account's private key, sealed under a secret that only travelled
 *  screen to camera; parking that in a relay queue for up to thirty days would be
 *  a worse exposure than requiring both devices to be awake for the few seconds
 *  the ceremony takes. So this is delivered to a live socket or it fails, exactly
 *  like the delivery note (DESIGN 7.5), and nothing is written down. */
export interface SendLinkMsg {
  t: 'sendLink'
  reqId: string
  to: string
  /** One sealed chunk from src/crypto/link.ts, base64url. */
  chunk: string
}

/** Register this device's prekey bundle as a device of `accountId` (Sesame).
 *  Consumes no invite: a new device is not a new user. The account must already
 *  have published a roster listing this device, which only its account key can
 *  produce, so the roster is what authorizes this in an invite's place. */
export interface RegisterDeviceMsg {
  t: 'registerDevice'
  reqId: string
  accountId: string
  bundle: WirePublishedBundle
}

/** Ask where an account's devices are. Answered with null for any account that
 *  has never published a roster, which today is every account. */
export interface FetchRosterMsg {
  t: 'fetchRoster'
  reqId: string
  accountId: string
}

/** Record which key replaces this account's (Sesame, account-key rotation). Like
 *  the roster, the statement carries its own authorization: it is signed by the
 *  account being rotated and counter-signed by the key taking over, and the
 *  Directory verifies both against a key it already holds for that account. */
export interface PublishRotationMsg {
  t: 'publishRotation'
  reqId: string
  statement: WireRotationStatement
}

/** Ask whether an account rotated, and to what. Answered with null for every
 *  account that never did, which is almost all of them. ONE hop: a chain is
 *  followed by asking again, because each hop has to be verified under the key
 *  the hop before it introduced, and the relay cannot do that for anyone. */
export interface FetchRotationMsg {
  t: 'fetchRotation'
  reqId: string
  accountId: string
}

/** Re-assert that this device belongs to `accountId` (Sesame). The device id is
 *  the server-verified one from this socket, never a body claim, and the account
 *  must already list it in a signed roster. Idempotent, and sent on connect by a
 *  linked device so the Directory's record of which devices are whose heals for
 *  devices added before that record existed. */
export interface ClaimDeviceMsg {
  t: 'claimDevice'
  reqId: string
  accountId: string
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

/** "Which of these envelopes has the recipient's device picked up?" (delivery
 *  indicator). Answers what the relay already knows: an envelope is deleted from
 *  the recipient's inbox and its id recorded as seen when their device acks
 *  durable consumption. Used on reconnect to catch up on deliveries that happened
 *  while this device was offline, since the live report has no one to reach then.
 *  Bounded per request; the ids are the sender's own, so this reveals nothing the
 *  sender did not already generate. */
export interface DeliveredCheckMsg {
  t: 'deliveredCheck'
  reqId: string
  to: string
  ids: string[]
}

export type ClientMessage =
  | AuthMsg
  | RegisterMsg
  | PublishBundleMsg
  | FetchBundleMsg
  | MintInviteMsg
  | InviteRedemptionsMsg
  | PublishRosterMsg
  | FetchRosterMsg
  | PublishRotationMsg
  | FetchRotationMsg
  | ClaimDeviceMsg
  | RegisterDeviceMsg
  | SendLinkMsg
  | SendMsg
  | AckMsg
  | DrainMsg
  | DeliveredCheckMsg
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

/** A link chunk arriving at the device being linked. `from` is the server-verified
 *  device that sent it, which is a routing fact only: what actually authenticates
 *  the transfer is that it opens under the secret from the scanned code. */
export interface LinkChunkMsg {
  t: 'linkChunk'
  from: string
  chunk: string
}

export interface RosterPublishedMsg {
  t: 'rosterPublished'
  reqId: string
  version: number
}

export interface RosterMsg {
  t: 'roster'
  reqId: string
  accountId: string
  /** null: this account has never published a roster, so it is the single device
   *  at its own account id. Not an error, and the common case. */
  roster: WireDeviceRoster | null
  /** Set when this account rotated its key away: the signed statement naming the
   *  successor, so whoever is asking where to send can find out they moved in the
   *  same round trip. Optional on the wire, since a relay that predates it will
   *  not send one. Never believed without verifying it under the key the caller
   *  already holds. */
  rotation?: WireRotationStatement | null
}

export interface DeviceClaimedMsg {
  t: 'deviceClaimed'
  reqId: string
  claimed: boolean
}

export interface RotationPublishedMsg {
  t: 'rotationPublished'
  reqId: string
  /** Echoed back so the caller can see the Directory recorded the successor it
   *  meant. A repeat of a rotation already recorded answers here rather than
   *  failing, so retrying an interrupted rotation is safe. */
  newAccountId: string
}

export interface RotationMsg {
  t: 'rotation'
  reqId: string
  accountId: string
  /** null: this account never rotated, which is almost all of them. */
  statement: WireRotationStatement | null
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

/** Unsolicited: the recipient's device has picked this envelope up (it acked
 *  durable consumption and the relay dropped the queued copy). This is the
 *  RELAY'S WORD, exactly like `sent`, not a signed statement by the peer: a
 *  malicious relay can withhold it, and could assert it for an envelope it in fact
 *  dropped. It is a UI hint, never a security property, and the UI labels it as
 *  such. Fire-and-forget: if the sender has no live socket, nothing is stored and
 *  nothing is queued (the sender catches up with `deliveredCheck` on reconnect). */
export interface DeliveredMsg {
  t: 'delivered'
  id: string
  /** Who picked it up. UNTRUSTED, and used only to locate a local history row:
   *  a relay naming the wrong peer just points at a row that does not exist, and
   *  the update is a no-op. It is not new information either way, since the sender
   *  chose that recipient. */
  from: string
}

/** Reply to `deliveredCheck`: the subset of the asked-about ids the recipient's
 *  inbox has recorded as consumed. */
export interface DeliveredListMsg {
  t: 'deliveredList'
  reqId: string
  ids: string[]
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
  | RosterPublishedMsg
  | RosterMsg
  | RotationPublishedMsg
  | RotationMsg
  | DeviceClaimedMsg
  | LinkChunkMsg
  | DeliverMsg
  | SentMsg
  | DeliveredMsg
  | DeliveredListMsg
  | ErrorMsg
