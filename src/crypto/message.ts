// Structured message payload (P10a): what we now put INSIDE the ratchet AEAD as
// the plaintext, replacing raw utf8 text. It gives both sides a shared content
// id and a message KIND, which delete-for-everyone (P10d) and the ephemeral flag
// (P10e) need, while staying backward-compatible with pre-P10 plain-text.
//
// Layout (binary):
//   magic(4)   = "NJM1"
//   version(1) = 0x01
//   kind(1)    = 0x01 text | 0x02 delete | 0x03 session-refresh
//                | 0x04 retry-request | 0x05 device hello | 0x06 sync-sent
//                | 0x07 sync-delete | 0x08 sync-received | 0x09 sync-received-delete
//   msgId(16)  = the SHARED content id (history key / delete target)
//   text only: flags(1, bit0 = ephemeral, bit1 = fanned out; other bits reserved,
//              ignored), body(utf8)
//   delete:    nothing further (msgId is the target)
//   refresh:   nothing further (see encodeRefreshMessage; never decoded)
//   retry:     nothing further (its msgId is only an id, it targets nothing)
//   hello:     accountId (52 ASCII), the account the sending DEVICE claims
//   sync:      accountId (52 ASCII), then ts (u64be), then body(utf8): a copy of
//              a message YOU sent, for your own other devices
//   syncDel:   accountId (52 ASCII); msgId is the target. Drops YOUR OWN copy of a
//              message you sent, on your other devices
//   syncRecv:  accountId (52 ASCII), ts (u64be), body(utf8): a copy of a message
//              somebody ELSE sent to this account, passed on to its other devices
//              because the sender did not address them itself
//   syncRDel:  accountId (52 ASCII); msgId is the target. Drops the RECEIVED copy
//              of a message that account sent, on your other devices
//
// Two ids (red-team must-fix): this msgId is the CONTENT id and lives ONLY here,
// inside the authenticated plaintext. It is NOT the transport/envelope id (which
// stays a fresh per-envelope value used for relay dedup/ack). History is keyed by
// this content id and a delete targets it; nothing content-level is ever keyed on
// the relay-visible, relay-malleable envelope id.
//
// decodeMessage is TOTAL (never throws): a payload with no magic is a pre-P10
// plain-text message (legacy); a payload WITH the magic but structurally invalid,
// an unknown kind, or an unknown version is `malformed`, and the caller renders
// NOTHING (forward-compat: unknown things are clean-ignored, never thrown,
// rendered-as-legacy, or rejected). It runs in the caller AFTER the ratchet+seen
// commit, so a malformed record can never roll back protocol state.

import { concatBytes, randomBytes, u64be, utf8 } from './primitives'
import type { RotationStatement } from './rotation'

export const MSG_MAGIC = utf8('NJM1') // 0x4e 0x4a 0x4d 0x31
export const MSG_VERSION = 0x01
export const MSG_KIND_TEXT = 0x01
export const MSG_KIND_DELETE = 0x02
export const MSG_KIND_REFRESH = 0x03
export const MSG_KIND_RETRY = 0x04
export const MSG_KIND_HELLO = 0x05
export const MSG_KIND_SYNC_SENT = 0x06
export const MSG_KIND_SYNC_DELETE = 0x07
export const MSG_KIND_SYNC_RECV = 0x08
export const MSG_KIND_SYNC_RECV_DELETE = 0x09
/** Account-key rotation: "the account you know as X is now Y". Carries the whole
 *  signed statement, so it is checkable on its own under the key the receiver
 *  already holds rather than on the say-so of the session it arrived over. */
export const MSG_KIND_ROTATION = 0x0a
/** A user id is 52 base32 characters (DESIGN 3), and a hello carries exactly one. */
const ACCOUNT_ID_LEN = 52
const ACCOUNT_ID_RE = /^[a-z2-7]{52}$/
const HEADER_LEN = 4 + 1 + 1 + 16 // magic + version + kind + msgId = 22
const FLAG_EPHEMERAL = 0x01
/**
 * bit1: the sender addressed every device on the recipient's published device
 * list, so the recipient does not need to pass this on to its own other devices.
 *
 * It rides a RESERVED flag bit rather than a new field or a new kind, and that is
 * load-bearing rather than tidy. The flags byte is followed immediately by the
 * body, so any new field would move the body and every build already out there
 * would render the field as text. A reserved bit is the one place a sender can
 * say something new that older builds are already specified to ignore.
 *
 * Read the ABSENCE, not the presence: a message with the bit clear is one nobody
 * promised to have fanned out, which is every message from every build that
 * predates multi-device. That is exactly the population this exists to cover.
 *
 * NO BUILD FROM v1.14.3 ONWARD SETS THIS BIT, and it is kept anyway. The claim
 * could only ever be an intent (the plaintext is sealed before any copy commits),
 * and a wrong intent loses a message permanently and silently, so the send path
 * now always passes false. It stays defined, read and honored because senders
 * running v1.12.0 through v1.14.2 will keep setting it for as long as they are out
 * there, and a receiver must keep doing what those senders asked. Treat bit1 as
 * spent: do not reuse it for something else.
 */
const FLAG_FANNED = 0x02
/** Defensive cap on a decoded body. The send path caps at 8000 chars and the
 *  relay caps ciphertext at 64 KiB, so a body this large is not one of ours. */
export const MSG_MAX_BODY_BYTES = 64 * 1024

export type DecodedMessage =
  | { kind: 'text'; id: Uint8Array; body: string; ephemeral: boolean; fanned: boolean }
  | { kind: 'delete'; id: Uint8Array }
  | { kind: 'retry'; id: Uint8Array }
  | { kind: 'hello'; id: Uint8Array; accountId: string }
  | { kind: 'syncSent'; id: Uint8Array; accountId: string; ts: number; body: string }
  | { kind: 'syncDelete'; id: Uint8Array; accountId: string }
  | { kind: 'syncRecv'; id: Uint8Array; accountId: string; ts: number; body: string }
  | { kind: 'syncRecvDelete'; id: Uint8Array; accountId: string }
  | { kind: 'rotation'; id: Uint8Array; statement: RotationStatement }
  | { kind: 'legacy'; body: string }
  | { kind: 'malformed' }

const decoder = new TextDecoder()

function hasMagic(b: Uint8Array): boolean {
  return (
    b.length >= 4 && b[0] === MSG_MAGIC[0] && b[1] === MSG_MAGIC[1] && b[2] === MSG_MAGIC[2] && b[3] === MSG_MAGIC[3]
  )
}

/** A fresh 16-byte content message id. */
export function newMsgId(): Uint8Array {
  return randomBytes(16)
}

/** Encode a text message. `id` is the 16-byte content msgId. `fanned` says the
 *  sender addressed every device the recipient's published device list named, so
 *  the receiving device does not need to pass a copy to its own siblings. */
export function encodeTextMessage(id: Uint8Array, body: string, ephemeral: boolean, fanned = false): Uint8Array {
  if (id.length !== 16) throw new Error('message: msgId must be 16 bytes')
  const flags = (ephemeral ? FLAG_EPHEMERAL : 0) | (fanned ? FLAG_FANNED : 0)
  return concatBytes(MSG_MAGIC, Uint8Array.from([MSG_VERSION, MSG_KIND_TEXT]), id, Uint8Array.from([flags]), utf8(body))
}

/** Encode a delete control message targeting content msgId `id`. */
export function encodeDeleteMessage(id: Uint8Array): Uint8Array {
  if (id.length !== 16) throw new Error('message: msgId must be 16 bytes')
  return concatBytes(MSG_MAGIC, Uint8Array.from([MSG_VERSION, MSG_KIND_DELETE]), id)
}

/** Encode a session-refresh message (Phase D, DESIGN 8.3). Sent once to each
 *  imported contact after a move so THEIR next send rides a live session instead
 *  of the dead one their device still holds. Its entire value is the fresh X3DH
 *  initial it rides in on; the payload itself means nothing. decodeMessage
 *  deliberately does NOT learn this kind: every receiver, old build or new,
 *  classifies it `malformed` and renders/persists NOTHING, which is exactly the
 *  desired behavior, while the protocol layer still promotes the new session. */
export function encodeRefreshMessage(id: Uint8Array): Uint8Array {
  if (id.length !== 16) throw new Error('message: msgId must be 16 bytes')
  return concatBytes(MSG_MAGIC, Uint8Array.from([MSG_VERSION, MSG_KIND_REFRESH]), id)
}

/** Encode a retry-request (DESIGN 8.10): "I could not read something you sent me
 *  recently; re-establish and send your recent messages again."
 *
 *  It deliberately names NOTHING. A device that could not decrypt never learned
 *  the content ids inside those messages, only the relay's opaque transport ids,
 *  so it is incapable of asking for a specific message. That is a structural rate
 *  limit rather than a policy one: any number of unreadable messages collapses
 *  into one session-level request, and no future version can widen it without
 *  changing the wire format.
 *
 *  `id` is a fresh content id used only to give the record an identity; unlike a
 *  delete, it targets nothing. Unlike the session-refresh above, this kind IS
 *  taught to decodeMessage, because the receiver has to act on it. Older builds
 *  (1.9.0 and before) classify it `malformed` and ignore it, so a request to a
 *  contact who has not updated degrades to exactly the v1.9.0 behavior: nothing is
 *  shown or stored, but the X3DH initial it rides still promotes a live session. */
export function encodeRetryRequest(id: Uint8Array): Uint8Array {
  if (id.length !== 16) throw new Error('message: msgId must be 16 bytes')
  return concatBytes(MSG_MAGIC, Uint8Array.from([MSG_VERSION, MSG_KIND_RETRY]), id)
}

/**
 * Encode a device hello (Sesame): "the device sending this belongs to account X".
 *
 * Conversations are filed by ACCOUNT while sessions run between DEVICES, so a
 * receiver has to be able to attribute an incoming device to a person. It cannot
 * work that out on its own: what it caches is account-to-devices, and a message
 * from a device it has never seen gives it nothing to look the account up BY.
 *
 * So the sender says. The claim is worth nothing on its own and is not treated as
 * worth anything: the receiver checks it against that account's signed roster,
 * which only the account key can produce. A device claiming an account that has
 * not listed it is simply not attributed.
 *
 * Only a LINKED device needs to send this. On a first device the account key IS
 * the device key, so its device id already equals its account id and a receiver
 * that has never heard of it correctly reads it as an account of one, which is
 * every user today.
 */
export function encodeHelloMessage(id: Uint8Array, accountId: string): Uint8Array {
  if (id.length !== 16) throw new Error('message: msgId must be 16 bytes')
  if (!ACCOUNT_ID_RE.test(accountId)) throw new Error('message: hello needs a full-width account id')
  return concatBytes(MSG_MAGIC, Uint8Array.from([MSG_VERSION, MSG_KIND_HELLO]), id, utf8(accountId))
}

/**
 * Encode a copy of a message for the sender's OWN other devices (Sesame).
 *
 * A peer's devices each get the message itself. This is the other direction: what
 * your laptop needs so a message you sent from your phone appears there too. It
 * cannot be the same record, because the receiving device has to file it as
 * something YOU sent to somebody ELSE, which needs two things an ordinary text
 * does not carry: which conversation it belongs to, and when it was originally
 * written. Without the timestamp the copy would sort to whenever the laptop
 * happened to be switched on.
 *
 * `id` is the ORIGINAL content id, so both of your devices key the same message
 * the same way and a later delete reaches it on both.
 */
export function encodeSyncSentMessage(id: Uint8Array, accountId: string, ts: number, body: string): Uint8Array {
  if (id.length !== 16) throw new Error('message: msgId must be 16 bytes')
  if (!ACCOUNT_ID_RE.test(accountId)) throw new Error('message: sync needs a full-width account id')
  if (!Number.isSafeInteger(ts) || ts < 0) throw new Error('message: sync needs a real timestamp')
  return concatBytes(
    MSG_MAGIC,
    Uint8Array.from([MSG_VERSION, MSG_KIND_SYNC_SENT]),
    id,
    utf8(accountId),
    u64be(ts),
    utf8(body),
  )
}

/**
 * Encode a delete of one of YOUR OWN messages, for your own other devices (Sesame).
 *
 * Deleting a message you sent has to reach two different kinds of place: the
 * recipient's devices, which drop a message they received, and your own other
 * devices, which drop one they sent. The ordinary delete control cannot do the
 * second, because it names only the target and a receiver removes it from the
 * INBOUND side of whichever conversation the sender is. This says which
 * conversation the message was in, so your laptop can find its outbound copy.
 */
export function encodeSyncDeleteMessage(id: Uint8Array, accountId: string): Uint8Array {
  if (id.length !== 16) throw new Error('message: msgId must be 16 bytes')
  if (!ACCOUNT_ID_RE.test(accountId)) throw new Error('message: sync delete needs a full-width account id')
  return concatBytes(MSG_MAGIC, Uint8Array.from([MSG_VERSION, MSG_KIND_SYNC_DELETE]), id, utf8(accountId))
}

/**
 * Encode a copy of a message somebody ELSE sent, for this account's own other
 * devices (Sesame): the forwarding fallback.
 *
 * A sender running a build that knows about device lists addresses every device
 * itself, and no forwarding happens. Every OTHER sender, which is every contact
 * until they update and every contact who could not read the list at the moment
 * they sent, addresses one device only. Without this, linking a second device
 * would appear to work and then silently miss most of the conversation for as
 * long as that window lasts, which is measured in months rather than days.
 *
 * So the device that DID receive it passes a copy on. `accountId` is who the
 * message came from, `ts` is when it arrived here (not now: a copy stamped on
 * arrival at the sibling would sort to whenever that device was next opened), and
 * `id` is the ORIGINAL content id, so both devices key it the same way and a
 * later delete finds it on both.
 *
 * Session-only messages are never forwarded. They are the one kind deliberately
 * written down nowhere (8.7), and a forward would sit in the outbox until it was
 * delivered, which is a durable record of exactly the thing that promised not to
 * leave one.
 */
export function encodeSyncRecvMessage(id: Uint8Array, accountId: string, ts: number, body: string): Uint8Array {
  if (id.length !== 16) throw new Error('message: msgId must be 16 bytes')
  if (!ACCOUNT_ID_RE.test(accountId)) throw new Error('message: forward needs a full-width account id')
  if (!Number.isSafeInteger(ts) || ts < 0) throw new Error('message: forward needs a real timestamp')
  return concatBytes(
    MSG_MAGIC,
    Uint8Array.from([MSG_VERSION, MSG_KIND_SYNC_RECV]),
    id,
    utf8(accountId),
    u64be(ts),
    utf8(body),
  )
}

/**
 * Encode a forwarded delete: the other half of the fallback above.
 *
 * A delete control carries no flags byte (it is header-only, and a build that
 * predates this would classify a longer one as malformed and stop honoring
 * deletes altogether), so a receiving device cannot tell whether the sender
 * addressed its siblings. It therefore forwards every inbound delete, which is
 * safe because applying one twice is a no-op: the row is already gone and the
 * tombstone is already recorded.
 */
export function encodeSyncRecvDeleteMessage(id: Uint8Array, accountId: string): Uint8Array {
  if (id.length !== 16) throw new Error('message: msgId must be 16 bytes')
  if (!ACCOUNT_ID_RE.test(accountId)) throw new Error('message: forwarded delete needs a full-width account id')
  return concatBytes(MSG_MAGIC, Uint8Array.from([MSG_VERSION, MSG_KIND_SYNC_RECV_DELETE]), id, utf8(accountId))
}

/**
 * Encode an account-key rotation announcement: "the account you know as X is now
 * Y, and here is the statement that proves it".
 *
 * The whole statement rides inside, because it has to be checkable on its own:
 * the receiver verifies it under the account key it ALREADY holds for X, not
 * under anything this message or its session says. That is what makes the
 * announcement a delivery mechanism rather than an authority, and it is why the
 * same bytes can arrive over a session, be fetched from the Directory later by
 * somebody who was offline, or be handed over by one of your own devices, and
 * mean exactly the same thing in all three cases.
 *
 * Fixed-width fields in a pinned order, like every other kind here.
 */
export function encodeRotationMessage(id: Uint8Array, st: RotationStatement): Uint8Array {
  if (id.length !== 16) throw new Error('message: msgId must be 16 bytes')
  if (!ACCOUNT_ID_RE.test(st.oldAccountId) || !ACCOUNT_ID_RE.test(st.newAccountId)) {
    throw new Error('message: rotation needs full-width account ids')
  }
  if (st.newAccountKey.length !== 32) throw new Error('message: rotation key must be 32 bytes')
  if (st.oldSig.length !== 64 || st.newSig.length !== 64) throw new Error('message: rotation sigs must be 64 bytes')
  return concatBytes(
    MSG_MAGIC,
    Uint8Array.from([MSG_VERSION, MSG_KIND_ROTATION]),
    id,
    utf8(st.oldAccountId),
    utf8(st.newAccountId),
    st.newAccountKey,
    u64be(st.rotatedAt),
    st.oldSig,
    st.newSig,
  )
}

/** Total decoder, never throws. See the file header for the classification. */
export function decodeMessage(bytes: Uint8Array): DecodedMessage {
  if (!hasMagic(bytes)) {
    return { kind: 'legacy', body: decoder.decode(bytes) } // pre-P10 plain text
  }
  if (bytes.length < HEADER_LEN) return { kind: 'malformed' }
  if (bytes[4] !== MSG_VERSION) return { kind: 'malformed' } // unknown version -> clean-ignore
  const kind = bytes[5]
  const id = bytes.slice(6, 22)
  if (kind === MSG_KIND_TEXT) {
    if (bytes.length < HEADER_LEN + 1) return { kind: 'malformed' } // missing flags byte
    const flags = bytes[22]
    const bodyBytes = bytes.slice(23)
    if (bodyBytes.length > MSG_MAX_BODY_BYTES) return { kind: 'malformed' }
    // Only bits 0 and 1 are defined; the rest stay reserved and ignored (that is
    // what made bit1 usable at all, and the same promise has to hold for bit2).
    return {
      kind: 'text',
      id,
      body: decoder.decode(bodyBytes),
      ephemeral: (flags & FLAG_EPHEMERAL) !== 0,
      fanned: (flags & FLAG_FANNED) !== 0,
    }
  }
  if (kind === MSG_KIND_DELETE) {
    if (bytes.length !== HEADER_LEN) return { kind: 'malformed' } // a delete is header-only
    return { kind: 'delete', id }
  }
  if (kind === MSG_KIND_RETRY) {
    if (bytes.length !== HEADER_LEN) return { kind: 'malformed' } // a retry-request is header-only
    return { kind: 'retry', id }
  }
  // The two copy records (one for a message this account SENT, one for a message
  // it RECEIVED) share a layout exactly, and are decoded by one routine so they
  // cannot drift apart in validation. Only the direction they mean differs.
  if (kind === MSG_KIND_SYNC_SENT || kind === MSG_KIND_SYNC_RECV) {
    const prefix = HEADER_LEN + ACCOUNT_ID_LEN + 8
    if (bytes.length < prefix) return { kind: 'malformed' }
    const accountId = decoder.decode(bytes.slice(HEADER_LEN, HEADER_LEN + ACCOUNT_ID_LEN))
    if (!ACCOUNT_ID_RE.test(accountId)) return { kind: 'malformed' }
    const tsBytes = bytes.slice(HEADER_LEN + ACCOUNT_ID_LEN, prefix)
    let ts = 0
    for (const b of tsBytes) ts = ts * 256 + b
    if (!Number.isSafeInteger(ts)) return { kind: 'malformed' }
    const bodyBytes = bytes.slice(prefix)
    if (bodyBytes.length > MSG_MAX_BODY_BYTES) return { kind: 'malformed' }
    const copyKind = kind === MSG_KIND_SYNC_SENT ? 'syncSent' : 'syncRecv'
    return { kind: copyKind, id, accountId, ts, body: decoder.decode(bodyBytes) }
  }
  if (kind === MSG_KIND_SYNC_DELETE || kind === MSG_KIND_SYNC_RECV_DELETE) {
    if (bytes.length !== HEADER_LEN + ACCOUNT_ID_LEN) return { kind: 'malformed' }
    const accountId = decoder.decode(bytes.slice(HEADER_LEN))
    if (!ACCOUNT_ID_RE.test(accountId)) return { kind: 'malformed' }
    const delKind = kind === MSG_KIND_SYNC_DELETE ? 'syncDelete' : 'syncRecvDelete'
    return { kind: delKind, id, accountId }
  }
  if (kind === MSG_KIND_HELLO) {
    if (bytes.length !== HEADER_LEN + ACCOUNT_ID_LEN) return { kind: 'malformed' }
    const accountId = decoder.decode(bytes.slice(HEADER_LEN))
    // Checked here so no caller can be handed something that is not an id at all.
    // It is still only a CLAIM: the roster check is what makes it mean anything.
    if (!ACCOUNT_ID_RE.test(accountId)) return { kind: 'malformed' }
    return { kind: 'hello', id, accountId }
  }
  if (kind === MSG_KIND_ROTATION) {
    // Exact length: every field is fixed-width, so anything else is not one of
    // ours. Shape only, as everywhere in this decoder. Both signatures are
    // checked by verifyRotation under a key the CALLER already holds.
    const want = HEADER_LEN + ACCOUNT_ID_LEN * 2 + 32 + 8 + 64 + 64
    if (bytes.length !== want) return { kind: 'malformed' }
    let at = HEADER_LEN
    const oldAccountId = decoder.decode(bytes.slice(at, at + ACCOUNT_ID_LEN))
    at += ACCOUNT_ID_LEN
    const newAccountId = decoder.decode(bytes.slice(at, at + ACCOUNT_ID_LEN))
    at += ACCOUNT_ID_LEN
    if (!ACCOUNT_ID_RE.test(oldAccountId) || !ACCOUNT_ID_RE.test(newAccountId)) return { kind: 'malformed' }
    const newAccountKey = bytes.slice(at, at + 32)
    at += 32
    let rotatedAt = 0
    for (const b of bytes.slice(at, at + 8)) rotatedAt = rotatedAt * 256 + b
    at += 8
    if (!Number.isSafeInteger(rotatedAt)) return { kind: 'malformed' }
    const oldSig = bytes.slice(at, at + 64)
    const newSig = bytes.slice(at + 64, at + 128)
    return {
      kind: 'rotation',
      id,
      statement: { oldAccountId, newAccountId, newAccountKey, rotatedAt, oldSig, newSig },
    }
  }
  return { kind: 'malformed' } // unknown kind -> clean-ignore
}
