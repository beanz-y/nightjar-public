// Structured message payload (P10a): what we now put INSIDE the ratchet AEAD as
// the plaintext, replacing raw utf8 text. It gives both sides a shared content
// id and a message KIND, which delete-for-everyone (P10d) and the ephemeral flag
// (P10e) need, while staying backward-compatible with pre-P10 plain-text.
//
// Layout (binary):
//   magic(4)   = "NJM1"
//   version(1) = 0x01
//   kind(1)    = 0x01 text | 0x02 delete
//   msgId(16)  = the SHARED content id (history key / delete target)
//   text only: flags(1, bit0 = ephemeral; other bits reserved, ignored), body(utf8)
//   delete:    nothing further (msgId is the target)
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

import { concatBytes, randomBytes, utf8 } from './primitives'

export const MSG_MAGIC = utf8('NJM1') // 0x4e 0x4a 0x4d 0x31
export const MSG_VERSION = 0x01
export const MSG_KIND_TEXT = 0x01
export const MSG_KIND_DELETE = 0x02
const HEADER_LEN = 4 + 1 + 1 + 16 // magic + version + kind + msgId = 22
const FLAG_EPHEMERAL = 0x01
/** Defensive cap on a decoded body. The send path caps at 8000 chars and the
 *  relay caps ciphertext at 64 KiB, so a body this large is not one of ours. */
export const MSG_MAX_BODY_BYTES = 64 * 1024

export type DecodedMessage =
  | { kind: 'text'; id: Uint8Array; body: string; ephemeral: boolean }
  | { kind: 'delete'; id: Uint8Array }
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

/** Encode a text message. `id` is the 16-byte content msgId. */
export function encodeTextMessage(id: Uint8Array, body: string, ephemeral: boolean): Uint8Array {
  if (id.length !== 16) throw new Error('message: msgId must be 16 bytes')
  const flags = ephemeral ? FLAG_EPHEMERAL : 0
  return concatBytes(MSG_MAGIC, Uint8Array.from([MSG_VERSION, MSG_KIND_TEXT]), id, Uint8Array.from([flags]), utf8(body))
}

/** Encode a delete control message targeting content msgId `id`. */
export function encodeDeleteMessage(id: Uint8Array): Uint8Array {
  if (id.length !== 16) throw new Error('message: msgId must be 16 bytes')
  return concatBytes(MSG_MAGIC, Uint8Array.from([MSG_VERSION, MSG_KIND_DELETE]), id)
}

/** Total decoder — never throws. See the file header for the classification. */
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
    // Only bit0 is defined; other bits are reserved and ignored (forward-compat).
    return { kind: 'text', id, body: decoder.decode(bodyBytes), ephemeral: (flags & FLAG_EPHEMERAL) !== 0 }
  }
  if (kind === MSG_KIND_DELETE) {
    if (bytes.length !== HEADER_LEN) return { kind: 'malformed' } // a delete is header-only
    return { kind: 'delete', id }
  }
  return { kind: 'malformed' } // unknown kind -> clean-ignore
}
