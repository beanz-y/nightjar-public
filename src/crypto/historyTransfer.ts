// Carrying saved messages to a device already on the account (DESIGN 8.12).
//
// A linked device starts empty, deliberately. This is the separate act that moves
// history across afterwards, and it goes screen to camera ONLY: unlike linking,
// there is no relay fallback here and there is not going to be one. The reason is
// not secrecy (the bytes are sealed either way) but volume and honesty: this can
// be hundreds of kilobytes of everything you have ever said, and handing that to
// the relay to hold, even sealed, is a different promise from the one DESIGN 7.5
// makes about what the relay stores.
//
// Envelope:
//   0   4   magic "NJHT"
//   4   1   format version (0x01)
//   5   16  salt
//   21  ..  XChaCha20-Poly1305 ciphertext || tag, the header as AAD
//
// key||nonce = HKDF(secret, salt, INFO_HISTORY_XFER, 56), where `secret` came off
// the receiving device's screen. So opening it proves the sender photographed
// that screen, exactly as in the link ceremony, and nothing else can open it.
//
// ONE sealed piece rather than chunks. Chunking exists so a transfer can ride the
// relay's envelope ceiling; the fountain layer above does its own splitting, so
// here it would only be a second reassembly format to get wrong.
//
// The contents are the portable history unit Phase D already defined and bounded
// (historyUnit.ts). That unit was written to outlive the move package for exactly
// this moment, so nothing about the message rows is reinvented here.

import {
  HISTORY_XFER_MAGIC,
  HISTORY_XFER_MAX_BYTES,
  HISTORY_XFER_SALT_BYTES,
  HISTORY_XFER_VERSION,
  INFO_HISTORY_XFER,
  LINK_SECRET_BYTES,
} from './constants'
import { type HistoryUnitMessage, decodeHistoryUnit, encodeHistoryUnit } from './historyUnit'
import {
  XCHACHA_KEY_BYTES,
  XCHACHA_NONCE_BYTES,
  aeadOpen,
  aeadSeal,
  concatBytes,
  hkdfSha256,
  randomBytes,
  utf8,
} from './primitives'

const HEADER_LEN = 4 + 1 + HISTORY_XFER_SALT_BYTES // 21
const decoder = new TextDecoder()
const ACCOUNT_ID_RE = /^[a-z2-7]{52}$/

/** A transfer could not be parsed, or was refused on its shape. */
export class HistoryTransferError extends Error {
  constructor(message: string) {
    super(`saved messages: ${message}`)
    this.name = 'HistoryTransferError'
  }
}

/** A transfer did not authenticate: it was not sealed under this device's code. */
export class HistoryTransferAuthError extends Error {
  constructor(message = 'this transfer did not open with the code on this screen') {
    super(`saved messages: ${message}`)
    this.name = 'HistoryTransferAuthError'
  }
}

export interface HistoryTransferPayload {
  /** The account these messages belong to. The receiver refuses anything that is
   *  not its own: a sealed blob proves the sender was in the room, not that they
   *  are you, and writing a stranger's conversations into your history under
   *  their peer ids would be the same class of mistake the forwarded-copy records
   *  refuse (DESIGN 8.11). */
  accountId: string
  messages: HistoryUnitMessage[]
  createdAt: number
}

function keyNonce(secret: Uint8Array, salt: Uint8Array): { key: Uint8Array; nonce: Uint8Array } {
  const out = hkdfSha256(secret, salt, utf8(INFO_HISTORY_XFER), XCHACHA_KEY_BYTES + XCHACHA_NONCE_BYTES)
  return { key: out.slice(0, XCHACHA_KEY_BYTES), nonce: out.slice(XCHACHA_KEY_BYTES) }
}

/**
 * Seal saved messages for one transfer.
 *
 * Refuses over the size ceiling rather than truncating. A truncated history is
 * worse than none: it would land on the other device looking complete, with an
 * arbitrary slice of a conversation missing in the middle and nothing to say so.
 * The caller's job is to offer a shorter span of time instead.
 */
export function sealHistoryTransfer(payload: HistoryTransferPayload, secret: Uint8Array): Uint8Array {
  if (secret.length !== LINK_SECRET_BYTES) throw new HistoryTransferError('secret must be 32 bytes')
  if (!ACCOUNT_ID_RE.test(payload.accountId)) throw new HistoryTransferError('needs a full-width account id')
  const body = utf8(
    JSON.stringify({
      t: 'njhx',
      v: 1,
      accountId: payload.accountId,
      createdAt: payload.createdAt,
      unit: encodeHistoryUnit(payload.messages),
    }),
  )
  if (body.length > HISTORY_XFER_MAX_BYTES) {
    throw new HistoryTransferError('there is more here than one transfer can carry')
  }
  const salt = randomBytes(HISTORY_XFER_SALT_BYTES)
  const header = concatBytes(utf8(HISTORY_XFER_MAGIC), Uint8Array.from([HISTORY_XFER_VERSION]), salt)
  const { key, nonce } = keyNonce(secret, salt)
  return concatBytes(header, aeadSeal(key, nonce, body, header))
}

/**
 * Open a transfer. Order of operations is pinned by tests and matches every other
 * sealed format here: bounds BEFORE any key derivation, the AEAD BEFORE any
 * JSON.parse, and the payload discriminator BEFORE any field is read.
 */
export function openHistoryTransfer(blob: Uint8Array, secret: Uint8Array, now: number): HistoryTransferPayload {
  if (secret.length !== LINK_SECRET_BYTES) throw new HistoryTransferError('secret must be 32 bytes')
  if (blob.length < HEADER_LEN + 16) throw new HistoryTransferError('too short to be one of ours')
  const magic = utf8(HISTORY_XFER_MAGIC)
  for (let i = 0; i < 4; i++) if (blob[i] !== magic[i]) throw new HistoryTransferError('not a saved-messages transfer')
  if (blob[4] !== HISTORY_XFER_VERSION) throw new HistoryTransferError('unsupported transfer version')
  if (blob.length > HEADER_LEN + HISTORY_XFER_MAX_BYTES + 64) throw new HistoryTransferError('transfer is too large')

  const header = blob.slice(0, HEADER_LEN)
  const salt = blob.slice(5, 5 + HISTORY_XFER_SALT_BYTES)
  const { key, nonce } = keyNonce(secret, salt)
  let body: Uint8Array
  try {
    body = aeadOpen(key, nonce, blob.slice(HEADER_LEN), header)
  } catch {
    throw new HistoryTransferAuthError()
  }

  let raw: unknown
  try {
    raw = JSON.parse(decoder.decode(body))
  } catch {
    throw new HistoryTransferError('transfer is not readable')
  }
  const o = raw as Record<string, unknown>
  // Discriminator first: the link payload and the move payload are also `v: 1`
  // JSON, and identifying a blob by which fields it happens to have is how
  // cross-format bugs start.
  if (!o || o.t !== 'njhx' || o.v !== 1) throw new HistoryTransferError('not a saved-messages payload')
  const accountId = String(o.accountId ?? '')
  if (!ACCOUNT_ID_RE.test(accountId)) throw new HistoryTransferError('transfer names no account')
  const createdAt = typeof o.createdAt === 'number' && Number.isSafeInteger(o.createdAt) ? o.createdAt : 0
  // decodeHistoryUnit does the row-level validation and bounding, including the
  // timestamp ceiling that stops a wild ts pinning the conversation list forever.
  const { messages } = decodeHistoryUnit(o.unit, now)
  return { accountId, messages, createdAt }
}

/** The fixed header width, exported so a test can pin it. */
export const HISTORY_XFER_HEADER_LEN = HEADER_LEN
