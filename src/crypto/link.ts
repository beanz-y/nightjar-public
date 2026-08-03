// Linking a device (Sesame). What an existing device sends a new one so it can
// join the account: the account key, the contacts, the nicknames.
//
// The envelope discipline is the move package's (see move.ts), with one
// deliberate difference: there is no passphrase and no key derivation cost,
// because the key is already a fresh 32-byte secret that travelled screen to
// camera rather than over the network. That secret does two jobs at once. It
// encrypts the payload, and because only a device that scanned the code can hold
// it, opening the payload PROVES the sender is the device that was standing in
// the room. So linking needs no key agreement and no prior registration: the
// transfer can be addressed to a device that has published nothing yet.
//
// Chunk layout (each chunk is independently sealed and independently opened):
//   0   4   magic "NJLK"
//   4   1   format version (0x01)
//   5   16  transfer id (fresh per link; ties chunks of one transfer together)
//   21  2   chunk index  (u16be)
//   23  2   chunk count  (u16be)
//   25  16  salt (FRESH per chunk: a constant salt with one secret would reuse
//            the keystream across chunks, the trap move.ts documents)
//   41  ..  XChaCha20-Poly1305 ciphertext || tag, the header as AAD
//
// key||nonce = HKDF(secret, salt, INFO_LINK, 56).
//
// Sealing each chunk separately, rather than sealing once and slicing, is what
// makes reassembly boring: a relay can reorder, duplicate or drop chunks and the
// worst it achieves is a transfer that does not complete. It cannot splice two
// transfers together (the id is in the AAD), cannot move a chunk to another
// position (the index is too), and cannot alter one byte of any of them.
//
// Order of operations is pinned by tests, and matches move.ts for the same
// reasons: header bounds are checked BEFORE any key derivation, the AEAD
// authenticates BEFORE any JSON.parse, and the payload discriminator is checked
// before any field is read.

import {
  INFO_LINK,
  LINK_FORMAT_VERSION,
  LINK_MAGIC,
  LINK_MAX_CHUNKS,
  LINK_MAX_CHUNK_BYTES,
  LINK_MAX_PAYLOAD_BYTES,
  LINK_SALT_BYTES,
  LINK_SECRET_BYTES,
  MOVE_MAX_ALIASES,
  BACKUP_MAX_CONTACTS,
} from './constants'
import { accountIdOf } from './identity'
import { MAX_ALIAS_LENGTH } from '../trust/contactStore'
import {
  XCHACHA_KEY_BYTES,
  XCHACHA_NONCE_BYTES,
  aeadOpen,
  aeadSeal,
  concatBytes,
  ed25519Public,
  hkdfSha256,
  randomBytes,
  utf8,
} from './primitives'
import { b64decode, b64encode } from '../wire/codec'

const HEADER_LEN = 4 + 1 + 16 + 2 + 2 + LINK_SALT_BYTES // 41
const decoder = new TextDecoder()

/** A link payload could not be parsed or was refused on its shape. */
export class LinkFormatError extends Error {
  constructor(message: string) {
    super(`link: ${message}`)
    this.name = 'LinkFormatError'
  }
}

/** A chunk did not authenticate: wrong secret, or tampered with in flight. */
export class LinkAuthError extends Error {
  constructor(message = 'this transfer did not open with that code') {
    super(`link: ${message}`)
    this.name = 'LinkAuthError'
  }
}

/** One contact as a link carries it. Trust is deliberately absent: see below. */
export interface LinkContact {
  peerId: string
  ikSig: string
}

export interface LinkPayload {
  accountId: string
  /** The account signing key's private half (32 bytes). This is the whole point
   *  of a link: it is what makes the new device a device OF this account. */
  accountKeyPriv: Uint8Array
  contacts: LinkContact[]
  aliases: Record<string, string>
  createdAt: number
}

function keyNonce(secret: Uint8Array, salt: Uint8Array): { key: Uint8Array; nonce: Uint8Array } {
  const out = hkdfSha256(secret, salt, utf8(INFO_LINK), XCHACHA_KEY_BYTES + XCHACHA_NONCE_BYTES)
  return { key: out.slice(0, XCHACHA_KEY_BYTES), nonce: out.slice(XCHACHA_KEY_BYTES) }
}

function u16be(n: number): Uint8Array {
  return Uint8Array.from([(n >> 8) & 0xff, n & 0xff])
}

/**
 * Seal a payload into chunks addressed to one transfer.
 *
 * `transferId` is generated here rather than accepted, for the same reason
 * sealMove exposes no salt override: a caller that reused one across two links
 * would let chunks of one be spliced into the other.
 *
 * `chunkBytes` exists because the chunking is a property of the RELAY, not of the
 * format: envelopes are capped at 64 KiB, so a transfer that rides them has to be
 * cut up. A transfer that goes screen to camera has no such cap, and the fountain
 * layer does its own splitting, so passing the payload ceiling here yields exactly
 * one sealed unit and the optical path needs no second format to reassemble.
 */
export function sealLink(
  payload: LinkPayload,
  secret: Uint8Array,
  chunkBytes = LINK_MAX_CHUNK_BYTES,
): Uint8Array[] {
  if (secret.length !== LINK_SECRET_BYTES) throw new LinkFormatError('secret must be 32 bytes')
  if (chunkBytes < 1 || chunkBytes > LINK_MAX_PAYLOAD_BYTES) throw new LinkFormatError('bad chunk size')
  const body = utf8(
    JSON.stringify({
      t: 'njlink',
      v: 1,
      accountId: payload.accountId,
      accountKey: b64encode(payload.accountKeyPriv),
      contacts: payload.contacts.map((c) => ({ peerId: c.peerId, ikSig: c.ikSig })),
      aliases: payload.aliases,
      createdAt: payload.createdAt,
    }),
  )
  if (body.length > LINK_MAX_PAYLOAD_BYTES) {
    throw new LinkFormatError('there is too much here to send to a new device')
  }
  const transferId = randomBytes(16)
  const count = Math.max(1, Math.ceil(body.length / chunkBytes))
  const out: Uint8Array[] = []
  for (let i = 0; i < count; i++) {
    const slice = body.slice(i * chunkBytes, (i + 1) * chunkBytes)
    const salt = randomBytes(LINK_SALT_BYTES)
    const header = concatBytes(
      utf8(LINK_MAGIC),
      Uint8Array.from([LINK_FORMAT_VERSION]),
      transferId,
      u16be(i),
      u16be(count),
      salt,
    )
    const { key, nonce } = keyNonce(secret, salt)
    out.push(concatBytes(header, aeadSeal(key, nonce, slice, header)))
  }
  return out
}

/** A chunk's header, read before anything is decrypted. */
export interface LinkChunkHeader {
  transferId: string
  index: number
  count: number
}

/** Parse and bounds-check a chunk header WITHOUT the secret, so a receiver can
 *  group and bound a transfer before it has decided to open anything. */
export function readLinkChunkHeader(chunk: Uint8Array): LinkChunkHeader {
  if (chunk.length < HEADER_LEN + 16) throw new LinkFormatError('chunk is too short to be one of ours')
  const magic = utf8(LINK_MAGIC)
  for (let i = 0; i < 4; i++) if (chunk[i] !== magic[i]) throw new LinkFormatError('not a link transfer')
  if (chunk[4] !== LINK_FORMAT_VERSION) throw new LinkFormatError('unsupported link format version')
  const index = (chunk[21] << 8) | chunk[22]
  const count = (chunk[23] << 8) | chunk[24]
  if (count < 1 || count > LINK_MAX_CHUNKS) throw new LinkFormatError('implausible chunk count')
  if (index >= count) throw new LinkFormatError('chunk index outside its own transfer')
  // Bounded by what the whole PAYLOAD may be rather than by the relay's chunk
  // size, because a chunk that travelled optically is deliberately one piece. The
  // relay path keeps its own, much smaller ceiling on the envelopes it will carry,
  // enforced where it belongs: at the relay.
  if (chunk.length > HEADER_LEN + LINK_MAX_PAYLOAD_BYTES + 64) throw new LinkFormatError('chunk is too large')
  return { transferId: b64encode(chunk.slice(5, 21)), index, count }
}

/** Open one chunk, returning its plaintext slice. Authenticates before it
 *  returns anything, so a chunk that fails is never partially believed. */
function openChunk(chunk: Uint8Array, secret: Uint8Array): Uint8Array {
  readLinkChunkHeader(chunk) // bounds first, always
  const header = chunk.slice(0, HEADER_LEN)
  const salt = chunk.slice(25, 25 + LINK_SALT_BYTES)
  const { key, nonce } = keyNonce(secret, salt)
  try {
    return aeadOpen(key, nonce, chunk.slice(HEADER_LEN), header)
  } catch {
    throw new LinkAuthError()
  }
}

/**
 * Open a complete transfer. `chunks` may arrive in any order and may repeat; it
 * must contain every index of exactly one transfer.
 *
 * Contacts come back with NO trust attached, and that is a product decision
 * rather than an omission: a device earns its own verification. A linked device
 * shows every contact as unverified until the person compares safety numbers on
 * THAT device, so nothing, not even another of your own devices, can mark a
 * contact verified here. See DESIGN 6.2.
 */
export function openLink(chunks: readonly Uint8Array[], secret: Uint8Array): LinkPayload {
  if (secret.length !== LINK_SECRET_BYTES) throw new LinkFormatError('secret must be 32 bytes')
  if (chunks.length === 0) throw new LinkFormatError('no chunks')
  const headers = chunks.map(readLinkChunkHeader)
  const { transferId, count } = headers[0]
  if (headers.some((h) => h.transferId !== transferId)) throw new LinkFormatError('chunks are from different transfers')
  if (headers.some((h) => h.count !== count)) throw new LinkFormatError('chunks disagree about the transfer size')
  const byIndex = new Map<number, Uint8Array>()
  for (let i = 0; i < chunks.length; i++) {
    if (!byIndex.has(headers[i].index)) byIndex.set(headers[i].index, chunks[i])
  }
  if (byIndex.size !== count) throw new LinkFormatError(`transfer is incomplete (${byIndex.size} of ${count})`)

  const parts: Uint8Array[] = []
  for (let i = 0; i < count; i++) parts.push(openChunk(byIndex.get(i) as Uint8Array, secret))
  const body = concatBytes(...parts)
  if (body.length > LINK_MAX_PAYLOAD_BYTES) throw new LinkFormatError('payload is too large')

  let raw: unknown
  try {
    raw = JSON.parse(decoder.decode(body))
  } catch {
    throw new LinkFormatError('payload is not readable')
  }
  const o = raw as Record<string, unknown>
  // Discriminator BEFORE any field is read: other payload formats in this project
  // are also `v:1` JSON, and sniffing for fields is how cross-format bugs start.
  if (!o || o.t !== 'njlink' || o.v !== 1) throw new LinkFormatError('not a link payload')

  const accountKeyPriv = b64decode(String(o.accountKey ?? ''), 32)
  const accountId = String(o.accountId ?? '')
  // The account id must be the hash of the key that came with it, or this device
  // would join an account under a key that cannot sign for it.
  if (accountIdOf(ed25519Public(accountKeyPriv)) !== accountId) {
    throw new LinkFormatError('the account key does not match the account it claims')
  }

  const contacts: LinkContact[] = []
  const rawContacts = Array.isArray(o.contacts) ? o.contacts : []
  for (const c of rawContacts.slice(0, BACKUP_MAX_CONTACTS)) {
    const row = c as { peerId?: unknown; ikSig?: unknown }
    if (typeof row.peerId !== 'string' || typeof row.ikSig !== 'string') continue
    try {
      // Same binding every other contact path enforces: drop rather than throw, so
      // one bad row cannot cost the whole link.
      if (accountIdOf(b64decode(row.ikSig, 32)) !== row.peerId) continue
    } catch {
      continue
    }
    contacts.push({ peerId: row.peerId, ikSig: row.ikSig })
  }

  const aliases: Record<string, string> = Object.create(null) as Record<string, string>
  const rawAliases = (o.aliases ?? {}) as Record<string, unknown>
  if (typeof rawAliases === 'object' && rawAliases !== null) {
    const known = new Set(contacts.map((c) => c.peerId))
    for (const [peer, name] of Object.entries(rawAliases).slice(0, MOVE_MAX_ALIASES)) {
      if (typeof name !== 'string' || !known.has(peer)) continue
      aliases[peer] = name.trim().slice(0, MAX_ALIAS_LENGTH)
    }
  }

  const createdAt = typeof o.createdAt === 'number' && Number.isSafeInteger(o.createdAt) ? o.createdAt : 0
  return { accountId, accountKeyPriv, contacts, aliases, createdAt }
}

/** The fixed header width, exported so a test can pin it. */
export const LINK_HEADER_LEN = HEADER_LEN
