// Move package (Phase D, DESIGN 8.3). One deliberately made file that carries a
// device's whole standing to a NEW device: identity, contacts with their trust,
// local nicknames, deletion markers, and the saved message history as a
// [historyUnit]. Sessions, prekeys, and tombstones never ride (forward secrecy;
// their premises are per-device).
//
// Envelope: byte-for-byte the backup blob's discipline (see backup.ts):
//   0   4   magic "NJMV"
//   4   1   format version (0x01)
//   5   4   Argon2id m (u32be, KiB)
//   9   1   Argon2id t (passes)
//   10  1   Argon2id p (lanes)
//   11  16  salt (fresh CSPRNG per export; sealMove exposes NO override, because
//            a fixed salt with a reused passphrase would be a two-time pad over
//            every message the user ever kept)
//   27  ..  XChaCha20-Poly1305 ciphertext || tag, header as AAD
//
// key||nonce = HKDF(Argon2id(canonicalized passphrase, salt, m/t/p), zeros,
// INFO_MOVE, 56). The info string is what domain-separates a move key from a
// backup key; it is selected HERE, from the magic this module owns, never passed
// in by a caller (a shared openEnvelope(blob, info) is how cross-format bugs are
// born; red-team hard rule).
//
// The passphrase is GENERATED-ONLY on export (~100 bits) and hand-typed once on
// the new device, so this module canonicalizes what the human types: NFC,
// lowercase, then strip everything outside the base32 alphabet (dashes, spaces,
// autocorrect debris). The entropy lives in the 20 generated characters, all of
// which survive canonicalization unchanged.
//
// Order of operations is pinned by tests and must not drift: header bounds are
// checked BEFORE the KDF runs (DoS gate), the AEAD authenticates BEFORE any
// JSON.parse (a hostile payload is never parsed), and the payload discriminator
// `t:'njmv'` is checked before any field is read (the backup payload is also
// `v:1` JSON; field-presence sniffing would cross-parse).

import {
  BACKUP_MAX_M_KIB,
  BACKUP_MAX_T,
  BACKUP_MIN_M_KIB,
  BACKUP_SALT_BYTES,
  INFO_MOVE,
  MOVE_FORMAT_VERSION,
  MOVE_MAGIC,
  MOVE_MAX_ALIASES,
  MOVE_MAX_PAYLOAD_BYTES,
  BACKUP_MAX_CONTACTS,
} from './constants'
import { type BackupKdf, type BackupParams, DEFAULT_BACKUP_PARAMS, argon2idKdf } from './backup'
import { type DecodedHistoryUnit, type HistoryUnitMessage, decodeHistoryUnit, encodeHistoryUnit } from './historyUnit'
import { type Identity, deriveUserId, deserializeIdentity, serializeIdentity } from './identity'
import {
  XCHACHA_KEY_BYTES,
  XCHACHA_NONCE_BYTES,
  aeadOpen,
  aeadSeal,
  concatBytes,
  hkdfSha256,
  randomBytes,
  u32be,
  utf8,
} from './primitives'
import { b64decode, b64encode } from '../wire/codec'
import { type Contact, MAX_ALIAS_LENGTH, MAX_DISMISSALS, type TrustLevel } from '../trust/contactStore'

const HEADER_LEN = 4 + 1 + 4 + 1 + 1 + BACKUP_SALT_BYTES
const MAGIC_BYTES = utf8(MOVE_MAGIC)
const TRUST_LEVELS: readonly TrustLevel[] = ['unverified', 'invite', 'verified']
const USER_ID_RE = /^[a-z2-7]{52}$/

export class MoveFormatError extends Error {
  constructor(msg: string) {
    super(msg)
    this.name = 'MoveFormatError'
  }
}

/** Parsed but did not authenticate: wrong passphrase or a corrupted / tampered
 *  file. Indistinguishable by design (AEAD). */
export class MoveAuthError extends Error {
  constructor() {
    super('wrong passphrase, or the move file is corrupted')
    this.name = 'MoveAuthError'
  }
}

/** What the human typed, reduced to what the generator emits: NFC, lowercase,
 *  every character outside [a-z2-7] removed (dashes, spaces, capitalization,
 *  autocorrect artifacts). Pinned by a known-answer test; changing this locks
 *  users out of files they already made. */
export function canonicalizeMovePassphrase(passphrase: string): string {
  return passphrase.normalize('NFC').toLowerCase().replace(/[^a-z2-7]/g, '')
}

/** The KDF chain, exported so a known-answer test can pin the exact
 *  canonicalize -> argon2id -> HKDF -> key||nonce construction (a round-trip
 *  cannot: seal and open share this function). */
export async function deriveMoveKeyNonce(
  passphrase: string,
  salt: Uint8Array,
  params: BackupParams,
  kdf: BackupKdf = argon2idKdf,
): Promise<{ key: Uint8Array; nonce: Uint8Array }> {
  const canon = canonicalizeMovePassphrase(passphrase)
  if (canon.length === 0) throw new MoveFormatError('passphrase is empty after normalization')
  const raw = await kdf(utf8(canon), salt, params)
  if (raw.length !== 32) throw new MoveFormatError('kdf returned an unexpected length')
  const out = hkdfSha256(raw, new Uint8Array(32), utf8(INFO_MOVE), XCHACHA_KEY_BYTES + XCHACHA_NONCE_BYTES)
  return { key: out.slice(0, XCHACHA_KEY_BYTES), nonce: out.slice(XCHACHA_KEY_BYTES) }
}

function encodeHeader(params: BackupParams, salt: Uint8Array): Uint8Array {
  return concatBytes(
    MAGIC_BYTES,
    Uint8Array.from([MOVE_FORMAT_VERSION]),
    u32be(params.m),
    Uint8Array.from([params.t, params.p]),
    salt,
  )
}

/** Parse and bounds-check a blob's header WITHOUT running the KDF (the DoS
 *  gate). The caller must additionally refuse oversized FILES before reading
 *  them into memory at all; this check is the last line, not the first. */
export function parseMoveHeader(blob: Uint8Array): { params: BackupParams; salt: Uint8Array } {
  if (blob.length < HEADER_LEN + 16) throw new MoveFormatError('not a Nightjar move file (too short)')
  if (blob.length > HEADER_LEN + MOVE_MAX_PAYLOAD_BYTES + 64) {
    throw new MoveFormatError('move file is implausibly large')
  }
  // An identity backup fed here gets the real reason, mirroring the special case
  // in parseBackupHeader for the reverse mistake.
  if (blob[0] === 0x4e && blob[1] === 0x4a && blob[2] === 0x42 && blob[3] === 0x4b) {
    throw new MoveFormatError('this is an identity backup (.njbk), not a move file')
  }
  for (let i = 0; i < 4; i++) {
    if (blob[i] !== MAGIC_BYTES[i]) throw new MoveFormatError('not a Nightjar move file')
  }
  if (blob[4] !== MOVE_FORMAT_VERSION) {
    throw new MoveFormatError(`move file format ${blob[4]} is not supported by this app version`)
  }
  const m = ((blob[5] << 24) | (blob[6] << 16) | (blob[7] << 8) | blob[8]) >>> 0
  const t = blob[9]
  const p = blob[10]
  if (m < BACKUP_MIN_M_KIB || m > BACKUP_MAX_M_KIB) throw new MoveFormatError('move KDF memory parameter out of range')
  if (t < 1 || t > BACKUP_MAX_T) throw new MoveFormatError('move KDF pass count out of range')
  if (p !== 1) throw new MoveFormatError('move KDF lane count out of range')
  return { params: { m, t, p }, salt: blob.slice(11, HEADER_LEN) }
}

// --- payload ----------------------------------------------------------------

/** A deletion marker as the file carries it. `hadSession` deliberately does NOT
 *  ride: it answers "did THIS device's published prekeys get consumed", and the
 *  import's re-registration (fresh prekeys, old vends cleared server-side)
 *  falsifies that premise by construction, so the importer records false. */
export interface MoveDismissal {
  at: number
  auto: boolean
}

export interface MovePayload {
  identity: Identity
  contacts: Contact[]
  aliases: Record<string, string>
  dismissals: Record<string, MoveDismissal>
  messages: HistoryUnitMessage[]
  createdAt: number
}

export interface OpenedMove {
  payload: MovePayload
  dropped: {
    contacts: number
    aliases: number
    dismissals: number
    /** Rows dropped by validation, PLUS rows naming a peer with no accepted
     *  contact row (nothing may create a conversation with a peer the file does
     *  not also introduce as a contact). */
    messages: number
    /** Duplicate (peer, dir, id) rows collapsed (they share one storage key;
     *  uncounted, the import report would lie). */
    collapsed: number
  }
}

interface WirePayload {
  t: 'njmv'
  v: number
  createdAt: number
  identity: string
  contacts: Array<{ peerId: string; ikSig: string; trust: string; firstSeen: number; verifiedAt: number | null }>
  aliases: Record<string, string>
  dismissals: Record<string, { at: number; auto?: boolean }>
  history: unknown
}

/** Encode the payload. The EXPORT side gathers and bounds (refusing over-cap
 *  with counts); encode enforces the same caps as a backstop and THROWS rather
 *  than truncating: a silently partial move file is the worst outcome this
 *  format can produce. */
export function encodeMovePayload(
  identity: Identity,
  contacts: Contact[],
  aliases: Record<string, string>,
  dismissals: Record<string, MoveDismissal>,
  messages: HistoryUnitMessage[],
  createdAt: number,
): Uint8Array {
  if (contacts.length > BACKUP_MAX_CONTACTS) throw new MoveFormatError('too many contacts for a move file')
  if (Object.keys(aliases).length > MOVE_MAX_ALIASES) throw new MoveFormatError('too many nicknames for a move file')
  if (Object.keys(dismissals).length > MAX_DISMISSALS) {
    throw new MoveFormatError('too many deletion markers for a move file')
  }
  const wire: WirePayload = {
    t: 'njmv',
    v: 1,
    createdAt,
    identity: b64encode(serializeIdentity(identity)),
    contacts: contacts.map((c) => ({
      peerId: c.peerId,
      ikSig: c.ikSig,
      trust: c.trust,
      firstSeen: c.firstSeen,
      verifiedAt: c.verifiedAt,
    })),
    aliases,
    dismissals,
    history: encodeHistoryUnit(messages),
  }
  const bytes = utf8(JSON.stringify(wire))
  if (bytes.length > MOVE_MAX_PAYLOAD_BYTES) throw new MoveFormatError('move payload exceeds the size cap')
  return bytes
}

/** Decode + validate an AUTHENTICATED payload. Exported for tests (parse-order
 *  and discriminator pins). Foreign or corrupt rows are dropped and counted;
 *  structural problems throw. */
export function decodeMovePayload(bytes: Uint8Array, now: number): OpenedMove {
  if (bytes.length > MOVE_MAX_PAYLOAD_BYTES) throw new MoveFormatError('move payload too large')
  let wire: WirePayload
  try {
    wire = JSON.parse(new TextDecoder().decode(bytes)) as WirePayload
  } catch {
    throw new MoveFormatError('move payload is not valid JSON')
  }
  if (!wire || typeof wire !== 'object') throw new MoveFormatError('move payload malformed')
  if (wire.t !== 'njmv') throw new MoveFormatError('not a move payload')
  if (wire.v !== 1) throw new MoveFormatError('move payload version unsupported')
  if (typeof wire.identity !== 'string') throw new MoveFormatError('move payload missing identity')
  const identity = deserializeIdentity(b64decode(wire.identity, 192))

  // Contacts: the same row validation and userId<->key binding check as the
  // backup path (duplicated, not shared: backup.ts is a frozen format and this
  // file must never grow a decoder the two formats reach through one door).
  const contacts: Contact[] = []
  const contactIds = new Set<string>()
  let droppedContacts = 0
  const rows = Array.isArray(wire.contacts) ? wire.contacts : []
  if (rows.length > BACKUP_MAX_CONTACTS) throw new MoveFormatError('move payload holds too many contacts')
  for (const r of rows) {
    try {
      if (
        !r ||
        typeof r.peerId !== 'string' ||
        typeof r.ikSig !== 'string' ||
        !TRUST_LEVELS.includes(r.trust as TrustLevel) ||
        !Number.isFinite(r.firstSeen) ||
        !(r.verifiedAt === null || Number.isFinite(r.verifiedAt))
      ) {
        throw new Error('shape')
      }
      if (deriveUserId(b64decode(r.ikSig, 32)) !== r.peerId) throw new Error('binding')
      if (contactIds.has(r.peerId)) throw new Error('duplicate')
      contacts.push({
        peerId: r.peerId,
        ikSig: r.ikSig,
        trust: r.trust as TrustLevel,
        firstSeen: r.firstSeen,
        verifiedAt: r.verifiedAt,
      })
      contactIds.add(r.peerId)
    } catch {
      droppedContacts++
    }
  }

  // Nicknames: cosmetic, but keys join the conversation-list union, so a junk
  // key would render a phantom thread. Prototype-safe map, bounded values.
  const aliases: Record<string, string> = Object.create(null) as Record<string, string>
  let droppedAliases = 0
  if (wire.aliases !== undefined) {
    if (!wire.aliases || typeof wire.aliases !== 'object' || Array.isArray(wire.aliases)) {
      throw new MoveFormatError('move payload nicknames malformed')
    }
    const entries = Object.entries(wire.aliases as Record<string, unknown>)
    if (entries.length > MOVE_MAX_ALIASES) throw new MoveFormatError('move payload holds too many nicknames')
    for (const [k, v] of entries) {
      if (!USER_ID_RE.test(k) || typeof v !== 'string' || v.trim().length === 0) {
        droppedAliases++
        continue
      }
      aliases[k] = v.trim().slice(0, MAX_ALIAS_LENGTH)
    }
  }

  // Deletion markers: `at` is clamped to now (a future-dated marker would
  // outlive the 30-day intent and evict genuine ones from the bounded store).
  const dismissals: Record<string, MoveDismissal> = Object.create(null) as Record<string, MoveDismissal>
  let droppedDismissals = 0
  if (wire.dismissals !== undefined) {
    if (!wire.dismissals || typeof wire.dismissals !== 'object' || Array.isArray(wire.dismissals)) {
      throw new MoveFormatError('move payload deletion markers malformed')
    }
    const entries = Object.entries(wire.dismissals as Record<string, unknown>)
    if (entries.length > MAX_DISMISSALS) throw new MoveFormatError('move payload holds too many deletion markers')
    for (const [k, v] of entries) {
      const d = v as { at?: unknown; auto?: unknown }
      if (!USER_ID_RE.test(k) || !d || typeof d !== 'object' || typeof d.at !== 'number' || !Number.isSafeInteger(d.at) || d.at < 0) {
        droppedDismissals++
        continue
      }
      dismissals[k] = { at: Math.min(d.at, now), auto: typeof d.auto === 'boolean' ? d.auto : true }
    }
  }

  // History: the self-validating unit, then the contact binding: a row naming a
  // peer the file did not introduce as a contact is dropped (nothing may create
  // a conversation with no contact row, no trust badge, and no session behind it).
  const unit: DecodedHistoryUnit = decodeHistoryUnit(wire.history, now)
  const messages: HistoryUnitMessage[] = []
  let droppedMessages = unit.dropped
  for (const m of unit.messages) {
    if (!contactIds.has(m.peer)) {
      droppedMessages++
      continue
    }
    messages.push(m)
  }

  return {
    payload: {
      identity,
      contacts,
      aliases,
      dismissals,
      messages,
      createdAt: Number.isFinite(wire.createdAt) ? wire.createdAt : 0,
    },
    dropped: {
      contacts: droppedContacts,
      aliases: droppedAliases,
      dismissals: droppedDismissals,
      messages: droppedMessages,
      collapsed: unit.collapsed,
    },
  }
}

// --- seal / open ------------------------------------------------------------

/** Seal a move package. No salt override exists on purpose (see the header);
 *  tests pin deriveMoveKeyNonce instead of this entry point. */
export async function sealMove(
  payload: {
    identity: Identity
    contacts: Contact[]
    aliases: Record<string, string>
    dismissals: Record<string, MoveDismissal>
    messages: HistoryUnitMessage[]
  },
  passphrase: string,
  opts: { createdAt?: number; params?: BackupParams; kdf?: BackupKdf } = {},
): Promise<Uint8Array> {
  const params = opts.params ?? DEFAULT_BACKUP_PARAMS
  const salt = randomBytes(BACKUP_SALT_BYTES)
  const header = encodeHeader(params, salt)
  const { key, nonce } = await deriveMoveKeyNonce(passphrase, salt, params, opts.kdf ?? argon2idKdf)
  const bytes = encodeMovePayload(
    payload.identity,
    payload.contacts,
    payload.aliases,
    payload.dismissals,
    payload.messages,
    opts.createdAt ?? Date.now(),
  )
  const ciphertext = aeadSeal(key, nonce, bytes, header)
  return concatBytes(header, ciphertext)
}

export async function openMove(
  blob: Uint8Array,
  passphrase: string,
  opts: { kdf?: BackupKdf; now?: number } = {},
): Promise<OpenedMove> {
  const { params, salt } = parseMoveHeader(blob)
  const header = blob.slice(0, HEADER_LEN)
  const ciphertext = blob.slice(HEADER_LEN)
  const { key, nonce } = await deriveMoveKeyNonce(passphrase, salt, params, opts.kdf ?? argon2idKdf)
  let payload: Uint8Array
  try {
    payload = aeadOpen(key, nonce, ciphertext, header)
  } catch {
    throw new MoveAuthError()
  }
  return decodeMovePayload(payload, opts.now ?? Date.now())
}
