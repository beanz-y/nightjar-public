// Identity backup (P8, DESIGN 8.3). A backup is the identity (both private
// keys) plus the contact-trust map, wrapped under a key derived from a user
// passphrase with Argon2id. The relay never sees the blob, the passphrase, or
// the plaintext; v1 is download-only.
//
// Blob layout (all lengths fixed, header authenticated as AEAD AAD):
//   0   4   magic "NJBK"
//   4   1   format version (0x01)
//   5   4   Argon2id m (u32be, KiB)
//   9   1   Argon2id t (passes)
//   10  1   Argon2id p (lanes)
//   11  16  salt (fresh CSPRNG per export)
//   27  ..  XChaCha20-Poly1305 ciphertext || tag
//
// Key material: raw = Argon2id(NFC(passphrase), salt, m, t, p, 32 bytes), then
// key||nonce = HKDF-SHA256(raw, zeros, "Nightjar_Backup_v1", 56). The nonce is
// unique by construction (fresh salt -> fresh raw -> fresh key+nonce), matching
// the project rule that nonces are derived, never random alongside a reused key.
//
// Restore-side discipline: every header field is bounds-checked BEFORE the KDF
// runs, so a hostile blob cannot make the client allocate gigabytes or spin for
// minutes; the payload is size- and shape-checked before anything is trusted,
// and the identity bytes go through the fail-closed deserializeIdentity.

import { argon2id } from '@noble/hashes/argon2'
import {
  BACKUP_ARGON2_M_KIB,
  BACKUP_ARGON2_P,
  BACKUP_ARGON2_T,
  BACKUP_FORMAT_VERSION,
  BACKUP_MAGIC,
  BACKUP_MAX_CONTACTS,
  BACKUP_MAX_M_KIB,
  BACKUP_MAX_PAYLOAD_BYTES,
  BACKUP_MAX_T,
  BACKUP_MIN_M_KIB,
  BACKUP_SALT_BYTES,
  INFO_BACKUP,
  PASSPHRASE_MIN_LENGTH,
} from './constants'
import { type Identity, deriveUserId, deserializeIdentity, serializeIdentity } from './identity'
import {
  XCHACHA_KEY_BYTES,
  XCHACHA_NONCE_BYTES,
  aeadOpen,
  aeadSeal,
  base32lower,
  concatBytes,
  hkdfSha256,
  randomBytes,
  u32be,
  utf8,
} from './primitives'
import { b64decode, b64encode } from '../wire/codec'
import type { Contact, TrustLevel } from '../trust/contactStore'

const HEADER_LEN = 4 + 1 + 4 + 1 + 1 + BACKUP_SALT_BYTES
const MAGIC_BYTES = utf8(BACKUP_MAGIC)
const TRUST_LEVELS: readonly TrustLevel[] = ['unverified', 'invite', 'verified']

/** The blob is not a Nightjar backup, is a version we do not speak, or carries
 *  parameters outside the accepted range (a hostile or corrupted file). */
export class BackupFormatError extends Error {
  constructor(msg: string) {
    super(msg)
    this.name = 'BackupFormatError'
  }
}

/** The blob parsed but did not authenticate: wrong passphrase or a corrupted /
 *  tampered file. Indistinguishable by design (AEAD). */
export class BackupAuthError extends Error {
  constructor() {
    super('wrong passphrase, or the backup file is corrupted')
    this.name = 'BackupAuthError'
  }
}

/** Argon2id as an injectable seam: the UI runs it in a Web Worker so the page
 *  stays responsive; tests and node callers use this synchronous default. */
export type BackupKdf = (
  passphrase: Uint8Array,
  salt: Uint8Array,
  params: { m: number; t: number; p: number },
) => Promise<Uint8Array> | Uint8Array

export const argon2idKdf: BackupKdf = (passphrase, salt, { m, t, p }) =>
  argon2id(passphrase, salt, { m, t, p, dkLen: 32 })

export interface BackupParams {
  m: number
  t: number
  p: number
}

export const DEFAULT_BACKUP_PARAMS: BackupParams = {
  m: BACKUP_ARGON2_M_KIB,
  t: BACKUP_ARGON2_T,
  p: BACKUP_ARGON2_P,
}

/** What a backup holds. Sessions and history are deliberately absent
 *  (DESIGN 8.3: syncing ratchet state would break forward secrecy). */
export interface BackupPayload {
  identity: Identity
  contacts: Contact[]
  createdAt: number
}

/** Result of opening a blob: the payload plus how many contact rows were
 *  dropped by validation (0 for any blob this code produced). */
export interface OpenedBackup {
  payload: BackupPayload
  droppedContacts: number
}

/** Normalize a typed passphrase: Unicode NFC (iOS/Android IMEs disagree on
 *  composition) and whitespace-trimmed (paste artifacts). */
export function normalizePassphrase(passphrase: string): string {
  return passphrase.normalize('NFC').trim()
}

/** The typed-passphrase floor (DESIGN 8.3/14). The generated passphrase always
 *  passes. Returns null when acceptable, else a human-readable reason. */
export function passphraseIssue(passphrase: string): string | null {
  const n = normalizePassphrase(passphrase)
  if (n.length < PASSPHRASE_MIN_LENGTH) {
    return `use at least ${PASSPHRASE_MIN_LENGTH} characters (a few random words, or the generated passphrase)`
  }
  return null
}

/** 20 base32 characters (~100 bits) in dash-separated groups: strong enough
 *  that the blob reduces to the cipher, and typeable from a paper note. */
export function generateBackupPassphrase(): string {
  const chars = base32lower(randomBytes(13)).slice(0, 20)
  const groups: string[] = []
  for (let i = 0; i < 20; i += 4) groups.push(chars.slice(i, i + 4))
  return groups.join('-')
}

function encodeHeader(params: BackupParams, salt: Uint8Array): Uint8Array {
  return concatBytes(
    MAGIC_BYTES,
    Uint8Array.from([BACKUP_FORMAT_VERSION]),
    u32be(params.m),
    Uint8Array.from([params.t, params.p]),
    salt,
  )
}

/** The KDF chain, exported so a known-answer test can pin the exact
 *  argon2id -> HKDF -> key||nonce construction (a round-trip alone cannot: seal
 *  and open share this function, so a symmetric change passes silently). */
export async function deriveKeyNonce(
  passphrase: string,
  salt: Uint8Array,
  params: BackupParams,
  kdf: BackupKdf = argon2idKdf,
): Promise<{ key: Uint8Array; nonce: Uint8Array }> {
  const raw = await kdf(utf8(normalizePassphrase(passphrase)), salt, params)
  if (raw.length !== 32) throw new BackupFormatError('kdf returned an unexpected length')
  const out = hkdfSha256(raw, new Uint8Array(32), utf8(INFO_BACKUP), XCHACHA_KEY_BYTES + XCHACHA_NONCE_BYTES)
  return { key: out.slice(0, XCHACHA_KEY_BYTES), nonce: out.slice(XCHACHA_KEY_BYTES) }
}

// --- payload codec ----------------------------------------------------------

interface WirePayload {
  v: number
  createdAt: number
  identity: string // b64url of the 192-byte serialized identity
  contacts: Array<{ peerId: string; ikSig: string; trust: string; firstSeen: number; verifiedAt: number | null }>
}

export function encodeBackupPayload(identity: Identity, contacts: Contact[], createdAt: number): Uint8Array {
  const wire: WirePayload = {
    v: 1,
    createdAt,
    identity: b64encode(serializeIdentity(identity)),
    contacts: contacts.slice(0, BACKUP_MAX_CONTACTS).map((c) => ({
      peerId: c.peerId,
      ikSig: c.ikSig,
      trust: c.trust,
      firstSeen: c.firstSeen,
      verifiedAt: c.verifiedAt,
    })),
  }
  return utf8(JSON.stringify(wire))
}

function decodeBackupPayload(bytes: Uint8Array): OpenedBackup {
  if (bytes.length > BACKUP_MAX_PAYLOAD_BYTES) throw new BackupFormatError('backup payload too large')
  let wire: WirePayload
  try {
    wire = JSON.parse(new TextDecoder().decode(bytes)) as WirePayload
  } catch {
    throw new BackupFormatError('backup payload is not valid JSON')
  }
  if (!wire || typeof wire !== 'object' || wire.v !== 1) {
    throw new BackupFormatError('backup payload version unsupported')
  }
  if (typeof wire.identity !== 'string') throw new BackupFormatError('backup payload missing identity')
  // deserializeIdentity fails closed: pub/priv match both keys + idkbind verify.
  const identity = deserializeIdentity(b64decode(wire.identity, 192))

  const contacts: Contact[] = []
  let dropped = 0
  const rows = Array.isArray(wire.contacts) ? wire.contacts.slice(0, BACKUP_MAX_CONTACTS) : []
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
      // The binding check: a contact row's key must hash to its userId, exactly
      // as the live recordFirstContact enforces (DESIGN 6.1).
      if (deriveUserId(b64decode(r.ikSig, 32)) !== r.peerId) throw new Error('binding')
      contacts.push({
        peerId: r.peerId,
        ikSig: r.ikSig,
        trust: r.trust as TrustLevel,
        firstSeen: r.firstSeen,
        verifiedAt: r.verifiedAt,
      })
    } catch {
      dropped += 1
    }
  }
  return {
    payload: { identity, contacts, createdAt: Number.isFinite(wire.createdAt) ? wire.createdAt : 0 },
    droppedContacts: dropped,
  }
}

// --- seal / open ------------------------------------------------------------

export async function sealBackup(
  identity: Identity,
  contacts: Contact[],
  passphrase: string,
  opts: { createdAt?: number; params?: BackupParams; salt?: Uint8Array; kdf?: BackupKdf } = {},
): Promise<Uint8Array> {
  const params = opts.params ?? DEFAULT_BACKUP_PARAMS
  const salt = opts.salt ?? randomBytes(BACKUP_SALT_BYTES)
  if (salt.length !== BACKUP_SALT_BYTES) throw new BackupFormatError('salt must be 16 bytes')
  const header = encodeHeader(params, salt)
  const { key, nonce } = await deriveKeyNonce(passphrase, salt, params, opts.kdf ?? argon2idKdf)
  const payload = encodeBackupPayload(identity, contacts, opts.createdAt ?? Date.now())
  const ciphertext = aeadSeal(key, nonce, payload, header)
  return concatBytes(header, ciphertext)
}

/** Parse and bounds-check a blob's header WITHOUT running the KDF. Returns the
 *  cost parameters so the UI can warn before a long derivation. */
export function parseBackupHeader(blob: Uint8Array): { params: BackupParams; salt: Uint8Array } {
  if (blob.length < HEADER_LEN + 16) throw new BackupFormatError('not a Nightjar backup (too short)')
  // Upper bound BEFORE the KDF/AEAD: a genuine blob is the header + a payload
  // capped at BACKUP_MAX_PAYLOAD_BYTES plus AEAD overhead, so anything larger is
  // hostile. Refusing it here avoids allocating/AEAD-scanning a huge file.
  if (blob.length > HEADER_LEN + BACKUP_MAX_PAYLOAD_BYTES + 64) {
    throw new BackupFormatError('backup file is implausibly large')
  }
  for (let i = 0; i < 4; i++) {
    if (blob[i] !== MAGIC_BYTES[i]) throw new BackupFormatError('not a Nightjar backup')
  }
  if (blob[4] !== BACKUP_FORMAT_VERSION) {
    throw new BackupFormatError(`backup format ${blob[4]} is not supported by this app version`)
  }
  const m = ((blob[5] << 24) | (blob[6] << 16) | (blob[7] << 8) | blob[8]) >>> 0
  const t = blob[9]
  const p = blob[10]
  // Refuse out-of-range parameters BEFORE any KDF work: this is the DoS gate.
  if (m < BACKUP_MIN_M_KIB || m > BACKUP_MAX_M_KIB) throw new BackupFormatError('backup KDF memory parameter out of range')
  if (t < 1 || t > BACKUP_MAX_T) throw new BackupFormatError('backup KDF pass count out of range')
  if (p !== 1) throw new BackupFormatError('backup KDF lane count out of range')
  return { params: { m, t, p }, salt: blob.slice(11, HEADER_LEN) }
}

export async function openBackup(
  blob: Uint8Array,
  passphrase: string,
  opts: { kdf?: BackupKdf } = {},
): Promise<OpenedBackup> {
  const { params, salt } = parseBackupHeader(blob)
  const header = blob.slice(0, HEADER_LEN)
  const ciphertext = blob.slice(HEADER_LEN)
  const { key, nonce } = await deriveKeyNonce(passphrase, salt, params, opts.kdf ?? argon2idKdf)
  let payload: Uint8Array
  try {
    payload = aeadOpen(key, nonce, ciphertext, header)
  } catch {
    throw new BackupAuthError()
  }
  return decodeBackupPayload(payload)
}
