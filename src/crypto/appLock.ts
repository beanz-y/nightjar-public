// App-lock key wrapping (P10c). All at-rest local data (message history bodies +
// metadata, and the contact list) is encrypted under a random 32-byte Local Data
// Key (LDK). The LDK is NEVER persisted unwrapped: it is generated in RAM at
// enrollment, wrapped under a KEK derived from each enabled unlock method, and
// only the wraps are stored. Reading local data requires unwrapping the LDK with
// the user's secret through Nightjar; a device image without the secret yields
// only ciphertext.
//
// KEK derivation:
//   - knowledge factor (passphrase / PIN): kek||nonce =
//       HKDF-SHA256( Argon2id(NFC(secret), argonSalt, 64MiB/t3/p1), hkdfSalt,
//                    "Nightjar_LockWrap_v1" )
//   - biometric (WebAuthn PRF): kek||nonce = HKDF-SHA256(prfSecret, hkdfSalt, same info)
// Both use a FRESH per-wrap hkdfSalt (and the knowledge path a fresh argonSalt),
// so the constant biometric prfSecret can never cause key/nonce reuse across wraps.
// The wrap AEAD binds the method kind + wrap format version as AAD.
//
// This module is pure crypto (no storage, no DOM); the stateful lock manager and
// the WebAuthn calls live in the storage/UI layers. Argon2id is an injectable seam
// so the UI can run it in a Web Worker and tests can stub it.

import { argon2id } from '@noble/hashes/argon2'
import {
  INFO_LOCK_WRAP,
  LOCK_ARGON2_M_KIB,
  LOCK_ARGON2_P,
  LOCK_ARGON2_T,
  LOCK_SALT_BYTES,
  LOCK_WRAP_FORMAT_VERSION,
} from './constants'
import {
  XCHACHA_KEY_BYTES,
  XCHACHA_NONCE_BYTES,
  aeadOpen,
  aeadSeal,
  concatBytes,
  domainSeparate,
  hkdfSha256,
  randomBytes,
  utf8,
} from './primitives'
import { b64decode, b64encode } from '../wire/codec'

/** Local Data Key length. */
export const LDK_BYTES = 32
const WRAP_AAD_TAG = 'Nightjar-ldkwrap-v1'

export type LockMethodKind = 'pass' | 'pin' | 'bio'

/** Argon2id params for a knowledge-factor KEK. */
export interface Argon2Params {
  m: number
  t: number
  p: number
}
export const DEFAULT_LOCK_ARGON2: Argon2Params = { m: LOCK_ARGON2_M_KIB, t: LOCK_ARGON2_T, p: LOCK_ARGON2_P }

/** Injectable Argon2id (the UI runs it in a worker; tests stub it). */
export type Argon2Kdf = (secret: Uint8Array, salt: Uint8Array, params: Argon2Params) => Promise<Uint8Array> | Uint8Array
export const argon2idKdf: Argon2Kdf = (secret, salt, { m, t, p }) => argon2id(secret, salt, { m, t, p, dkLen: 32 })

/** A wrapped LDK for one enabled unlock method. `wrap` = AEAD(kek, nonce, LDK). */
export interface KnowledgeWrap {
  kind: 'pass' | 'pin'
  argonSalt: Uint8Array
  hkdfSalt: Uint8Array
  m: number
  t: number
  p: number
  wrap: Uint8Array
}
export interface BioWrap {
  kind: 'bio'
  credentialId: Uint8Array
  hkdfSalt: Uint8Array
  wrap: Uint8Array
}
export type WrapRecord = KnowledgeWrap | BioWrap

/** The blob persisted at rest describing the configured lock (one per device). */
export interface LockRecord {
  version: number
  methods: WrapRecord[]
}

/** Wrong secret, corrupt/tampered wrap, or (biometric) the wrong authenticator.
 *  Indistinguishable by design (AEAD failure). */
export class AppLockAuthError extends Error {
  constructor() {
    super('incorrect passphrase / PIN, or the app-lock data is corrupted')
    this.name = 'AppLockAuthError'
  }
}

/** Normalize a typed secret: Unicode NFC (IMEs disagree) + trim (paste artifacts).
 *  A numeric PIN is unaffected by NFC/trim, so this is safe for both. */
export function normalizeSecret(secret: string): string {
  return secret.normalize('NFC').trim()
}

/** A fresh Local Data Key. */
export function generateLdk(): Uint8Array {
  return randomBytes(LDK_BYTES)
}

function kekFromRaw(raw: Uint8Array, hkdfSalt: Uint8Array): { key: Uint8Array; nonce: Uint8Array } {
  const out = hkdfSha256(raw, hkdfSalt, utf8(INFO_LOCK_WRAP), XCHACHA_KEY_BYTES + XCHACHA_NONCE_BYTES)
  return { key: out.slice(0, XCHACHA_KEY_BYTES), nonce: out.slice(XCHACHA_KEY_BYTES) }
}

async function kekFromSecret(
  secret: string,
  argonSalt: Uint8Array,
  hkdfSalt: Uint8Array,
  params: Argon2Params,
  kdf: Argon2Kdf,
): Promise<{ key: Uint8Array; nonce: Uint8Array }> {
  const raw = await kdf(utf8(normalizeSecret(secret)), argonSalt, params)
  if (raw.length !== 32) throw new Error('app-lock: kdf returned an unexpected length')
  return kekFromRaw(raw, hkdfSalt)
}

function wrapAad(kind: LockMethodKind): Uint8Array {
  return domainSeparate(WRAP_AAD_TAG, utf8(kind), Uint8Array.from([LOCK_WRAP_FORMAT_VERSION]))
}

function sealLdk(ldk: Uint8Array, kek: Uint8Array, nonce: Uint8Array, kind: LockMethodKind): Uint8Array {
  return aeadSeal(kek, nonce, ldk, wrapAad(kind))
}

function openLdk(wrap: Uint8Array, kek: Uint8Array, nonce: Uint8Array, kind: LockMethodKind): Uint8Array {
  let ldk: Uint8Array
  try {
    ldk = aeadOpen(kek, nonce, wrap, wrapAad(kind))
  } catch {
    throw new AppLockAuthError()
  }
  if (ldk.length !== LDK_BYTES) throw new AppLockAuthError()
  return ldk
}

// --- knowledge factor (passphrase / PIN) ------------------------------------

export async function wrapKnowledge(
  ldk: Uint8Array,
  secret: string,
  kind: 'pass' | 'pin',
  opts: { params?: Argon2Params; kdf?: Argon2Kdf } = {},
): Promise<KnowledgeWrap> {
  const params = opts.params ?? DEFAULT_LOCK_ARGON2
  const argonSalt = randomBytes(LOCK_SALT_BYTES)
  const hkdfSalt = randomBytes(LOCK_SALT_BYTES)
  const { key, nonce } = await kekFromSecret(secret, argonSalt, hkdfSalt, params, opts.kdf ?? argon2idKdf)
  return { kind, argonSalt, hkdfSalt, m: params.m, t: params.t, p: params.p, wrap: sealLdk(ldk, key, nonce, kind) }
}

export async function unwrapKnowledge(
  rec: KnowledgeWrap,
  secret: string,
  kdf: Argon2Kdf = argon2idKdf,
): Promise<Uint8Array> {
  const { key, nonce } = await kekFromSecret(secret, rec.argonSalt, rec.hkdfSalt, { m: rec.m, t: rec.t, p: rec.p }, kdf)
  return openLdk(rec.wrap, key, nonce, rec.kind)
}

// --- biometric (WebAuthn PRF) -----------------------------------------------
// The PRF secret is supplied by the platform authenticator (the UI does the
// WebAuthn calls); this module only wraps/unwraps with it.

export function wrapBiometric(ldk: Uint8Array, credentialId: Uint8Array, prfSecret: Uint8Array): BioWrap {
  const hkdfSalt = randomBytes(LOCK_SALT_BYTES)
  const { key, nonce } = kekFromRaw(prfSecret, hkdfSalt)
  return { kind: 'bio', credentialId, hkdfSalt, wrap: sealLdk(ldk, key, nonce, 'bio') }
}

export function unwrapBiometric(rec: BioWrap, prfSecret: Uint8Array): Uint8Array {
  const { key, nonce } = kekFromRaw(prfSecret, rec.hkdfSalt)
  return openLdk(rec.wrap, key, nonce, 'bio')
}

// --- sub-keys off the LDK ---------------------------------------------------
// Independent purpose-keys via HKDF with distinct info. The LDK is already a
// uniformly random 32 bytes, so a fixed (zero) salt is fine; the info separates
// uses. Fresh per-record salts for the actual row/blob AEAD are added by callers.

export function subKey(ldk: Uint8Array, info: string): Uint8Array {
  return hkdfSha256(ldk, new Uint8Array(32), utf8(info), 32)
}

// --- generic at-rest blob sealing (used for the contact store) --------------
// Seal an arbitrary keystore blob under a sub-key with a fresh per-blob salt, so
// the same sub-key never reuses a keystream. `label` is bound in the AAD so a
// blob for one keystore slot cannot be swapped into another. Wire = salt || ct.

const BLOB_INFO = 'Nightjar_Blob_v1'
const BLOB_AAD_TAG = 'Nightjar-blob-v1'
const BLOB_SALT_BYTES = 16

export function sealBlob(subkey: Uint8Array, label: string, plain: Uint8Array): Uint8Array {
  const salt = randomBytes(BLOB_SALT_BYTES)
  const out = hkdfSha256(subkey, salt, utf8(BLOB_INFO), XCHACHA_KEY_BYTES + XCHACHA_NONCE_BYTES)
  const ct = aeadSeal(out.slice(0, XCHACHA_KEY_BYTES), out.slice(XCHACHA_KEY_BYTES), plain, domainSeparate(BLOB_AAD_TAG, utf8(label)))
  return concatBytes(salt, ct)
}

export function openBlob(subkey: Uint8Array, label: string, blob: Uint8Array): Uint8Array {
  if (blob.length < BLOB_SALT_BYTES + 16) throw new AppLockAuthError()
  const salt = blob.slice(0, BLOB_SALT_BYTES)
  const out = hkdfSha256(subkey, salt, utf8(BLOB_INFO), XCHACHA_KEY_BYTES + XCHACHA_NONCE_BYTES)
  try {
    return aeadOpen(out.slice(0, XCHACHA_KEY_BYTES), out.slice(XCHACHA_KEY_BYTES), blob.slice(BLOB_SALT_BYTES), domainSeparate(BLOB_AAD_TAG, utf8(label)))
  } catch {
    throw new AppLockAuthError()
  }
}

// --- LockRecord serialization (for the KeyStore) ----------------------------
// JSON with base64url byte fields. No secret material is in a LockRecord (only
// wraps + public salts + params), so plaintext-at-rest is fine and intended.

/** The blob is not a lock record we understand (corruption or a newer format). */
export class LockRecordFormatError extends Error {
  constructor(msg: string) {
    super(msg)
    this.name = 'LockRecordFormatError'
  }
}

export function encodeLockRecord(rec: LockRecord): Uint8Array {
  const methods = rec.methods.map((m) =>
    m.kind === 'bio'
      ? { kind: 'bio', credentialId: b64encode(m.credentialId), hkdfSalt: b64encode(m.hkdfSalt), wrap: b64encode(m.wrap) }
      : {
          kind: m.kind,
          argonSalt: b64encode(m.argonSalt),
          hkdfSalt: b64encode(m.hkdfSalt),
          m: m.m,
          t: m.t,
          p: m.p,
          wrap: b64encode(m.wrap),
        },
  )
  return utf8(JSON.stringify({ version: rec.version, methods }))
}

export function decodeLockRecord(bytes: Uint8Array): LockRecord {
  let obj: unknown
  try {
    obj = JSON.parse(new TextDecoder().decode(bytes))
  } catch {
    throw new LockRecordFormatError('lock record is not valid JSON')
  }
  const o = obj as { version?: unknown; methods?: unknown }
  if (!o || typeof o !== 'object' || o.version !== 1 || !Array.isArray(o.methods) || o.methods.length === 0) {
    throw new LockRecordFormatError('unsupported or empty lock record')
  }
  const methods: WrapRecord[] = o.methods.map((raw: unknown) => {
    const r = raw as Record<string, unknown>
    if (r.kind === 'bio') {
      if (typeof r.credentialId !== 'string' || typeof r.hkdfSalt !== 'string' || typeof r.wrap !== 'string') {
        throw new LockRecordFormatError('malformed biometric wrap')
      }
      return { kind: 'bio', credentialId: b64decode(r.credentialId), hkdfSalt: b64decode(r.hkdfSalt), wrap: b64decode(r.wrap) }
    }
    if (r.kind === 'pass' || r.kind === 'pin') {
      if (
        typeof r.argonSalt !== 'string' ||
        typeof r.hkdfSalt !== 'string' ||
        typeof r.wrap !== 'string' ||
        !Number.isInteger(r.m) ||
        !Number.isInteger(r.t) ||
        !Number.isInteger(r.p)
      ) {
        throw new LockRecordFormatError('malformed knowledge wrap')
      }
      return {
        kind: r.kind,
        argonSalt: b64decode(r.argonSalt),
        hkdfSalt: b64decode(r.hkdfSalt),
        m: r.m as number,
        t: r.t as number,
        p: r.p as number,
        wrap: b64decode(r.wrap),
      }
    }
    throw new LockRecordFormatError(`unknown wrap kind ${String(r.kind)}`)
  })
  return { version: 1, methods }
}
