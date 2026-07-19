// Thin, single-provider wrappers over the audited @noble primitives (DESIGN 2).
// Everything the rest of the app does cryptographically routes through here, so
// the choice of library and the domain-separation discipline live in one place.
// @noble is the SOLE X25519/Ed25519 provider (DESIGN 8.1, P0): we do not mix in
// WebCrypto for curve ops, to avoid a two-provider divergence edge case.

import { ed25519, x25519 } from '@noble/curves/ed25519'
import { sha256, sha512 } from '@noble/hashes/sha2'
import { hkdf } from '@noble/hashes/hkdf'
import { hmac } from '@noble/hashes/hmac'
import { xchacha20poly1305 } from '@noble/ciphers/chacha'
import { base32 } from '@scure/base'

const TEXT = new TextEncoder()

export interface KeyPair {
  readonly privateKey: Uint8Array
  readonly publicKey: Uint8Array
}

// --- bytes helpers -------------------------------------------------------

export const utf8 = (s: string): Uint8Array => TEXT.encode(s)

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n)
  crypto.getRandomValues(b)
  return b
}

export function concatBytes(...arrays: readonly Uint8Array[]): Uint8Array {
  let total = 0
  for (const a of arrays) total += a.length
  const out = new Uint8Array(total)
  let at = 0
  for (const a of arrays) {
    out.set(a, at)
    at += a.length
  }
  return out
}

/** Constant-time equality. Use for any comparison of secret or authenticated bytes. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

/** Lexicographic byte comparison. Ordering only (NOT constant-time); used to
 *  canonicalize the safety-number input, which is public. */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length)
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] - b[i]
  }
  return a.length - b.length
}

/** 4-byte big-endian encoding of an unsigned 32-bit integer. */
export function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, n, false)
  return b
}

/** 8-byte big-endian encoding of a non-negative integer up to 2^53 (safe JS
 *  integer range), used for millisecond timestamps in signed prekeys. */
export function u64be(n: number): Uint8Array {
  const b = new Uint8Array(8)
  const dv = new DataView(b.buffer)
  dv.setUint32(0, Math.floor(n / 0x100000000), false)
  dv.setUint32(4, n >>> 0, false)
  return b
}

/**
 * Domain separation for signatures and hashed transcripts (DESIGN 2, 4.1).
 * Every field, starting with the tag itself, is length-framed as
 * u32be(length) || bytes. Framing the TAG (not only the parts) makes the
 * encoding STRUCTURALLY injective: it holds even if one tag were a byte-prefix
 * of another (e.g. "spk" vs "spk-v1"), so a value signed under one tag can never
 * be reinterpreted under a different one. This is the shared encoding behind the
 * idkbind / spk / auth signatures; changing the layout is a wire-format change.
 */
export function domainSeparate(tag: string, ...parts: readonly Uint8Array[]): Uint8Array {
  const tagBytes = utf8(tag)
  const chunks: Uint8Array[] = [u32be(tagBytes.length), tagBytes]
  for (const part of parts) chunks.push(u32be(part.length), part)
  return concatBytes(...chunks)
}

// --- hashes / KDFs -------------------------------------------------------

export const hash256 = (m: Uint8Array): Uint8Array => sha256(m)
export const hash512 = (m: Uint8Array): Uint8Array => sha512(m)

export function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  return hkdf(sha256, ikm, salt, info, length)
}

export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256, key, data)
}

// --- X25519 (DH) ---------------------------------------------------------

export function x25519Generate(): KeyPair {
  const privateKey = x25519.utils.randomSecretKey()
  return { privateKey, publicKey: x25519.getPublicKey(privateKey) }
}

export function x25519Public(privateKey: Uint8Array): Uint8Array {
  return x25519.getPublicKey(privateKey)
}

/** Raw X25519. @noble throws on an all-zero (low-order) result, which is the
 *  behaviour we want: a contributory-key attack fails closed rather than
 *  yielding a predictable shared secret. */
export function x25519Dh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(privateKey, publicKey)
}

// --- Ed25519 (signatures) ------------------------------------------------

export function ed25519Generate(): KeyPair {
  const privateKey = ed25519.utils.randomSecretKey()
  return { privateKey, publicKey: ed25519.getPublicKey(privateKey) }
}

export function ed25519Public(privateKey: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(privateKey)
}

export function ed25519Sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
  return ed25519.sign(message, privateKey)
}

export function ed25519Verify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  return ed25519.verify(signature, message, publicKey)
}

// --- AEAD (XChaCha20-Poly1305) -------------------------------------------

export const XCHACHA_KEY_BYTES = 32
export const XCHACHA_NONCE_BYTES = 24

export function aeadSeal(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Uint8Array {
  return xchacha20poly1305(key, nonce, aad).encrypt(plaintext)
}

/** Throws if the tag fails (tampered ciphertext or wrong AAD/key/nonce). */
export function aeadOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array,
): Uint8Array {
  return xchacha20poly1305(key, nonce, aad).decrypt(ciphertext)
}

// --- encoding ------------------------------------------------------------

/** Lowercase, unpadded RFC 4648 base32. Used for the full-width user id. */
export function base32lower(bytes: Uint8Array): string {
  return base32.encode(bytes).replace(/=+$/, '').toLowerCase()
}
