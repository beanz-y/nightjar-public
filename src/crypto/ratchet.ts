// The Double Ratchet (DESIGN 5). The per-conversation message engine: a fresh
// key per message (forward secrecy), a DH ratchet that heals after a compromise
// (post-compromise security), and out-of-order handling via stored skipped keys.
//
// The state machine is PURE and immutable from the caller's view: encrypt and
// decrypt return a NEW state and never mutate the input. That is how the
// section 5.3 discipline is realised:
//   - Receive works on a clone and returns the new state ONLY on AEAD success,
//     so a forged or replayed packet throws and leaves the caller's state
//     untouched ("commit only on AEAD success").
//   - Send returns the advanced state; the caller persists it BEFORE releasing
//     the envelope, and retransmits the byte-identical envelope on retry, so a
//     crash can never reuse a message key ("commit before release, encrypt
//     once").
// Atomic persistence and the single-writer lock are P3; wiring the initial
// message + X3DH replay guard onto the wire is P4.

import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { INFO_DR_ROOT, INFO_MSG_KEY, MAX_SKIP, VERSION } from './constants'
import {
  type KeyPair,
  aeadOpen,
  aeadSeal,
  bytesEqual,
  concatBytes,
  hkdfSha256,
  hmacSha256,
  u32be,
  utf8,
  x25519Dh,
  x25519Generate,
} from './primitives'

export interface MessageHeader {
  readonly version: number
  readonly dhPub: Uint8Array
  readonly pn: number // length of the previous sending chain
  readonly n: number // message number in the current sending chain
}

export interface RatchetState {
  dhs: KeyPair | null // our current ratchet keypair (sending)
  dhr: Uint8Array | null // remote ratchet public key (receiving)
  rk: Uint8Array // root key
  cks: Uint8Array | null // sending chain key
  ckr: Uint8Array | null // receiving chain key
  ns: number // sending message number
  nr: number // receiving message number
  pn: number // length of the previous sending chain
  skipped: Map<string, Uint8Array> // key `${hex(dhr)}:${n}` -> message key
  ad: Uint8Array // X3DH associated data, constant for the session
}

// --- key derivations (DESIGN 5.1), all domain-separated -------------------

const MSG_KEY_SALT = new Uint8Array(32)

/** Root/DH-ratchet step: (RK', CK) = HKDF(ikm = DH_out, salt = RK, info). */
export function kdfRk(rk: Uint8Array, dhOut: Uint8Array): { rk: Uint8Array; ck: Uint8Array } {
  const out = hkdfSha256(dhOut, rk, utf8(INFO_DR_ROOT), 64)
  return { rk: out.slice(0, 32), ck: out.slice(32, 64) }
}

/** Symmetric chain step: MK = HMAC(CK, 0x01), CK' = HMAC(CK, 0x02). */
export function kdfCk(ck: Uint8Array): { ck: Uint8Array; mk: Uint8Array } {
  return {
    mk: hmacSha256(ck, Uint8Array.from([0x01])),
    ck: hmacSha256(ck, Uint8Array.from([0x02])),
  }
}

/** Message-key expansion: HKDF(MK) -> 32-byte content key || 24-byte nonce. */
export function expandMk(mk: Uint8Array): { key: Uint8Array; nonce: Uint8Array } {
  const out = hkdfSha256(mk, MSG_KEY_SALT, utf8(INFO_MSG_KEY), 56)
  return { key: out.slice(0, 32), nonce: out.slice(32, 56) }
}

/** Canonical header encoding, authenticated as AEAD associated data (DESIGN 5.2). */
export function encodeHeader(h: MessageHeader): Uint8Array {
  return concatBytes(Uint8Array.from([h.version]), h.dhPub, u32be(h.pn), u32be(h.n))
}

function skKey(dhr: Uint8Array, n: number): string {
  return `${bytesToHex(dhr)}:${n}`
}

// --- initialisation, seeded from X3DH (DESIGN 4 -> 5) ---------------------

/** Initiator (Alice): she generates the first ratchet key and takes one DH
 *  ratchet step against the responder's signed prekey, so she can send first. */
export function initRatchetInitiator(
  sk: Uint8Array,
  ad: Uint8Array,
  remoteSpkPub: Uint8Array,
  firstRatchetKey?: KeyPair,
): RatchetState {
  // firstRatchetKey is a test-only seam for deterministic known-answer vectors;
  // production omits it and a fresh ratchet key is generated.
  const dhs = firstRatchetKey ?? x25519Generate()
  const { rk, ck } = kdfRk(sk, x25519Dh(dhs.privateKey, remoteSpkPub))
  return { dhs, dhr: remoteSpkPub, rk, cks: ck, ckr: null, ns: 0, nr: 0, pn: 0, skipped: new Map(), ad }
}

/** Responder (Bob): his ratchet key is his signed prekey keypair; he cannot
 *  send until he has received the initiator's first message. */
export function initRatchetResponder(sk: Uint8Array, ad: Uint8Array, spkKeyPair: KeyPair): RatchetState {
  return { dhs: spkKeyPair, dhr: null, rk: sk, cks: null, ckr: null, ns: 0, nr: 0, pn: 0, skipped: new Map(), ad }
}

// --- encrypt / decrypt ----------------------------------------------------

export function ratchetEncrypt(
  state: RatchetState,
  plaintext: Uint8Array,
): { state: RatchetState; header: MessageHeader; ciphertext: Uint8Array } {
  if (!state.cks || !state.dhs) {
    throw new Error('ratchet: cannot send before receiving the first message')
  }
  const { ck, mk } = kdfCk(state.cks)
  const header: MessageHeader = { version: VERSION, dhPub: state.dhs.publicKey, pn: state.pn, n: state.ns }
  const { key, nonce } = expandMk(mk)
  const ciphertext = aeadSeal(key, nonce, plaintext, concatBytes(state.ad, encodeHeader(header)))
  // Return the advanced state; the caller MUST persist it before releasing the
  // envelope, and MUST NOT re-encrypt on retry (DESIGN 5.3 send discipline).
  const newState: RatchetState = { ...cloneState(state), cks: ck, ns: state.ns + 1 }
  return { state: newState, header, ciphertext }
}

export function ratchetDecrypt(
  state: RatchetState,
  header: MessageHeader,
  ciphertext: Uint8Array,
): { state: RatchetState; plaintext: Uint8Array } {
  // 1. Bound the work BEFORE deriving anything: a forged header with a huge n or
  //    pn must be rejected without running the chain (compute + storage DoS).
  assertWithinSkipBound(state, header)

  // 2. All mutation happens on a clone; we return it ONLY if the AEAD verifies.
  const s = cloneState(state)

  // 3. A stored skipped key handles an out-of-order arrival directly.
  const stored = s.skipped.get(skKey(header.dhPub, header.n))
  if (stored) {
    const plaintext = openMessage(stored, header, ciphertext, s.ad)
    s.skipped.delete(skKey(header.dhPub, header.n))
    return { state: s, plaintext }
  }

  // 4. A new remote ratchet key means a DH ratchet step.
  if (!s.dhr || !bytesEqual(header.dhPub, s.dhr)) {
    skipMessageKeys(s, header.pn)
    dhRatchet(s, header)
  }

  // 5. Advance the receiving chain to this message, then decrypt.
  skipMessageKeys(s, header.n)
  if (s.ckr === null) {
    // A header naming our current dhr while no receiving chain exists yet (e.g. a
    // forged packet citing the victim's PUBLIC signed prekey before any real
    // message). Fail in the same shape as an auth failure, never a raw TypeError.
    throw new Error('ratchet: no receiving chain for this header')
  }
  const { ck, mk } = kdfCk(s.ckr)
  const plaintext = openMessage(mk, header, ciphertext, s.ad) // throws -> old state kept
  s.ckr = ck
  s.nr += 1
  return { state: s, plaintext }
}

// --- internals ------------------------------------------------------------

function openMessage(mk: Uint8Array, header: MessageHeader, ciphertext: Uint8Array, ad: Uint8Array): Uint8Array {
  const { key, nonce } = expandMk(mk)
  return aeadOpen(key, nonce, ciphertext, concatBytes(ad, encodeHeader(header)))
}

function assertWithinSkipBound(state: RatchetState, header: MessageHeader): void {
  const sameChain = state.dhr !== null && bytesEqual(header.dhPub, state.dhr)
  if (sameChain) {
    if (header.n - state.nr > MAX_SKIP) throw new Error('ratchet: skip bound exceeded')
  } else {
    if (state.ckr !== null && header.pn - state.nr > MAX_SKIP) {
      throw new Error('ratchet: skip bound exceeded (previous chain)')
    }
    if (header.n > MAX_SKIP) throw new Error('ratchet: skip bound exceeded (new chain)')
  }
}

function skipMessageKeys(s: RatchetState, until: number): void {
  if (s.ckr === null) return
  while (s.nr < until) {
    const { ck, mk } = kdfCk(s.ckr)
    // Storage cap (DESIGN 5.3): evict the oldest skipped key when full. In the
    // real client the evicted message ids are surfaced as "unrecoverable".
    if (s.skipped.size >= MAX_SKIP) {
      const oldest = s.skipped.keys().next().value
      if (oldest !== undefined) s.skipped.delete(oldest)
    }
    s.skipped.set(skKey(s.dhr as Uint8Array, s.nr), mk)
    s.ckr = ck
    s.nr += 1
  }
}

function dhRatchet(s: RatchetState, header: MessageHeader): void {
  s.pn = s.ns
  s.ns = 0
  s.nr = 0
  s.dhr = header.dhPub
  const recv = kdfRk(s.rk, x25519Dh((s.dhs as KeyPair).privateKey, s.dhr))
  s.rk = recv.rk
  s.ckr = recv.ck
  s.dhs = x25519Generate()
  const send = kdfRk(s.rk, x25519Dh(s.dhs.privateKey, s.dhr))
  s.rk = send.rk
  s.cks = send.ck
}

function cloneState(s: RatchetState): RatchetState {
  return {
    dhs: s.dhs ? { privateKey: s.dhs.privateKey.slice(), publicKey: s.dhs.publicKey.slice() } : null,
    dhr: s.dhr ? s.dhr.slice() : null,
    rk: s.rk.slice(),
    cks: s.cks ? s.cks.slice() : null,
    ckr: s.ckr ? s.ckr.slice() : null,
    ns: s.ns,
    nr: s.nr,
    pn: s.pn,
    skipped: new Map(Array.from(s.skipped, ([k, v]) => [k, v.slice()])),
    ad: s.ad.slice(),
  }
}

// --- serialization (DESIGN 5.4: sessions survive serialization; P3 persists) --

export interface RatchetSnapshot {
  dhsPriv: string | null
  dhsPub: string | null
  dhr: string | null
  rk: string
  cks: string | null
  ckr: string | null
  ns: number
  nr: number
  pn: number
  skipped: Array<{ dhr: string; n: number; mk: string }>
  ad: string
}

export function serializeRatchet(s: RatchetState): RatchetSnapshot {
  return {
    dhsPriv: s.dhs ? bytesToHex(s.dhs.privateKey) : null,
    dhsPub: s.dhs ? bytesToHex(s.dhs.publicKey) : null,
    dhr: s.dhr ? bytesToHex(s.dhr) : null,
    rk: bytesToHex(s.rk),
    cks: s.cks ? bytesToHex(s.cks) : null,
    ckr: s.ckr ? bytesToHex(s.ckr) : null,
    ns: s.ns,
    nr: s.nr,
    pn: s.pn,
    skipped: Array.from(s.skipped, ([k, v]) => {
      const idx = k.lastIndexOf(':')
      return { dhr: k.slice(0, idx), n: Number(k.slice(idx + 1)), mk: bytesToHex(v) }
    }),
    ad: bytesToHex(s.ad),
  }
}

export function deserializeRatchet(snap: RatchetSnapshot): RatchetState {
  return {
    dhs:
      snap.dhsPriv && snap.dhsPub
        ? { privateKey: hexToBytes(snap.dhsPriv), publicKey: hexToBytes(snap.dhsPub) }
        : null,
    dhr: snap.dhr ? hexToBytes(snap.dhr) : null,
    rk: hexToBytes(snap.rk),
    cks: snap.cks ? hexToBytes(snap.cks) : null,
    ckr: snap.ckr ? hexToBytes(snap.ckr) : null,
    ns: snap.ns,
    nr: snap.nr,
    pn: snap.pn,
    skipped: new Map(snap.skipped.map((e) => [`${e.dhr}:${e.n}`, hexToBytes(e.mk)])),
    ad: hexToBytes(snap.ad),
  }
}
